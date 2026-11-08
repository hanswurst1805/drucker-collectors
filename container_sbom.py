#!/usr/bin/env python3
from __future__ import annotations
"""
Container-SBOM: liest die Paketlisten laufender Docker-/Podman-Images mit Syft.

Wird von netasset_collector.py und spool_collector.py genutzt (optional – fehlt
diese Datei oder Syft, läuft der Collector normal weiter). Liest nur das Image,
greift nicht in laufende Container ein. Jedes Image wird nur gescannt, wenn es
neu ist oder der letzte Scan älter als RESCAN_SECONDS ist.

Syft installieren: install_syft.sh
"""

import glob
import json
import logging
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

log = logging.getLogger("netasset-collector")

RESCAN_SECONDS = 7 * 86400
LIST_TIMEOUT = 20
SCAN_TIMEOUT = 900

# Ohne API-Socket: Image einhängen und das Dateisystem scannen (kein Tar, kein Dienst)
_MOUNT_SCAN = (
    'm=$(podman image mount "$1") || exit 1; '
    'SYFT_CHECK_FOR_APP_UPDATE=false SYFT_PARALLELISM=2 SYFT_FILE_METADATA_SELECTION=none '
    '"$2" "dir:$m" --override-default-catalogers image -q -o cyclonedx-json; rc=$?; '
    'podman image unmount "$1" >/dev/null 2>&1; exit $rc'
)


def find_syft() -> str | None:
    candidates = [os.environ.get("DRUCKER_SYFT"), shutil.which("syft"), "/opt/drucker-tools/syft"]
    candidates += sorted(glob.glob("/home/*/drucker-tools/syft"))
    candidates.append(str(Path.home() / "drucker-tools/syft"))
    for path in candidates:
        if path and os.access(path, os.X_OK):
            return path
    return None


def _root_may_run(path: str) -> bool:
    """Als root nur eine Binary starten, die kein anderer Benutzer ändern kann."""
    st = os.stat(path)
    return st.st_uid == 0 and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _contexts() -> list[dict]:
    """Docker, Podman und – als root – das rootless Podman jedes aktiven Benutzers."""
    ctxs: list[dict] = []
    if shutil.which("docker") and Path("/var/run/docker.sock").exists():
        ctxs.append({"engine": "docker", "user": None, "uid": None})
    if shutil.which("podman"):
        ctxs.append({"engine": "podman", "user": None, "uid": None})
        if hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("runuser"):
            import pwd
            run_user = Path("/run/user")
            for d in sorted(run_user.iterdir()) if run_user.is_dir() else []:
                if d.name.isdigit() and d.name != "0":
                    try:
                        pw = pwd.getpwuid(int(d.name))
                    except KeyError:
                        continue
                    ctxs.append({"engine": "podman", "user": pw.pw_name, "uid": pw.pw_uid, "home": pw.pw_dir})
    return ctxs


def _argv(ctx: dict, args: list[str]) -> list[str]:
    if ctx["user"]:
        # runuser -u behält root's HOME – rootless Podman scheitert sonst an /root/.config
        return ["runuser", "-u", ctx["user"], "--", "env", f"HOME={ctx['home']}", f"USER={ctx['user']}",
                f"LOGNAME={ctx['user']}", f"XDG_RUNTIME_DIR=/run/user/{ctx['uid']}", ctx["engine"], *args]
    return [ctx["engine"], *args]


def _run(argv: list[str], timeout: int) -> str | None:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True, cwd="/").stdout
    except (subprocess.SubprocessError, OSError) as e:
        stderr = getattr(e, "stderr", "") or ""
        log.warning("Container: %s fehlgeschlagen: %s", argv[0], (stderr.strip().splitlines() or [e])[-1])
        return None


def list_running_images() -> list[dict] | None:
    """Laufende Images, je Image-ID einmal. None, wenn eine Engine nicht antwortet."""
    images: dict[str, dict] = {}
    for ctx in _contexts():
        out = _run(_argv(ctx, ["ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"]), LIST_TIMEOUT)
        if out is None:
            return None     # lieber nichts melden als Images fälschlich entfernen
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 3 or not parts[2]:
                continue    # Pod-Infra-Container haben kein Image
            cid, name, ref = parts[:3]
            inspected = _run(_argv(ctx, ["inspect", "--format", "{{.Image}}", cid]), LIST_TIMEOUT)
            if not inspected or not inspected.strip():
                return None
            image_id = inspected.strip().removeprefix("sha256:")
            entry = images.setdefault(image_id, {"image_id": image_id, "image_ref": ref, "containers": [], "_ctx": ctx})
            entry["containers"].append(name)
    return list(images.values())


def _scan(syft: str, ctx: dict, image_id: str) -> dict | None:
    if ctx["engine"] == "docker":
        env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false", SYFT_PARALLELISM="2", SYFT_FILE_METADATA_SELECTION="none")
        try:
            out = subprocess.run([syft, f"docker:{image_id}", "-q", "-o", "cyclonedx-json"], capture_output=True,
                                 text=True, timeout=SCAN_TIMEOUT, check=True, env=env).stdout
        except (subprocess.SubprocessError, OSError) as e:
            log.warning("Syft %s: %s", image_id[:12], e)
            return None
    elif ctx["user"]:
        out = _run(_argv(ctx, ["unshare", "sh", "-c", _MOUNT_SCAN, "_", image_id, syft]), SCAN_TIMEOUT)
    else:
        out = _run(["sh", "-c", _MOUNT_SCAN, "_", image_id, syft], SCAN_TIMEOUT)
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        log.warning("Syft %s: keine gültige Ausgabe", image_id[:12])
        return None


def _packages(bom: dict) -> tuple[list[dict], str | None]:
    packages, distro = [], None
    for comp in bom.get("components") or []:
        if comp.get("type") == "operating-system":
            distro = f'{comp.get("name", "")} {comp.get("version", "")}'.strip()
        elif comp.get("type") != "file" and comp.get("purl") and comp.get("name") and comp.get("version"):
            packages.append({"name": comp["name"], "version": comp["version"], "purl": comp["purl"],
                             "type": comp["purl"][4:].split("/")[0]})
    return packages, distro


def _state_file() -> Path:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/drucker/container_sbom.json")
    return Path.home() / ".cache/drucker/container_sbom.json"


def _load_state() -> dict:
    try:
        return json.loads(_state_file().read_text())
    except (OSError, ValueError):
        return {}


def collect() -> list[dict] | None:
    """
    Images für POST /api/v1/container-images. Unveränderte Images ohne Paketliste.
    None = nichts melden (kein Syft oder eine Engine antwortet nicht).
    """
    syft = find_syft()
    if not syft:
        log.info("Container-SBOM: Syft nicht gefunden, übersprungen (install_syft.sh)")
        return None
    images = list_running_images()
    if images is None:
        return None
    state, now = _load_state(), time.time()
    for image in images:
        ctx = image.pop("_ctx")
        if now - state.get(image["image_id"], 0) < RESCAN_SECONDS:
            continue
        if not ctx["user"] and hasattr(os, "geteuid") and os.geteuid() == 0 and not _root_may_run(syft):
            log.warning("Container-SBOM: %s gehört nicht root, %s nicht gescannt", syft, image["image_ref"])
            continue
        started = time.time()
        bom = _scan(syft, ctx, image["image_id"])
        if bom is None:
            continue
        image["packages"], image["distro"] = _packages(bom)
        log.info("Container-SBOM: %s – %d Pakete (%.0fs)", image["image_ref"], len(image["packages"]), time.time() - started)
    return images


def remember(images: list[dict]) -> None:
    """Nach erfolgreichem Melden/Ablegen: gescannte Images merken, nicht mehr laufende vergessen."""
    state, now = _load_state(), time.time()
    new = {i["image_id"]: (now if "packages" in i else state.get(i["image_id"], 0)) for i in images}
    path = _state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(new))
