#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset Jumpbox – aufgezeichnete SSH-Session zu einem Zielhost.

Ablauf:
  1. Operator meldet sich an der Jumpbox an und ruft `na-jump <ziel>` auf
     (bzw. wird per sshd ForceCommand automatisch hierher geleitet).
  2. Es wird eine Session-UUID erzeugt und per `script` die komplette
     Terminal-Session aufgezeichnet, während eine SSH-Verbindung zum Ziel
     aufgebaut wird. Die UUID wird via SetEnv an das Ziel durchgereicht
     (dort taggt der Kommando-Hook seine Logs damit – siehe na_cmdlog.sh).
  3. Nach dem Logout wird die Aufzeichnung an NetAsset hochgeladen
     (POST /api/v1/sessions/ingest).

Konfiguration: na_jump.conf  ([netasset] api_url/api_key, [jump] optional)
Aufruf:
  na-jump <ziel>            # ziel = host oder user@host
  na-jump --list           # erlaubte Ziele (falls allow_targets gesetzt)
"""

import argparse
import configparser
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

CONF_PATHS = [
    Path(__file__).parent / "na_jump.conf",
    Path("/etc/netasset/na_jump.conf"),
]


def load_config() -> dict:
    cfg = configparser.ConfigParser()
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            break
    na = cfg["netasset"] if "netasset" in cfg else {}
    jump = cfg["jump"] if "jump" in cfg else {}
    allow = [t.strip() for t in jump.get("allow_targets", "").split(",") if t.strip()]
    return {
        "api_url": os.environ.get("NETASSET_URL", na.get("api_url", "https://ocs.kiste.org")).rstrip("/"),
        "api_key": os.environ.get("NETASSET_API_KEY", na.get("api_key", "")),
        "timeout": int(na.get("timeout", "30")),
        "ssh_options": jump.get("ssh_options", "").split() if jump.get("ssh_options") else [],
        "allow_targets": allow,
    }


def resolve_target(argv: list[str], config: dict) -> str:
    """Ermittelt das Ziel aus Argument oder SSH_ORIGINAL_COMMAND (ForceCommand)."""
    target = argv[0] if argv else ""
    if not target:
        # ForceCommand-Modus: ursprüngliches Kommando = gewünschtes Ziel
        orig = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
        target = orig.split()[0] if orig else ""
    if not target:
        sys.exit("Kein Ziel angegeben. Aufruf: na-jump <host|user@host>")
    if config["allow_targets"]:
        host = target.split("@")[-1]
        if host not in config["allow_targets"]:
            sys.exit(f"Ziel '{host}' nicht in allow_targets erlaubt.")
    return target


def record_session(target: str, session_uuid: str, config: dict) -> tuple[str, str, int]:
    """
    Baut die SSH-Verbindung auf und zeichnet sie mit `script` auf.
    Gibt (typescript, timing, exit_code) zurück.
    """
    if not shutil.which("script"):
        sys.exit("'script' (util-linux) ist nicht installiert – Aufzeichnung nicht möglich.")

    tmpdir = tempfile.mkdtemp(prefix="na-jump-")
    typescript = os.path.join(tmpdir, "typescript")
    timing = os.path.join(tmpdir, "timing")

    ssh_cmd = ["ssh", "-o", f"SetEnv=NA_SESSION_ID={session_uuid}"]
    ssh_cmd += config["ssh_options"]
    ssh_cmd += [target]
    ssh_str = " ".join(ssh_cmd)

    # script-Aufruf möglichst kompatibel: neue util-linux nutzt --log-out/--log-timing,
    # ältere nur Positional + --timing. Fallback: nur Typescript ohne Timing.
    attempts = [
        ["script", "-q", "--log-out", typescript, "--log-timing", timing, "-c", ssh_str],
        ["script", "-q", "--timing=" + timing, "-c", ssh_str, typescript],
        ["script", "-q", "-c", ssh_str, typescript],
    ]
    exit_code = 1
    for cmd in attempts:
        try:
            proc = subprocess.run(cmd)
            exit_code = proc.returncode
            break
        except FileNotFoundError:
            continue
        except Exception:
            continue

    ts = _read_text(typescript)
    tm = _read_text(timing)
    shutil.rmtree(tmpdir, ignore_errors=True)
    return ts, tm, exit_code


def _read_text(path: str) -> str:
    try:
        with open(path, "rb") as f:
            # Terminal-Streams enthalten Steuerzeichen – tolerant dekodieren
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def upload(config: dict, payload: dict) -> None:
    if not config["api_key"]:
        print("WARN: NETASSET_API_KEY fehlt – Aufzeichnung wird NICHT hochgeladen.", file=sys.stderr)
        return
    url = f"{config['api_url']}/api/v1/sessions/ingest"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "X-API-Key": config["api_key"]},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config["timeout"]) as resp:
            json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"WARN: Upload fehlgeschlagen ({e.code}): {e.read().decode(errors='replace')[:300]}",
              file=sys.stderr)
    except Exception as e:
        print(f"WARN: Upload fehlgeschlagen: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="NetAsset Jumpbox – aufgezeichnete SSH-Session")
    parser.add_argument("target", nargs="?", help="host oder user@host")
    parser.add_argument("--list", action="store_true", help="erlaubte Ziele anzeigen")
    args = parser.parse_args()

    config = load_config()

    if args.list:
        targets = config["allow_targets"]
        print("\n".join(targets) if targets else "(keine allow_targets gesetzt – alle Ziele erlaubt)")
        return

    target = resolve_target([args.target] if args.target else [], config)

    session_uuid = uuid.uuid4().hex
    operator = os.environ.get("SUDO_USER") or getpass.getuser()
    jumpbox_host = socket.gethostname()
    client_ip = (os.environ.get("SSH_CONNECTION", "").split() or [None])[0]
    target_user, _, target_host = target.partition("@")
    if not target_host:
        target_host = target_user
        target_user = None

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    print(f"[na-jump] Session {session_uuid} → {target} (wird aufgezeichnet)")

    typescript, timing, exit_code = record_session(target, session_uuid, config)

    ended = datetime.now(timezone.utc)
    duration = int(time.monotonic() - t0)

    upload(config, {
        "session_uuid": session_uuid,
        "operator": operator,
        "jumpbox_host": jumpbox_host,
        "target_host": target_host,
        "target_user": target_user,
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "duration_sec": duration,
        "exit_code": exit_code,
        "recording_format": "script-typescript",
        "recording": typescript,
        "timing": timing,
        "client_ip": client_ip,
    })
    print(f"[na-jump] Session beendet ({duration}s), Aufzeichnung übertragen.")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
