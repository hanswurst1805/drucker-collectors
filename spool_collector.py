#!/usr/bin/env python3
from __future__ import annotations
"""
DRUCKER Spool Collector – sammelt wie netasset_collector.py, lädt aber nicht
hoch, sondern legt das Ergebnis als JSON-Datei in einem lokalen Spool-
Verzeichnis ab. Ein Server, der diesen Host erreicht, holt die Dateien per
scp ab und spielt sie mit spool_import.py in seine NetAsset-API ein.

Damit braucht der gesammelte Host keine Verbindung zum Server (z. B. VPS
ohne von hier erreichbare Adresse) und keinen API-Key.

Ablage:  <spool_dir>/<hostname>_<UTC-Zeitstempel>.json
         Format "drucker-spool/1": {"format", "created_at", "collector",
                                    "device": {...}, "sbom": [...]}

Konfiguration: netasset_collector.conf (tags, exposure_level, min_confidence,
osquery_bin) + Abschnitt [spool] oder Umgebungsvariablen:
  [spool]
  dir   = /var/spool/drucker      (DRUCKER_SPOOL_DIR)
  keep  = 48                      (DRUCKER_SPOOL_KEEP)  ältere Dateien löschen
  group = drucker-spool           (DRUCKER_SPOOL_GROUP) darf lesen (scp-User)

Aufruf:
  sudo python3 spool_collector.py
  python3 spool_collector.py --stdout     # nur ausgeben, nichts ablegen
"""

import argparse
import configparser
import datetime as dt
import grp
import json
import logging
import os
import re
import sys
from pathlib import Path

from netasset_collector import CONF_PATHS, collect, load_config, log, require_osquery

SPOOL_FORMAT = "drucker-spool/1"


def load_spool_config() -> dict:
    cfg = configparser.ConfigParser()
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            break
    section = cfg["spool"] if "spool" in cfg else {}
    return {
        "dir": Path(os.environ.get("DRUCKER_SPOOL_DIR", section.get("dir", "/var/spool/drucker"))),
        "keep": int(os.environ.get("DRUCKER_SPOOL_KEEP", section.get("keep", "48"))),
        "group": os.environ.get("DRUCKER_SPOOL_GROUP", section.get("group", "")),
    }


def prepare_dir(spool_dir: Path, group: str) -> int | None:
    """Spool-Verzeichnis anlegen. Gibt die GID der Lese-Gruppe zurück (oder None)."""
    spool_dir.mkdir(parents=True, exist_ok=True)
    gid = None
    if group:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            log.error("Gruppe %s existiert nicht (groupadd %s)", group, group)
            sys.exit(1)
        os.chown(spool_dir, -1, gid)
        spool_dir.chmod(0o2750)   # setgid: neue Dateien erben die Gruppe
    else:
        spool_dir.chmod(0o700)
    return gid


def write_bundle(spool_dir: Path, bundle: dict, gid: int | None) -> Path:
    """Atomar schreiben: erst .tmp, dann umbenennen – scp sieht nie halbe Dateien."""
    host = re.sub(r"[^A-Za-z0-9._-]", "_", bundle["device"].get("hostname") or "unknown")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = spool_dir / f"{host}_{stamp}.json"
    tmp = spool_dir / f".{target.name}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False)
    tmp.chmod(0o640 if gid is not None else 0o600)
    if gid is not None:
        os.chown(tmp, -1, gid)
    os.replace(tmp, target)
    return target


def prune(spool_dir: Path, keep: int) -> None:
    files = sorted(spool_dir.glob("*.json"))
    for old in files[:-keep] if keep > 0 else []:
        old.unlink()
        log.info("Alte Spool-Datei gelöscht: %s", old.name)


def main():
    parser = argparse.ArgumentParser(description="DRUCKER Spool Collector (Ablage statt Upload)")
    parser.add_argument("--stdout", action="store_true", help="Bundle ausgeben statt ablegen")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config()
    spool = load_spool_config()

    device, packages = collect(config, require_osquery(config))
    bundle = {
        "format": SPOOL_FORMAT,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "collector": "netasset_collector",
        "device": device,
        "sbom": packages,
    }

    if args.stdout:
        print(json.dumps(bundle, indent=2, ensure_ascii=False))
        return

    gid = prepare_dir(spool["dir"], spool["group"])
    path = write_bundle(spool["dir"], bundle, gid)
    log.info("Abgelegt: %s (%d Pakete)", path, len(packages))
    prune(spool["dir"], spool["keep"])


if __name__ == "__main__":
    main()
