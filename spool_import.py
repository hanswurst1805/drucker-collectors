#!/usr/bin/env python3
from __future__ import annotations
"""
DRUCKER Spool Import – läuft auf dem Server (z. B. VPS) und spielt die per
scp abgeholten Dateien von spool_collector.py in die NetAsset-API ein:

  POST /api/v1/discovery/ingest       → Asset anlegen/aktualisieren
  POST /api/v1/sbom/assets/{id}/sbom  → SBOM hochladen

Erfolgreich importierte Dateien wandern nach <inbox>/done/. Eine Datei, die
dort schon liegt, wird nicht erneut importiert – scp darf also immer wieder
alles abholen. Bei einem Fehler bricht der Lauf ab (Reihenfolge bleibt
erhalten), die Datei bleibt in der Inbox und wird beim nächsten Lauf erneut
versucht.

API-Zugang wie netasset_collector.py: netasset_collector.conf oder
NETASSET_URL / NETASSET_API_KEY.

Aufruf:
  python3 spool_import.py /var/lib/drucker/inbox
  python3 spool_import.py /var/lib/drucker/inbox --dry-run
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from netasset_collector import load_config, log, push_asset, push_sbom
from spool_collector import SPOOL_FORMAT


def import_file(config: dict, path: Path, no_sbom: bool) -> None:
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if bundle.get("format") != SPOOL_FORMAT:
        raise ValueError(f"unbekanntes Format: {bundle.get('format')!r}")
    asset_id = push_asset(config, bundle["device"])
    if not asset_id:
        raise RuntimeError("API hat keine asset_id zurückgegeben")
    if not no_sbom:
        push_sbom(config, asset_id, bundle.get("sbom") or [])


def main():
    parser = argparse.ArgumentParser(description="DRUCKER Spool Import")
    parser.add_argument("inbox", type=Path, help="Verzeichnis mit abgeholten *.json")
    parser.add_argument("--dry-run", action="store_true", help="Nur auflisten, nichts senden")
    parser.add_argument("--no-sbom", action="store_true", help="SBOM-Upload überspringen")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config()
    if not config["api_key"] and not args.dry_run:
        log.error("NETASSET_API_KEY nicht gesetzt.")
        sys.exit(1)

    done = args.inbox / "done"
    done.mkdir(parents=True, exist_ok=True)

    imported = 0
    for path in sorted(args.inbox.glob("*.json")):
        if (done / path.name).exists():
            path.unlink()          # schon importiert, nur erneut abgeholt
            continue
        if args.dry_run:
            log.info("Würde importieren: %s", path.name)
            continue
        log.info("Importiere %s", path.name)
        try:
            import_file(config, path, args.no_sbom)
        except Exception as e:
            log.error("%s: %s", path.name, e)
            sys.exit(1)
        path.rename(done / path.name)
        imported += 1

    log.info("Fertig: %d Datei(en) importiert.", imported)


if __name__ == "__main__":
    main()
