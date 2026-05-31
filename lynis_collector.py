#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset Lynis Collector

Liest den Lynis-Report (lynis-report.dat) und lädt ihn per API hoch.
Ermittelt die Asset-ID automatisch per Hostname oder IP.

Lynis erzeugt den Report mit:
    sudo lynis audit system

Aufruf:
    python3 lynis_collector.py                          # aus Config
    python3 lynis_collector.py --run-lynis              # Lynis zuerst ausführen
    python3 lynis_collector.py --report /pfad/report.dat
    python3 lynis_collector.py --asset-id UUID          # direkt angeben
"""

import argparse
import configparser
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netasset-lynis")

# ---------------------------------------------------------------------------
# Standard-Report-Pfade je nach OS
# ---------------------------------------------------------------------------

LYNIS_REPORT_PATHS = [
    Path("/var/log/lynis-report.dat"),
    Path("/var/log/lynis/report.dat"),
    Path(Path.home() / ".lynis/lynis-report.dat"),
]

CONF_PATHS = [
    Path(__file__).parent / "lynis_collector.conf",
    Path(__file__).parent / "netasset_collector.conf",  # Fallback auf osquery-Config
    Path("/etc/netasset/lynis_collector.conf"),
    Path("/etc/netasset/netasset_collector.conf"),
    Path.home() / "Library/NetAsset/lynis_collector.conf",
    Path(os.environ.get("APPDATA", "C:/ProgramData")) / "NetAsset/lynis_collector.conf",
]

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

def load_config(config_file: str | None = None) -> dict:
    cfg = configparser.ConfigParser()
    if config_file:
        cfg.read(config_file)
        log.info("Konfiguration: %s", config_file)
    else:
        for path in CONF_PATHS:
            if path.exists():
                cfg.read(path)
                log.info("Konfiguration: %s", path)
                break

    s = cfg["netasset"] if "netasset" in cfg else {}
    return {
        "api_url":  os.environ.get("NETASSET_URL", s.get("api_url", "https://ocs.kiste.org")),
        "api_key":  os.environ.get("NETASSET_API_KEY", s.get("api_key", "")),
        "asset_id": os.environ.get("NETASSET_ASSET_ID", s.get("asset_id", "")),
        "timeout":  int(s.get("timeout", "30")),
    }

# ---------------------------------------------------------------------------
# Asset-ID ermitteln
# ---------------------------------------------------------------------------

def find_asset_id(api_url: str, api_key: str, timeout: int) -> str | None:
    """
    Sucht das passende Asset per Hostname oder IP.
    Gibt die Asset-ID zurück oder None wenn nicht gefunden.
    """
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = None

    base = api_url.rstrip("/") + "/api/v1/assets"
    headers = {"X-API-Key": api_key}

    # Erst per Hostname suchen
    for param, value in [("hostname", hostname), ("ip_address", ip)]:
        if not value:
            continue
        url = f"{base}?{param}={urllib.parse.quote(value)}&limit=1"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                assets = json.loads(resp.read())
                if assets:
                    log.info("Asset gefunden per %s=%s: %s", param, value, assets[0]["id"])
                    return assets[0]["id"]
        except Exception as e:
            log.debug("Suche per %s fehlgeschlagen: %s", param, e)

    return None

# ---------------------------------------------------------------------------
# Lynis ausführen
# ---------------------------------------------------------------------------

def run_lynis() -> Path | None:
    """Führt Lynis aus und gibt den Pfad zum Report zurück."""
    import shutil
    lynis = shutil.which("lynis")
    if not lynis:
        log.error("lynis nicht gefunden. Installieren: apt install lynis")
        return None

    log.info("Führe Lynis aus (sudo lynis audit system)...")
    try:
        result = subprocess.run(
            ["sudo", lynis, "audit", "system", "--quiet", "--no-colors"],
            timeout=300,
            capture_output=True,
            text=True,
        )
        if result.returncode not in (0, 1):
            log.warning("Lynis exit %d: %s", result.returncode, result.stderr[:200])
    except subprocess.TimeoutExpired:
        log.error("Lynis Timeout nach 5 Minuten")
        return None
    except Exception as e:
        log.error("Lynis Fehler: %s", e)
        return None

    # Report finden
    for path in LYNIS_REPORT_PATHS:
        if path.exists():
            log.info("Report gefunden: %s", path)
            return path

    log.error("Report nicht gefunden nach Lynis-Ausführung")
    return None

# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

def upload_report(report_path: Path, asset_id: str, api_url: str, api_key: str, timeout: int) -> dict:
    """Lädt den Report per multipart/form-data hoch."""
    import email.mime.multipart
    import email.mime.base
    import email.encoders

    url = f"{api_url.rstrip('/')}/api/v1/reports/assets/{asset_id}"
    filename = report_path.name

    # Multipart-Body manuell bauen (kein requests verfügbar)
    boundary = "NetAssetBoundary1337"
    content = report_path.read_bytes()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-API-Key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read())
            return result
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {detail}") from e

# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    import urllib.parse

    parser = argparse.ArgumentParser(description="NetAsset Lynis Collector")
    parser.add_argument("--config",    "-c",  help="Konfigurationsdatei")
    parser.add_argument("--report",    "-r",  help="Pfad zur lynis-report.dat")
    parser.add_argument("--asset-id",  "-a",  help="Asset-ID (UUID), sonst automatisch ermittelt")
    parser.add_argument("--run-lynis",        action="store_true", help="Lynis zuerst ausführen")
    parser.add_argument("--verbose",   "-v",  action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config(args.config)

    if not config["api_key"]:
        log.error("NETASSET_API_KEY nicht gesetzt. In lynis_collector.conf eintragen.")
        sys.exit(1)

    # 1. Report-Datei bestimmen
    report_path = None

    if args.run_lynis:
        report_path = run_lynis()
        if not report_path:
            sys.exit(1)
    elif args.report:
        report_path = Path(args.report)
    else:
        # Standard-Pfade durchsuchen
        for p in LYNIS_REPORT_PATHS:
            if p.exists():
                report_path = p
                log.info("Report gefunden: %s", p)
                break

    if not report_path or not report_path.exists():
        log.error(
            "Kein Lynis-Report gefunden. Entweder:\n"
            "  1. sudo lynis audit system  (dann nochmal aufrufen)\n"
            "  2. --report /pfad/lynis-report.dat\n"
            "  3. --run-lynis  (führt Lynis direkt aus)"
        )
        sys.exit(1)

    log.info("Report: %s (%d Bytes)", report_path, report_path.stat().st_size)

    # 2. Asset-ID bestimmen: CLI > Config > automatisch per Hostname/IP
    asset_id = args.asset_id or config.get("asset_id", "")
    if not asset_id:
        log.info("Suche Asset per Hostname/IP...")
        asset_id = find_asset_id(config["api_url"], config["api_key"], config["timeout"])

    if not asset_id:
        log.error(
            "Asset nicht gefunden. Optionen:\n"
            "  1. --asset-id UUID  (Asset-ID aus der NetAsset-GUI)\n"
            "  2. Erst osquery-Collector laufen lassen damit das Asset angelegt wird"
        )
        sys.exit(1)

    log.info("Asset-ID: %s", asset_id)

    # 3. Upload
    log.info("Lade Report hoch...")
    try:
        result = upload_report(report_path, asset_id, config["api_url"], config["api_key"], config["timeout"])
    except Exception as e:
        log.error("Upload fehlgeschlagen: %s", e)
        sys.exit(1)

    idx = result.get("parsed_data", {}).get("hardening_index")
    warn = result.get("warnings_count", 0)
    sugg = result.get("suggestions_count", 0)

    log.info(
        "Erfolgreich hochgeladen!\n"
        "  Hardening-Index: %s/100\n"
        "  Warnings: %d\n"
        "  Suggestions: %d\n"
        "  Report-ID: %s",
        idx if idx is not None else "—",
        warn, sugg,
        result.get("id", "?"),
    )


if __name__ == "__main__":
    main()
