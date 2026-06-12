#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset ESET PROTECT Cloud Collector

Liest per ESET Connect API (Device Management) alle von ESET PROTECT
verwalteten Endpoints aus und meldet sie als Assets an NetAsset.

Voraussetzungen:
  - ESET PROTECT Cloud mit aktivierter ESET Connect API
  - Dedizierter API-User (ESET PROTECT Hub / ESET Business Account ->
    Mein Profil / API Users), siehe:
    https://help.eset.com/eset_connect/en-US/create_api_user_account.html
  - Region des Tenants (eu/de/us/ca/jpn) und OAuth2-Token-Endpoint, siehe
    Swagger-UI deines Tenants -> Authentication
    https://help.eset.com/eset_connect/en-US/authenticate_api_user.html

Aufruf:
  python3 eset_collector.py               # Upload
  python3 eset_collector.py --dry-run     # nur anzeigen
  python3 eset_collector.py --dump-raw    # erstes Gerät als Rohdaten (JSON) ausgeben
"""

import argparse
import configparser
import json
import logging
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netasset-eset")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

CONF_PATHS = [
    Path(__file__).parent / "eset_collector.conf",
    Path("/etc/netasset/eset_collector.conf"),
    Path.home() / "Library/NetAsset/eset_collector.conf",
    Path(os.environ.get("APPDATA", "C:/ProgramData")) / "NetAsset/eset_collector.conf",
]

REGION_HOST = {
    "eu": "eu",
    "de": "de",
    "us": "us",
    "ca": "ca",
    "jpn": "jpn",
}


def load_config() -> dict:
    cfg = configparser.ConfigParser()
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            log.info("Konfiguration: %s", path)
            break

    es = cfg["eset"] if "eset" in cfg else {}
    na = cfg["netasset"] if "netasset" in cfg else {}

    region = os.environ.get("ESET_REGION", es.get("region", "eu")).lower()
    if region not in REGION_HOST:
        log.warning("Unbekannte Region '%s', verwende 'eu'", region)
        region = "eu"

    return {
        "region": region,
        "username": os.environ.get("ESET_USER", es.get("username", "")),
        "password": os.environ.get("ESET_PASS", es.get("password", "")),
        "token_url": os.environ.get("ESET_TOKEN_URL", es.get("token_url", "")),
        "api_url": os.environ.get("NETASSET_URL", na.get("api_url", "https://ocs.kiste.org")),
        "api_key": os.environ.get("NETASSET_API_KEY", na.get("api_key", "")),
        "exposure_level": na.get("exposure_level", "INTERN"),
        "tags": [t.strip() for t in na.get("tags", "eset,managed-endpoint").split(",")],
        "timeout": int(na.get("timeout", "30")),
        "min_confidence": _parse_min_confidence(
            os.environ.get("NETASSET_MIN_CONFIDENCE", na.get("min_confidence", ""))
        ),
    }


def _parse_min_confidence(raw: str) -> float | None:
    """Parsed min_confidence (0.0-1.0 oder 0-100%). Leer/ungültig -> None."""
    raw = (raw or "").strip().rstrip("%")
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    if value > 1.0:
        value = value / 100.0
    return max(0.0, min(1.0, value))


# ---------------------------------------------------------------------------
# ESET Connect API
# ---------------------------------------------------------------------------

def get_token(config: dict) -> str:
    """OAuth2 Password-Grant gegen den ESET Identity Provider."""
    token_url = config["token_url"]
    if not token_url:
        log.error(
            "Kein token_url konfiguriert. Bitte in eset_collector.conf [eset] "
            "token_url= aus der Swagger-UI deines Tenants (Authentication) "
            "eintragen: https://help.eset.com/eset_connect/en-US/authenticate_api_user.html"
        )
        sys.exit(1)

    body = urllib.parse.urlencode({
        "grant_type": "password",
        "username": config["username"],
        "password": config["password"],
    }).encode()

    req = urllib.request.Request(
        token_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config["timeout"]) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        log.error("Login bei ESET fehlgeschlagen (%d): %s", e.code, detail[:500])
        sys.exit(1)

    token = data.get("access_token")
    if not token:
        log.error("Antwort enthielt kein access_token: %s", json.dumps(data)[:500])
        sys.exit(1)
    return token


def fetch_devices(config: dict, token: str) -> list[dict]:
    """Lädt alle Geräte über /v1/devices (paginiert)."""
    host = REGION_HOST[config["region"]]
    base = f"https://{host}.device-management.eset.systems/v1/devices"

    devices: list[dict] = []
    page_token = None
    while True:
        params = {"pageSize": "200"}
        if page_token:
            params["pageToken"] = page_token
        url = base + "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=config["timeout"]) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            log.error("Geräte-Abfrage fehlgeschlagen (%d): %s", e.code, detail[:500])
            sys.exit(1)

        devices.extend(data.get("devices", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break

    log.info("ESET Connect: %d Geräte gefunden", len(devices))
    return devices


# ---------------------------------------------------------------------------
# Mapping ESET -> NetAsset Asset
# ---------------------------------------------------------------------------

def map_device(d: dict, config: dict) -> dict | None:
    hostname = d.get("displayName") or d.get("originalDisplayName")
    if not hostname:
        return None

    hw_profiles = d.get("hardwareProfiles") or [{}]
    hw = hw_profiles[0] if hw_profiles else {}

    mac = None
    for adapter in hw.get("networkAdapters", []) or []:
        mac_raw = adapter.get("macAddress")
        if mac_raw:
            mac = mac_raw.lower().replace("-", ":")
            break

    serial = hw.get("serialNumber") or hw.get("biosSerialNumber")

    os_info = d.get("operatingSystem") or {}
    os_type = (os_info.get("type") or os_info.get("platform") or "").lower()
    asset_type = "server" if "server" in os_type else "client"

    status = (d.get("functionalityStatus") or "unknown").lower().replace("_", "-")

    return {
        "hostname": hostname,
        "ip_address": d.get("primaryLocalIpAddress"),
        "mac_address": mac,
        "serial_number": serial,
        "chassis_id": d.get("uuid"),
        "asset_type": asset_type,
        "os_name": os_info.get("name") or os_info.get("platform"),
        "os_version": os_info.get("version"),
        "manufacturer": hw.get("manufacturer"),
        "model": hw.get("model"),
        "exposure_level": config["exposure_level"],
        "tags": config["tags"] + [f"eset-status-{status}"],
        "source": "eset-collector",
        **(
            {"min_confidence": config["min_confidence"]}
            if config["min_confidence"] is not None else {}
        ),
    }


# ---------------------------------------------------------------------------
# NetAsset API
# ---------------------------------------------------------------------------

def api_post(url: str, api_key: str, data, timeout: int = 30):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        log.error("API Fehler %d auf %s: %s", e.code, url, detail[:500])
        raise


def push(config: dict, assets: list[dict], dry_run: bool = False):
    if dry_run:
        print("\n=== DRY RUN ===\n")
        for a in assets:
            print(f"{a['hostname']:<30} {a.get('ip_address') or '—':<16} "
                  f"{a.get('mac_address') or '—':<18} {a.get('os_name') or '—'}")
        print(f"\n{len(assets)} Geräte gesamt")
        return

    base = config["api_url"].rstrip("/")
    created = merged = flagged = 0
    for i in range(0, len(assets), 50):
        res = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], assets[i:i + 50], config["timeout"])
        for item in (res or []):
            a = item.get("action", "")
            if a == "created":
                created += 1
            elif a == "merged":
                merged += 1
            else:
                flagged += 1
    log.info("Geräte: %d neu, %d aktualisiert, %d Konflikt", created, merged, flagged)


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NetAsset ESET PROTECT Cloud Collector")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--dump-raw", action="store_true", help="Rohdaten des ersten Geräts ausgeben")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config()

    if not config["username"] or not config["password"]:
        log.error("ESET-Zugangsdaten fehlen (eset_collector.conf -> [eset] username/password)")
        sys.exit(1)

    if not config["api_key"] and not args.dry_run:
        log.error("NETASSET_API_KEY nicht gesetzt.")
        sys.exit(1)

    token = get_token(config)
    devices = fetch_devices(config, token)

    if args.dump_raw:
        print(json.dumps(devices[0] if devices else {}, indent=2))
        return

    assets = [a for a in (map_device(d, config) for d in devices) if a]
    push(config, assets, dry_run=args.dry_run)
    if not args.dry_run:
        log.info("Fertig.")


if __name__ == "__main__":
    main()
