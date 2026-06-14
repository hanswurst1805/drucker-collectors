#!/usr/bin/env python3
from __future__ import annotations
"""
ESET PROTECT Cloud – Endpoint-Status

Zeigt für alle in ESET Connect verwalteten Endpoints:
  - AV/Schutzstatus (functionalityStatus)
  - Betriebssystem + letzte Synchronisation
  - Offene Alarme/Detections (unresolved)

Vor dem ersten Lauf unten unter CONFIG die Zugangsdaten eintragen:
  - region: eu / de / us / ca / jpn
  - username / password: dedizierter API-User (NICHT die normalen
    Login-Daten!), siehe
    https://help.eset.com/eset_connect/en-US/create_api_user_account.html

Der OAuth2-Token-Endpoint ergibt sich automatisch aus der Region
(https://{region}.business-account.iam.eset.systems/oauth/token).

Aufruf:
  python3 eset_status.py
  python3 eset_status.py --days 7      # Alarme der letzten 7 Tage (Standard: 30)
  python3 eset_status.py --raw         # Rohdaten als JSON ausgeben
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# CONFIG – hier Zugangsdaten eintragen
# ---------------------------------------------------------------------------

CONFIG = {
    "region": "eu",                 # eu / de / us / ca / jpn
    "username": "",                 # API-User (ESET PROTECT Hub -> API Users)
    "password": "",
    "timeout": 30,
}

REGION_HOST = {"eu": "eu", "de": "de", "us": "us", "ca": "ca", "jpn": "jpn"}


# ---------------------------------------------------------------------------
# ESET Connect API
# ---------------------------------------------------------------------------

def get_token(config: dict) -> str:
    if not config["username"] or not config["password"]:
        sys.exit("Bitte CONFIG['username']/CONFIG['password'] (API-User) eintragen.")

    host = REGION_HOST[config["region"]]
    token_url = f"https://{host}.business-account.iam.eset.systems/oauth/token"

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
        sys.exit(f"Login fehlgeschlagen ({e.code}): {e.read().decode(errors='replace')[:500]}")

    token = data.get("access_token")
    if not token:
        sys.exit(f"Antwort enthielt kein access_token: {json.dumps(data)[:500]}")
    return token


def api_get(url: str, token: str, timeout: int) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:500]
        msg = f"API-Fehler {e.code} auf {url}: {body or '(leere Antwort)'}"
        if e.code == 403:
            msg += (
                "\n\n403 = Token war gültig, aber der API-User hat keine "
                "Berechtigung für diese API. In ESET PROTECT Hub / ESET "
                "Business Account beim API-User die passenden Permission "
                "Sets zuweisen (z.B. fuer 'Device Management' / "
                "'Detection & Response'), siehe:\n"
                "https://help.eset.com/eset_connect/en-US/create_api_user_account.html"
            )
        sys.exit(msg)


def fetch_devices(config: dict, token: str) -> list[dict]:
    host = REGION_HOST[config["region"]]
    base = f"https://{host}.device-management.eset.systems/v1/devices"

    devices: list[dict] = []
    page_token = None
    while True:
        params = {"pageSize": "200"}
        if page_token:
            params["pageToken"] = page_token
        data = api_get(base + "?" + urllib.parse.urlencode(params), token, config["timeout"])
        devices.extend(data.get("devices", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return devices


def fetch_detections(config: dict, token: str, days: int) -> list[dict]:
    host = REGION_HOST[config["region"]]
    base = f"https://{host}.incident-management.eset.systems/v2/detections"
    start_time = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    detections: list[dict] = []
    page_token = None
    while True:
        params = {"pageSize": "200", "startTime": start_time}
        if page_token:
            params["pageToken"] = page_token
        data = api_get(base + "?" + urllib.parse.urlencode(params), token, config["timeout"])
        detections.extend(data.get("detections", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return detections


# ---------------------------------------------------------------------------
# Ausgabe
# ---------------------------------------------------------------------------

def print_devices(devices: list[dict]) -> None:
    print(f"\n=== Endpoints ({len(devices)}) ===\n")
    print(f"{'Name':<28} {'Status':<20} {'OS':<28} {'IP':<16} {'Letzte Sync'}")
    print("-" * 110)
    for d in devices:
        name = (d.get("displayName") or d.get("originalDisplayName") or "?")[:27]
        status = d.get("functionalityStatus") or "?"
        os_info = d.get("operatingSystem") or {}
        os_str = f"{os_info.get('name') or os_info.get('platform') or '?'} {os_info.get('version') or ''}".strip()[:27]
        ip = d.get("primaryLocalIpAddress") or "—"
        last_sync = d.get("lastSyncTime") or "—"
        print(f"{name:<28} {status:<20} {os_str:<28} {ip:<16} {last_sync}")

    bad = [d for d in devices if d.get("functionalityStatus") != "OK"]
    if bad:
        print(f"\n{len(bad)} Endpoint(s) mit Status != OK")


def print_detections(detections: list[dict], days: int) -> None:
    open_dets = [d for d in detections if not d.get("resolved")]
    print(f"\n=== Offene Alarme (letzte {days} Tage): {len(open_dets)} von {len(detections)} ===\n")
    if not open_dets:
        return
    print(f"{'Zeit':<22} {'Gerät':<25} {'Schwere':<14} {'Bedrohung'}")
    print("-" * 100)
    for det in sorted(open_dets, key=lambda d: d.get("occurTime") or "", reverse=True):
        when = (det.get("occurTime") or "—")[:19]
        device = ((det.get("device") or {}).get("displayName") or "?")[:24]
        severity = det.get("severityLevel") or "?"
        threat = det.get("displayName") or det.get("typeName") or "?"
        print(f"{when:<22} {device:<25} {severity:<14} {threat}")


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="ESET PROTECT Cloud – Endpoint-Status")
    parser.add_argument("--days", type=int, default=30, help="Alarme der letzten N Tage (Standard: 30)")
    parser.add_argument("--raw", action="store_true", help="Rohdaten als JSON ausgeben")
    args = parser.parse_args()

    config = CONFIG
    if config["region"] not in REGION_HOST:
        sys.exit(f"Unbekannte Region '{config['region']}' (eu/de/us/ca/jpn)")

    token = get_token(config)
    devices = fetch_devices(config, token)
    detections = fetch_detections(config, token, args.days)

    if args.raw:
        print(json.dumps({"devices": devices, "detections": detections}, indent=2))
        return

    print_devices(devices)
    print_detections(detections, args.days)


if __name__ == "__main__":
    main()
