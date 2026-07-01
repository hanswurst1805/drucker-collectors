#!/usr/bin/env python3
from __future__ import annotations
"""
ESET Connect – Verbindungstest (credential-frei, versionierbar)

Prüft in zwei Schritten, ob der ESET-API-Zugang funktioniert:
  1) Login (OAuth2) → Token holen
  2) Minimaler API-Zugriff (GET /v1/devices?pageSize=1)

Zugangsdaten werden NICHT im Skript gespeichert, sondern kommen aus:
  - Umgebungsvariablen:  ESET_REGION, ESET_USER, ESET_PASS
  - oder eset_collector.conf ([eset] region/username/password)

Aufruf:
  ESET_REGION=de ESET_USER='api@…' ESET_PASS='…' python3 eset_check.py
  # oder einfach, wenn eset_collector.conf existiert:
  python3 eset_check.py

Hinweis zur Region: Der Login funktioniert regionsübergreifend, die GERÄTE
liegen aber nur in der Region deiner ESET-PROTECT-Cloud-Instanz. Liefert Schritt
2 überall 404, ist meist die Region falsch (eu/de/us/ca/jpn durchprobieren).
"""

import configparser
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REGIONS = {"eu", "de", "us", "ca", "jpn"}
CONF_PATHS = [
    Path(__file__).parent / "eset_collector.conf",
    Path("/etc/netasset/eset_collector.conf"),
    Path("/opt/drucker-collectors/eset_collector.conf"),
]
TIMEOUT = 30


def ok(msg):   print(f"  \033[32mOK\033[0m   {msg}")
def fail(msg): print(f"  \033[31mFEHLER\033[0m {msg}")
def info(msg): print(f"       {msg}")


def load_config() -> dict:
    """Env-Variablen haben Vorrang, sonst eset_collector.conf ([eset])."""
    es = {}
    for p in CONF_PATHS:
        if p.exists():
            cfg = configparser.ConfigParser()
            cfg.read(p)
            if "eset" in cfg:
                es = cfg["eset"]
            break
    return {
        "region": (os.environ.get("ESET_REGION") or es.get("region", "eu")).lower(),
        "username": os.environ.get("ESET_USER") or es.get("username", ""),
        "password": os.environ.get("ESET_PASS") or es.get("password", ""),
    }


def main() -> int:
    cfg = load_config()
    r = cfg["region"]
    if r not in REGIONS:
        fail(f"Unbekannte Region '{r}' (erlaubt: {', '.join(sorted(REGIONS))})")
        return 2
    if not cfg["username"] or not cfg["password"]:
        fail("Keine Zugangsdaten gefunden.")
        info("ESET_USER/ESET_PASS setzen oder eset_collector.conf ([eset]) füllen.")
        return 2

    token_url = f"https://{r}.business-account.iam.eset.systems/oauth/token"
    devices_url = f"https://{r}.device-management.eset.systems/v1/devices?pageSize=1"

    # --- Schritt 1: Login / Token ---
    print(f"1) Login (OAuth2) – Region '{r}'")
    info(token_url)
    body = urllib.parse.urlencode({
        "grant_type": "password",
        "username": cfg["username"],
        "password": cfg["password"],
    }).encode()
    req = urllib.request.Request(
        token_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        fail(f"Login fehlgeschlagen: HTTP {e.code}")
        info(e.read().decode(errors="replace")[:400] or "(keine Antwort)")
        if e.code in (400, 401):
            info("→ Zugangsdaten prüfen. Es MUSS ein dedizierter API-User sein")
            info("  (ESET PROTECT Hub → Benutzer → 'Integrationen' aktiviert).")
        return 1
    except urllib.error.URLError as e:
        fail(f"Netzwerk/DNS-Problem: {e.reason}")
        info("→ Region korrekt? Firewall/Proxy blockt ausgehend HTTPS?")
        return 1

    token = data.get("access_token")
    if not token:
        fail(f"Antwort ohne access_token: {json.dumps(data)[:300]}")
        return 1
    ok(f"Token erhalten (gültig {data.get('expires_in', '?')} s).")

    # --- Schritt 2: API-Zugriff ---
    print("\n2) API-Zugriff (Device Management)")
    info(devices_url)
    req = urllib.request.Request(devices_url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.loads(resp.read())
        ok(f"Zugriff erfolgreich (HTTP 200). Geräte im Sample: {len(payload.get('devices', []))}.")
        print("\n\033[32mVerbindung vollständig OK.\033[0m Der Collector sollte laufen (region=%s)." % r)
        return 0
    except urllib.error.HTTPError as e:
        fail(f"API-Zugriff fehlgeschlagen: HTTP {e.code}")
        info(e.read().decode(errors="replace")[:400] or "(keine Antwort)")
        if e.code == 404:
            info("→ Meist falsche Region: der Login klappt überall, die Geräte liegen")
            info("  aber nur in der Region deiner Instanz. eu/de/us/ca/jpn durchprobieren")
            info("  (ESET_REGION=… python3 eset_check.py).")
        elif e.code == 403:
            info("→ Token ok, aber dem API-User fehlt die Berechtigung (Permission Set).")
        elif e.code == 401:
            info("→ Token abgelehnt – Region der API-URLs prüfen.")
        return 1
    except urllib.error.URLError as e:
        fail(f"Netzwerk/DNS-Problem: {e.reason}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
