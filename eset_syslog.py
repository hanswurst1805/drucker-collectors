#!/usr/bin/env python3
from __future__ import annotations
"""
ESET → Syslog Collector

Zieht ESET-Endpoint-Detections per ESET Connect API (/v1/detections) und schickt
jedes Ereignis als Syslog-Nachricht an einen Syslog-/SIEM-Server weiter.
Unabhängig vom eingebauten ESET-PROTECT-Syslog-Export.

Ablauf:
  Login (OAuth2) → Detections seit letztem Lauf holen → als Syslog senden →
  Zustand (letzter Zeitpunkt + gesendete IDs) merken (kein Doppelversand).

Konfiguration: eset_syslog.conf (siehe eset_syslog.conf.example) oder ENV.
Aufruf:
  python3 eset_syslog.py                 # holen + senden
  python3 eset_syslog.py --dry-run       # Nachrichten nur anzeigen
  python3 eset_syslog.py --lookback-days 7   # beim ersten Lauf weiter zurück
  python3 eset_syslog.py --format cef    # CEF statt RFC5424

Als Cron/systemd-Timer regelmäßig ausführen (z.B. alle 5 Minuten).
"""

import argparse
import configparser
import json
import logging
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("eset-syslog")

CONF_PATHS = [
    Path(__file__).parent / "eset_syslog.conf",
    Path("/etc/netasset/eset_syslog.conf"),
]
REGION_HOST = {"eu": "eu", "de": "de", "us": "us", "ca": "ca", "jpn": "jpn"}

FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5,
              "local0": 16, "local1": 17, "local2": 18, "local3": 19,
              "local4": 20, "local5": 21, "local6": 22, "local7": 23}

# ESET severityLevel (entpräfixt) → Syslog-Severity (0=emerg … 7=debug)
SEV_TO_SYSLOG = {"HIGH": 3, "MEDIUM": 4, "LOW": 5, "INFORMATIONAL": 6, "DIAGNOSTIC": 7}
# CEF-Severity (0–10)
SEV_TO_CEF = {"HIGH": 9, "MEDIUM": 6, "LOW": 3, "INFORMATIONAL": 2, "DIAGNOSTIC": 1}


# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

def load_config(path_arg: str | None) -> dict:
    cfg = configparser.ConfigParser()
    paths = [Path(path_arg)] if path_arg else CONF_PATHS
    for p in paths:
        if p.exists():
            cfg.read(p)
            log.info("Konfiguration: %s", p)
            break
    es = cfg["eset"] if "eset" in cfg else {}
    sl = cfg["syslog"] if "syslog" in cfg else {}
    st = cfg["state"] if "state" in cfg else {}

    region = (os.environ.get("ESET_REGION") or es.get("region", "eu")).lower()
    if region not in REGION_HOST:
        log.warning("Unbekannte Region '%s' – 'eu'", region); region = "eu"

    return {
        "region": region,
        "username": os.environ.get("ESET_USER") or es.get("username", ""),
        "password": os.environ.get("ESET_PASS") or es.get("password", ""),
        "timeout": int(es.get("timeout", "30")),
        "syslog_host": os.environ.get("SYSLOG_HOST") or sl.get("host", ""),
        "syslog_port": int(os.environ.get("SYSLOG_PORT") or sl.get("port", "514")),
        "protocol": (sl.get("protocol", "udp")).lower(),
        "format": (sl.get("format", "rfc5424")).lower(),
        "facility": FACILITIES.get(sl.get("facility", "local0"), 16),
        "app_name": sl.get("app_name", "ESET"),
        "source_host": sl.get("hostname", socket.gethostname()),
        "state_file": st.get("file", str(Path(__file__).parent / "eset_syslog.state.json")),
        "lookback_days": int(st.get("lookback_days", "1")),
    }


# ---------------------------------------------------------------------------
# ESET Connect API
# ---------------------------------------------------------------------------

def get_token(config: dict) -> str:
    host = REGION_HOST[config["region"]]
    url = f"https://{host}.business-account.iam.eset.systems/oauth/token"
    body = urllib.parse.urlencode({
        "grant_type": "password",
        "username": config["username"],
        "password": config["password"],
    }).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=config["timeout"]) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        log.error("Login fehlgeschlagen (%d): %s", e.code, e.read().decode(errors="replace")[:300])
        sys.exit(1)
    token = data.get("access_token")
    if not token:
        log.error("Kein access_token: %s", json.dumps(data)[:300]); sys.exit(1)
    return token


def fetch_detections(config: dict, token: str, start_iso: str) -> list[dict]:
    host = REGION_HOST[config["region"]]
    base = f"https://{host}.incident-management.eset.systems/v1/detections"
    out: list[dict] = []
    page_token = None
    while True:
        params = {"pageSize": "500", "startTime": start_iso}
        if page_token:
            params["pageToken"] = page_token
        req = urllib.request.Request(base + "?" + urllib.parse.urlencode(params),
                                     headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=config["timeout"]) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            log.error("Detections-Abfrage fehlgeschlagen (%d): %s",
                      e.code, e.read().decode(errors="replace")[:300])
            break
        out.extend(data.get("detections", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return out


def _strip(v, prefix):
    return v[len(prefix):] if isinstance(v, str) and v.startswith(prefix) else v


def normalize(d: dict) -> dict:
    ctx = d.get("context") or {}
    return {
        "uuid": d.get("uuid") or "",
        "severity": _strip(d.get("severityLevel"), "SEVERITY_LEVEL_") or "UNSPECIFIED",
        "category": _strip(d.get("category"), "DETECTION_CATEGORY_") or "",
        "type": d.get("typeName") or "",
        "name": d.get("displayName") or d.get("objectName") or d.get("typeName") or "detection",
        "object": d.get("objectName") or "",
        "hash": d.get("objectHashSha1") or "",
        "url": d.get("objectUrl") or "",
        "device_uuid": ctx.get("deviceUuid") or "",
        "user": ctx.get("userName") or "",
        "time": d.get("occurTime") or "",
        "process": (ctx.get("process") or {}).get("path") or "",
    }


# ---------------------------------------------------------------------------
# Syslog-Formatierung + Versand
# ---------------------------------------------------------------------------

def _iso_to_dt(iso: str) -> datetime:
    try:
        return datetime.strptime(iso.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return datetime.now(timezone.utc)


def build_message(ev: dict, config: dict) -> str:
    sev_syslog = SEV_TO_SYSLOG.get(ev["severity"], 6)
    pri = config["facility"] * 8 + sev_syslog
    ts = _iso_to_dt(ev["time"])
    host = config["source_host"]
    app = config["app_name"]

    if config["format"] == "cef":
        # CEF in Syslog gewrappt (RFC5424-Header + CEF-Payload)
        cef = (f"CEF:0|ESET|PROTECT|1.0|{ev['type'] or 'detection'}|{ev['name']}|"
               f"{SEV_TO_CEF.get(ev['severity'], 5)}|"
               f"cat={ev['category']} deviceExternalId={ev['device_uuid']} "
               f"duser={ev['user']} fileHash={ev['hash']} fname={ev['object']} "
               f"request={ev['url']} externalId={ev['uuid']}")
        header = f"<{pri}>1 {ts.strftime('%Y-%m-%dT%H:%M:%S%z')} {host} {app} - {ev['uuid'][:32] or '-'} -"
        return f"{header} {cef}"

    # Default: RFC5424, MSG als key=value
    msg = (f"detection severity={ev['severity']} category={ev['category']} "
           f"type=\"{ev['type']}\" name=\"{ev['name']}\" object=\"{ev['object']}\" "
           f"sha1={ev['hash']} device={ev['device_uuid']} user={ev['user']} "
           f"process=\"{ev['process']}\" id={ev['uuid']}")
    return (f"<{pri}>1 {ts.strftime('%Y-%m-%dT%H:%M:%S%z')} {host} {app} - "
            f"{ev['uuid'][:32] or '-'} - {msg}")


def make_sender(config: dict):
    host, port, proto = config["syslog_host"], config["syslog_port"], config["protocol"]
    if proto == "tcp":
        sock = socket.create_connection((host, port), timeout=config["timeout"])

        def send(line: str):
            sock.sendall((line + "\n").encode("utf-8"))   # Octet-Newline-Framing
        return send, sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(line: str):
        sock.sendto(line.encode("utf-8"), (host, port))
    return send, sock


# ---------------------------------------------------------------------------
# Zustand (Dedup)
# ---------------------------------------------------------------------------

def load_state(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return {"last_time": None, "sent": []}


def save_state(path: str, state: dict):
    try:
        Path(path).write_text(json.dumps(state))
    except OSError as e:
        log.warning("State nicht speicherbar (%s): %s", path, e)


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="ESET → Syslog Collector")
    ap.add_argument("--config")
    ap.add_argument("--dry-run", action="store_true", help="Nachrichten nur anzeigen, nicht senden")
    ap.add_argument("--lookback-days", type=int, help="Startfenster beim ersten Lauf (überschreibt Config)")
    ap.add_argument("--format", choices=["rfc5424", "cef"], help="Syslog-Format")
    args = ap.parse_args()

    config = load_config(args.config)
    if args.format:
        config["format"] = args.format
    if not config["username"] or not config["password"]:
        log.error("ESET-Zugangsdaten fehlen ([eset] username/password oder ESET_USER/ESET_PASS).")
        sys.exit(1)
    if not args.dry_run and not config["syslog_host"]:
        log.error("Kein Syslog-Ziel ([syslog] host oder SYSLOG_HOST).")
        sys.exit(1)

    state = load_state(config["state_file"])
    lookback = args.lookback_days if args.lookback_days is not None else config["lookback_days"]
    start_iso = state.get("last_time") or (
        datetime.now(timezone.utc) - timedelta(days=lookback)).strftime("%Y-%m-%dT%H:%M:%SZ")

    token = get_token(config)
    raw = fetch_detections(config, token, start_iso)
    events = sorted((normalize(d) for d in raw), key=lambda e: e["time"])

    already = set(state.get("sent", []))
    new = [e for e in events if e["uuid"] and e["uuid"] not in already]
    log.info("%d Detections seit %s, davon %d neu", len(events), start_iso, len(new))

    if not new:
        return

    sender = sock = None
    if not args.dry_run:
        try:
            sender, sock = make_sender(config)
        except OSError as e:
            log.error("Syslog-Verbindung fehlgeschlagen (%s:%s/%s): %s",
                      config["syslog_host"], config["syslog_port"], config["protocol"], e)
            sys.exit(1)

    sent_ids = []
    for e in new:
        line = build_message(e, config)
        if args.dry_run:
            print(line)
        else:
            sender(line)
        sent_ids.append(e["uuid"])

    if sock:
        sock.close()

    if not args.dry_run:
        # letzten Zeitpunkt + zuletzt gesendete IDs (Rand-Dedup) merken
        newest = max((e["time"] for e in new if e["time"]), default=state.get("last_time"))
        state["last_time"] = newest
        state["sent"] = (state.get("sent", []) + sent_ids)[-2000:]
        save_state(config["state_file"], state)
        log.info("%d Ereignisse an %s:%s (%s, %s) gesendet.", len(sent_ids),
                 config["syslog_host"], config["syslog_port"], config["protocol"], config["format"])


if __name__ == "__main__":
    main()
