#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset – Upload einer screen-Aufzeichnung nach dem Logout.

Wird von na_screen_rec.sh aufgerufen. Liest api_url/api_key aus der vorhandenen
netasset_collector.conf (kein separater Key nötig) und schickt das screen-Log
als Aufzeichnung an POST /api/v1/sessions/ingest.
"""

import argparse
import configparser
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

CONF_PATHS = [
    Path("/etc/netasset/netasset_collector.conf"),
    Path("/opt/drucker-collectors/netasset_collector.conf"),
    Path.home() / "drucker-collectors/netasset_collector.conf",
    Path.home() / "Library/NetAsset/netasset_collector.conf",
]

MAX_RECORDING = 9_500_000  # etwas unter dem 10-MB-Serverlimit


def load_config() -> dict:
    cfg = configparser.ConfigParser()
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            break
    na = cfg["netasset"] if "netasset" in cfg else {}
    return {
        "api_url": os.environ.get("NETASSET_URL", na.get("api_url", "")).rstrip("/"),
        "api_key": os.environ.get("NETASSET_API_KEY", na.get("api_key", "")),
        "timeout": int(na.get("timeout", "30")),
    }


def _duration(started: str, ended: str) -> int | None:
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        return int((datetime.strptime(ended, fmt) - datetime.strptime(started, fmt)).total_seconds())
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default=None)
    parser.add_argument("--logfile", required=True)
    parser.add_argument("--started", default=None)
    parser.add_argument("--ended", default=None)
    parser.add_argument("--exit", dest="exit_code", type=int, default=None)
    args = parser.parse_args()

    config = load_config()
    if not config["api_url"] or not config["api_key"]:
        sys.exit("netasset_collector.conf: api_url/api_key fehlen – kein Upload")

    try:
        with open(args.logfile, "rb") as f:
            recording = f.read().decode("utf-8", errors="replace")
    except OSError as e:
        sys.exit(f"Logdatei nicht lesbar: {e}")

    if len(recording) > MAX_RECORDING:
        recording = recording[:MAX_RECORDING] + "\n[... gekürzt – Limit erreicht ...]\n"

    payload = {
        "session_uuid": args.session,
        "operator": args.user or "unbekannt",
        "target_host": args.host,
        "target_user": args.user,
        "started_at": args.started,
        "ended_at": args.ended,
        "duration_sec": _duration(args.started, args.ended) if args.started and args.ended else None,
        "exit_code": args.exit_code,
        "recording_format": "screen-log",
        "recording": recording,
    }

    url = f"{config['api_url']}/api/v1/sessions/ingest"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": config["api_key"]},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=config["timeout"]) as resp:
            json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"Upload fehlgeschlagen ({e.code}): {e.read().decode(errors='replace')[:300]}")
    except Exception as e:
        sys.exit(f"Upload fehlgeschlagen: {e}")


if __name__ == "__main__":
    main()
