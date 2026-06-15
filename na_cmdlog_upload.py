#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset – Upload der zielseitig protokollierten Kommandos einer Jumpbox-Session.

Wird vom Logout-Hook (na_cmdlog.sh) aufgerufen. Liest api_url/api_key aus der
vorhandenen netasset_collector.conf (kein separater Key nötig) und schickt die
Kommandoliste an POST /api/v1/sessions/<uuid>/commands.

Eingabedatei (TSV):  seq <tab> iso-zeit <tab> cwd <tab> base64(command)
"""

import argparse
import base64
import configparser
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONF_PATHS = [
    Path("/etc/netasset/netasset_collector.conf"),
    Path("/opt/netasset-collector/netasset_collector.conf"),
    Path.home() / "Library/NetAsset/netasset_collector.conf",
]


def load_netasset_config() -> dict:
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


def parse_commands(path: str) -> list[dict]:
    commands = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                continue
            seq, ts, cwd, cmd_b64 = parts
            try:
                command = base64.b64decode(cmd_b64).decode("utf-8", errors="replace")
            except Exception:
                command = cmd_b64
            commands.append({
                "seq": int(seq) if seq.isdigit() else len(commands) + 1,
                "executed_at": ts,
                "command": command,
                "cwd": cwd or None,
            })
    return commands


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default=None)
    parser.add_argument("--file", required=True)
    args = parser.parse_args()

    config = load_netasset_config()
    if not config["api_url"] or not config["api_key"]:
        sys.exit("netasset_collector.conf: api_url/api_key fehlen")

    commands = parse_commands(args.file)
    if not commands:
        return
    for c in commands:
        c["os_user"] = args.user

    qs = urllib.parse.urlencode({"target_host": args.host, "operator": args.user or ""})
    url = f"{config['api_url']}/api/v1/sessions/{args.session}/commands?{qs}"
    body = json.dumps(commands).encode()
    req = urllib.request.Request(
        url, data=body,
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
