#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset Fritz!Box Collector

Liest per TR-064 API (fritzconnection) die Fritz!Box aus und meldet:
  1. Die Fritz!Box selbst als Asset (Router/Firewall)
  2. Alle bekannten Netzwerkgeräte (aktiv + inaktiv, LAN und WLAN)

Voraussetzungen:
  pip install fritzconnection

Fritz!Box vorbereiten:
  Heimnetzwerk -> Netzwerk -> "Zugang fuer Anwendungen erlauben" aktivieren
  (TR-064 muss aktiviert sein - Standard bei neueren Modellen)

Aufruf:
  python3 fritzbox_collector.py               # Upload
  python3 fritzbox_collector.py --dry-run     # nur anzeigen
  python3 fritzbox_collector.py --active-only # nur aktive Geraete
"""

import argparse
import configparser
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netasset-fritzbox")

# ---------------------------------------------------------------------------
# fritzconnection prüfen
# ---------------------------------------------------------------------------

try:
    from fritzconnection.lib.fritzhosts import FritzHosts
    from fritzconnection.lib.fritzstatus import FritzStatus
    from fritzconnection.core.fritzconnection import FritzConnection
    HAS_FRITZ = True
except ImportError:
    HAS_FRITZ = False

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

CONF_PATHS = [
    Path(__file__).parent / "fritzbox_collector.conf",
    Path("/etc/netasset/fritzbox_collector.conf"),
    Path.home() / "Library/NetAsset/fritzbox_collector.conf",
    Path(os.environ.get("APPDATA", "C:/ProgramData")) / "NetAsset/fritzbox_collector.conf",
]


def load_config() -> dict:
    cfg = configparser.ConfigParser()
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            log.info("Konfiguration: %s", path)
            break

    fb = cfg["fritzbox"] if "fritzbox" in cfg else {}
    na = cfg["netasset"] if "netasset" in cfg else {}
    return {
        "host": os.environ.get("FRITZ_HOST", fb.get("host", "192.168.178.1")),
        "port": int(fb.get("port", "49000")),
        "username": os.environ.get("FRITZ_USER", fb.get("username", "")),
        "password": os.environ.get("FRITZ_PASS", fb.get("password", "")),
        "use_tls": fb.get("use_tls", "false").lower() == "true",
        "api_url": os.environ.get("NETASSET_URL", na.get("api_url", "https://ocs.kiste.org")),
        "api_key": os.environ.get("NETASSET_API_KEY", na.get("api_key", "")),
        "exposure_level": na.get("exposure_level", "INTERN"),
        "tags": [t.strip() for t in na.get("tags", "fritzbox,avm").split(",")],
        "timeout": int(na.get("timeout", "15")),
    }


# ---------------------------------------------------------------------------
# Daten sammeln
# ---------------------------------------------------------------------------

INTERFACE_LABELS = {
    "802.11": "WLAN",
    "Ethernet": "LAN",
    "HomePlug": "Powerline",
}


def collect(config: dict, active_only: bool = False) -> dict:
    """Sammelt alle Daten von der Fritz!Box via TR-064."""
    kwargs = {
        "address": config["host"],
        "port": config["port"],
        "use_tls": config["use_tls"],
    }
    if config["username"]:
        kwargs["user"] = config["username"]
    if config["password"]:
        kwargs["password"] = config["password"]

    log.info("Verbinde mit Fritz!Box %s...", config["host"])

    # --- Fritz!Box selbst ---
    fc = FritzConnection(**kwargs)
    fs = FritzStatus(**kwargs)

    model = fc.modelname or "Fritz!Box"
    firmware = fc.system_version or ""
    serial = None
    try:
        info = fc.call_action("DeviceInfo1", "GetInfo")
        serial = info.get("NewSerialNumber") or None
        if not firmware:
            firmware = info.get("NewSoftwareVersion", "")
    except Exception:
        pass

    # WAN-IP (externe IP)
    wan_ip = None
    try:
        wan_ip = fs.external_ip
    except Exception:
        pass

    # LAN-IP der Fritz!Box
    lan_ip = config["host"]

    # LAN-MAC
    lan_mac = None
    try:
        lan_info = fc.call_action("LANEthernetInterfaceConfig1", "GetInfo")
        lan_mac = lan_info.get("NewMACAddress", "").lower() or None
    except Exception:
        pass

    fritz_device = {
        "hostname": "fritzbox",
        "ip_address": lan_ip,
        "mac_address": lan_mac,
        "serial_number": serial,
        "chassis_id": serial,
        "manufacturer": "AVM",
        "model": model,
        "firmware_version": firmware,
        "os_name": "Fritz!OS",
        "os_version": firmware,
        "asset_type": "firewall",
        "open_ports": [
            {"port": 80,    "proto": "tcp", "service": "http",  "reachable_from": ["intern"]},
            {"port": 443,   "proto": "tcp", "service": "https", "reachable_from": ["intern"]},
            {"port": 49000, "proto": "tcp", "service": "tr-064","reachable_from": ["intern"]},
        ],
    }

    if wan_ip:
        fritz_device["_wan_ip"] = wan_ip

    # --- Netzwerkgeräte ---
    fh = FritzHosts(**kwargs)
    hosts = fh.get_hosts_info()

    neighbors = []
    for host in hosts:
        if active_only and not host.get("status"):
            continue

        # Interface-Typ human-readable
        iface_raw = host.get("interface_type", "")
        iface = INTERFACE_LABELS.get(iface_raw, iface_raw or "unbekannt")
        if "WLAN" in iface:
            # WLAN-Band ergänzen wenn verfügbar
            band = host.get("X_AVM-DE_Speed", "")
            iface = f"WLAN ({band})" if band else "WLAN"

        neighbors.append({
            "ip":       host.get("ip"),
            "mac":      (host.get("mac") or "").lower() or None,
            "hostname": host.get("name") or None,
            "active":   bool(host.get("status")),
            "interface":iface,
            "comment":  f"Interface: {iface}" + (" [aktiv]" if host.get("status") else " [inaktiv]"),
        })

    active_count = sum(1 for n in neighbors if n.get("active"))
    log.info(
        "Gesammelt: %s (%s), %d Hosts (%d aktiv), WAN-IP: %s",
        model, firmware, len(neighbors), active_count, wan_ip or "—"
    )

    return {"device": fritz_device, "neighbors": neighbors}


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
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def push(config: dict, data: dict, push_neighbors: bool = True, dry_run: bool = False):
    base = config["api_url"].rstrip("/")
    device = data["device"]
    neighbors = data["neighbors"]

    wan_ip = device.pop("_wan_ip", None)
    device["exposure_level"] = config["exposure_level"]
    device["tags"] = config["tags"] + (["wan-ip-" + wan_ip.replace(".", "-")] if wan_ip else [])
    device["source"] = "fritzbox-collector"

    if dry_run:
        print("\n=== DRY RUN ===\n")
        print("Fritz!Box Asset:")
        print(json.dumps(device, indent=2))
        if wan_ip:
            print(f"\n  WAN-IP: {wan_ip}")
        print(f"\nGeräte ({len(neighbors)}):")
        for n in neighbors:
            status = "✓" if n.get("active") else "·"
            print(f"  {status} {(n['ip'] or '—'):<18} {(n['mac'] or '—'):<20} "
                  f"{(n['hostname'] or '—'):<25} {n.get('interface','')}")
        return

    # Fritz!Box als Asset
    result = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], [device], config["timeout"])
    action = result[0].get("action") if result else "?"
    log.info("Fritz!Box Asset: %s", action)

    if not push_neighbors or not neighbors:
        return

    # Nur Hosts mit IP UND (Hostname oder MAC) pushen
    neighbor_devices = []
    for n in neighbors:
        # Mindestens IP oder MAC muss vorhanden sein
        if not n.get("ip") and not n.get("mac"):
            continue
        # Geräte ohne IP überspringen (inaktiv, nur im ARP-Cache)
        if not n.get("ip"):
            continue
        # Fritz!Box selbst überspringen
        if n.get("ip") == config["host"]:
            continue

        tags = ["fritzbox-host"]
        if n.get("active"):
            tags.append("active")
        if n.get("interface"):
            iface_tag = n["interface"].lower().replace(" ", "-").replace("(", "").replace(")", "")
            tags.append(iface_tag)

        neighbor_devices.append({
            "hostname": n.get("hostname"),
            "ip_address": n.get("ip"),
            "mac_address": n.get("mac"),
            "asset_type": "client",
            "exposure_level": config["exposure_level"],
            "tags": tags,
            "source": "fritzbox-hosts",
        })

    if neighbor_devices:
        created = merged = flagged = 0
        for i in range(0, len(neighbor_devices), 50):
            res = api_post(
                f"{base}/api/v1/discovery/ingest",
                config["api_key"],
                neighbor_devices[i:i+50],
                config["timeout"],
            )
            for item in (res or []):
                a = item.get("action", "")
                if a == "created": created += 1
                elif a == "merged": merged += 1
                else: flagged += 1
        log.info("Geräte: %d neu, %d aktualisiert, %d Konflikt", created, merged, flagged)


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NetAsset Fritz!Box Collector")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--active-only", action="store_true", help="Nur aktive Geräte")
    parser.add_argument("--no-neighbors", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not HAS_FRITZ:
        log.error("fritzconnection nicht installiert.")
        log.error("Bitte ausführen: pip install fritzconnection")
        sys.exit(1)

    config = load_config()

    if not config["api_key"] and not args.dry_run:
        log.error("NETASSET_API_KEY nicht gesetzt.")
        sys.exit(1)

    try:
        data = collect(config, active_only=args.active_only)
    except Exception as e:
        log.error("Fehler beim Sammeln: %s", e)
        log.error("TR-064 aktiviert? Fritz!Box -> Heimnetzwerk -> Netzwerk -> "
                  "'Zugang fuer Anwendungen erlauben'")
        sys.exit(1)

    push(config, data, push_neighbors=not args.no_neighbors, dry_run=args.dry_run)
    if not args.dry_run:
        log.info("Fertig.")


if __name__ == "__main__":
    main()
