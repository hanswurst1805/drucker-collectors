#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset MikroTik Collector

Verbindet sich per REST API (RouterOS 7.1+) oder SNMP (alle Versionen)
und meldet an die NetAsset API:

  1. Den MikroTik selbst als Asset (Router/Switch)
  2. Alle per ARP/DHCP bekannten Geräte als Discovery-Assets

Voraussetzungen (REST API):
  - RouterOS 7.1 oder neuer
  - REST API aktiviert: /ip/services -> api-ssl oder www-ssl

Voraussetzungen (SNMP):
  - SNMP aktiviert auf dem MikroTik: /snmp set enabled=yes
  - Community-String bekannt (default: public)
  - snmpwalk/snmpget installiert (apt install snmp)

Aufruf:
  python3 mikrotik_collector.py                    # aus Config
  python3 mikrotik_collector.py --dry-run          # nur anzeigen
  python3 mikrotik_collector.py --no-neighbors     # nur MikroTik, keine Nachbarn
"""

import argparse
import configparser
import json
import logging
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import base64
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netasset-mikrotik")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

CONF_PATHS = [
    Path(__file__).parent / "mikrotik_collector.conf",
    Path("/etc/netasset/mikrotik_collector.conf"),
    Path.home() / "Library/NetAsset/mikrotik_collector.conf",
    Path(os.environ.get("APPDATA", "C:/ProgramData")) / "NetAsset/mikrotik_collector.conf",
]


def load_config() -> dict:
    cfg = configparser.ConfigParser()
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            log.info("Konfiguration: %s", path)
            break

    s = cfg["mikrotik"] if "mikrotik" in cfg else {}
    na = cfg["netasset"] if "netasset" in cfg else {}
    return {
        # MikroTik
        "host": os.environ.get("MIKROTIK_HOST", s.get("host", "")),
        "username": os.environ.get("MIKROTIK_USER", s.get("username", "admin")),
        "password": os.environ.get("MIKROTIK_PASS", s.get("password", "")),
        "use_https": s.get("use_https", "true").lower() == "true",
        "verify_ssl": s.get("verify_ssl", "false").lower() == "true",
        "port_rest": int(s.get("port_rest", "443")),
        "snmp_community": s.get("snmp_community", "public"),
        "snmp_port": int(s.get("snmp_port", "161")),
        "mode": s.get("mode", "rest"),  # rest | snmp
        # NetAsset
        "api_url": os.environ.get("NETASSET_URL", na.get("api_url", "https://ocs.kiste.org")),
        "api_key": os.environ.get("NETASSET_API_KEY", na.get("api_key", "")),
        "exposure_level": na.get("exposure_level", "INTERN"),
        "tags": [t.strip() for t in na.get("tags", "mikrotik,router").split(",")],
        "timeout": int(na.get("timeout", "15")),
    }


# ---------------------------------------------------------------------------
# MikroTik REST API Client (RouterOS 7.1+)
# ---------------------------------------------------------------------------

class MikroTikREST:
    def __init__(self, host: str, username: str, password: str,
                 use_https: bool = True, port: int = 443, verify_ssl: bool = False):
        scheme = "https" if use_https else "http"
        self.base = f"{scheme}://{host}:{port}/rest"
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
        }
        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def get(self, path: str) -> list[dict]:
        url = self.base + path
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            log.warning("REST %s -> HTTP %d", path, e.code)
            return []
        except Exception as e:
            log.warning("REST %s -> %s", path, e)
            return []

    def collect(self) -> dict:
        """Sammelt alle relevanten Daten vom MikroTik."""
        log.info("Verbinde per REST API...")

        resource    = self.get("/system/resource")
        identity    = self.get("/system/identity")
        routerboard = self.get("/system/routerboard")
        addresses   = self.get("/ip/address")
        interfaces  = self.get("/interface")
        arp         = self.get("/ip/arp")
        dhcp        = self.get("/ip/dhcp-server/lease")
        bridges     = self.get("/interface/bridge")
        bridge_hosts= self.get("/interface/bridge/host")  # MAC-Adresstabelle
        bridge_ports= self.get("/interface/bridge/port")
        vlans       = self.get("/interface/bridge/vlan")

        res = resource[0] if resource else {}
        idn = identity[0] if identity else {}
        rb  = routerboard[0] if routerboard else {}

        # Gerätetyp anhand Board-Name ermitteln
        board_name = (res.get("board-name") or rb.get("model") or "").upper()
        asset_type = _detect_asset_type(board_name, bridges, interfaces)
        log.info("Erkannter Gerätetyp: %s (Board: %s)", asset_type, board_name)

        # Primäre IP + MAC
        primary_ip, primary_mac = _find_primary_ip(addresses, interfaces)

        # VLAN-Info als Tags
        vlan_tags = []
        for vlan in vlans:
            vid = vlan.get("vlan-ids")
            if vid:
                vlan_tags.append(f"vlan-{vid}")

        # Offene Services
        services = self.get("/ip/service")
        open_ports = []
        for svc in services:
            if not svc.get("disabled") and svc.get("port"):
                open_ports.append({
                    "port": int(svc["port"]),
                    "proto": "tcp",
                    "service": svc.get("name"),
                    "reachable_from": ["intern"],
                })

        # Nachbarn: ARP + DHCP + Bridge MAC-Tabelle
        neighbors = _parse_neighbors(arp, dhcp)
        neighbors = _enrich_with_bridge_hosts(neighbors, bridge_hosts, bridge_ports)

        return {
            "device": {
                "hostname": idn.get("name", "mikrotik"),
                "ip_address": primary_ip,
                "mac_address": primary_mac,
                "serial_number": rb.get("serial-number") or None,
                "chassis_id": rb.get("serial-number") or None,
                "manufacturer": "MikroTik",
                "model": res.get("board-name") or rb.get("model"),
                "firmware_version": rb.get("current-firmware") or res.get("version"),
                "os_name": "RouterOS",
                "os_version": res.get("version"),
                "open_ports": open_ports,
                "_asset_type": asset_type,
                "_vlan_tags": vlan_tags,
                "_bridge_count": len(bridges),
                "_port_count": sum(1 for i in interfaces
                                   if i.get("type") in ("ether", "sfp", "sfp-sfpplus")),
            },
            "neighbors": neighbors,
        }


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _detect_asset_type(board_name: str, bridges: list, interfaces: list) -> str:
    """Ermittelt ob das Gerät Router oder Switch ist."""
    # CRS = Cloud Router Switch, CSS = Cloud Smart Switch → Switch
    if board_name.startswith(("CRS", "CSS")):
        return "switch"
    # RB = RouterBoard, CCR = Cloud Core Router → Router
    if board_name.startswith(("CCR", "RB4011", "RB5009", "RB1100")):
        return "router"
    # Heuristik: wenn Bridges vorhanden und mehr als 4 Ethernet-Ports → Switch
    eth_ports = sum(1 for i in interfaces
                    if i.get("type") in ("ether", "sfp", "sfp-sfpplus"))
    if bridges and eth_ports >= 4:
        return "switch"
    return "router"


def _find_primary_ip(addresses: list, interfaces: list) -> tuple[str | None, str | None]:
    """Findet die primäre IP + MAC (erste aktive, nicht-loopback Adresse)."""
    for addr in addresses:
        if addr.get("disabled") or not addr.get("address"):
            continue
        ip = addr["address"].split("/")[0]
        iface_name = addr.get("interface", "")
        mac = None
        for iface in interfaces:
            if iface.get("name") == iface_name and iface.get("mac-address"):
                mac = iface["mac-address"].lower()
                break
        return ip, mac
    return None, None


def _enrich_with_bridge_hosts(
    neighbors: list[dict],
    bridge_hosts: list[dict],
    bridge_ports: list[dict],
) -> list[dict]:
    """
    Ergänzt Nachbarn um Port-Info aus der Bridge MAC-Tabelle.
    Fügt auch Geräte hinzu die nur im Bridge-Table stehen (kein ARP-Eintrag).
    """
    # Port-ID -> Interface-Name Mapping
    port_map = {p.get(".id"): p.get("interface") for p in bridge_ports}

    existing_macs = {n.get("mac") for n in neighbors if n.get("mac")}

    for host in bridge_hosts:
        mac = (host.get("mac-address") or "").lower()
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            continue
        # Eigene Bridge-MAC überspringen (local=true)
        if host.get("local") == "true":
            continue

        port_iface = port_map.get(host.get("on-interface")) or host.get("on-interface") or ""

        if mac in existing_macs:
            # Port-Info zu bestehendem Nachbar ergänzen
            for n in neighbors:
                if n.get("mac") == mac:
                    n["_switch_port"] = port_iface
                    break
        else:
            # Neuer Nachbar nur aus Bridge-Table (kein ARP, z.B. Tagged VLAN)
            neighbors.append({
                "ip": None,
                "mac": mac,
                "hostname": None,
                "comment": f"Bridge-Port: {port_iface}",
                "_switch_port": port_iface,
            })
            existing_macs.add(mac)

    return neighbors


# ---------------------------------------------------------------------------
# SNMP-Fallback (alle RouterOS-Versionen)
# ---------------------------------------------------------------------------

def _snmp_get(host: str, community: str, oid: str, port: int = 161) -> str:
    cmd = ["snmpget", "-v2c", "-c", community, "-Oqv",
           f"{host}:{port}", oid]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip().strip('"')
    except Exception:
        return ""


def _snmp_walk(host: str, community: str, oid: str, port: int = 161) -> list[tuple[str, str]]:
    cmd = ["snmpwalk", "-v2c", "-c", community, "-Oqn",
           f"{host}:{port}", oid]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        rows = []
        for line in r.stdout.strip().splitlines():
            if " " in line:
                k, v = line.split(" ", 1)
                rows.append((k.strip(), v.strip().strip('"')))
        return rows
    except Exception:
        return []


def collect_snmp(host: str, community: str, port: int = 161) -> dict:
    log.info("Verbinde per SNMP...")
    if not shutil.which("snmpget"):
        raise RuntimeError("snmpwalk/snmpget nicht gefunden (apt install snmp)")

    hostname  = _snmp_get(host, community, "1.3.6.1.2.1.1.5.0", port)
    descr     = _snmp_get(host, community, "1.3.6.1.2.1.1.1.0", port)
    # RouterOS-Version aus sysDescr extrahieren
    os_version = ""
    if "RouterOS" in descr:
        parts = descr.split()
        for i, p in enumerate(parts):
            if p == "RouterOS" and i + 1 < len(parts):
                os_version = parts[i + 1]
                break

    # Interfaces: ifDescr + ifPhysAddress
    iface_names = dict(_snmp_walk(host, community, "1.3.6.1.2.1.2.2.1.2", port))
    iface_macs  = dict(_snmp_walk(host, community, "1.3.6.1.2.1.2.2.1.6", port))

    # IP-Adressen
    ip_iface = dict(_snmp_walk(host, community, "1.3.6.1.2.1.4.20.1.2", port))
    ip_list  = list(ip_iface.keys())
    primary_ip = ip_list[0].split(".")[-4:] if ip_list else None
    if primary_ip:
        primary_ip = ".".join(str(x) for x in primary_ip)
        # Korrigieren: OID-Format ist 1.3.6.1.2.1.4.20.1.2.X.X.X.X
        for oid_key in ip_iface:
            ip_part = oid_key.replace("1.3.6.1.2.1.4.20.1.2.", "").strip(".")
            if ip_part and not ip_part.startswith("127."):
                primary_ip = ip_part
                break

    # ARP-Tabelle
    arp_ips  = dict(_snmp_walk(host, community, "1.3.6.1.2.1.4.22.1.3", port))
    arp_macs = dict(_snmp_walk(host, community, "1.3.6.1.2.1.4.22.1.2", port))
    neighbors = []
    for oid_key, ip in arp_ips.items():
        suffix = oid_key.replace("1.3.6.1.2.1.4.22.1.3.", "").strip(".")
        mac_raw = arp_macs.get(f"1.3.6.1.2.1.4.22.1.2.{suffix}", "")
        mac = ":".join(f"{int(b):02x}" for b in mac_raw.split() if b.isdigit()) if mac_raw else None
        if ip and not ip.startswith("127."):
            neighbors.append({"ip": ip, "mac": mac, "hostname": None, "comment": None})

    return {
        "device": {
            "hostname": hostname or host,
            "ip_address": primary_ip or host,
            "mac_address": None,
            "manufacturer": "MikroTik",
            "model": None,
            "os_name": "RouterOS",
            "os_version": os_version,
            "open_ports": [],
        },
        "neighbors": neighbors,
    }


# ---------------------------------------------------------------------------
# Nachbar-Parser (ARP + DHCP)
# ---------------------------------------------------------------------------

def _parse_neighbors(arp: list[dict], dhcp: list[dict]) -> list[dict]:
    """Kombiniert ARP-Tabelle und DHCP-Leases zu einer Nachbarliste."""
    seen: dict[str, dict] = {}

    # ARP-Tabelle
    for entry in arp:
        ip = entry.get("address")
        mac = (entry.get("mac-address") or "").lower()
        if not ip or ip.startswith("224.") or ip.endswith(".255"):
            continue
        seen[mac or ip] = {
            "ip": ip,
            "mac": mac or None,
            "hostname": None,
            "comment": entry.get("comment"),
        }

    # DHCP-Leases ergänzen (haben oft Hostnamen)
    for lease in dhcp:
        mac = (lease.get("mac-address") or "").lower()
        ip = lease.get("address")
        hostname = lease.get("host-name") or lease.get("comment") or None
        if mac in seen:
            seen[mac]["hostname"] = hostname
        elif ip:
            seen[ip] = {"ip": ip, "mac": mac or None, "hostname": hostname, "comment": None}

    return list(seen.values())


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
    neighbors = data.get("neighbors", [])

    # Asset-Typ + Tags aus gesammelten Daten
    asset_type = device.pop("_asset_type", "router")
    vlan_tags  = device.pop("_vlan_tags", [])
    device.pop("_bridge_count", None)
    device.pop("_port_count", None)

    device["asset_type"]     = asset_type
    device["exposure_level"] = config["exposure_level"]
    device["tags"]           = config["tags"] + vlan_tags + [asset_type]
    device["source"]         = "mikrotik-collector"

    if dry_run:
        print("\n=== DRY RUN ===\n")
        print("MikroTik-Asset:")
        print(json.dumps(device, indent=2))
        print(f"\nNachbarn ({len(neighbors)}):")
        for n in neighbors[:10]:
            print(f"  {n['ip']:<18} {n.get('mac') or '—':<20} {n.get('hostname') or '—'}")
        if len(neighbors) > 10:
            print(f"  ... +{len(neighbors)-10} weitere")
        return

    # MikroTik selbst
    result = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], [device], config["timeout"])
    action = result[0].get("action") if result else "?"
    log.info("MikroTik-Asset: %s (%s)", device.get("hostname"), action)

    if not push_neighbors or not neighbors:
        return

    # Nachbarn als Discovery-Devices
    neighbor_devices = []
    for n in neighbors:
        if not n.get("ip") or n["ip"] == device.get("ip_address"):
            continue
        neighbor_devices.append({
            "hostname": n.get("hostname"),
            "ip_address": n["ip"],
            "mac_address": n.get("mac"),
            "asset_type": "server",
            "exposure_level": config["exposure_level"],
            "tags": ["arp-discovered", "via-mikrotik"],
            "source": "mikrotik-arp",
        })

    if neighbor_devices:
        # In Batches von 50
        created = merged = flagged = 0
        for i in range(0, len(neighbor_devices), 50):
            batch = neighbor_devices[i:i+50]
            res = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], batch, config["timeout"])
            for item in (res or []):
                a = item.get("action", "")
                if a == "created": created += 1
                elif a == "merged": merged += 1
                else: flagged += 1
        log.info("Nachbarn: %d neu, %d aktualisiert, %d Konflikt", created, merged, flagged)


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NetAsset MikroTik Collector")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-neighbors", action="store_true", help="Keine Nachbarn pushen")
    parser.add_argument("--snmp", action="store_true", help="SNMP statt REST API erzwingen")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config()

    if not config["host"]:
        log.error("MIKROTIK_HOST nicht gesetzt. In mikrotik_collector.conf eintragen.")
        sys.exit(1)

    if not config["api_key"] and not args.dry_run:
        log.error("NETASSET_API_KEY nicht gesetzt.")
        sys.exit(1)

    log.info("MikroTik: %s", config["host"])

    try:
        if args.snmp or config["mode"] == "snmp":
            data = collect_snmp(config["host"], config["snmp_community"], config["snmp_port"])
        else:
            client = MikroTikREST(
                config["host"], config["username"], config["password"],
                use_https=config["use_https"],
                port=config["port_rest"],
                verify_ssl=config["verify_ssl"],
            )
            data = client.collect()
    except Exception as e:
        log.error("Fehler beim Sammeln: %s", e)
        sys.exit(1)

    dev = data["device"]
    log.info(
        "Gesammelt: %s (%s %s), %d Nachbarn",
        dev.get("hostname"), dev.get("os_name"), dev.get("os_version"),
        len(data.get("neighbors", [])),
    )

    push(config, data, push_neighbors=not args.no_neighbors, dry_run=args.dry_run)
    if not args.dry_run:
        log.info("Fertig.")


if __name__ == "__main__":
    main()
