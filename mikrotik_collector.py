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
import http.client
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


def _section_to_config(s: dict, na: dict) -> dict:
    """Wandelt einen configparser-Abschnitt in ein Config-Dict um."""
    return {
        "username":       os.environ.get("MIKROTIK_USER", s.get("username", "admin")),
        "password":       os.environ.get("MIKROTIK_PASS", s.get("password", "")),
        "use_https":      s.get("use_https", "true").lower() == "true",
        "verify_ssl":     s.get("verify_ssl", "false").lower() == "true",
        "port_rest":      int(s.get("port_rest", "443")),
        "snmp_community": s.get("snmp_community", "public"),
        "snmp_port":      int(s.get("snmp_port", "161")),
        "mode":           s.get("mode", "rest"),
        "api_url":        os.environ.get("NETASSET_URL",     na.get("api_url",  "https://ocs.kiste.org")),
        "api_key":        os.environ.get("NETASSET_API_KEY", na.get("api_key",  "")),
        "exposure_level": na.get("exposure_level", "INTERN"),
        "tags":           [t.strip() for t in na.get("tags", "mikrotik,router").split(",")],
        "timeout":        int(na.get("timeout", "15")),
    }


def _parse_hosts(s: dict) -> list[str]:
    """Liest hosts/host aus einem Config-Abschnitt."""
    single = os.environ.get("MIKROTIK_HOST", s.get("host", ""))
    multi_raw = s.get("hosts", "")
    if multi_raw:
        return [h.strip() for h in multi_raw.replace(",", "\n").splitlines() if h.strip()]
    elif single:
        return [single]
    return []


def load_configs(config_files: list[str] | None = None) -> list[dict]:
    """
    Lädt eine oder mehrere Config-Dateien und gibt eine Liste von
    per-Host-Configs zurück.

    Unterstützte Formate:
    ─────────────────────
    1. Mehrere Dateien via -c file1.conf -c file2.conf
       Jede Datei hat ihren eigenen [mikrotik]-Block mit Credentials + hosts.

    2. Per-Host-Sections in einer Datei:
         [mikrotik]           ← Defaults + gemeinsame Hosts
         username = admin
         password = geheim

         [mikrotik:192.168.1.5]   ← Überschreibt nur diesen Host
         password = anderes_pw
         port_rest = 8443
    """
    all_host_configs: list[dict] = []

    files_to_read: list[str] = []
    if config_files:
        files_to_read = config_files
    else:
        for path in CONF_PATHS:
            if path.exists():
                files_to_read = [str(path)]
                break

    if not files_to_read:
        log.warning("Keine Config-Datei gefunden.")
        return []

    for config_file in files_to_read:
        cfg = configparser.ConfigParser()
        cfg.read(config_file)
        log.info("Konfiguration: %s", config_file)

        if "mikrotik" not in cfg:
            log.warning("%s: Kein [mikrotik]-Abschnitt gefunden, übersprungen.", config_file)
            continue

        defaults = cfg["mikrotik"]
        na       = cfg["netasset"] if "netasset" in cfg else {}
        base_cfg = _section_to_config(defaults, na)

        # Hosts aus dem Default-Abschnitt
        default_hosts = _parse_hosts(defaults)

        # Per-Host-Sections: [mikrotik:IP] oder [mikrotik:hostname]
        host_overrides: dict[str, dict] = {}
        for section in cfg.sections():
            if section.startswith("mikrotik:"):
                host_ip = section.split(":", 1)[1].strip()
                # Merge: Default-Config + Override-Werte
                override = dict(defaults)
                override.update(dict(cfg[section]))
                host_overrides[host_ip] = _section_to_config(override, na)

        # Hosts aus expliziten [mikrotik:IP]-Sections die NICHT in hosts= stehen
        for host_ip in host_overrides:
            if host_ip not in default_hosts:
                default_hosts.append(host_ip)

        if not default_hosts:
            log.warning("%s: Keine Hosts konfiguriert.", config_file)
            continue

        for host in default_hosts:
            # Override hat Vorrang vor Default
            host_cfg = host_overrides.get(host, base_cfg).copy()
            host_cfg["host"]  = host
            host_cfg["hosts"] = [host]
            all_host_configs.append(host_cfg)

    return all_host_configs


# Rückwärtskompatibilität für direkten import
def load_config(config_file: str | None = None) -> dict:
    configs = load_configs([config_file] if config_file else None)
    if not configs:
        return {"hosts": [], "host": ""}
    # Alle Hosts zusammenführen (alte API: ein Dict mit hosts-Liste)
    merged = configs[0].copy()
    merged["hosts"] = [c["host"] for c in configs]
    return merged


# ---------------------------------------------------------------------------
# MikroTik REST API Client (RouterOS 7.1+)
# ---------------------------------------------------------------------------

class MikroTikREST:
    def __init__(self, host: str, username: str, password: str,
                 use_https: bool = True, port: int = 443, verify_ssl: bool = False):
        self._host = host
        self._port = port
        self.use_https = use_https
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/json",
        }
        self._ssl_ctx = None
        if use_https:
            self._ssl_ctx = ssl.create_default_context()
            if not verify_ssl:
                self._ssl_ctx.check_hostname = False
                self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def get(self, path: str) -> list[dict]:
        """HTTP GET via http.client (umgeht urllib SSL-Handler)."""
        url_path = "/rest" + path
        try:
            if self.use_https:
                conn = http.client.HTTPSConnection(
                    self._host, self._port, context=self._ssl_ctx, timeout=15
                )
            else:
                conn = http.client.HTTPConnection(
                    self._host, self._port, timeout=15
                )
            conn.request("GET", url_path, headers=self.headers)
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read())
                # MikroTik gibt für Einzel-Ressourcen ein Dict zurück,
                # für Collections ein Array – wir normalisieren auf Liste
                if isinstance(data, dict):
                    return [data]
                return data if isinstance(data, list) else []
            log.warning("REST %s -> HTTP %d", path, resp.status)
            return []
        except Exception as e:
            log.warning("REST %s -> %s", path, e)
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

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

        # Offene Ports aus Services + Firewall
        services  = self.get("/ip/service")
        fw_input  = self.get("/ip/firewall/filter")
        # LLDP/CDP-Nachbarn
        lldp      = self.get("/ip/neighbor")
        # WLAN-Clients – Registration-Table (RouterOS 6/7 Classic WLAN)
        wlan_clients = self.get("/interface/wireless/registration-table")
        # WLAN-Clients – CAPsMAN / WiFi (RouterOS 7.x)
        capsman_clients = self.get("/caps-man/registration-table")
        wifi_clients    = self.get("/interface/wifi/registration-table")

        # Services → offene Ports (aktiv + erreichbarkeit per Firewall)
        extern_ports = _extern_ports_from_firewall(fw_input)
        log.debug("Services von API (%d Einträge): %s", len(services), services)

        open_ports = []
        for svc in services:
            # RouterOS liefert disabled als String "true"/"false" oder bool
            disabled = svc.get("disabled", "false")
            if disabled == "true" or disabled is True:
                continue
            port_val = svc.get("port")
            if not port_val:
                continue
            try:
                port_num = int(port_val)
            except (ValueError, TypeError):
                continue
            reachable = ["extern"] if port_num in extern_ports else ["intern"]
            open_ports.append({
                "port": port_num,
                "proto": "tcp",
                "service": svc.get("name", ""),
                "reachable_from": reachable,
            })

        # Fallback: Socket-Check bekannter MikroTik-Ports wenn API nichts liefert
        if not open_ports:
            log.warning("Keine Ports via REST API – führe Socket-Fallback durch...")
            open_ports = _probe_mikrotik_ports(self._host)

        # UDP-Dienste ergänzen
        udp_services = self.get("/ip/dns")
        if udp_services and udp_services[0].get("allow-remote-requests") in ("true", True):
            open_ports.append({"port": 53, "proto": "udp", "service": "dns", "reachable_from": ["intern"]})
        for udp_port, svc_name in [(123, "ntp"), (161, "snmp"), (1701, "l2tp"), (500, "ike"), (4500, "ipsec-nat")]:
            if udp_port in extern_ports:
                open_ports.append({"port": udp_port, "proto": "udp", "service": svc_name, "reachable_from": ["extern"]})

        log.info("Ports erkannt: %d (davon extern: %d)", len(open_ports),
                 sum(1 for p in open_ports if "extern" in p.get("reachable_from", [])))

        # System-Health als Metadaten
        uptime   = res.get("uptime", "")
        cpu_load = res.get("cpu-load", "")
        mem_free = res.get("free-memory", "")
        mem_total= res.get("total-memory", "")

        log.info(
            "System: uptime=%s cpu=%s%% mem=%s/%s",
            uptime, cpu_load, mem_free, mem_total
        )

        # Nachbarn: ARP + DHCP + Bridge MAC + LLDP + WLAN-Clients (alle Quellen)
        neighbors = _parse_neighbors(arp, dhcp)
        neighbors = _enrich_with_bridge_hosts(neighbors, bridge_hosts, bridge_ports)
        neighbors = _enrich_with_lldp(neighbors, lldp)
        # Classic WLAN + CAPsMAN + WiFi (RouterOS 7) zusammenführen
        all_wlan = wlan_clients + capsman_clients + wifi_clients
        neighbors = _enrich_with_wlan(neighbors, all_wlan)

        wlan_count = sum(1 for n in neighbors if n.get("_source") == "wlan")
        arp_count  = sum(1 for n in neighbors if n.get("_source") != "wlan")
        log.info("Nachbarn: %d gesamt (%d ARP/DHCP, %d WLAN)", len(neighbors), arp_count, wlan_count)

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

def _probe_mikrotik_ports(host: str, timeout: float = 2.0) -> list[dict]:
    """
    Socket-basierter Fallback: prüft bekannte MikroTik-Ports direkt.
    Wird verwendet wenn /ip/service keine Daten liefert.
    """
    import socket
    MIKROTIK_PORTS = [
        (21,   "tcp", "ftp"),
        (22,   "tcp", "ssh"),
        (23,   "tcp", "telnet"),
        (80,   "tcp", "www"),
        (443,  "tcp", "www-ssl"),
        (8291, "tcp", "winbox"),
        (8728, "tcp", "api"),
        (8729, "tcp", "api-ssl"),
        (8080, "tcp", "www-alt"),
    ]
    found = []
    for port, proto, name in MIKROTIK_PORTS:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                found.append({
                    "port": port,
                    "proto": proto,
                    "service": name,
                    "reachable_from": ["intern"],
                })
                log.debug("Port offen: %d/%s (%s)", port, proto, name)
        except (ConnectionRefusedError, OSError):
            pass
    log.info("Socket-Fallback: %d Ports offen auf %s", len(found), host)
    return found


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


def _extern_ports_from_firewall(fw_rules: list[dict]) -> set[int]:
    """Extrahiert Ports die per Firewall-Accept-Regel von extern erreichbar sind."""
    extern = set()
    for rule in fw_rules:
        if (rule.get("chain") == "input"
                and rule.get("action") == "accept"
                and not rule.get("disabled")
                and rule.get("dst-port")):
            for p in str(rule["dst-port"]).split(","):
                p = p.strip()
                if p.isdigit():
                    extern.add(int(p))
                elif "-" in p:
                    try:
                        lo, hi = p.split("-")
                        extern.update(range(int(lo), int(hi) + 1))
                    except ValueError:
                        pass
    return extern


def _enrich_with_lldp(neighbors: list[dict], lldp: list[dict]) -> list[dict]:
    """Ergänzt Nachbarn mit LLDP/CDP-Daten (Hostname, Interface)."""
    existing_ips = {n.get("ip") for n in neighbors if n.get("ip")}

    for entry in lldp:
        ip = entry.get("address") or entry.get("ipv4-address")
        mac = (entry.get("mac-address") or "").lower() or None
        hostname = entry.get("identity") or entry.get("system-name") or None
        iface = entry.get("interface", "")
        platform = entry.get("system-description", "")

        if ip and ip not in existing_ips:
            neighbors.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "comment": f"LLDP via {iface}" + (f" ({platform[:40]})" if platform else ""),
                "_source": "lldp",
            })
        elif ip:
            for n in neighbors:
                if n.get("ip") == ip:
                    if not n.get("hostname") and hostname:
                        n["hostname"] = hostname
                    n["_lldp_iface"] = iface
                    break

    return neighbors


def _enrich_with_wlan(neighbors: list[dict], clients: list[dict]) -> list[dict]:
    """Ergänzt/fügt WLAN-Clients aus der Registration-Tabelle hinzu."""
    existing_macs = {n.get("mac") for n in neighbors if n.get("mac")}

    for c in clients:
        mac = (c.get("mac-address") or "").lower()
        if not mac:
            continue
        signal = c.get("signal-strength", "")
        iface = c.get("interface", "")
        tx_rate = c.get("tx-rate", "")

        comment = f"WLAN {iface}" + (f" Signal: {signal}" if signal else "")

        if mac not in existing_macs:
            neighbors.append({
                "ip": None,
                "mac": mac,
                "hostname": None,
                "comment": comment,
                "_source": "wlan",
                "_wlan_signal": signal,
                "_wlan_tx_rate": tx_rate,
            })
        else:
            for n in neighbors:
                if n.get("mac") == mac:
                    n["_wlan_signal"] = signal
                    n["_wlan_tx_rate"] = tx_rate
                    break

    return neighbors


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


def _build_neighbor_device(n: dict, config: dict, mikrotik_ip: str | None) -> dict | None:
    """Wandelt einen Nachbar-Eintrag in ein NetAsset Discovery-Device um."""
    ip  = n.get("ip")
    mac = n.get("mac")

    # Weder IP noch MAC → nicht push-bar
    if not ip and not mac:
        return None
    # MikroTik selbst überspringen
    if ip and ip == mikrotik_ip:
        return None

    source_type = n.get("_source", "arp")   # arp | wlan | lldp | bridge

    # Tags je nach Herkunft
    tags = ["via-mikrotik"]
    if source_type == "wlan":
        tags += ["wlan-client", "wireless"]
        asset_type = "client"
    elif source_type == "lldp":
        tags += ["lldp-discovered"]
        asset_type = "switch"   # LLDP-Nachbarn sind meist Netzwerkgeräte
    else:
        tags += ["arp-discovered"]
        asset_type = "server"

    # Zusatzinfos als Notes
    notes_parts = []
    if n.get("_wlan_signal"):
        notes_parts.append(f"WLAN-Signal: {n['_wlan_signal']}")
    if n.get("_wlan_tx_rate"):
        notes_parts.append(f"TX-Rate: {n['_wlan_tx_rate']}")
    if n.get("_switch_port"):
        notes_parts.append(f"Switch-Port: {n['_switch_port']}")
    if n.get("_lldp_iface"):
        notes_parts.append(f"LLDP-Interface: {n['_lldp_iface']}")
    if n.get("comment"):
        notes_parts.append(n["comment"])

    device: dict = {
        "hostname":       n.get("hostname"),
        "ip_address":     ip,
        "mac_address":    mac,
        "asset_type":     asset_type,
        "exposure_level": config["exposure_level"],
        "tags":           tags,
        "source":         f"mikrotik-{source_type}",
    }
    if notes_parts:
        device["notes"] = "\n".join(notes_parts)

    return device


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

    # Nachbar-Devices aufbauen
    mikrotik_ip = device.get("ip_address")
    neighbor_devices = []
    for n in neighbors:
        nd = _build_neighbor_device(n, config, mikrotik_ip)
        if nd:
            neighbor_devices.append(nd)

    # Statistik nach Typ
    by_src: dict[str, int] = {}
    for nd in neighbor_devices:
        src = nd.get("source", "?")
        by_src[src] = by_src.get(src, 0) + 1

    if dry_run:
        print("\n=== DRY RUN ===\n")
        print("MikroTik-Asset:")
        print(json.dumps(device, indent=2))
        ports = device.get("open_ports") or []
        if ports:
            print(f"\nPorts ({len(ports)}):")
            for p in ports:
                reach = ",".join(p.get("reachable_from", []))
                print(f"  {p['port']}/{p['proto']:<4} {p.get('service',''):<12} [{reach}]")
        else:
            print("\nPorts: keine erkannt")
        print(f"\nNachbarn gesamt: {len(neighbor_devices)}")
        for src, cnt in sorted(by_src.items()):
            print(f"  {src}: {cnt}")
        print()
        # Aufgeschlüsselt nach Quelle anzeigen
        for src_filter in ("mikrotik-wlan", "mikrotik-arp", "mikrotik-lldp", "mikrotik-bridge"):
            group = [nd for nd in neighbor_devices if nd.get("source") == src_filter]
            if not group:
                continue
            label = src_filter.replace("mikrotik-", "").upper()
            print(f"── {label} ({len(group)}) ──")
            for nd in group[:15]:
                ip_s  = (nd.get("ip_address") or "—").ljust(18)
                mac_s = (nd.get("mac_address") or "—").ljust(20)
                host  = nd.get("hostname") or "—"
                notes = nd.get("notes", "")
                print(f"  {ip_s} {mac_s} {host}  {notes}")
            if len(group) > 15:
                print(f"  ... +{len(group)-15} weitere")
            print()
        return

    # MikroTik selbst pushen
    result = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], [device], config["timeout"])
    action = result[0].get("action") if result else "?"
    log.info("MikroTik-Asset: %s (%s)", device.get("hostname"), action)

    if not push_neighbors or not neighbor_devices:
        return

    # Nachbarn in Batches von 50 pushen
    created = merged = flagged = 0
    for i in range(0, len(neighbor_devices), 50):
        batch = neighbor_devices[i:i+50]
        res = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], batch, config["timeout"])
        for item in (res or []):
            a = item.get("action", "")
            if a == "created":  created += 1
            elif a == "merged": merged  += 1
            else:               flagged += 1

    log.info(
        "Nachbarn: %d neu, %d aktualisiert, %d Konflikt  (ARP:%d WLAN:%d LLDP:%d Bridge:%d)",
        created, merged, flagged,
        by_src.get("mikrotik-arp", 0),
        by_src.get("mikrotik-wlan", 0),
        by_src.get("mikrotik-lldp", 0),
        by_src.get("mikrotik-bridge", 0),
    )


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetAsset MikroTik Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  # Einzelne Config
  python3 mikrotik_collector.py -c mikrotik.conf

  # Mehrere Configs mit unterschiedlichen Passwörtern
  python3 mikrotik_collector.py -c site1.conf -c site2.conf -c office.conf

  # Dry-Run über alle Configs
  python3 mikrotik_collector.py -c site1.conf -c site2.conf --dry-run

Config-Format mit per-Host-Passwörtern (eine Datei):
  [mikrotik]
  username = admin
  password = standard_pw
  hosts =
      192.168.1.1
      192.168.1.2

  [mikrotik:192.168.1.3]   # Überschreibt nur diesen Host
  password = anderes_pw
  port_rest = 8443
""",
    )
    parser.add_argument(
        "--config", "-c",
        action="append",
        dest="configs",
        metavar="FILE",
        help="Config-Datei (mehrfach verwendbar: -c a.conf -c b.conf)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-neighbors", action="store_true", help="Keine Nachbarn pushen")
    parser.add_argument("--snmp", action="store_true", help="SNMP statt REST API erzwingen")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    host_configs = load_configs(args.configs)

    if not host_configs:
        log.error("Kein Host konfiguriert. 'host' oder 'hosts' in der Config eintragen.")
        sys.exit(1)

    if not args.dry_run:
        missing_key = [c["host"] for c in host_configs if not c.get("api_key")]
        if missing_key:
            log.error("Kein API-Key für: %s", ", ".join(missing_key))
            sys.exit(1)

    log.info("Starte Scan: %d MikroTik-Gerät(e)", len(host_configs))

    errors = 0
    for host_config in host_configs:
        host = host_config["host"]
        log.info("─── %s (user=%s, port=%s) ───",
                 host, host_config["username"], host_config["port_rest"])

        try:
            if args.snmp or host_config["mode"] == "snmp":
                data = collect_snmp(host, host_config["snmp_community"], host_config["snmp_port"])
            else:
                client = MikroTikREST(
                    host,
                    host_config["username"],
                    host_config["password"],
                    use_https=host_config["use_https"],
                    port=host_config["port_rest"],
                    verify_ssl=host_config["verify_ssl"],
                )
                data = client.collect()
        except Exception as e:
            log.error("Fehler bei %s: %s", host, e)
            errors += 1
            continue

        dev = data["device"]
        log.info(
            "Gesammelt: %s (%s %s), %d Nachbarn",
            dev.get("hostname"), dev.get("os_name"), dev.get("os_version"),
            len(data.get("neighbors", [])),
        )

        push(host_config, data, push_neighbors=not args.no_neighbors, dry_run=args.dry_run)

    if not args.dry_run:
        log.info("Fertig. %d/%d Geräte erfolgreich.", len(host_configs) - errors, len(host_configs))


if __name__ == "__main__":
    main()
