#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset MikroTik-Switch Collector

Speziell für MikroTik CRS/CSS-Switches (RouterOS).
Sammelt switch-spezifische Daten und meldet sie an NetAsset:

  1. Den Switch selbst als Asset (Typ: switch)
  2. Port-Tabelle mit Status (up/down, Speed, Duplex)
  3. VLAN-Konfiguration
  4. Verbundene Geräte aus der FDB (MAC-Adresstabelle) + ARP

Voraussetzungen:
  - RouterOS 7.1+ mit REST API aktiviert
  - Alternativ: RouterOS 6.x mit SNMP

Aufruf:
  python3 mikrotik_switch_collector.py                   # aus Config
  python3 mikrotik_switch_collector.py --dry-run         # nur anzeigen
  python3 mikrotik_switch_collector.py -c switch.conf    # explizite Config
  python3 mikrotik_switch_collector.py -c a.conf -c b.conf  # mehrere Configs
"""

import argparse
import base64
import configparser
import http.client
import json
import logging
import os
import socket
import ssl
import sys
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netasset-switch")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

CONF_PATHS = [
    Path(__file__).parent / "mikrotik_switch_collector.conf",
    Path("/etc/netasset/mikrotik_switch_collector.conf"),
    Path.home() / "Library/NetAsset/mikrotik_switch_collector.conf",
    Path(os.environ.get("APPDATA", "C:/ProgramData")) / "NetAsset/mikrotik_switch_collector.conf",
]


def _section_to_config(s: dict, na: dict) -> dict:
    return {
        "username":        os.environ.get("MIKROTIK_USER", s.get("username", "admin")),
        "password":        os.environ.get("MIKROTIK_PASS", s.get("password", "")),
        "use_https":       s.get("use_https", "false").lower() == "true",
        "verify_ssl":      s.get("verify_ssl", "false").lower() == "true",
        "port_rest":       int(s.get("port_rest", "80")),
        "mode":            s.get("mode", "rest"),           # rest | snmp
        "snmp_community":  s.get("snmp_community", "public"),
        "snmp_port":       int(s.get("snmp_port", "161")),
        "snmp_version":    s.get("snmp_version", "2c"),     # 1 | 2c
        "api_url":         os.environ.get("NETASSET_URL",     na.get("api_url",  "https://ocs.kiste.org")),
        "api_key":         os.environ.get("NETASSET_API_KEY", na.get("api_key",  "")),
        "exposure_level":  na.get("exposure_level", "INTERN"),
        "tags":            [t.strip() for t in na.get("tags", "mikrotik,switch").split(",")],
        "timeout":         int(na.get("timeout", "15")),
        "push_neighbors":  na.get("push_neighbors", "true").lower() == "true",
    }


def _parse_hosts(s: dict) -> list[str]:
    single = os.environ.get("MIKROTIK_HOST", s.get("host", ""))
    multi_raw = s.get("hosts", "")
    if multi_raw:
        return [h.strip() for h in multi_raw.replace(",", "\n").splitlines() if h.strip()]
    elif single:
        return [single]
    return []


def load_configs(config_files: list[str] | None = None) -> list[dict]:
    """
    Lädt eine oder mehrere Config-Dateien.
    Unterstützt per-Host-Sections: [mikrotik-switch:192.168.1.2]
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

        section_name = "mikrotik-switch" if "mikrotik-switch" in cfg else \
                       "mikrotik_switch"  if "mikrotik_switch"  in cfg else \
                       "mikrotik"         if "mikrotik"         in cfg else None
        if not section_name:
            log.warning("%s: Kein [mikrotik-switch]-Abschnitt gefunden.", config_file)
            continue

        defaults  = cfg[section_name]
        na        = cfg["netasset"] if "netasset" in cfg else {}
        base_cfg  = _section_to_config(defaults, na)
        all_hosts = _parse_hosts(defaults)

        # Per-Host-Overrides: [mikrotik-switch:IP]
        host_overrides: dict[str, dict] = {}
        for sec in cfg.sections():
            for prefix in ("mikrotik-switch:", "mikrotik_switch:", "mikrotik:"):
                if sec.startswith(prefix):
                    host_ip = sec.split(":", 1)[1].strip()
                    merged  = dict(defaults)
                    merged.update(dict(cfg[sec]))
                    host_overrides[host_ip] = _section_to_config(merged, na)
                    if host_ip not in all_hosts:
                        all_hosts.append(host_ip)

        for host in all_hosts:
            hc = host_overrides.get(host, base_cfg).copy()
            hc["host"] = host
            all_host_configs.append(hc)

    return all_host_configs


# ---------------------------------------------------------------------------
# REST-API Client
# ---------------------------------------------------------------------------

class SwitchREST:
    def __init__(self, host: str, username: str, password: str,
                 use_https: bool = False, port: int = 80, verify_ssl: bool = False):
        self._host = host
        self._port = port
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
                self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    def get(self, path: str) -> list[dict]:
        url_path = "/rest" + path
        try:
            if self._ssl_ctx:
                conn = http.client.HTTPSConnection(
                    self._host, self._port, context=self._ssl_ctx, timeout=15)
            else:
                conn = http.client.HTTPConnection(self._host, self._port, timeout=15)
            conn.request("GET", url_path, headers=self.headers)
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read())
                return [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
            log.debug("REST %s → HTTP %d", path, resp.status)
            return []
        except Exception as e:
            log.debug("REST %s → %s", path, e)
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def collect(self) -> dict:
        log.info("Verbinde mit Switch %s...", self._host)

        # System
        resource    = self.get("/system/resource")
        identity    = self.get("/system/identity")
        routerboard = self.get("/system/routerboard")
        res = resource[0]    if resource    else {}
        idn = identity[0]    if identity    else {}
        rb  = routerboard[0] if routerboard else {}

        # Netzwerk
        addresses  = self.get("/ip/address")
        interfaces = self.get("/interface")
        eth_ifaces = self.get("/interface/ethernet")

        # Switch-spezifisch
        bridges      = self.get("/interface/bridge")
        bridge_ports = self.get("/interface/bridge/port")
        bridge_hosts = self.get("/interface/bridge/host")   # FDB
        vlans        = self.get("/interface/bridge/vlan")
        arp          = self.get("/ip/arp")
        dhcp_leases  = self.get("/ip/dhcp-server/lease")

        # Dienste (für offene Ports)
        services = self.get("/ip/service")

        log.info(
            "System: %s | RouterOS %s | Board: %s | uptime: %s",
            idn.get("name", "?"),
            res.get("version", "?"),
            res.get("board-name") or rb.get("model", "?"),
            res.get("uptime", "?"),
        )

        # Primäre IP + MAC
        primary_ip, primary_mac = _find_primary(addresses, interfaces)

        # Port-Tabelle aufbauen
        port_table = _build_port_table(interfaces, eth_ifaces, bridge_ports, vlans)
        log.info(
            "Ports: %d gesamt, %d up, %d down",
            len(port_table),
            sum(1 for p in port_table if p["running"]),
            sum(1 for p in port_table if not p["running"]),
        )

        # Offene Dienste
        open_ports = _collect_open_ports(services, self._host)

        # VLAN-Zusammenfassung
        vlan_ids = sorted({
            int(v["vlan-ids"])
            for v in vlans
            if v.get("vlan-ids", "").isdigit()
        })

        # FDB → Nachbarn
        neighbors = _fdb_to_neighbors(bridge_hosts, bridge_ports, arp, dhcp_leases)
        log.info(
            "FDB-Einträge: %d (%d mit IP, %d nur MAC)",
            len(neighbors),
            sum(1 for n in neighbors if n.get("ip")),
            sum(1 for n in neighbors if not n.get("ip")),
        )

        return {
            "device": {
                "hostname":        idn.get("name", self._host),
                "ip_address":      primary_ip,
                "mac_address":     primary_mac,
                "serial_number":   rb.get("serial-number") or None,
                "chassis_id":      rb.get("serial-number") or None,
                "manufacturer":    "MikroTik",
                "model":           res.get("board-name") or rb.get("model"),
                "firmware_version": rb.get("current-firmware") or res.get("version"),
                "os_name":         "RouterOS",
                "os_version":      res.get("version"),
                "open_ports":      open_ports,
            },
            "port_table": port_table,
            "vlan_ids":   vlan_ids,
            "neighbors":  neighbors,
        }


# ---------------------------------------------------------------------------
# SNMP-Collector
# ---------------------------------------------------------------------------

# Standard-MIB OIDs
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"
OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME   = "1.3.6.1.2.1.1.3.0"
OID_IF_DESCR     = "1.3.6.1.2.1.2.2.1.2"    # ifDescr
OID_IF_TYPE      = "1.3.6.1.2.1.2.2.1.3"    # ifType  (6=ethernet)
OID_IF_SPEED     = "1.3.6.1.2.1.2.2.1.5"    # ifSpeed (bps)
OID_IF_PHYSADDR  = "1.3.6.1.2.1.2.2.1.6"    # ifPhysAddress (MAC)
OID_IF_ADMSTATUS = "1.3.6.1.2.1.2.2.1.7"    # 1=up, 2=down
OID_IF_OPRSTATUS = "1.3.6.1.2.1.2.2.1.8"    # 1=up, 2=down
OID_IP_ADDRTABLE = "1.3.6.1.2.1.4.20.1"     # ipAddrTable
OID_IP_ADDR      = "1.3.6.1.2.1.4.20.1.1"   # ipAdEntAddr
OID_IP_IFINDEX   = "1.3.6.1.2.1.4.20.1.2"   # ipAdEntIfIndex
OID_ARP_IP       = "1.3.6.1.2.1.4.22.1.3"   # ipNetToMediaNetAddress
OID_ARP_MAC      = "1.3.6.1.2.1.4.22.1.2"   # ipNetToMediaPhysAddress
# BRIDGE-MIB (dot1d)
OID_FDB_MAC      = "1.3.6.1.2.1.17.4.3.1.1" # dot1dTpFdbAddress
OID_FDB_PORT     = "1.3.6.1.2.1.17.4.3.1.2" # dot1dTpFdbPort
OID_FDB_STATUS   = "1.3.6.1.2.1.17.4.3.1.3" # 3=learned, 5=self
OID_BRIDGE_PORT  = "1.3.6.1.2.1.17.1.4.1.2" # dot1dBasePortIfIndex
# Q-BRIDGE-MIB (VLANs)
OID_VLAN_NAME    = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # dot1qVlanStaticName
OID_VLAN_EGRESS  = "1.3.6.1.2.1.17.7.1.4.3.1.2"  # dot1qVlanStaticEgressPorts


def _mp_model(version: str) -> int:
    return 1 if version == "2c" else 0   # 0=SNMPv1, 1=SNMPv2c


def _snmp_check() -> str:
    """Gibt die pysnmp-API-Variante zurück ('v7' oder 'v4') oder wirft RuntimeError."""
    try:
        from pysnmp.hlapi.v3arch.asyncio import get_cmd  # noqa: F401
        return "v7"
    except ImportError:
        pass
    try:
        from pysnmp.hlapi import getCmd  # noqa: F401
        return "v4"
    except ImportError:
        pass
    raise RuntimeError(
        "pysnmp ist nicht installiert.\n"
        "Bitte installieren:  pip install pysnmp"
    )


def _asyncio_run(coro):
    """asyncio.run() mit SelectorEventLoop auf Windows (ProactorEventLoop hat kein UDP)."""
    import asyncio
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(coro)


# ── pysnmp 7.x (async) ───────────────────────────────────────────────────────
# Alle Abfragen für einen Host in EINER async-Funktion bündeln,
# damit nur ein Event-Loop und ein SnmpEngine-Objekt genutzt wird.

async def _snmp_collect_v7(host: str, community: str, port: int, mp_model: int,
                            gets: list[str], walks: list[str]) -> tuple[dict, dict]:
    """Führt mehrere GET- und WALK-Abfragen in einer Session aus.

    Returns:
        get_results:  {oid: str}
        walk_results: {oid_prefix: list[tuple[str, Any]]}
    """
    from pysnmp.hlapi.v3arch.asyncio import (           # type: ignore[import]
        SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
        get_cmd, next_cmd,
    )
    engine    = SnmpEngine()
    transport = UdpTransportTarget((host, port), timeout=5, retries=1)
    auth      = CommunityData(community, mpModel=mp_model)
    ctx       = ContextData()

    get_results:  dict[str, str]          = {}
    walk_results: dict[str, list]         = {}

    try:
        # ── GETs ──────────────────────────────────────────────────────────────
        for oid in gets:
            try:
                errorInd, errorStatus, _, varBinds = await get_cmd(
                    engine, auth, transport, ctx,
                    ObjectType(ObjectIdentity(oid)),
                )
                if errorInd:
                    log.debug("SNMP GET %s – %s", oid, errorInd)
                    continue
                if errorStatus:
                    log.debug("SNMP GET %s – %s", oid, errorStatus.prettyPrint())
                    continue
                for vb in varBinds:
                    get_results[oid] = str(vb[1]).strip().strip('"')
            except Exception as e:
                log.debug("SNMP GET %s exception: %s", oid, e)

        # ── WALKs ─────────────────────────────────────────────────────────────
        for oid in walks:
            rows: list[tuple[str, object]] = []
            try:
                async for errorInd, errorStatus, _, varBinds in next_cmd(
                    engine, auth, transport, ctx,
                    ObjectType(ObjectIdentity(oid)),
                    lexicographic_mode=False,
                ):
                    if errorInd:
                        log.debug("SNMP WALK %s – %s", oid, errorInd)
                        break
                    if errorStatus:
                        log.debug("SNMP WALK %s – %s", oid, errorStatus.prettyPrint())
                        break
                    for vb in varBinds:
                        rows.append((str(vb[0]), vb[1]))
            except Exception as e:
                log.debug("SNMP WALK %s exception: %s", oid, e)
            walk_results[oid] = rows

    finally:
        engine.close_dispatcher()

    return get_results, walk_results


# ── pysnmp 4.x/5.x (sync) ────────────────────────────────────────────────────

def _snmp_collect_v4(host: str, community: str, port: int, mp_model: int,
                     gets: list[str], walks: list[str]) -> tuple[dict, dict]:
    from pysnmp.hlapi import (                          # type: ignore[import]
        SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
        getCmd, nextCmd,
    )
    get_results:  dict[str, str]  = {}
    walk_results: dict[str, list] = {}

    def _engine():
        return SnmpEngine()

    transport_args = dict(timeout=5, retries=1)
    auth = CommunityData(community, mpModel=mp_model)

    for oid in gets:
        try:
            errorInd, errorStatus, _, varBinds = next(getCmd(
                _engine(), auth,
                UdpTransportTarget((host, port), **transport_args),
                ContextData(), ObjectType(ObjectIdentity(oid)),
            ))
            if not errorInd and not errorStatus:
                for vb in varBinds:
                    get_results[oid] = str(vb[1]).strip().strip('"')
        except Exception as e:
            log.debug("SNMP GET %s exception: %s", oid, e)

    for oid in walks:
        rows: list = []
        try:
            for errorInd, errorStatus, _, varBinds in nextCmd(
                _engine(), auth,
                UdpTransportTarget((host, port), **transport_args),
                ContextData(), ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if errorInd or errorStatus:
                    break
                for vb in varBinds:
                    rows.append((str(vb[0]), vb[1]))
        except Exception as e:
            log.debug("SNMP WALK %s exception: %s", oid, e)
        walk_results[oid] = rows

    return get_results, walk_results


# ── Einheitliche Schnittstelle ────────────────────────────────────────────────

def _snmp_query(host: str, community: str, port: int, version: str,
                gets: list[str], walks: list[str]) -> tuple[dict, dict]:
    """Führt alle GET- und WALK-Abfragen für einen Host aus."""
    api   = _snmp_check()
    model = _mp_model(version)
    if api == "v7":
        return _asyncio_run(_snmp_collect_v7(host, community, port, model, gets, walks))
    return _snmp_collect_v4(host, community, port, model, gets, walks)


def _snmp_walk_str(host: str, community: str, oid: str, port: int = 161, version: str = "2c") -> dict[str, str]:
    """Einzelner WALK als {oid_str: str} – Hilfsfunktion für collect_snmp."""
    _, walk_results = _snmp_query(host, community, port, version, gets=[], walks=[oid])
    return {k: str(v) for k, v in walk_results.get(oid, [])}


def _snmp_walk(host: str, community: str, oid: str, port: int = 161, version: str = "2c") -> list:
    """Einzelner WALK als list[(oid_str, raw_val)] – für MAC-OIDs."""
    _, walk_results = _snmp_query(host, community, port, version, gets=[], walks=[oid])
    return walk_results.get(oid, [])


def _mac_from_snmp(val) -> str | None:
    """Normalisiert einen pysnmp-OctetString-Wert oder String auf aa:bb:cc:dd:ee:ff."""
    # pysnmp OctetString: Zugriff auf Raw-Bytes über asNumbers() oder asOctets()
    try:
        nums = val.asNumbers()      # tuple of ints
        if len(nums) == 6:
            return ":".join(f"{b:02x}" for b in nums)
    except AttributeError:
        pass
    # Fallback: als String interpretieren
    raw = str(val)
    # Format "0x001122334455"
    if raw.startswith("0x"):
        raw = raw[2:]
    # Formatvarianten bereinigen: "-", ":", " "
    clean = raw.replace(":", "").replace("-", "").replace(" ", "")
    if len(clean) == 12 and all(c in "0123456789abcdefABCDEF" for c in clean):
        return ":".join(clean[i:i+2] for i in range(0, 12, 2)).lower()
    return None


def collect_snmp(host: str, community: str = "public", port: int = 161, version: str = "2c") -> dict:
    """Sammelt Switch-Daten via SNMP (IF-MIB + BRIDGE-MIB + Q-BRIDGE-MIB).
    Benötigt: pip install pysnmp
    """
    _snmp_check()   # früh fehlschlagen wenn nicht installiert

    log.info("Verbinde per SNMP (%s, community=%s)...", host, community)

    # ── Alle Abfragen in einem einzigen Aufruf ────────────────────────────────
    GET_OIDS = [OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_UPTIME]
    WALK_OIDS = [
        OID_IF_DESCR, OID_IF_TYPE, OID_IF_SPEED, OID_IF_PHYSADDR,
        OID_IF_ADMSTATUS, OID_IF_OPRSTATUS,
        OID_IP_ADDR, OID_ARP_IP, OID_ARP_MAC,
        OID_FDB_MAC, OID_FDB_PORT, OID_FDB_STATUS,
        OID_BRIDGE_PORT, OID_VLAN_NAME,
    ]
    get_r, walk_r = _snmp_query(host, community, port, version, GET_OIDS, WALK_OIDS)

    def ws(oid: str) -> dict[str, str]:
        """Walk-Ergebnis als {oid_str: str}."""
        return {k: str(v) for k, v in walk_r.get(oid, [])}

    def wr(oid: str) -> dict[str, object]:
        """Walk-Ergebnis als {oid_str: raw} – für MAC-OIDs."""
        return dict(walk_r.get(oid, []))

    # ── System ────────────────────────────────────────────────────────────────
    sys_name   = get_r.get(OID_SYS_NAME,  "")
    sys_descr  = get_r.get(OID_SYS_DESCR, "")
    sys_uptime = get_r.get(OID_SYS_UPTIME,"")

    # RouterOS-Version aus sysDescr extrahieren
    os_version = ""
    if "RouterOS" in sys_descr:
        parts = sys_descr.split()
        for i, part in enumerate(parts):
            if part == "RouterOS" and i + 1 < len(parts):
                os_version = parts[i + 1]
                break

    log.info("System: %s | %s | uptime: %s", sys_name or host, sys_descr[:60], sys_uptime)

    # ── Interfaces ────────────────────────────────────────────────────────────
    if_descr  = ws(OID_IF_DESCR)
    if_type   = ws(OID_IF_TYPE)
    if_speed  = ws(OID_IF_SPEED)
    if_mac    = wr(OID_IF_PHYSADDR)   # raw für _mac_from_snmp
    if_admin  = ws(OID_IF_ADMSTATUS)
    if_oper   = ws(OID_IF_OPRSTATUS)

    # ifIndex → Interface-Name + Details
    iface_by_idx: dict[str, dict] = {}
    port_table: list[dict] = []
    primary_mac: str | None = None

    for oid_key, descr in if_descr.items():
        idx = oid_key.split(".")[-1]
        itype = if_type.get(f"1.3.6.1.2.1.2.2.1.3.{idx}", "")

        # Nur Ethernet-Interfaces (ifType=6) und ggf. Aggregates (161=ieee8023adLag)
        if itype not in ("6", "161"):
            continue

        speed_bps = int(if_speed.get(f"1.3.6.1.2.1.2.2.1.5.{idx}", "0") or "0")
        speed_str = _bps_to_human(speed_bps)

        mac_raw = if_mac.get(f"1.3.6.1.2.1.2.2.1.6.{idx}", "")
        mac     = _mac_from_snmp(mac_raw)

        admin_up = if_admin.get(f"1.3.6.1.2.1.2.2.1.7.{idx}", "2") == "1"
        oper_up  = if_oper.get(f"1.3.6.1.2.1.2.2.1.8.{idx}",  "2") == "1"

        iface_by_idx[idx] = {"name": descr, "mac": mac}

        if mac and not primary_mac and descr.lower() in ("bridge", "vlan1", "ether1", "lo0"):
            primary_mac = mac

        port_table.append({
            "name":         descr,
            "running":      oper_up,
            "disabled":     not admin_up,
            "mac":          mac,
            "speed":        speed_str,
            "full_duplex":  None,   # nicht über Standard-MIB verfügbar
            "pvid":         "1",    # wird unten aus Q-BRIDGE überschrieben
            "bridge":       "",
            "tagged_vlans": [],
            "comment":      "",
        })

    port_table.sort(key=lambda p: p["name"])

    # ── IP-Adressen ───────────────────────────────────────────────────────────
    primary_ip: str | None = None
    for oid_key, ip in ws(OID_IP_ADDR).items():
        if ip and not ip.startswith("127."):
            primary_ip = ip
            break

    # ── ARP ───────────────────────────────────────────────────────────────────
    arp_ips  = ws(OID_ARP_IP)
    arp_macs = wr(OID_ARP_MAC)   # raw für _mac_from_snmp
    arp_by_mac: dict[str, str] = {}
    for oid_key, ip in arp_ips.items():
        suffix  = oid_key.replace(OID_ARP_IP + ".", "")
        mac_raw = arp_macs.get(f"{OID_ARP_MAC}.{suffix}", "")
        mac     = _mac_from_snmp(mac_raw)
        if mac and ip and not ip.startswith("127."):
            arp_by_mac[mac] = ip

    # ── FDB (dot1dTpFdb) ─────────────────────────────────────────────────────
    fdb_macs   = wr(OID_FDB_MAC)    # raw (MAC)
    fdb_ports  = ws(OID_FDB_PORT)
    fdb_status = ws(OID_FDB_STATUS)

    # Bridge-Port-Nummer → ifIndex
    bp_to_ifidx = {
        oid_key.split(".")[-1]: str(v)
        for oid_key, v in walk_r.get(OID_BRIDGE_PORT, [])
    }

    neighbors: list[dict] = []
    seen_macs: set[str]   = set()

    for oid_key, mac_raw in fdb_macs.items():
        suffix = oid_key.replace(OID_FDB_MAC + ".", "")
        status = fdb_status.get(f"{OID_FDB_STATUS}.{suffix}", "")
        # 3=learned, 5=self → eigene MACs überspringen
        if status == "5":
            continue

        mac = _mac_from_snmp(mac_raw)
        if not mac or mac in seen_macs:
            continue
        seen_macs.add(mac)

        bridge_port = fdb_ports.get(f"{OID_FDB_PORT}.{suffix}", "")
        if_idx      = bp_to_ifidx.get(bridge_port, "")
        port_name   = iface_by_idx.get(if_idx, {}).get("name", f"port{bridge_port}")
        ip          = arp_by_mac.get(mac)

        neighbors.append({
            "ip":          ip,
            "mac":         mac,
            "hostname":    None,
            "switch_port": port_name,
            "_source":     "fdb-snmp",
        })

    # ── VLANs (Q-BRIDGE) ─────────────────────────────────────────────────────
    vlan_names = ws(OID_VLAN_NAME)
    vlan_ids   = sorted({
        int(oid_key.split(".")[-1])
        for oid_key in vlan_names
        if oid_key.split(".")[-1].isdigit() and int(oid_key.split(".")[-1]) < 4094
    })
    log.info(
        "Interfaces: %d Ports | FDB: %d Geräte | VLANs: %s",
        len(port_table), len(neighbors),
        ", ".join(str(v) for v in vlan_ids) if vlan_ids else "—",
    )

    # ── Open Ports: Socket-Check ──────────────────────────────────────────────
    open_ports = _socket_probe_ports(host)

    return {
        "device": {
            "hostname":        sys_name or host,
            "ip_address":      primary_ip or host,
            "mac_address":     primary_mac,
            "manufacturer":    "MikroTik",
            "model":           None,
            "os_name":         "RouterOS",
            "os_version":      os_version or None,
            "open_ports":      open_ports,
        },
        "port_table": port_table,
        "vlan_ids":   vlan_ids,
        "neighbors":  neighbors,
    }


def _bps_to_human(bps: int) -> str:
    if bps >= 1_000_000_000:
        return f"{bps // 1_000_000_000}Gbps"
    if bps >= 1_000_000:
        return f"{bps // 1_000_000}Mbps"
    if bps > 0:
        return f"{bps // 1_000}Kbps"
    return ""


def _socket_probe_ports(host: str, timeout: float = 2.0) -> list[dict]:
    KNOWN = [(22,"ssh"),(80,"www"),(443,"www-ssl"),(8291,"winbox"),(8728,"api"),(8729,"api-ssl")]
    found = []
    for port, name in KNOWN:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                found.append({"port": port, "proto": "tcp",
                              "service": name, "reachable_from": ["intern"]})
        except OSError:
            pass
    return found


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _find_primary(addresses: list, interfaces: list) -> tuple[str | None, str | None]:
    for addr in addresses:
        if addr.get("disabled") in ("true", True):
            continue
        ip = addr.get("address", "").split("/")[0]
        if not ip:
            continue
        mac = None
        iface_name = addr.get("interface", "")
        for iface in interfaces:
            if iface.get("name") == iface_name:
                mac = (iface.get("mac-address") or "").lower() or None
                break
        return ip, mac
    return None, None


def _build_port_table(
    interfaces: list,
    eth_ifaces: list,
    bridge_ports: list,
    vlans: list,
) -> list[dict]:
    """Erstellt eine strukturierte Port-Tabelle mit Status, Speed, VLAN."""

    # Ethernet-Details (Speed, Duplex) per Interface-Name
    eth_detail: dict[str, dict] = {e.get("name", ""): e for e in eth_ifaces}

    # Bridge-Port → PVID (Access-VLAN)
    bp_pvid: dict[str, str] = {}
    bp_bridge: dict[str, str] = {}
    for bp in bridge_ports:
        name = bp.get("interface", "")
        bp_pvid[name]   = bp.get("pvid", "1")
        bp_bridge[name] = bp.get("bridge", "")

    # VLAN-Tagged-Ports sammeln: vlan_id → set(ports)
    vlan_tagged: dict[str, list[str]] = {}
    for v in vlans:
        vid   = v.get("vlan-ids", "")
        ports = [p.strip() for p in v.get("tagged", "").split(",") if p.strip()]
        if vid:
            vlan_tagged.setdefault(vid, []).extend(ports)

    ports = []
    for iface in interfaces:
        itype = iface.get("type", "")
        if itype not in ("ether", "sfp", "sfp-sfpplus", "sfpplus"):
            continue
        name    = iface.get("name", "")
        running = iface.get("running") in (True, "true")
        comment = iface.get("comment", "") or ""

        eth = eth_detail.get(name, {})
        speed_raw = eth.get("rate") or eth.get("speed") or ""

        # Tagged VLANs für diesen Port
        tagged_vlans = [vid for vid, plist in vlan_tagged.items() if name in plist]

        ports.append({
            "name":         name,
            "running":      running,
            "disabled":     iface.get("disabled") in (True, "true"),
            "mac":          (iface.get("mac-address") or "").lower() or None,
            "speed":        speed_raw,
            "full_duplex":  eth.get("full-duplex") in (True, "true"),
            "pvid":         bp_pvid.get(name, "1"),
            "bridge":       bp_bridge.get(name, ""),
            "tagged_vlans": sorted(tagged_vlans),
            "comment":      comment,
        })

    return sorted(ports, key=lambda p: p["name"])


def _collect_open_ports(services: list, host: str) -> list[dict]:
    """Liest aktive Dienste; Socket-Fallback wenn API nichts liefert."""
    open_ports = []
    for svc in services:
        disabled = svc.get("disabled", "false")
        if disabled in ("true", True):
            continue
        port_val = svc.get("port")
        if not port_val:
            continue
        try:
            port_num = int(port_val)
        except (ValueError, TypeError):
            continue
        open_ports.append({
            "port":           port_num,
            "proto":          "tcp",
            "service":        svc.get("name", ""),
            "reachable_from": ["intern"],
        })

    if not open_ports:
        log.warning("Keine Ports via API – Socket-Fallback...")
        KNOWN = [(22,"ssh"),(80,"www"),(443,"www-ssl"),(8291,"winbox"),(8728,"api"),(8729,"api-ssl")]
        for port, name in KNOWN:
            try:
                with socket.create_connection((host, port), timeout=2):
                    open_ports.append({"port": port, "proto": "tcp",
                                       "service": name, "reachable_from": ["intern"]})
            except OSError:
                pass

    log.info("Ports erkannt: %d", len(open_ports))
    return open_ports


def _fdb_to_neighbors(
    bridge_hosts: list,
    bridge_ports: list,
    arp: list,
    dhcp_leases: list,
) -> list[dict]:
    """
    Kombiniert FDB (MAC-Adresstabelle), ARP und DHCP zu einer Nachbarliste.
    """
    # Port-ID → Interface-Name
    port_map = {p.get(".id", ""): p.get("interface", "") for p in bridge_ports}

    # ARP: IP → MAC
    arp_by_mac: dict[str, str] = {}
    arp_by_ip:  dict[str, str] = {}
    for entry in arp:
        ip  = entry.get("address", "")
        mac = (entry.get("mac-address") or "").lower()
        if ip and mac:
            arp_by_mac[mac] = ip
            arp_by_ip[ip]   = mac

    # DHCP: MAC → Hostname
    dhcp_hostname: dict[str, str] = {}
    for lease in dhcp_leases:
        mac      = (lease.get("mac-address") or "").lower()
        hostname = lease.get("host-name") or lease.get("comment") or ""
        if mac and hostname:
            dhcp_hostname[mac] = hostname

    neighbors: list[dict] = []
    seen_macs: set[str]   = set()

    for host in bridge_hosts:
        mac = (host.get("mac-address") or "").lower()
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            continue
        # Eigene Bridge-MACs überspringen
        if host.get("local") in (True, "true"):
            continue
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        port_iface = port_map.get(host.get("on-interface", "")) or host.get("on-interface", "")
        ip         = arp_by_mac.get(mac)
        hostname   = dhcp_hostname.get(mac)

        neighbors.append({
            "ip":          ip,
            "mac":         mac,
            "hostname":    hostname,
            "switch_port": port_iface,
            "_source":     "fdb",
        })

    return neighbors


# ---------------------------------------------------------------------------
# NetAsset Push
# ---------------------------------------------------------------------------

def api_post(url: str, api_key: str, data, timeout: int = 30):
    body = json.dumps(data).encode()
    req  = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def push(config: dict, data: dict, dry_run: bool = False):
    device     = data["device"]
    port_table = data.get("port_table", [])
    vlan_ids   = data.get("vlan_ids", [])
    neighbors  = data.get("neighbors", [])

    # Switch-Asset aufbauen
    device["asset_type"]     = "switch"
    device["exposure_level"] = config["exposure_level"]
    device["source"]         = "mikrotik-switch-collector"

    tags = list(config["tags"])
    if vlan_ids:
        tags += [f"vlan-{v}" for v in vlan_ids[:10]]  # max 10 VLAN-Tags
    tags.append("switch")
    device["tags"] = tags

    # Ports als Notes (kompakt)
    port_up   = [p["name"] for p in port_table if p["running"]]
    port_down = [p["name"] for p in port_table if not p["running"] and not p["disabled"]]
    notes_lines = []
    if port_up:
        notes_lines.append(f"Aktive Ports ({len(port_up)}): {', '.join(port_up)}")
    if port_down:
        notes_lines.append(f"Inaktive Ports ({len(port_down)}): {', '.join(port_down)}")
    if vlan_ids:
        notes_lines.append(f"VLANs: {', '.join(str(v) for v in vlan_ids)}")
    if notes_lines:
        device["notes"] = "\n".join(notes_lines)

    if dry_run:
        _dry_run_output(device, port_table, vlan_ids, neighbors)
        return

    # Switch pushen
    base   = config["api_url"].rstrip("/")
    result = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], [device], config["timeout"])
    action = result[0].get("action", "?") if result else "?"
    log.info("Switch-Asset: %s (%s)", device.get("hostname"), action)

    if not config.get("push_neighbors", True) or not neighbors:
        return

    # Verbundene Geräte pushen
    neighbor_devices = []
    for n in neighbors:
        ip  = n.get("ip")
        mac = n.get("mac")
        if not ip and not mac:
            continue

        notes = f"Switch-Port: {n['switch_port']}" if n.get("switch_port") else ""

        neighbor_devices.append({
            "hostname":       n.get("hostname"),
            "ip_address":     ip,
            "mac_address":    mac,
            "asset_type":     "server",
            "exposure_level": config["exposure_level"],
            "tags":           ["fdb-discovered", "via-switch", f"via-{device.get('hostname', 'switch')}"],
            "source":         "mikrotik-fdb",
            **({"notes": notes} if notes else {}),
        })

    if not neighbor_devices:
        return

    created = merged = flagged = 0
    for i in range(0, len(neighbor_devices), 50):
        batch = neighbor_devices[i:i+50]
        res   = api_post(f"{base}/api/v1/discovery/ingest", config["api_key"], batch, config["timeout"])
        for item in (res or []):
            a = item.get("action", "")
            if a == "created":  created += 1
            elif a == "merged": merged  += 1
            else:               flagged += 1

    log.info("FDB-Geräte: %d neu, %d aktualisiert, %d Konflikt", created, merged, flagged)


def _dry_run_output(device: dict, port_table: list, vlan_ids: list, neighbors: list):
    print("\n" + "═" * 60)
    print("  DRY RUN – MikroTik Switch Collector")
    print("═" * 60)

    print(f"\n▶ Switch-Asset")
    print(f"  Hostname:  {device.get('hostname', '?')}")
    print(f"  IP:        {device.get('ip_address', '?')}")
    print(f"  MAC:       {device.get('mac_address', '?')}")
    print(f"  Model:     {device.get('model', '?')}")
    print(f"  RouterOS:  {device.get('os_version', '?')}")
    print(f"  Tags:      {', '.join(device.get('tags', []))}")

    ports = device.get("open_ports") or []
    if ports:
        print(f"\n▶ Dienste ({len(ports)})")
        for p in ports:
            print(f"  {p['port']}/{p['proto']:<4} {p.get('service','')}")

    if port_table:
        up   = [p for p in port_table if p["running"]]
        down = [p for p in port_table if not p["running"] and not p["disabled"]]
        dis  = [p for p in port_table if p["disabled"]]
        print(f"\n▶ Switch-Ports ({len(port_table)} gesamt: {len(up)} up, {len(down)} down, {len(dis)} disabled)")
        print(f"  {'Port':<14} {'Status':<8} {'Speed':<12} {'PVID':<6} {'Tagged VLANs'}")
        print(f"  {'-'*14} {'-'*8} {'-'*12} {'-'*6} {'-'*20}")
        for p in port_table:
            status = "UP" if p["running"] else ("DISABLED" if p["disabled"] else "DOWN")
            tvlans = ",".join(p["tagged_vlans"]) or "—"
            comment = f"  ← {p['comment']}" if p["comment"] else ""
            print(f"  {p['name']:<14} {status:<8} {p['speed']:<12} {p['pvid']:<6} {tvlans}{comment}")

    if vlan_ids:
        print(f"\n▶ VLANs ({len(vlan_ids)}): {', '.join(str(v) for v in vlan_ids)}")

    if neighbors:
        with_ip   = [n for n in neighbors if n.get("ip")]
        mac_only  = [n for n in neighbors if not n.get("ip")]
        print(f"\n▶ Verbundene Geräte aus FDB ({len(neighbors)}: {len(with_ip)} mit IP, {len(mac_only)} nur MAC)")
        print(f"  {'IP':<18} {'MAC':<20} {'Port':<14} Hostname")
        print(f"  {'-'*18} {'-'*20} {'-'*14} {'-'*20}")
        for n in neighbors[:30]:
            print(f"  {(n.get('ip') or '—'):<18} {(n.get('mac') or '—'):<20} "
                  f"{(n.get('switch_port') or '—'):<14} {n.get('hostname') or '—'}")
        if len(neighbors) > 30:
            print(f"  ... +{len(neighbors)-30} weitere")

    print()


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NetAsset MikroTik-Switch Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python3 mikrotik_switch_collector.py -c switches.conf
  python3 mikrotik_switch_collector.py -c sw_keller.conf -c sw_eg.conf --dry-run
""",
    )
    parser.add_argument("--config", "-c", action="append", dest="configs",
                        metavar="FILE", help="Config-Datei (mehrfach verwendbar)")
    parser.add_argument("--dry-run",      action="store_true")
    parser.add_argument("--no-neighbors", action="store_true", help="Keine FDB-Geräte pushen")
    parser.add_argument("--snmp",         action="store_true",
                        help="SNMP statt REST API verwenden (überschreibt mode= in Config)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    host_configs = load_configs(args.configs)
    if not host_configs:
        log.error("Kein Switch konfiguriert. 'host' oder 'hosts' in der Config eintragen.")
        sys.exit(1)

    if not args.dry_run:
        missing = [c["host"] for c in host_configs if not c.get("api_key")]
        if missing:
            log.error("Kein API-Key für: %s", ", ".join(missing))
            sys.exit(1)

    log.info("Starte Scan: %d Switch(es)", len(host_configs))
    errors = 0

    for host_config in host_configs:
        host = host_config["host"]
        mode = "snmp" if args.snmp else host_config.get("mode", "rest")
        log.info("━━━ %s (mode=%s) ━━━", host, mode)

        try:
            if mode == "snmp":
                data = collect_snmp(
                    host,
                    community=host_config.get("snmp_community", "public"),
                    port=host_config.get("snmp_port", 161),
                    version=host_config.get("snmp_version", "2c"),
                )
            else:
                client = SwitchREST(
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

        if args.no_neighbors:
            host_config = {**host_config, "push_neighbors": False}

        push(host_config, data, dry_run=args.dry_run)

    if not args.dry_run:
        log.info("Fertig. %d/%d Switches erfolgreich.", len(host_configs) - errors, len(host_configs))


if __name__ == "__main__":
    main()
