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
        "username":       os.environ.get("MIKROTIK_USER", s.get("username", "admin")),
        "password":       os.environ.get("MIKROTIK_PASS", s.get("password", "")),
        "use_https":      s.get("use_https", "false").lower() == "true",
        "verify_ssl":     s.get("verify_ssl", "false").lower() == "true",
        "port_rest":      int(s.get("port_rest", "80")),
        "api_url":        os.environ.get("NETASSET_URL",     na.get("api_url",  "https://ocs.kiste.org")),
        "api_key":        os.environ.get("NETASSET_API_KEY", na.get("api_key",  "")),
        "exposure_level": na.get("exposure_level", "INTERN"),
        "tags":           [t.strip() for t in na.get("tags", "mikrotik,switch").split(",")],
        "timeout":        int(na.get("timeout", "15")),
        "push_neighbors": na.get("push_neighbors", "true").lower() == "true",
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
        log.info("━━━ %s (user=%s, port=%s) ━━━",
                 host, host_config["username"], host_config["port_rest"])

        try:
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
