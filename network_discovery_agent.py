#!/usr/bin/env python3
"""
NetAsset Network Discovery Agent

Scannt das Netzwerk per nmap, erkennt neue Systeme automatisch
und meldet sie an die NetAsset API (ocs.kiste.org).

Features:
  - CIDR-Ranges konfigurierbar (mehrere möglich)
  - OS-Detection, Service-Erkennung, Port-Scan
  - MAC-Adressen via ARP (Layer 2, nur im selben Subnetz)
  - Daemon-Modus: läuft als Service, scannt regelmäßig
  - Neue Hosts werden automatisch angelegt, bekannte aktualisiert
  - Konflikt-Queue bei uneindeutigem Match

Voraussetzungen:
  - nmap installiert (apt install nmap / winget install Insecure.Nmap)
  - Root/Administrator-Rechte für OS-Detection und ARP-Scan
  - Python 3.10+

Aufruf:
  sudo python3 network_discovery_agent.py               # einmaliger Scan
  sudo python3 network_discovery_agent.py --daemon      # Dauerbetrieb
  sudo python3 network_discovery_agent.py --dry-run     # nur scannen, nicht hochladen
"""

import argparse
import configparser
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netasset-discovery")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

CONF_PATHS = [
    Path(__file__).parent / "discovery_agent.conf",
    Path("/etc/netasset/discovery_agent.conf"),
]

DEFAULTS = {
    "api_url": "https://ocs.kiste.org",
    "api_key": "",
    "networks": "192.168.0.0/24",       # Kommagetrennte CIDR-Ranges
    "exclude_hosts": "",                 # IPs die nicht gescannt werden
    "scan_interval_minutes": "60",       # Daemon-Modus: Pause zwischen Scans
    "nmap_flags": "-sS -sV -O -T4 --open --host-timeout 30s",
    "exposure_level": "INTERN",
    "tags": "nmap-discovery",
    "timeout": "30",
    "max_hosts_per_run": "254",          # Sicherheitsgrenze
}


def load_config() -> dict:
    cfg = configparser.ConfigParser(defaults=DEFAULTS)
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            log.info("Konfiguration: %s", path)
            break

    section = cfg["discovery"] if "discovery" in cfg else cfg["DEFAULT"]
    return {
        "api_url": os.environ.get("NETASSET_URL", section.get("api_url")),
        "api_key": os.environ.get("NETASSET_API_KEY", section.get("api_key")),
        "networks": [n.strip() for n in section.get("networks").split(",") if n.strip()],
        "exclude_hosts": [h.strip() for h in section.get("exclude_hosts").split(",") if h.strip()],
        "scan_interval": int(section.get("scan_interval_minutes")) * 60,
        "nmap_flags": section.get("nmap_flags").split(),
        "exposure_level": section.get("exposure_level"),
        "tags": [t.strip() for t in section.get("tags").split(",") if t.strip()],
        "timeout": int(section.get("timeout")),
        "max_hosts": int(section.get("max_hosts_per_run")),
    }


# ---------------------------------------------------------------------------
# nmap-Wrapper + XML-Parser
# ---------------------------------------------------------------------------

def find_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        # Windows
        for candidate in [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ]:
            if Path(candidate).exists():
                return candidate
        raise RuntimeError("nmap nicht gefunden. Installieren: apt install nmap")
    return path


def run_nmap(networks: list[str], flags: list[str], exclude: list[str], nmap_bin: str) -> str:
    """Führt nmap aus und gibt XML-Output zurück."""
    cmd = [nmap_bin] + flags + ["-oX", "-"]

    if exclude:
        cmd += ["--exclude", ",".join(exclude)]

    cmd += networks

    log.info("Starte nmap: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # max 10 Minuten
        )
        if result.returncode not in (0, 1):  # 1 = some hosts down, OK
            log.warning("nmap exit %d: %s", result.returncode, result.stderr[:200])
        return result.stdout
    except subprocess.TimeoutExpired:
        log.error("nmap Timeout nach 10 Minuten")
        return ""
    except Exception as e:
        log.error("nmap Fehler: %s", e)
        return ""


def parse_nmap_xml(xml_str: str) -> list[dict]:
    """Parsed nmap XML-Output in strukturierte Host-Dicts."""
    if not xml_str.strip():
        return []

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        log.error("XML-Parse-Fehler: %s", e)
        return []

    hosts = []
    for host in root.findall("host"):
        # Nur Hosts die "up" sind
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        host_data: dict = {}

        # IP + MAC Adressen
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                host_data["ip_address"] = addr.get("addr")
            elif addr_type == "mac":
                host_data["mac_address"] = addr.get("addr", "").lower()
                vendor = addr.get("vendor", "")
                if vendor:
                    host_data["_mac_vendor"] = vendor

        # Hostname
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                if hn.get("type") in ("PTR", "user"):
                    host_data["hostname"] = hn.get("name")
                    break

        # OS-Detection
        os_elem = host.find("os")
        if os_elem is not None:
            matches = os_elem.findall("osmatch")
            if matches:
                best = matches[0]  # Bester Match (höchste Accuracy)
                os_name = best.get("name", "")
                accuracy = int(best.get("accuracy", "0"))
                if accuracy >= 80:  # Nur bei >80% Confidence
                    host_data["_os_raw"] = os_name
                    host_data["_os_accuracy"] = accuracy
                    # OS-Name normalisieren
                    os_lower = os_name.lower()
                    if "linux" in os_lower:
                        host_data["os_name"] = "Linux"
                    elif "windows" in os_lower:
                        host_data["os_name"] = "Windows"
                    elif "macos" in os_lower or "mac os" in os_lower or "darwin" in os_lower:
                        host_data["os_name"] = "macOS"
                    elif "cisco" in os_lower or "ios" in os_lower:
                        host_data["os_name"] = "Cisco IOS"
                    elif "juniper" in os_lower:
                        host_data["os_name"] = "Juniper JunOS"
                    elif "fortinet" in os_lower or "fortios" in os_lower:
                        host_data["os_name"] = "FortiOS"
                    elif "freebsd" in os_lower:
                        host_data["os_name"] = "FreeBSD"
                    else:
                        host_data["os_name"] = os_name.split("(")[0].strip()

                    # Version aus OS-Name extrahieren
                    for oc in best.findall("osclass"):
                        if oc.get("osgen"):
                            host_data["os_version"] = oc.get("osgen")
                            break

        # Asset-Typ aus OS/Ports ableiten
        host_data["asset_type"] = _guess_asset_type(host_data, host)

        # Offene Ports
        ports_elem = host.find("ports")
        open_ports = []
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid", 0))
                proto = port.get("protocol", "tcp")
                service = port.find("service")
                svc_name = service.get("name", "") if service is not None else ""
                svc_ver = service.get("version", "") if service is not None else ""
                svc_product = service.get("product", "") if service is not None else ""

                open_ports.append({
                    "port": portid,
                    "proto": proto,
                    "service": svc_name or None,
                    "version": (f"{svc_product} {svc_ver}".strip()) or None,
                    "reachable_from": ["intern"],
                })

        host_data["open_ports"] = open_ports

        # Nur Hosts mit IP
        if host_data.get("ip_address"):
            hosts.append(host_data)

    log.info("nmap: %d Hosts gefunden", len(hosts))
    return hosts


def _guess_asset_type(host_data: dict, host_xml) -> str:
    """Leitet den Asset-Typ aus OS und offenen Ports ab."""
    os_name = (host_data.get("os_name") or "").lower()
    os_raw = (host_data.get("_os_raw") or "").lower()
    vendor = (host_data.get("_mac_vendor") or "").lower()

    # Netzwerkgeräte
    if any(kw in os_raw for kw in ("cisco", "juniper", "arista", "mikrotik", "ubiquiti")):
        if "wireless" in os_raw or "access point" in os_raw:
            return "access-point"
        if "firewall" in os_raw or "fortinet" in os_raw or "checkpoint" in os_raw:
            return "firewall"
        return "switch"

    if any(kw in vendor for kw in ("cisco", "juniper", "arista", "mikrotik", "ubiquit")):
        return "switch"

    if any(kw in vendor for kw in ("fortinet", "palo alto", "check point", "sophos")):
        return "firewall"

    # Ports als Hinweis
    ports_elem = host_xml.find("ports")
    open_port_nums = set()
    if ports_elem:
        for p in ports_elem.findall("port"):
            s = p.find("state")
            if s is not None and s.get("state") == "open":
                open_port_nums.add(int(p.get("portid", 0)))

    if 3389 in open_port_nums or "windows" in os_name:
        return "client"

    if "printer" in os_raw or 9100 in open_port_nums:
        return "printer"

    if "linux" in os_name or 22 in open_port_nums:
        return "server"

    return "server"  # Default


# ---------------------------------------------------------------------------
# NetAsset API
# ---------------------------------------------------------------------------

def api_request(url: str, api_key: str, data, timeout: int = 30):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode()}") from e


def push_hosts(config: dict, hosts: list[dict]) -> dict:
    """Sendet alle Hosts an /api/v1/discovery/ingest."""
    url = config["api_url"].rstrip("/") + "/api/v1/discovery/ingest"

    devices = []
    for h in hosts:
        device = {
            "hostname": h.get("hostname"),
            "ip_address": h.get("ip_address"),
            "mac_address": h.get("mac_address"),
            "asset_type": h.get("asset_type", "server"),
            "os_name": h.get("os_name"),
            "os_version": h.get("os_version"),
            "exposure_level": config["exposure_level"],
            "open_ports": h.get("open_ports", []),
            "tags": config["tags"] + [f"os:{h.get('os_name','unknown').lower().split()[0]}"],
            "source": "nmap-discovery",
        }
        # Hersteller als Manufacturer
        if h.get("_mac_vendor"):
            device["manufacturer"] = h["_mac_vendor"]

        devices.append(device)

    result = api_request(url, config["api_key"], devices, config["timeout"])
    stats = {"created": 0, "merged": 0, "flagged": 0, "errors": 0}
    for item in (result or []):
        action = item.get("action", "error")
        stats[action] = stats.get(action, 0) + 1
    return stats


# ---------------------------------------------------------------------------
# Scan-Zyklus
# ---------------------------------------------------------------------------

def run_scan(config: dict, nmap_bin: str, dry_run: bool = False) -> None:
    started = datetime.now(timezone.utc)
    log.info("=== Scan gestartet: %s Netzwerke ===", ", ".join(config["networks"]))

    xml_output = run_nmap(
        config["networks"],
        config["nmap_flags"],
        config["exclude_hosts"],
        nmap_bin,
    )

    if not xml_output:
        log.warning("Kein nmap-Output erhalten")
        return

    hosts = parse_nmap_xml(xml_output)

    if not hosts:
        log.info("Keine aktiven Hosts gefunden")
        return

    # Zusammenfassung
    types = {}
    for h in hosts:
        t = h.get("asset_type", "?")
        types[t] = types.get(t, 0) + 1
    log.info("Gefunden: %s", ", ".join(f"{v}× {k}" for k, v in sorted(types.items())))

    if dry_run:
        print("\n=== DRY RUN – wird NICHT hochgeladen ===\n")
        for h in hosts:
            print(f"  {h['ip_address']:<18} {h.get('hostname') or '—':<30} "
                  f"{h.get('asset_type'):<12} "
                  f"{h.get('os_name') or '?'} "
                  f"Ports: {len(h.get('open_ports',[]))}")
        return

    # Upload
    log.info("Lade %d Hosts hoch...", len(hosts))
    stats = push_hosts(config, hosts)
    duration = (datetime.now(timezone.utc) - started).total_seconds()
    log.info(
        "Fertig in %.1fs: %d neu, %d aktualisiert, %d Konflikt, %d Fehler",
        duration,
        stats.get("created", 0),
        stats.get("merged", 0),
        stats.get("flagged", 0),
        stats.get("errors", 0),
    )


# ---------------------------------------------------------------------------
# Daemon-Modus
# ---------------------------------------------------------------------------

_running = True


def _handle_signal(sig, frame):
    global _running
    log.info("Signal %d empfangen – beende nach aktuellem Scan", sig)
    _running = False


def run_daemon(config: dict, nmap_bin: str) -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    interval = config["scan_interval"]
    log.info("Daemon gestartet – Scan alle %d Minuten", interval // 60)

    while _running:
        try:
            run_scan(config, nmap_bin)
        except Exception as e:
            log.error("Scan-Fehler: %s", e)

        if not _running:
            break

        log.info("Nächster Scan in %d Minuten...", interval // 60)
        for _ in range(interval):
            if not _running:
                break
            time.sleep(1)

    log.info("Daemon beendet")


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NetAsset Network Discovery Agent")
    parser.add_argument("--daemon", "-d", action="store_true",
                        help="Dauerbetrieb: scannt regelmäßig")
    parser.add_argument("--dry-run", action="store_true",
                        help="Nur scannen, nicht hochladen")
    parser.add_argument("--networks", "-n",
                        help="Netzwerke überschreiben, z.B. 192.168.1.0/24,10.0.0.0/16")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config()

    if args.networks:
        config["networks"] = [n.strip() for n in args.networks.split(",")]

    if not config["api_key"] and not args.dry_run:
        log.error("NETASSET_API_KEY fehlt. In discovery_agent.conf eintragen oder als Env-Variable setzen.")
        sys.exit(1)

    if not config["networks"]:
        log.error("Keine Netzwerk-Ranges konfiguriert.")
        sys.exit(1)

    nmap_bin = find_nmap()
    log.info("nmap: %s", nmap_bin)

    # Root-Check (nmap braucht root für OS-Detection)
    if os.name != "nt" and os.geteuid() != 0:
        log.warning("Kein Root – OS-Detection und ARP deaktiviert (nur TCP-Scan)")
        # Flags ohne privilegierte Optionen
        config["nmap_flags"] = [f for f in config["nmap_flags"]
                                 if f not in ("-sS", "-O", "--privileged")]
        config["nmap_flags"] = ["-sT" if f == "-sS" else f for f in config["nmap_flags"]]

    if args.daemon:
        run_daemon(config, nmap_bin)
    else:
        run_scan(config, nmap_bin, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
