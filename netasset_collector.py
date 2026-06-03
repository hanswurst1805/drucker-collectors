#!/usr/bin/env python3
from __future__ import annotations
"""
NetAsset Collector – osquery-basiert, läuft auf Linux und Windows.

Sammelt:
  - Systeminfo (Hostname, OS, Hardware)
  - Netzwerk-Interfaces + IP-Adressen
  - Offene Ports (listening)
  - Installierte Pakete (SBOM)

Und pusht alles an die NetAsset API:
  POST /api/v1/discovery/ingest  → Asset anlegen/aktualisieren
  POST /api/v1/sbom/assets/{id}/sbom → SBOM hochladen

Konfiguration: netasset_collector.conf (oder Umgebungsvariablen)

Aufruf:
  python3 netasset_collector.py
  python3 netasset_collector.py --dry-run   # kein Upload, nur anzeigen
"""

import argparse
import configparser
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netasset-collector")

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

CONF_PATHS = [
    Path(__file__).parent / "netasset_collector.conf",          # neben dem Script
    Path("/etc/netasset/netasset_collector.conf"),               # Linux systemweit
    Path.home() / "Library/NetAsset/netasset_collector.conf",   # macOS
    Path(os.environ.get("APPDATA", "C:/ProgramData")) / "NetAsset/netasset_collector.conf",  # Windows
]


def load_config() -> dict:
    cfg = configparser.ConfigParser()
    for path in CONF_PATHS:
        if path.exists():
            cfg.read(path)
            log.info("Konfiguration geladen: %s", path)
            break

    section = cfg["netasset"] if "netasset" in cfg else {}
    return {
        "api_url": os.environ.get("NETASSET_URL", section.get("api_url", "https://ocs.kiste.org")),
        "api_key": os.environ.get("NETASSET_API_KEY", section.get("api_key", "")),
        "tags": os.environ.get("NETASSET_TAGS", section.get("tags", "")).split(","),
        "exposure_level": os.environ.get("NETASSET_EXPOSURE", section.get("exposure_level", "INTERN")),
        "osquery_bin": section.get("osquery_bin", ""),
        "timeout": int(section.get("timeout", "30")),
    }


# ---------------------------------------------------------------------------
# osquery-Wrapper
# ---------------------------------------------------------------------------

def find_osquery() -> str | None:
    """Sucht osqueryi im PATH und an bekannten Orten."""
    candidates = ["osqueryi"]
    if platform.system() == "Windows":
        candidates += [
            r"C:\Program Files\osquery\osqueryi.exe",
            r"C:\Program Files (x86)\osquery\osqueryi.exe",
        ]
    else:
        candidates += ["/usr/bin/osqueryi", "/usr/local/bin/osqueryi", "/opt/osquery/bin/osqueryi"]

    for c in candidates:
        path = shutil.which(c) or (c if Path(c).exists() else None)
        if path:
            return path
    return None


def osquery(sql: str, osquery_bin: str) -> list[dict]:
    """Führt eine osquery-SQL-Abfrage aus und gibt das Ergebnis zurück."""
    try:
        result = subprocess.run(
            [osquery_bin, "--json", sql],
            capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace',
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
    except Exception as e:
        log.warning("osquery Fehler für '%s': %s", sql[:60], e)
    return []


# ---------------------------------------------------------------------------
# Datensammlung
# ---------------------------------------------------------------------------

def collect_system_info(q) -> dict:
    """Basis-Systeminfos via osquery."""
    rows = q("SELECT hostname, uuid, cpu_brand, cpu_physical_cores, physical_memory, hardware_vendor, hardware_model, hardware_serial FROM system_info LIMIT 1")
    if not rows:
        return {}
    row = rows[0]

    # serial_number: Hardware-Seriennummer wenn vorhanden
    serial = row.get("hardware_serial") or None
    if serial in ("", "0", "Default string", "To be filled by O.E.M.",
                  "System Serial Number", "None", "N/A"):
        serial = None

    # chassis_id: systemweite UUID – stabiler Identifier, verhindert Fehl-Merges
    uuid = row.get("uuid") or None
    if uuid in ("", "0", "00000000-0000-0000-0000-000000000000"):
        uuid = None

    return {
        "hostname": row.get("hostname"),
        "manufacturer": row.get("hardware_vendor"),
        "model": row.get("hardware_model"),
        "serial_number": serial,
        "chassis_id": uuid,   # Stable Key im Identity Resolver
        "_cpu": row.get("cpu_brand"),
        "_ram_bytes": row.get("physical_memory"),
    }


def collect_os_info(q) -> dict:
    """OS-Version via osquery."""
    rows = q("SELECT name, version, platform, arch FROM os_version LIMIT 1")
    if not rows:
        return {}
    row = rows[0]
    return {
        "os_name": row.get("name") or row.get("platform"),
        "os_version": row.get("version"),
        "os_arch": row.get("arch"),
    }


def collect_network(q) -> tuple[str | None, str | None, list[dict]]:
    """IP, MAC und offene Ports via osquery.
    Nutzt die Default-Route um das primäre IPv4-Interface zu bestimmen.
    """
    # 1. Default-Route Interface ermitteln (destination 0.0.0.0 = Default-GW)
    default_iface = None
    routes = q("""
        SELECT interface FROM routes
        WHERE destination = '0.0.0.0'
          AND netmask = '0'
          AND type = 'gateway'
        ORDER BY metric ASC
        LIMIT 1
    """)
    if routes:
        default_iface = routes[0].get("interface")

    # 2. IPv4-Adresse des Default-Route-Interface holen
    ip_address = None
    mac_address = None

    if default_iface:
        ifaces = q(f"""
            SELECT ia.address, id.mac
            FROM interface_addresses ia
            JOIN interface_details id ON ia.interface = id.interface
            WHERE ia.interface = '{default_iface}'
              AND ia.address NOT LIKE '127.%'
              AND ia.address NOT LIKE '%:%'
              AND length(ia.address) <= 15
            LIMIT 1
        """)
        if ifaces:
            ip_address = ifaces[0].get("address")
            mac_address = ifaces[0].get("mac")

    # Fallback: erste brauchbare IPv4-Adresse wenn Default-Route nicht gefunden
    if not ip_address:
        ifaces = q("""
            SELECT ia.address, ia.interface, id.mac
            FROM interface_addresses ia
            JOIN interface_details id ON ia.interface = id.interface
            WHERE ia.address NOT LIKE '127.%'
              AND ia.address NOT LIKE '%:%'
              AND length(ia.address) <= 15
              AND id.mac != '00:00:00:00:00:00'
            ORDER BY id.last_change DESC
            LIMIT 1
        """)
        if ifaces:
            ip_address = ifaces[0].get("address")
            mac_address = ifaces[0].get("mac")

    # Offene Ports (listening)
    ports_raw = q("""
        SELECT DISTINCT lp.port, lp.protocol, lp.address, p.name as process_name
        FROM listening_ports lp
        LEFT JOIN processes p ON lp.pid = p.pid
        WHERE lp.address != '127.0.0.1'
          AND lp.address != '::1'
          AND lp.port > 0
        ORDER BY lp.port
    """)

    proto_map = {"6": "tcp", "17": "udp"}
    open_ports = []
    seen = set()
    for p in ports_raw:
        port = int(p.get("port", 0))
        proto = proto_map.get(str(p.get("protocol", "6")), "tcp")
        key = (port, proto)
        if key in seen or port == 0:
            continue
        seen.add(key)
        open_ports.append({
            "port": port,
            "proto": proto,
            "service": p.get("process_name") or None,
            "reachable_from": ["intern"],
        })

    return ip_address, mac_address, open_ports


def collect_update_status(q) -> dict:
    """
    Ermittelt ausstehende Updates und Reboot-Status.
    Funktioniert auf Linux (apt/yum), macOS und Windows.
    """
    status = {
        "pending_updates": None,
        "reboot_required": False,
        "security_updates": None,
        "platform": platform.system(),
    }

    if platform.system() == "Linux":
        # Reboot erforderlich (Ubuntu/Debian)
        reboot_file = q("SELECT path FROM file WHERE path = '/var/run/reboot-required'")
        status["reboot_required"] = len(reboot_file) > 0

        # Anzahl ausstehender Updates (Ubuntu update-notifier)
        notifier = q("""
            SELECT content FROM yara
            WHERE path = '/var/lib/update-notifier/updates-available'
        """)
        if not notifier:
            # Fallback: Datei direkt lesen
            try:
                with open("/var/lib/update-notifier/updates-available") as f:
                    content = f.read()
                    import re as _re
                    m = _re.search(r'(\d+) packages can be updated', content)
                    if m:
                        status["pending_updates"] = int(m.group(1))
                    ms = _re.search(r'(\d+) of these updates are standard security updates', content)
                    if ms:
                        status["security_updates"] = int(ms.group(1))
            except Exception:
                pass

        # Fallback: apt-check wenn installiert
        if status["pending_updates"] is None:
            apt_check = q("""
                SELECT stdout FROM process_open_sockets
                LIMIT 0
            """)  # Dummy — echtes apt-check via subprocess
            try:
                import subprocess as _sp
                r = _sp.run(
                    ["/usr/lib/update-notifier/apt-check", "--human-readable"],
                    capture_output=True, text=True, timeout=10
                )
                if r.returncode == 0 and r.stderr:
                    import re as _re
                    m = _re.search(r'(\d+) packages can be updated', r.stderr)
                    if m:
                        status["pending_updates"] = int(m.group(1))
                    ms = _re.search(r'(\d+) of these updates are security updates', r.stderr)
                    if ms:
                        status["security_updates"] = int(ms.group(1))
            except Exception:
                pass

        # RHEL/CentOS: yum check-update
        if status["pending_updates"] is None:
            try:
                import subprocess as _sp
                r = _sp.run(
                    ["yum", "check-update", "--quiet"],
                    capture_output=True, text=True, timeout=30
                )
                # Exit code 100 = updates verfügbar
                if r.returncode in (0, 100):
                    lines = [l for l in r.stdout.strip().splitlines() if l and not l.startswith("Last")]
                    status["pending_updates"] = len(lines)
            except Exception:
                pass

    elif platform.system() == "Windows":
        # osquery windows_updates Tabelle
        updates = q("SELECT hot_fix_id, installed_on FROM wmi_hotfixes WHERE installed_on IS NULL")
        status["pending_updates"] = len(updates)

        # Reboot pending (Windows)
        reboot_pending = q("""
            SELECT data FROM registry
            WHERE key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
            AND name = 'PendingFileRenameOperations'
        """)
        status["reboot_required"] = len(reboot_pending) > 0

    elif platform.system() == "Darwin":
        # macOS: softwareupdate
        try:
            import subprocess as _sp
            r = _sp.run(
                ["softwareupdate", "--list"],
                capture_output=True, text=True, timeout=30
            )
            lines = [l for l in r.stdout.splitlines() if "* " in l or "Title:" in l]
            status["pending_updates"] = len(lines)
        except Exception:
            pass

    return status


def collect_packages(q) -> list[dict]:
    """Installierte Pakete via osquery — SBOM-Einträge."""
    packages = []

    if platform.system() == "Windows":
        # Windows: Programme aus Add/Remove Programs
        rows = q("SELECT name, version, publisher FROM programs WHERE name != ''")
        for r in rows:
            packages.append({
                "pkg_name": r.get("name", "").strip(),
                "pkg_version": r.get("version", "").strip() or "unknown",
                "pkg_type": "application",
                "source": "windows-programs",
            })
    elif platform.system() == "Darwin":
        # macOS: Homebrew
        brew = q("SELECT name, version FROM homebrew_packages WHERE name != ''")
        for r in brew:
            packages.append({
                "pkg_name": r.get("name", ""),
                "pkg_version": r.get("version", "unknown"),
                "pkg_type": "library",
                "source": "homebrew",
            })
        # macOS: .app-Anwendungen aus /Applications
        apps = q("SELECT name, bundle_short_version FROM apps WHERE bundle_short_version != '' LIMIT 200")
        for r in apps:
            name = r.get("name", "").replace(".app", "")
            packages.append({
                "pkg_name": name,
                "pkg_version": r.get("bundle_short_version", "unknown"),
                "pkg_type": "application",
                "source": "macos-apps",
            })
    else:
        # Linux: DEB oder RPM
        deb = q("SELECT name, version, source FROM deb_packages WHERE name != '' LIMIT 2000")
        if deb:
            for r in deb:
                packages.append({
                    "pkg_name": r.get("name", ""),
                    "pkg_version": r.get("version", "unknown"),
                    "pkg_type": "os-package",
                    "source": "dpkg",
                })
        else:
            rpm = q("SELECT name, version, release, arch FROM rpm_packages WHERE name != '' LIMIT 2000")
            for r in rpm:
                ver = r.get("version", "")
                rel = r.get("release", "")
                packages.append({
                    "pkg_name": r.get("name", ""),
                    "pkg_version": f"{ver}-{rel}" if rel else ver or "unknown",
                    "pkg_type": "os-package",
                    "source": "rpm",
                })

        # Python-Pakete
        pip = q("SELECT name, version FROM python_packages WHERE name != '' LIMIT 500")
        for r in pip:
            packages.append({
                "pkg_name": r.get("name", ""),
                "pkg_version": r.get("version", "unknown"),
                "pkg_type": "library",
                "source": "pip",
            })

    # Deduplizierung
    seen = set()
    result = []
    for p in packages:
        key = (p["pkg_name"], p["pkg_version"])
        if key not in seen and p["pkg_name"]:
            seen.add(key)
            result.append(p)

    return result


# ---------------------------------------------------------------------------
# API-Calls
# ---------------------------------------------------------------------------

def api_request(url: str, api_key: str, data: dict, timeout: int = 30) -> dict:
    """HTTP POST gegen die NetAsset API."""
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def push_asset(config: dict, device: dict) -> str | None:
    """Sendet Asset an /api/v1/discovery/ingest. Gibt asset_id zurück."""
    url = config["api_url"].rstrip("/") + "/api/v1/discovery/ingest"
    result = api_request(url, config["api_key"], [device], config["timeout"])
    if result and isinstance(result, list):
        item = result[0]
        asset_id = item.get("asset_id")
        action = item.get("action", "?")
        log.info("Asset %s: %s (id=%s)", device.get("hostname"), action, asset_id)
        return asset_id
    return None


def push_sbom(config: dict, asset_id: str, packages: list[dict]) -> None:
    """Sendet SBOM-Einträge an /api/v1/sbom/assets/{id}/sbom."""
    if not packages:
        return
    url = config["api_url"].rstrip("/") + f"/api/v1/sbom/assets/{asset_id}/sbom"
    # In Batches von 200
    for i in range(0, len(packages), 200):
        batch = packages[i:i+200]
        api_request(url, config["api_key"], batch, config["timeout"])
    log.info("SBOM: %d Pakete hochgeladen", len(packages))


# ---------------------------------------------------------------------------
# Hauptfunktion
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="NetAsset osquery Collector")
    parser.add_argument("--dry-run", action="store_true", help="Nur sammeln, nicht hochladen")
    parser.add_argument("--no-sbom", action="store_true", help="SBOM-Upload überspringen")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config()

    if not config["api_key"] and not args.dry_run:
        log.error("NETASSET_API_KEY nicht gesetzt. Bitte in netasset_collector.conf eintragen.")
        sys.exit(1)

    # osquery finden
    osquery_bin = config.get("osquery_bin") or find_osquery()
    if not osquery_bin:
        log.error("osquery nicht gefunden. Bitte installieren: https://osquery.io")
        sys.exit(1)
    log.info("osquery: %s", osquery_bin)

    # Query-Wrapper
    def q(sql: str) -> list[dict]:
        return osquery(sql, osquery_bin)

    log.info("Sammle Systemdaten...")

    # Daten sammeln
    sys_info = collect_system_info(q)
    os_info = collect_os_info(q)
    ip, mac, ports = collect_network(q)
    packages = collect_packages(q)

    # Asset-Typ ermitteln
    asset_type = "client"
    if platform.system() == "Linux":
        asset_type = "server"
    elif platform.system() == "Windows":
        asset_type = "client"
    elif platform.system() == "Darwin":
        asset_type = "client"

    # Tags zusammenbauen
    tags = [t.strip() for t in config["tags"] if t.strip()]
    tags.append(f"os:{platform.system().lower()}")

    device = {
        "hostname": sys_info.get("hostname") or platform.node(),
        "ip_address": ip,
        "mac_address": mac,
        "serial_number": sys_info.get("serial_number"),
        "chassis_id": sys_info.get("chassis_id"),  # System-UUID als Stable Key
        "asset_type": asset_type,
        "os_name": os_info.get("os_name"),
        "os_version": os_info.get("os_version"),
        "os_arch": os_info.get("os_arch"),
        "manufacturer": sys_info.get("manufacturer"),
        "model": sys_info.get("model"),
        "exposure_level": config["exposure_level"],
        "open_ports": ports,
        "tags": tags,
        "source": "osquery",
    }

    # Update-Status
    update_status = collect_update_status(q)
    pending = update_status.get("pending_updates")
    security = update_status.get("security_updates")
    reboot = update_status.get("reboot_required", False)

    # Als Tags speichern (sichtbar in der UI)
    if pending is not None:
        tags.append(f"updates:{pending}")
    if security is not None and security > 0:
        tags.append(f"security-updates:{security}")
    if reboot:
        tags.append("reboot-required")

    log.info(
        "Gesammelt: %s (%s %s), %d Ports, %d Pakete, %s ausstehende Updates%s",
        device["hostname"],
        device["os_name"] or "?",
        device["os_version"] or "?",
        len(ports),
        len(packages),
        str(pending) if pending is not None else "?",
        " [REBOOT]" if reboot else "",
    )

    if args.dry_run:
        print("\n=== DRY RUN – wird NICHT hochgeladen ===\n")
        print("Asset:")
        print(json.dumps(device, indent=2))
        print(f"\nSBOM: {len(packages)} Pakete (erste 5):")
        print(json.dumps(packages[:5], indent=2))
        return

    # Upload
    log.info("Lade Asset hoch...")
    asset_id = push_asset(config, device)

    if asset_id and not args.no_sbom:
        log.info("Lade SBOM hoch (%d Pakete)...", len(packages))
        push_sbom(config, asset_id, packages)

    log.info("Fertig.")


if __name__ == "__main__":
    main()
