# DRUCKER Collectors

Agenten für [DRUCKER Infrastructure Intelligence](https://github.com/hanswurst1805/netasset) — sammeln Systemdaten und senden sie automatisch an den DRUCKER-Server.

## Unterstützte Plattformen

| Collector | Plattform | Methode |
|---|---|---|
| `netasset_collector.py` | Linux / Windows / macOS | osquery |
| `mikrotik_collector.py` | MikroTik Router & Switches | REST API (7.1+) / SNMP |
| `fritzbox_collector.py` | AVM Fritz!Box | TR-064 |
| `network_discovery_agent.py` | Netzwerk-Scan | nmap |
| `lynis_collector.py` | Linux Sicherheits-Audit | Lynis |
| `eset_collector.py` | ESET PROTECT Cloud (verwaltete Endpoints) | ESET Connect API |
| `na_jump.py` | Jumpbox (Bastion) | Aufgezeichnete SSH-Session zu Zielhosts |

---

## Schnellstart

### Linux
```bash
git clone https://github.com/hanswurst1805/drucker-collectors.git /opt/drucker-collectors
cd /opt/drucker-collectors
sudo bash install_linux.sh
```

### macOS
```bash
git clone https://github.com/hanswurst1805/drucker-collectors.git ~/drucker-collectors
cd ~/drucker-collectors
bash install_macos.sh
```

### Windows (PowerShell als Administrator)
```powershell
git clone https://github.com/hanswurst1805/drucker-collectors.git C:\drucker-collectors
cd C:\drucker-collectors
powershell -ExecutionPolicy Bypass -File install_windows.ps1
```

---

## Konfiguration

Nach der Installation Config-Datei anpassen:

```ini
# /etc/netasset/netasset_collector.conf  (Linux/macOS)
# C:\ProgramData\NetAsset\netasset_collector.conf  (Windows)

[netasset]
api_url = https://dein-drucker-server.de
api_key = sk-na-...          # DRUCKER → Einstellungen → API Keys
tags = standort-kiel          # Beliebige Tags
exposure_level = INTERN
```

---

## Was wird gesammelt

- **Basis**: Hostname, IP, MAC, OS-Version, Hardware
- **Netzwerk**: Primäres Interface + Default-Route
- **Software (SBOM)**: Alle installierten Pakete (dpkg/rpm/pip/npm/homebrew/Apps)
- **Ports**: Lauschende Ports (intern/extern)
- **Updates**: Ausstehende Updates + Reboot-Status
- **Sicherheit**: CVE-Scan via OSV (automatisch nach Upload)

---

## Collector-spezifische Anleitungen

### MikroTik (Router/Switch)
```bash
cp mikrotik_collector.conf.example /etc/netasset/mikrotik.conf
nano /etc/netasset/mikrotik.conf   # hosts, username, password
python3 mikrotik_collector.py --config /etc/netasset/mikrotik.conf --dry-run
```

### Fritz!Box
```bash
pip install fritzconnection
cp fritzbox_collector.conf.example /etc/netasset/fritzbox.conf
nano /etc/netasset/fritzbox.conf
python3 fritzbox_collector.py --dry-run
```

### Netzwerk-Discovery (nmap)
```bash
apt install nmap
cp discovery_agent.conf.example /etc/netasset/discovery.conf
nano /etc/netasset/discovery.conf  # networks = 192.168.178.0/24
python3 network_discovery_agent.py --dry-run
```

### Lynis Sicherheits-Audit
```bash
apt install lynis
sudo lynis audit system
python3 lynis_collector.py    # lädt /var/log/lynis-report.dat hoch
```

### ESET PROTECT Cloud
```bash
cp eset_collector.conf.example /etc/netasset/eset_collector.conf
nano /etc/netasset/eset_collector.conf   # region, API-User

# Falls die Geräte-Felder vom Tenant abweichen, Rohdaten eines Geräts prüfen:
python3 eset_collector.py --dump-raw

python3 eset_collector.py --dry-run
```

Benötigt einen dedizierten **API-User** (nicht die normalen Login-Daten),
siehe: https://help.eset.com/eset_connect/en-US/create_api_user_account.html

### Jumpbox – aufgezeichnete SSH-Sessions

`na_jump.py` (Jumpbox) zeichnet SSH-Sessions zu Zielhosts auf und lädt sie an
NetAsset; `na_cmdlog.sh` + `na_cmdlog_upload.py` protokollieren zielseitig die
ausgeführten Kommandos. Beide werden über eine Session-UUID korreliert.

Vollständige Einrichtung (Jumpbox, sshd ForceCommand, Zielhosts):
siehe [docs/jumpbox_session_recording.md](docs/jumpbox_session_recording.md).

**Einfachere Variante (ohne Jumpbox):** `na_screen_rec.sh` zeichnet direkt auf
dem Zielserver per `screen` jede interaktive SSH-Session lokal auf und lädt sie
nach dem Logout an NetAsset (`na_screen_upload.py`). Siehe
[docs/screen_session_recording.md](docs/screen_session_recording.md).

#### Status-Check (ohne NetAsset)

Eigenständiges Skript `eset_status.py` zeigt direkt im Terminal den Zustand
aller ESET-Endpoints (Schutzstatus, OS, letzte Synchronisation) sowie offene
Alarme/Detections – unabhängig von NetAsset, nur zum Prüfen des API-Zugriffs:

```bash
# Region, API-User und Passwort direkt im Skript (CONFIG-Block) eintragen
python3 eset_status.py
python3 eset_status.py --days 7    # Alarme der letzten 7 Tage
python3 eset_status.py --raw       # Rohdaten als JSON
```

---

## Autostart

```bash
# Linux: systemd Timer (5 Min. nach Boot, dann stündlich)
sudo bash autostart_linux.sh

# macOS: LaunchAgent
bash autostart_macos.sh

# Windows: Task Scheduler
powershell -ExecutionPolicy Bypass -File autostart_windows.ps1
```

---

## Updates

```bash
cd /opt/drucker-collectors
git pull
# Collector läuft beim nächsten Autostart automatisch mit neuer Version
```

---

## Anforderungen

- **Python 3.10+**
- **osquery** (für Hauptcollector): [osquery.io](https://osquery.io)
- **Nmap** (für Discovery): `apt install nmap`
- **fritzconnection** (für Fritz!Box): `pip install fritzconnection`

---

## Lizenz

MIT — Teil des [DRUCKER](https://github.com/hanswurst1805/netasset) Projekts.
