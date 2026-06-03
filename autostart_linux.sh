#!/usr/bin/env bash
# DRUCKER Collector – Linux Autostart via systemd
#
# Richtet einen systemd-Service ein der:
#   - Beim Systemstart automatisch läuft
#   - Stündlich wiederholt (via systemd Timer)
#   - Bei Fehler automatisch neu startet
#
# Aufruf (als root):
#   bash autostart_linux.sh
#
# Voraussetzung: netasset_collector.py + netasset_collector.conf
# bereits installiert (via install_linux.sh)

set -euo pipefail

INSTALL_DIR="/opt/netasset-collector"
CONF_DIR="/etc/netasset"
LOG_FILE="/var/log/drucker-collector.log"
SERVICE_NAME="drucker-collector"

echo "==> DRUCKER Collector – Linux Autostart Setup"

# 1. Python3 prüfen
PYTHON=$(which python3 || echo "")
if [ -z "$PYTHON" ]; then
    echo "FEHLER: python3 nicht gefunden"
    exit 1
fi
echo "    Python: $PYTHON"

# 2. Collector prüfen
if [ ! -f "$INSTALL_DIR/netasset_collector.py" ]; then
    echo "FEHLER: $INSTALL_DIR/netasset_collector.py nicht gefunden"
    echo "Bitte zuerst install_linux.sh ausführen"
    exit 1
fi

# 3. Config prüfen
if [ ! -f "$CONF_DIR/netasset_collector.conf" ]; then
    echo "FEHLER: $CONF_DIR/netasset_collector.conf nicht gefunden"
    echo "Bitte api_key konfigurieren"
    exit 1
fi

# 4. systemd Service anlegen
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=DRUCKER Infrastructure Collector
Documentation=https://github.com/hanswurst1805/netasset
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PYTHON $INSTALL_DIR/netasset_collector.py
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
# Bei Fehler nicht sofort aufgeben
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

# 5. systemd Timer anlegen (stündlich + direkt nach Boot)
cat > /etc/systemd/system/${SERVICE_NAME}.timer << EOF
[Unit]
Description=DRUCKER Collector – stündlich + beim Boot
After=network-online.target

[Timer]
# 5 Minuten nach Boot (Netzwerk stabilisieren lassen)
OnBootSec=5min
# Danach stündlich
OnUnitActiveSec=1h
# Auch beim Start direkt ausführen
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 6. Services aktivieren
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}.timer
systemctl start  ${SERVICE_NAME}.timer

echo ""
echo "==> Autostart eingerichtet!"
echo ""
echo "Status:"
systemctl status ${SERVICE_NAME}.timer --no-pager 2>/dev/null || true
echo ""
echo "Nächste Ausführungen:"
systemctl list-timers ${SERVICE_NAME}.timer --no-pager 2>/dev/null || true
echo ""
echo "Befehle:"
echo "  Jetzt ausführen:  systemctl start ${SERVICE_NAME}.service"
echo "  Status:           systemctl status ${SERVICE_NAME}.timer"
echo "  Logs:             journalctl -u ${SERVICE_NAME}.service -f"
echo "  Deaktivieren:     systemctl disable ${SERVICE_NAME}.timer"
