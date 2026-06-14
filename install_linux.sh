#!/usr/bin/env bash
# NetAsset Collector – Linux Setup
#
# Installiert osquery und richtet einen Cron-Job ein.
# Aufruf: sudo bash install_linux.sh
set -euo pipefail

# Verzeichnis, in dem dieses Skript liegt (= Git-Checkout). Der Cron-Job
# läuft direkt von hier aus, damit "git pull" die laufende Version aktualisiert.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR"
CONF_DIR="/etc/netasset"
CRON_FILE="/etc/cron.d/netasset-collector"

echo "==> NetAsset Collector – Linux Setup"

# 1. osquery installieren
if ! command -v osqueryi &>/dev/null; then
    echo "==> Installiere osquery..."
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/osquery.gpg
        echo "deb [signed-by=/usr/share/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
            > /etc/apt/sources.list.d/osquery.list
        apt-get update -qq && apt-get install -y osquery
    elif command -v rpm &>/dev/null; then
        # RHEL/CentOS/Fedora
        curl -fsSL https://pkg.osquery.io/rpm/GPG | gpg --import
        curl -fsSL https://pkg.osquery.io/rpm/osquery-s3-rpm.repo \
            -o /etc/yum.repos.d/osquery-s3-rpm.repo
        yum install -y osquery
    else
        echo "FEHLER: Paketmanager nicht erkannt. osquery manuell installieren: https://osquery.io"
        exit 1
    fi
    echo "    osquery installiert: $(osqueryi --version)"
else
    echo "    osquery bereits vorhanden: $(osqueryi --version)"
fi

# 2. Python3 prüfen
if ! command -v python3 &>/dev/null; then
    echo "==> Installiere python3..."
    apt-get install -y python3 2>/dev/null || yum install -y python3 2>/dev/null || true
fi

# 3. Collector ausführbar machen, Config-Verzeichnis anlegen
echo "==> Verwende Collector aus $INSTALL_DIR"
mkdir -p "$CONF_DIR"
chmod +x "$INSTALL_DIR/netasset_collector.py"

# 4. Konfiguration anlegen (wenn noch nicht vorhanden)
if [ ! -f "$CONF_DIR/netasset_collector.conf" ]; then
    cp "$SCRIPT_DIR/netasset_collector.conf.example" "$CONF_DIR/netasset_collector.conf"
    echo ""
    echo "  WICHTIG: Konfiguration anpassen:"
    echo "  nano $CONF_DIR/netasset_collector.conf"
    echo "  → api_key eintragen (aus NetAsset → Einstellungen → API Keys)"
    echo ""
fi

# 5. Cron-Job einrichten (stündlich)
cat > "$CRON_FILE" << EOF
# NetAsset Collector – stündlich
0 * * * * root /usr/bin/python3 $INSTALL_DIR/netasset_collector.py >> /var/log/netasset-collector.log 2>&1
EOF
chmod 644 "$CRON_FILE"

echo ""
echo "==> Installation abgeschlossen!"
echo ""
echo "Nächste Schritte:"
echo "  1. nano $CONF_DIR/netasset_collector.conf  (api_key eintragen)"
echo "  2. Testlauf: python3 $INSTALL_DIR/netasset_collector.py --dry-run"
echo "  3. Erster Upload: python3 $INSTALL_DIR/netasset_collector.py"
echo "  4. Danach läuft der Cron-Job stündlich automatisch"
echo ""
echo "Logs: tail -f /var/log/netasset-collector.log"
