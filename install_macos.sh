#!/usr/bin/env bash
# NetAsset Collector - macOS Setup
# Installiert osquery und richtet einen LaunchAgent (stündlich) ein.
#
# Aufruf: bash install_macos.sh
set -euo pipefail

INSTALL_DIR="$HOME/Library/NetAsset/Collector"
CONF_DIR="$HOME/Library/NetAsset"
LAUNCH_AGENT="$HOME/Library/LaunchAgents/org.netasset.collector.plist"
LOG_FILE="$HOME/Library/Logs/netasset-collector.log"

echo "==> NetAsset Collector - macOS Setup"

# 1. osquery installieren
if ! command -v osqueryi &>/dev/null; then
    echo "==> Installiere osquery..."
    if command -v brew &>/dev/null; then
        brew install osquery
    else
        # Direktdownload .pkg
        PKG_URL="https://pkg.osquery.io/darwin/osquery-5.13.1.pkg"
        TMP_PKG="/tmp/osquery.pkg"
        echo "    Lade osquery herunter..."
        curl -fsSL "$PKG_URL" -o "$TMP_PKG"
        sudo installer -pkg "$TMP_PKG" -target /
        rm "$TMP_PKG"
    fi
    echo "    osquery installiert: $(osqueryi --version 2>/dev/null || echo 'ok')"
else
    echo "    osquery bereits vorhanden"
fi

# 2. Python3 pruefen
if ! command -v python3 &>/dev/null; then
    echo "==> Python3 nicht gefunden."
    if command -v brew &>/dev/null; then
        brew install python3
    else
        echo "    Bitte Python3 installieren: https://python.org"
        exit 1
    fi
fi

# 3. Collector-Dateien kopieren
echo "==> Installiere Collector nach $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR" "$CONF_DIR"
cp netasset_collector.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/netasset_collector.py"

# 4. Konfiguration anlegen
if [ ! -f "$CONF_DIR/netasset_collector.conf" ]; then
    cp netasset_collector.conf.example "$CONF_DIR/netasset_collector.conf"
    echo ""
    echo "  WICHTIG: Konfiguration anpassen:"
    echo "  open -e $CONF_DIR/netasset_collector.conf"
    echo "  -> api_key eintragen (NetAsset -> Einstellungen -> API Keys)"
    echo ""
fi

# 5. LaunchAgent (stündlich) einrichten
cat > "$LAUNCH_AGENT" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.netasset.collector</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$INSTALL_DIR/netasset_collector.py</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_FILE</string>
    <key>StandardErrorPath</key>
    <string>$LOG_FILE</string>
</dict>
</plist>
EOF

# LaunchAgent laden
launchctl unload "$LAUNCH_AGENT" 2>/dev/null || true
launchctl load "$LAUNCH_AGENT"

echo ""
echo "==> Setup abgeschlossen!"
echo ""
echo "Naechste Schritte:"
echo "  1. open -e $CONF_DIR/netasset_collector.conf"
echo "  2. Testlauf: python3 $INSTALL_DIR/netasset_collector.py --dry-run"
echo "  3. Erster Upload: python3 $INSTALL_DIR/netasset_collector.py"
echo "  4. Der LaunchAgent laeuft stündlich automatisch"
echo ""
echo "Logs: tail -f $LOG_FILE"
echo "Stop: launchctl unload $LAUNCH_AGENT"
