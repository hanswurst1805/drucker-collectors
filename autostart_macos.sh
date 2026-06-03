#!/usr/bin/env bash
# DRUCKER Collector – macOS Autostart via LaunchAgent
#
# Richtet einen LaunchAgent ein der:
#   - Beim Login automatisch startet
#   - Stündlich wiederholt
#   - Im Hintergrund läuft
#
# Aufruf (als normaler User, NICHT root):
#   bash autostart_macos.sh

set -euo pipefail

INSTALL_DIR="$HOME/Library/NetAsset/Collector"
CONF_DIR="$HOME/Library/NetAsset"
LOG_FILE="$HOME/Library/Logs/drucker-collector.log"
PLIST="$HOME/Library/LaunchAgents/org.drucker.collector.plist"
LABEL="org.drucker.collector"

echo "==> DRUCKER Collector – macOS Autostart Setup"

# Python prüfen
PYTHON=$(which python3 || echo "")
if [ -z "$PYTHON" ]; then
    echo "FEHLER: python3 nicht gefunden. Bitte installieren: https://python.org"
    exit 1
fi

# Collector prüfen
if [ ! -f "$INSTALL_DIR/netasset_collector.py" ]; then
    echo "FEHLER: Collector nicht gefunden: $INSTALL_DIR/netasset_collector.py"
    echo "Bitte zuerst install_macos.sh ausführen"
    exit 1
fi

# Config prüfen
if [ ! -f "$CONF_DIR/netasset_collector.conf" ]; then
    echo "FEHLER: Config nicht gefunden: $CONF_DIR/netasset_collector.conf"
    exit 1
fi

# LaunchAgent anlegen
mkdir -p "$HOME/Library/LaunchAgents"
mkdir -p "$HOME/Library/Logs"

cat > "$PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON}</string>
        <string>${INSTALL_DIR}/netasset_collector.py</string>
    </array>

    <!-- Stündlich ausführen -->
    <key>StartInterval</key>
    <integer>3600</integer>

    <!-- Direkt beim Login starten -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Logs -->
    <key>StandardOutPath</key>
    <string>${LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>${LOG_FILE}</string>

    <!-- Bei Absturz neu starten -->
    <key>KeepAlive</key>
    <false/>

    <!-- Nur wenn Netzwerk vorhanden -->
    <key>NetworkState</key>
    <true/>
</dict>
</plist>
EOF

# LaunchAgent laden
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"

echo ""
echo "==> Autostart eingerichtet!"
echo ""
echo "Befehle:"
echo "  Jetzt ausführen:  launchctl start $LABEL"
echo "  Stoppen:          launchctl stop $LABEL"
echo "  Deaktivieren:     launchctl unload $PLIST"
echo "  Logs:             tail -f $LOG_FILE"
echo ""
echo "Der Collector startet automatisch beim nächsten Login."
