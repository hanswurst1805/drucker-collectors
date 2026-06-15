#!/bin/sh
# NetAsset – aufgezeichnete screen-Session beim Login.
#
# Startet bei einem interaktiven SSH-Login automatisch eine screen-Session,
# die das komplette Terminal in eine lokale Logdatei schreibt. Nach dem Logout
# wird die Aufzeichnung an NetAsset hochgeladen (POST /api/v1/sessions/ingest)
# und erscheint dort unter "Audit-Sessions".
# Installation/Einbindung: siehe docs/screen_session_recording.md
#
# Logdatei:  $NA_SCREEN_LOGDIR/<user>-<datum>-<pid>.log
#            (Default-Verzeichnis: /var/log/screen-sessions, sonst $HOME)

# Schon in einer screen-Session? -> normale Shell, keine Verschachtelung.
[ -n "$STY" ] && exec "${SHELL:-/bin/bash}"

# Kein interaktives TTY (scp/sftp/Remote-Kommando) -> nicht aufzeichnen.
if [ ! -t 0 ]; then
    if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
        exec "${SHELL:-/bin/bash}" -c "$SSH_ORIGINAL_COMMAND"
    fi
    exec "${SHELL:-/bin/bash}"
fi

# screen vorhanden?
if ! command -v screen >/dev/null 2>&1; then
    echo "WARN: 'screen' nicht installiert – Session wird NICHT aufgezeichnet." >&2
    exec "${SHELL:-/bin/bash}"
fi

LOGDIR="${NA_SCREEN_LOGDIR:-/var/log/screen-sessions}"
mkdir -p "$LOGDIR" 2>/dev/null || LOGDIR="$HOME"
USER_NAME="${USER:-$(id -un)}"
TS="$(date +%Y%m%d-%H%M%S)"
LOGFILE="$LOGDIR/${USER_NAME}-${TS}-$$.log"

SESSION_UUID="$(tr -d '-' < /proc/sys/kernel/random/uuid 2>/dev/null)"
[ -n "$SESSION_UUID" ] || SESSION_UUID="$(date +%s)$$"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Logging über ein temporäres screenrc setzen (kompatibel auch mit älteren
# screen-Versionen ohne -Logfile-Flag).
RC="$(mktemp /tmp/na-screenrc.XXXXXX)"
cat > "$RC" <<EOF
logfile $LOGFILE
logfile flush 1
logtstamp on
deflog on
EOF

echo "[na-screen] Session wird aufgezeichnet: $LOGFILE"
# Bewusst KEIN exec: nach Session-Ende folgt der Upload.
screen -c "$RC" -S "rec-${TS}" /bin/bash
RC_CODE=$?
rm -f "$RC"
ENDED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Upload an NetAsset (best effort – Logdatei bleibt lokal erhalten).
UPLOADER="/opt/drucker-collectors/na_screen_upload.py"
[ -f "$UPLOADER" ] || UPLOADER="$HOME/drucker-collectors/na_screen_upload.py"
[ -f "$UPLOADER" ] || UPLOADER="/usr/local/bin/na_screen_upload.py"
if [ -f "$UPLOADER" ] && command -v python3 >/dev/null 2>&1; then
    python3 "$UPLOADER" \
        --session "$SESSION_UUID" --host "$(hostname)" --user "$USER_NAME" \
        --logfile "$LOGFILE" --started "$STARTED" --ended "$ENDED" \
        --exit "$RC_CODE" || true
fi

exit "$RC_CODE"
