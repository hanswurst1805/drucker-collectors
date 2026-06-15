# NetAsset Kommando-Logging für Jumpbox-Sessions
# Liegt im drucker-collectors Checkout (z.B. /opt/drucker-collectors) und wird
# über einen kleinen Stub in /etc/profile.d eingebunden (siehe docs), damit
# "git pull" die laufende Version aktualisiert.
#
# Aktiviert sich NUR, wenn die Session über die Jumpbox kam (NA_SESSION_ID
# gesetzt; via sshd "AcceptEnv NA_SESSION_ID" + na-jump SetEnv). Protokolliert
# jedes ausgeführte Kommando und lädt die Liste beim Logout an NetAsset hoch
# (POST /api/v1/sessions/<uuid>/commands). Korreliert dort mit der
# Jumpbox-Aufzeichnung über dieselbe NA_SESSION_ID.

# Nur interaktive Bash-Sessions mit gesetzter Session-ID
case "$-" in *i*) ;; *) return 2>/dev/null || true ;; esac
[ -n "$NA_SESSION_ID" ] || return 2>/dev/null || true
[ -n "$BASH_VERSION" ] || return 2>/dev/null || true

__NA_CMDLOG_FILE="$(mktemp /tmp/na-cmdlog.XXXXXX 2>/dev/null)" || return
__NA_CMD_SEQ=0
# Uploader aus dem drucker-collectors Checkout (mit Fallbacks)
__NA_UPLOADER="/opt/drucker-collectors/na_cmdlog_upload.py"
[ -f "$__NA_UPLOADER" ] || __NA_UPLOADER="$HOME/drucker-collectors/na_cmdlog_upload.py"
[ -f "$__NA_UPLOADER" ] || __NA_UPLOADER="/etc/netasset/na_cmdlog_upload.py"

__na_log_cmd() {
    local rc=$?
    local last
    # Letztes History-Kommando ohne führende Nummer
    last=$(HISTTIMEFORMAT='' history 1 2>/dev/null | sed 's/^ *[0-9]\+ *//')
    [ -n "$last" ] || return $rc
    # Duplikate (gleicher Prompt ohne neues Kommando) überspringen
    [ "$last" = "$__NA_LAST_CMD" ] && return $rc
    __NA_LAST_CMD="$last"
    __NA_CMD_SEQ=$((__NA_CMD_SEQ + 1))
    # TSV: seq \t ISO-Zeit \t cwd \t base64(command)  (base64 schützt vor Tabs/Newlines)
    printf '%s\t%s\t%s\t%s\n' \
        "$__NA_CMD_SEQ" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$PWD" \
        "$(printf '%s' "$last" | base64 | tr -d '\n')" \
        >> "$__NA_CMDLOG_FILE" 2>/dev/null
    return $rc
}

PROMPT_COMMAND="__na_log_cmd${PROMPT_COMMAND:+; $PROMPT_COMMAND}"

__na_cmdlog_flush() {
    [ -s "$__NA_CMDLOG_FILE" ] || { rm -f "$__NA_CMDLOG_FILE"; return; }
    if [ -f "$__NA_UPLOADER" ]; then
        python3 "$__NA_UPLOADER" \
            --session "$NA_SESSION_ID" \
            --host "$(hostname)" \
            --user "$(id -un)" \
            --file "$__NA_CMDLOG_FILE" >/dev/null 2>&1 || true
    fi
    rm -f "$__NA_CMDLOG_FILE"
}
trap __na_cmdlog_flush EXIT
