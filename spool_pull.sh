#!/usr/bin/env bash
# DRUCKER Spool Pull – läuft auf dem Server (z. B. VPS): holt die Dateien von
# spool_collector.py per scp ab und importiert sie mit spool_import.py.
#
#   bash spool_pull.sh user@host [/var/spool/drucker]
#
# Mehrere Hosts: einfach mehrmals aufrufen. Cron-Beispiel (stündlich, :15):
#   15 * * * * drucker /opt/drucker-collectors/spool_pull.sh collect@10.8.0.5 >> /var/log/drucker-spool.log 2>&1
#
# Umgebungsvariablen:
#   SPOOL_INBOX       lokales Ziel (Default /var/lib/drucker/inbox)
#   NETASSET_URL      API des Servers (z. B. http://localhost:8000)
#   NETASSET_API_KEY  API-Key mit Schreibrecht
set -euo pipefail

SRC="${1:?Aufruf: spool_pull.sh user@host [remote_dir]}"
REMOTE_DIR="${2:-/var/spool/drucker}"
INBOX="${SPOOL_INBOX:-/var/lib/drucker/inbox}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$INBOX"
# Leeres Spool ist kein Fehler: scp meldet dann "No such file" – abfangen.
if ssh -o BatchMode=yes "$SRC" "ls $REMOTE_DIR/*.json" >/dev/null 2>&1; then
    scp -q -p -o BatchMode=yes "$SRC:$REMOTE_DIR/*.json" "$INBOX/"
else
    echo "$(date '+%F %T') $SRC: keine Spool-Dateien"
fi

python3 "$HERE/spool_import.py" "$INBOX"
