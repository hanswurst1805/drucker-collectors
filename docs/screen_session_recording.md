# Aufgezeichnete Sessions mit `screen`

Bei einem interaktiven SSH-Login landet der User automatisch in einer
`screen`-Session, die das komplette Terminal in eine lokale Logdatei schreibt.
**Nach dem Logout** wird die Aufzeichnung automatisch an NetAsset hochgeladen
(`POST /api/v1/sessions/ingest`) und erscheint dort unter „Audit-Sessions".
Die Logdatei bleibt zusätzlich lokal erhalten.

## Ablauf aus Anwendersicht (so ist es gebaut)

1. **Ganz normal einloggen** – nichts Besonderes zu tun:
   ```bash
   ssh wartung@zielhost
   ```
2. Du landest **automatisch in einer aufgezeichneten `screen`-Session**
   (Hinweis im Terminal: `[na-screen] Session wird aufgezeichnet: …`).
   Ab hier arbeitest du wie gewohnt – alles, was du tust, wird mitgeschnitten.
3. **screen bequem nutzen** (optional):
   - Abdocken ohne zu beenden: `Ctrl-A` dann `d` (Session läuft im Hintergrund weiter)
   - Wieder andocken nach erneutem Login: `screen -r`
   - Mehrere Fenster: `Ctrl-A` dann `c` (neu), `Ctrl-A` dann `n`/`p` (wechseln)
4. **Beenden** mit `exit` (bzw. `Ctrl-D`). Beim Verlassen der screen-Session
   wird die Aufzeichnung **automatisch an NetAsset übertragen** und ist dort
   unter „Audit-Sessions" sowie am betroffenen Host einsehbar.

> Wichtig: Sauber per `exit` beenden. Nur **abdocken** (`Ctrl-A d`) lädt zwar das
> bisherige Log hoch, lässt die Session aber im Hintergrund weiterlaufen –
> beim nächsten `screen -r` arbeitest du in derselben Aufzeichnung weiter.

## 1. Skripte installieren

```bash
sudo cp na_screen_rec.sh /usr/local/bin/na-screen-rec
sudo chmod +x /usr/local/bin/na-screen-rec
# Uploader bleibt im Checkout (/opt/drucker-collectors) – wird automatisch gefunden.

# Voraussetzung: screen + python3
sudo apt install screen   # bzw. yum/dnf install screen

# Log-Verzeichnis anlegen (für den/die aufzuzeichnenden User schreibbar)
sudo mkdir -p /var/log/screen-sessions
sudo chmod 1733 /var/log/screen-sessions   # jeder darf schreiben, nicht lesen/löschen fremder Logs
```

**Upload-Zugangsdaten:** Der Uploader nutzt `api_url`/`api_key` aus der
vorhandenen `netasset_collector.conf` (also denselben Key wie der reguläre
Collector). Läuft auf dem Zielserver kein Collector, eine `netasset_collector.conf`
mit `[netasset] api_url=… api_key=…` unter `/etc/netasset/` anlegen.

> Ohne Schreibrecht auf `/var/log/screen-sessions` weicht das Skript auf das
> Home-Verzeichnis des Users aus. Anderes Verzeichnis: `NA_SCREEN_LOGDIR` setzen.

## 2. Automatisch beim Login starten

**Pro User** (empfohlen, am wenigsten invasiv) – in die `~/.bash_profile`
des betreffenden Users:

```bash
# Nur bei interaktivem SSH-Login, nicht wenn bereits in screen
if [ -z "$STY" ] && [ -t 0 ] && [ -n "$SSH_CONNECTION" ]; then
    exec na-screen-rec
fi
```

**Für alle User** alternativ als `/etc/profile.d/na-screen.sh` (gleicher
Inhalt). Achtung: betrifft dann auch root-Logins.

## 3. Erzwingen (optional, strenger)

Soll der User die Aufzeichnung nicht per Editieren seiner `~/.bash_profile`
umgehen können, stattdessen in `/etc/ssh/sshd_config`:

```
Match User <user>
    ForceCommand /usr/local/bin/na-screen-rec
```
dann `sudo systemctl reload sshd`. Das Skript behandelt `scp`/`sftp` und
Remote-Kommandos (kein TTY) korrekt und zeichnet nur interaktive Logins auf.

## 4. Verhalten / Hinweise

- **Logdatei** je Session: `/var/log/screen-sessions/<user>-<datum>-<pid>.log`
- **`logtstamp on`** schreibt periodisch Zeitstempel ins Log.
- Verschachtelung wird vermieden (`$STY`-Prüfung): in einer screen-Session
  startet keine zweite.
- Das Log enthält den rohen Terminal-Stream (inkl. Steuerzeichen). Zum sauberen
  Mitlesen z.B. `cat -v <log>` oder `sed 's/\x1b\[[0-9;]*[A-Za-z]//g' <log>`; im
  NetAsset-Frontend werden Steuerzeichen für die Anzeige entfernt.
- **Detach** (`Ctrl-A d`) statt Logout: die SSH-Verbindung schließt und es wird
  das bis dahin geschriebene Log hochgeladen; die screen-Session läuft im
  Hintergrund weiter. Sauberer Abschluss daher per `exit`/`logout`.
- Upload ist best effort: ist NetAsset nicht erreichbar, bleibt nur die lokale
  Logdatei (kein Retry).
- Voll integrierte Alternative mit zielseitiger Kommandoliste:
  Jumpbox-Variante (siehe [jumpbox_session_recording.md](jumpbox_session_recording.md)).
