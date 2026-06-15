# Jumpbox SSH-Session-Aufzeichnung

Aufgezeichnete SSH-Sessions über eine Jumpbox (Bastion) zu Zielhosts.
Zwei Quellen, korreliert über eine **Session-UUID**:

- **Jumpbox** (`na_jump.py`): zeichnet die komplette Terminal-Session per
  `script` auf und lädt sie nach dem Logout an NetAsset.
- **Zielhost** (`na_cmdlog.sh` + `na_cmdlog_upload.py`): protokolliert die
  tatsächlich ausgeführten Kommandos und lädt sie an NetAsset.

In NetAsset werden beide über `NA_SESSION_ID` zusammengeführt und – sofern der
Zielhost als Asset bekannt ist – mit dem Asset verknüpft.

```
[Operator] --ssh--> [Jumpbox: na-jump] --ssh (SetEnv NA_SESSION_ID)--> [Zielhost: profile.d-Hook]
                          │                                                   │
                  script-Aufzeichnung                                Kommando-Liste
                          └──────────── POST /api/v1/sessions/* ──────────────┘
```

---

## 1. NetAsset-Seite

Ein API-Key mit Schreibrecht anlegen (NetAsset → Einstellungen → API Keys).
Die Audit-Endpunkte:

- `POST /api/v1/sessions/ingest` – Jumpbox-Aufzeichnung
- `POST /api/v1/sessions/{uuid}/commands` – Zielseitige Kommandos
- `GET /api/v1/sessions` / `GET /api/v1/sessions/{id}` – Anzeige im Frontend

---

## 2. Jumpbox einrichten

```bash
# Voraussetzung: util-linux ("script") + python3
sudo cp na_jump.py /usr/local/bin/na-jump
sudo chmod +x /usr/local/bin/na-jump
sudo mkdir -p /etc/netasset
sudo cp na_jump.conf.example /etc/netasset/na_jump.conf
sudoedit /etc/netasset/na_jump.conf   # api_url, api_key (+ optional allow_targets)
```

Test:
```bash
na-jump web01.intern
# ... interaktive SSH-Session, nach Logout: "Aufzeichnung übertragen."
```

### Optional: erzwingen (ForceCommand)

Damit Operatoren **ausschließlich** über die Aufzeichnung verbinden können,
einen eigenen Login ohne freie Shell einrichten. In `/etc/ssh/sshd_config`:

```
Match User jumpuser
    ForceCommand /usr/local/bin/na-jump
    PermitTTY yes
    X11Forwarding no
    AllowTcpForwarding no
```

Der Operator ruft dann `ssh jumpuser@jumpbox <ziel>` – `<ziel>` landet via
`SSH_ORIGINAL_COMMAND` automatisch in `na-jump`. Ziele lassen sich über
`allow_targets` in der Config einschränken.

---

## 3. Zielhosts einrichten

Voraussetzung: Der Zielhost läuft bereits mit dem `netasset_collector`
(d.h. `/etc/netasset/netasset_collector.conf` mit `api_url`/`api_key` vorhanden) –
diese Zugangsdaten werden wiederverwendet, ein eigener Key ist nicht nötig.

```bash
# Kommando-Hook + Uploader installieren
sudo cp na_cmdlog.sh /etc/profile.d/na_cmdlog.sh
sudo cp na_cmdlog_upload.py /etc/netasset/na_cmdlog_upload.py
sudo chmod +x /etc/netasset/na_cmdlog_upload.py
```

Damit die Session-UUID von der Jumpbox ankommt, muss der sshd des Zielhosts
die Variable akzeptieren – in `/etc/ssh/sshd_config`:

```
AcceptEnv NA_SESSION_ID
```
danach `sudo systemctl reload sshd`.

> Der Hook aktiviert sich **nur**, wenn `NA_SESSION_ID` gesetzt ist (also die
> Verbindung über die Jumpbox kam). Direkte Logins werden nicht protokolliert.
> Es werden nur **Bash**-Sessions erfasst.

---

## 4. Funktionsweise / Grenzen

- **Volle Aufzeichnung** (Jumpbox): Ein-/Ausgaben der gesamten Terminal-Session,
  per `scriptreplay` bzw. im NetAsset-Frontend abspielbar.
- **Kommandoliste** (Ziel): saubere, durchsuchbare Liste der ausgeführten Befehle
  inkl. Zeitstempel, Arbeitsverzeichnis und OS-User.
- **Korrelation:** Beide Uploads teilen sich `NA_SESSION_ID`; egal welcher zuerst
  eintrifft, die Session in NetAsset wird angelegt bzw. ergänzt (upsert).
- **Grenzen:** Nur Bash auf dem Ziel; Aufzeichnung max. 10 MB (Server-Limit);
  bei nicht erreichbarem NetAsset geht der Upload verloren (kein Retry).
  Die Kommando-Extraktion umgeht `script`-Heuristik, indem sie zielseitig per
  Shell-Hook erfolgt – zuverlässiger als das Parsen des Terminal-Streams.
