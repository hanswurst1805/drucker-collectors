# ESET PROTECT – Logs per Syslog ausleiten

ESET PROTECT (Cloud & On-Prem) kann Events **zentral per Syslog** an einen
Syslog-/SIEM-Empfänger senden. Der Export läuft server-seitig für **alle**
verwalteten Endpoints – nicht pro Client und nicht als Datei-Upload, sondern als
laufender Stream von Syslog-Nachrichten.

> **Hinweis:** Ist der Syslog-Empfänger nicht erreichbar, werden Nachrichten
> **verworfen** (keine Queue, kein Nachsenden). Der Empfänger sollte also
> hochverfügbar sein bzw. die Verbindung stabil.

---

## 1. Voraussetzungen

- Ein erreichbarer Syslog-Server (Empfänger), der
  - **UTF-8 (BOM)** kodierte Nachrichten verarbeitet,
  - TLS unterstützt (empfohlen; ESET sendet an einen „TLS-compatible syslog server"),
  - ein gewähltes Payload-Format (JSON/LEEF/CEF) parsen kann.
- Netzwerk-Erreichbarkeit vom ESET-Server zum Empfänger (Port offen).
- Konsolen-Rechte zum Ändern der Server-Einstellungen (Admin).

---

## 2. Syslog-Server aktivieren

In der ESET PROTECT Konsole:

```
More (Mehr)  →  Settings (Einstellungen)  →  Advanced Settings
              →  Syslog server  →  "Use Syslog server" / "Enable Syslog sending" einschalten
```

Dann folgende Felder ausfüllen:

| Feld | Beschreibung | Empfehlung |
|---|---|---|
| **Payload format** | Format der Nutzdaten | `JSON` (am einfachsten zu parsen), alternativ `LEEF` (QRadar) oder `CEF` |
| **Log envelope format** | Rahmenformat | `Syslog (RFC 5424)` (moderner) oder `BSD (RFC 3164)` |
| **Minimal log level** | Mindest-Schweregrad | `Information` für alles, `Warning`/`Error` zum Filtern |
| **Destination** | IPv4 / FQDN des Empfängers | z.B. `siem.kiste.org` |
| **Port** | Ziel-Port (Drop-down) | je nach Empfänger, typ. `6514` (Syslog/TLS) bzw. `514` |
| **Validate CA Root certificates** | TLS-Zertifikatsprüfung | aktivieren + PEM-Zertifikatskette einfügen (empfohlen) |

---

## 3. Export der Logs einschalten

Zusätzlich zum Syslog-Server muss der eigentliche Log-Export aktiviert werden:

```
More  →  Settings  →  Advanced Settings  →  Logging  →  "Export logs to Syslog" einschalten
```

Hier die **Event-Typen** auswählen, die gesendet werden sollen:

- Antivirus / **Detection** (Bedrohungen)
- **HIPS**
- **Firewall**
- **Web protection** (Web Access Protection)
- **Audit Log** (Konsolen-Aktionen)
- **Blocked files**
- **ESET Inspect alerts** (nur mit ESET Inspect / EDR)
- **Incidents**

> Für die NetAsset-Integration sind v.a. **Detection** (AV-Alarme) und
> **Audit Log** relevant. Web/Firewall/HIPS je nach Bedarf.

---

## 4. Grenzen & Verhalten

- **Max. Nachrichtengröße:** 8 KB. Längere Nachrichten (> 8000 Zeichen) werden
  automatisch gekürzt.
- **Keine Zwischenspeicherung:** Bei nicht erreichbarem Empfänger gehen
  Nachrichten verloren.
- **Zeichenkodierung:** UTF-8 mit BOM – Empfänger muss das verstehen.
- **Zentral:** Es exportiert der ESET-Server, nicht der einzelne Endpoint-Agent.

---

## 5. Quick-Test des Empfängers

Vor der ESET-Konfiguration lässt sich ein einfacher Listener zum Mitlesen starten.

**TCP (Klartext, zum schnellen Sichtprüfen – nicht für Produktion):**
```bash
# lauscht auf Port 514/tcp und gibt eingehende Syslog-Zeilen aus
nc -lk 514
```

**TLS (näher an der echten ESET-Verbindung):**
```bash
# Selbstsigniertes Zertifikat (nur zum Test)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout syslog-test.key -out syslog-test.crt -days 30 -subj "/CN=siem.kiste.org"

# TLS-Listener auf 6514, zeigt eingehende Nachrichten
openssl s_server -accept 6514 -cert syslog-test.crt -key syslog-test.key -quiet
```

In ESET dann `Destination = <test-host>`, `Port = 6514`, TLS aktiv. Mit dem
Test-Zertifikat ggf. „Validate CA Root certificates" aus lassen oder die
`syslog-test.crt` als Kette einfügen.

Eine eingehende JSON-Detection-Nachricht sieht (gekürzt) etwa so aus:
```
<134>1 2026-06-15T10:12:33Z eset-protect ... {"event_type":"Threat_Event",
"hostname":"PC-01","threat_name":"EICAR-Test-File","action":"cleaned", ...}
```

---

## Quellen

- [Export logs to Syslog – ESET PROTECT (Cloud)](https://help.eset.com/protect_cloud/en-US/admin_server_settings_export_to_syslog.html)
- [Syslog server – ESET PROTECT (Cloud)](https://help.eset.com/protect_cloud/en-US/admin_server_settings_syslog.html)
- [Syslog security restrictions and limits – ESET PROTECT](https://help.eset.com/protect_cloud/en-US/syslogexportsettingsconstraints.html)
- [KB8022 – Export logs to Syslog server from ESET PROTECT](https://support.eset.com/en/kb8022-export-logs-to-syslog-server-from-eset-protect)
