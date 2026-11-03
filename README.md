# Sitewatch · Berendsohn

Deploybarer Projektstand für 820 Domains aus `urls.txt`. Stand: vorbereitet, **nicht live geschaltet** und nicht gegen die echten Webseiten oder SMTP getestet.

## Architektur

- Render Web Service (Docker): geschütztes Dashboard und API, serverseitige Seitennavigation, Anlegen/Import/Löschen.
- Render Postgres: persistente Sites, letzter Messwert, maximal 30 Verlaufspunkte im UI, persistente Alarm-Outbox.
- Render Cron Job (`*/5 * * * *`, UTC): bis zu 40 parallele Prüfungen. Render lässt pro Cron-Service nur einen Lauf gleichzeitig zu.
- Prüft A-Records (Anzeige; keine IP-Änderungsalarme), finalen HTTP-Status 200–299 nach bis zu 5 Weiterleitungen, `robots`/`googlebot`-Meta-Tag und `X-Robots-Tag: noindex`, TLS-Ablauf (0 Tage kritisch, <=14 Tage Warnung), Antwortzeit (>2000 ms Warnung). HTTP-/DNS-/TLS-Fehler sind kritisch. Nur die Startseite wird geprüft; nackte Domains werden als HTTPS interpretiert. Ausnahmen können explizit als `http://...` importiert werden.
- Nur beim Übergang von OK/ausstehend nach Warnung/Kritisch oder bei Eskalation Warnung → Kritisch wird ein Mail-Ereignis angelegt. Kritisch → Warnung und Wiederherstellung senden **keine** Mail. Wiederholte Fehler erzeugen keine neue Nachricht.
- Checks verfolgen Redirects, begrenzen Ports auf 80/443, prüfen jede Ziel-IP auf öffentliche Adressen und verbinden sich mit genau dieser IP (Schutz gegen DNS-Rebinding). Keine Login-Daten in Prüf-URLs.

## Inbetriebnahme

1. Code in ein **privates Git-Repository** legen und mit Render verbinden. Im Render Dashboard einen Blueprint aus der `render.yaml` im Repo anlegen. Prüfen, ob die vorgeschlagenen kostenpflichtigen Pläne (`starter`, `basic-256mb`) in der gewählten Region verfügbar sind; Kosten vor Bestätigung prüfen. Render Blueprint: https://render.com/docs/infrastructure-as-code
2. Vor dem Deploy `ADMIN_PASSWORD_HASH` generieren: auf einem vertrauenswürdigen Rechner mit Python 3.12 `python make_password_hash.py` ausführen; Passwort nur lokal eingeben. Hash als Secret in Render eintragen. Login-Benutzer ist `admin` (änderbar über `ADMIN_USER`). HTTP Basic ist für den einzelnen Nutzer vorgesehen; nur über HTTPS verwenden. Die öffentlich erreichbare `onrender.com`-Subdomain nach Einrichten der Custom Domain ggf. deaktivieren.
3. Das SMTP-Passwort **ausschließlich** als `SMTP_PASSWORD`-Secret im Cron-Service hinterlegen. Host, Port 587, STARTTLS, Benutzer/Absender und Empfänger sind in `render.yaml` vorkonfiguriert. Mit dem Mailanbieter prüfen, ob `do-not-reply@berendsohn-digital.de` als Absender erlaubt ist und SMTP aus Render erreichbar ist.
4. `EMAIL_ENABLED=false` beim ersten Scan beibehalten. Der initiale Import erfolgt einmalig aus `urls.txt` und wird bei Neustarts nicht erneut angelegt. Domains sind als `https://` importiert; zunächst Problemfälle prüfen (z. B. HTTP-only Sites, Server blockieren Bots). Während `EMAIL_ENABLED=false` werden **keine Alarm-Ereignisse angelegt**, damit beim Aktivieren keine Altlasten als Mail-Flut verschickt werden.
5. Web-Service in Render unter **Settings → Custom Domains** mit `monitoring.berendsohn.com` verbinden, DNS-Eintrag nach Render-Anzeige setzen und Domain verifizieren. Render kümmert sich um HTTPS. https://render.com/docs/custom-domains
6. Sobald Qualität und SMTP-Test mit einer neuen, kontrollierten Auffälligkeit bestätigt sind: `EMAIL_ENABLED=true` im Cron-Service setzen. Künftige Statuswechsel lösen sofort bei dieser Prüfung genau ein Mail-Ereignis aus; SMTP-Fehler bleiben in der Outbox und werden beim nächsten Lauf erneut versucht. Bei Sendung und Absturz vor Datenbank-Commit ist ausnahmsweise ein Doppelversand möglich.
7. Betrieb: Render-Logs und Run-History des Cron-Jobs prüfen, Datenbank-Backups und Kosten/Region verifizieren. Die DB speichert alle Checks ohne automatische Bereinigung; für langfristigen Betrieb Retention/Archivierung ergänzen. Einen externen Heartbeat für ausgefallene Cron-Läufe empfehlen wir zusätzlich.

**Noch benötigt:** Zugang zur Render-Umgebung und DNS-Verwaltung (oder jemand, der die Schritte ausführt), ein selbst gesetztes Admin-Passwort als Hash und das SMTP-Passwort als Render-Secret. Zugangsdaten niemals im Chat oder Repo teilen.

## Lokale Tests / Einschränkungen

`python -m unittest discover -s tests` prüft die netzwerkfreien Komponenten. Docker-Build, PostgreSQL-Integration, tatsächliche Webseiten, SMTP-STARTTLS und Render-Deployment sind in dieser Offline-Umgebung **nicht** ausgeführt worden. Vor Produktivfreigabe sind ein Testdeploy und End-to-End-Prüfungen nötig. `urls.txt` enthält 820 unterschiedliche Domains (nach Normalisierung). Die Anmeldung via Basic Auth bietet keine separate Login-Seite oder 2FA; für strengere Zugangsanforderungen einen vorgeschalteten SSO-/Access-Proxy vorsehen.
