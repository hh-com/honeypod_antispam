# Honeypod Antispam

PrestaShop module that protects the native contact form against automated spam bots — no CAPTCHA, no external service, no impact on real visitors.

**Languages / Sprachen:** [English](#english) | [Deutsch](#deutsch)

---

## English

### Description

Honeypod Antispam protects PrestaShop's built-in contact form (`ContactController` / `submitMessage`) against automated bot submissions using four independent, cumulative layers of defense. If **any** layer flags a submission, it is discarded silently before the core contact form module processes it — no error is shown and no confirmation e-mail is sent, so the bot gets no feedback that it was blocked.

1. **Honeypot fields** — three additional text fields (names configurable in the back office, with sensible defaults) that are hidden from real visitors via CSS but are still present in the HTML and get filled in by unsophisticated bots. The module also evaluates PrestaShop's own native honeypot field (`url`), which many themes already render in `contactform.tpl`.
2. **Timing check** — a hidden field carries a signed (HMAC-SHA256, using the shop's `_COOKIE_KEY_`) timestamp of when the form was rendered. Submissions that arrive faster than a configurable minimum fill time are treated as automated.
3. **Content heuristics** — messages containing an excessive number of `http(s)://` links, or any of the (empty by default) blocklist keywords configured in the back office, are treated as spam.
4. **Rate limiting** — a configurable maximum number of contact form submissions per IP address within a configurable time window.

Every attempt (allowed and blocked) is logged to a dedicated database table for statistics and rate-limiting purposes; entries older than 30 days are pruned automatically (no cron job required).

### Compatibility

| Requirement | Version |
|---|---|
| PrestaShop | 1.7.0.0 and later (1.7.x, 8.x, 9.x) |
| PHP | 7.1+ (whatever the target PrestaShop version requires) |
| Database | MySQL / MariaDB (uses `Db`, no raw `mysqli`/`PDO`) |

The module only uses APIs that have been stable since PrestaShop 1.7 (`Configuration`, `Tools`, `HelperForm`, `Db`, `Hook`), so no version-specific branching is required.

> **Important:** the module hooks the honeypot fields and the timing token into the `displayGDPRConsent` hook call inside `contactform.tpl` of the currently active theme. This is the reliable insertion point *for the theme this module was built for*. If you switch to a different theme, verify that its `contactform.tpl` (or the contact page template) still calls `displayGDPRConsent` **inside** the `<form>` tag — otherwise the honeypot fields and timing token will never be rendered, and legitimate submissions will be blocked by the timing check (since a missing token is treated as suspicious "fail closed").

### Installation

**Via ZIP upload (recommended):**
1. Zip the module folder so that `honeypod_antispam.php` is at the root of the archive inside a `honeypod_antispam/` folder (i.e. `honeypod_antispam.zip` → `honeypod_antispam/honeypod_antispam.php`).
2. Back office → **Modules → Module Manager → Upload a module**.
3. Select the ZIP file and confirm.
4. The module installs and activates automatically.

**Manual installation:**
1. Copy the `honeypod_antispam/` folder into `<shop-root>/modules/`.
2. Back office → **Modules → Module Manager**, search for "Honeypot Antispam", click **Install**.

Installation automatically:
- registers the hooks `displayGDPRConsent`, `actionDispatcherBefore`, `actionFrontControllerInitBefore`;
- creates the `PREFIX_honeypod_antispam_attempt` table for rate-limiting/statistics;
- sets all configuration values to their defaults (spam protection **enabled**).

Uninstalling the module removes all its configuration keys and drops the attempt table; the hooks are automatically unregistered by the PrestaShop core.

### Configuration

Back office → **Modules → Module Manager → Honeypot Antispam (Kontaktformular) → Configure**:

| Setting | Description | Default |
|---|---|---|
| Spam protection active | Master on/off switch, without uninstalling the module | On |
| Honeypot field name 1–3 | Field names, letters/digits/`_`/`-` only, must not collide with core/module field names, must be unique | `website`, `phone`, `company` |
| Minimum fill time (seconds) | Submissions faster than this are blocked | 4 |
| Max. links in message | Messages with at least this many `http(s)` links are blocked | 3 |
| Blocklist keywords | One keyword per line; empty by default so nothing is blocked until you've observed real spam patterns | *(empty)* |
| Max. requests per IP address | Rate limit ceiling | 10 |
| Rate limit time window (seconds) | Rate limit window | 3600 (1 hour) |

The configuration page also shows total blocked attempts plus a breakdown of the last 7 days by block reason (honeypot / timing / content / rate limit), so effectiveness can be monitored over time.

### Hooks & Technical Details

| Hook | Purpose |
|---|---|
| `displayGDPRConsent` | Renders the hidden honeypot fields and the signed timing token inside the contact form. |
| `actionDispatcherBefore` | Earliest reliable interception point, before front controller routing. |
| `actionFrontControllerInitBefore` | Secondary interception point (redundant by design, guarded against double execution) to reliably run before the contact form module processes the request regardless of PrestaShop version. |

**Security mechanisms already built in:**
- SQL: all dynamic query parts are cast to `(int)` or escaped with `pSQL()`; table/column names are fixed constants, never user input.
- Timing token: signed with `hash_hmac('sha256', ...)` and verified with the timing-safe `hash_equals()` — not vulnerable to timing attacks or trivial forgery.
- Output: all dynamic values reaching Smarty templates are explicitly escaped (`|escape:'html':'UTF-8'`), in addition to being restricted to a safe character set server-side before they are ever stored.
- Admin form: field names are validated against `^[a-zA-Z_][a-zA-Z0-9_\-]{1,32}$` and against a reserved-name list before being saved; any submitted value is HTML-escaped before being echoed back in a validation error message.
- CSRF: the configuration form is served and processed exclusively through PrestaShop's `AdminModules` controller, which already enforces the framework's admin token check.
- Privacy: only the IP address, timestamp, block flag and block reason are stored (no message content, no visitor identity); records older than 30 days are purged automatically.

**Known limitations (by design, not defects):**
- The timing token is stateless (not bound to a session or single use). A scripted bot that first fetches the page, waits out the minimum fill time, then submits could defeat the timing check alone — this is why the module layers content heuristics and rate limiting on top rather than relying on timing alone.
- If the active theme never renders the `displayGDPRConsent` hook inside the contact form's `<form>` tag, the module cannot inject its fields/token and — because a missing/invalid token is treated as suspicious — will end up blocking all contact form submissions. Always verify this after a theme change (see Compatibility section above).
- Rate limiting is per client IP address as reported by `Tools::getRemoteAddr()`. Behind a reverse proxy/CDN, make sure PrestaShop's trusted-proxy/`X-Forwarded-For` handling is configured correctly, otherwise all visitors may share one IP (rate limiting becomes ineffective or overly aggressive for everyone).

### License

Proprietary module developed by Harald Huber ([www.harald-huber.com](https://www.harald-huber.com)) — all rights reserved, not intended for redistribution.

---

## Deutsch

### Beschreibung

Honeypod Antispam schützt das native PrestaShop-Kontaktformular (`ContactController` / `submitMessage`) vor automatisierten Bot-Anfragen mittels vier unabhängiger, sich ergänzender Schutzschichten. Schlägt **eine** dieser Schichten an, wird die Anfrage stillschweigend verworfen, bevor das Kern-Kontaktformular sie verarbeitet — es erscheint keine Fehlermeldung und es wird keine Bestätigungs-Mail versendet, der Bot erhält also keinerlei Rückmeldung über die Blockierung.

1. **Honeypot-Felder** — drei zusätzliche Texteingabefelder (Feldnamen im Backend konfigurierbar, mit sinnvollen Standardwerten), die für echte Besucher per CSS unsichtbar sind, im HTML aber vorhanden bleiben und von einfachen Bots trotzdem ausgefüllt werden. Zusätzlich wird das bereits im Theme vorhandene, native PrestaShop-Honeypot-Feld (`url`) mit ausgewertet.
2. **Zeitprüfung** — ein verstecktes Feld enthält einen signierten (HMAC-SHA256, mit dem shopeigenen `_COOKIE_KEY_`) Zeitstempel des Formular-Renderzeitpunkts. Anfragen, die schneller als eine konfigurierbare Mindestzeit eintreffen, gelten als automatisiert.
3. **Inhalts-Heuristik** — Nachrichten mit auffällig vielen `http(s)://`-Links oder mit einem der (standardmäßig leeren) im Backend hinterlegten Sperrbegriffe gelten als Spam.
4. **Rate-Limiting** — eine konfigurierbare Höchstzahl an Kontaktformular-Anfragen pro IP-Adresse innerhalb eines konfigurierbaren Zeitfensters.

Jeder Versuch (erlaubt wie blockiert) wird in einer eigenen Datenbanktabelle protokolliert, für Statistik und Rate-Limiting; Einträge älter als 30 Tage werden automatisch bereinigt (kein Cronjob nötig).

### Kompatibilität

| Anforderung | Version |
|---|---|
| PrestaShop | ab 1.7.0.0 (1.7.x, 8.x, 9.x) |
| PHP | ab 7.1 (je nach Anforderung der jeweiligen PrestaShop-Version) |
| Datenbank | MySQL / MariaDB (nutzt `Db`, kein rohes `mysqli`/`PDO`) |

Das Modul verwendet ausschließlich APIs, die seit PrestaShop 1.7 stabil sind (`Configuration`, `Tools`, `HelperForm`, `Db`, `Hook`) — es ist keine versionsabhängige Fallunterscheidung nötig.

> **Wichtig:** Die Honeypot-Felder und das Zeit-Token werden über den Hook `displayGDPRConsent` innerhalb von `contactform.tpl` des aktuell aktiven Themes eingehängt. Das ist der zuverlässige Einhängepunkt *für das Theme, für das dieses Modul gebaut wurde*. Bei einem Theme-Wechsel unbedingt prüfen, ob dessen `contactform.tpl` (bzw. das Kontaktseiten-Template) `displayGDPRConsent` weiterhin **innerhalb** des `<form>`-Tags aufruft — andernfalls werden Honeypot-Felder und Zeit-Token nie gerendert, und echte Anfragen werden durch die Zeitprüfung blockiert (ein fehlendes Token gilt als verdächtig, "fail closed").

### Installation

**Per ZIP-Upload (empfohlen):**
1. Modulordner so zippen, dass `honeypod_antispam.php` innerhalb eines Ordners `honeypod_antispam/` im Archiv liegt (also `honeypod_antispam.zip` → `honeypod_antispam/honeypod_antispam.php`).
2. Backoffice → **Module → Modul-Manager → Ein Modul hochladen**.
3. ZIP-Datei auswählen und bestätigen.
4. Das Modul wird automatisch installiert und aktiviert.

**Manuelle Installation:**
1. Ordner `honeypod_antispam/` nach `<Shop-Wurzelverzeichnis>/modules/` kopieren.
2. Backoffice → **Module → Modul-Manager**, nach "Honeypot Antispam" suchen, auf **Installieren** klicken.

Bei der Installation werden automatisch:
- die Hooks `displayGDPRConsent`, `actionDispatcherBefore`, `actionFrontControllerInitBefore` registriert;
- die Tabelle `PREFIX_honeypod_antispam_attempt` für Rate-Limiting/Statistik angelegt;
- alle Konfigurationswerte auf ihre Standardwerte gesetzt (Spamschutz **aktiv**).

Bei der Deinstallation werden alle Konfigurationswerte sowie die Protokolltabelle entfernt; die Hooks werden automatisch durch den PrestaShop-Kern deregistriert.

### Konfiguration

Backoffice → **Module → Modul-Manager → Honeypot Antispam (Kontaktformular) → Konfigurieren**:

| Einstellung | Beschreibung | Standard |
|---|---|---|
| Spamschutz aktiv | Globaler Ein/Aus-Schalter, ohne das Modul deinstallieren zu müssen | Ein |
| Honeypot-Feldname 1–3 | Feldnamen, nur Buchstaben/Zahlen/`_`/`-`, dürfen nicht mit Kern-/Modul-Feldnamen kollidieren und müssen sich voneinander unterscheiden | `website`, `phone`, `company` |
| Mindest-Ausfüllzeit (Sekunden) | Schnellere Anfragen werden blockiert | 4 |
| Max. Links in der Nachricht | Nachrichten mit mindestens so vielen `http(s)`-Links werden blockiert | 3 |
| Sperrbegriffe | Ein Begriff pro Zeile; standardmäßig leer, damit nie ungeprüft echte Anfragen blockiert werden | *(leer)* |
| Max. Anfragen pro IP-Adresse | Obergrenze für das Rate-Limiting | 10 |
| Zeitfenster für Rate-Limit (Sekunden) | Zeitraum des Rate-Limitings | 3600 (1 Stunde) |

Die Konfigurationsseite zeigt zusätzlich die Gesamtzahl blockierter Versuche sowie eine Aufschlüsselung der letzten 7 Tage nach Blockiergrund (Honeypot / Zeitprüfung / Inhalt / Rate-Limit), damit sich die Wirksamkeit über die Zeit nachvollziehen lässt.

### Hooks & technische Details

| Hook | Zweck |
|---|---|
| `displayGDPRConsent` | Rendert die versteckten Honeypot-Felder und das signierte Zeit-Token im Kontaktformular. |
| `actionDispatcherBefore` | Frühestmöglicher zuverlässiger Einhängepunkt, vor dem Front-Controller-Routing. |
| `actionFrontControllerInitBefore` | Zusätzlicher Einhängepunkt (bewusst redundant, gegen doppelte Ausführung abgesichert), um je nach PrestaShop-Version zuverlässig vor der Verarbeitung durch das Kontaktformular zu greifen. |

**Bereits eingebaute Sicherheitsmechanismen:**
- SQL: alle dynamischen Query-Teile werden mit `(int)` typisiert oder mit `pSQL()` escaped; Tabellen-/Spaltennamen sind feste Konstanten, nie Benutzereingaben.
- Zeit-Token: signiert mit `hash_hmac('sha256', ...)` und zeitsicher verifiziert mit `hash_equals()` — nicht anfällig für Timing-Angriffe oder triviale Fälschung.
- Ausgabe: alle dynamischen Werte, die in Smarty-Templates landen, werden explizit escaped (`|escape:'html':'UTF-8'`), zusätzlich zur serverseitigen Beschränkung auf einen sicheren Zeichensatz vor der Speicherung.
- Admin-Formular: Feldnamen werden vor dem Speichern gegen `^[a-zA-Z_][a-zA-Z0-9_\-]{1,32}$` sowie eine Liste reservierter Namen geprüft; ein eingereichter Wert wird vor der Anzeige in einer Validierungsfehlermeldung HTML-escaped.
- CSRF: Das Konfigurationsformular läuft ausschließlich über den `AdminModules`-Controller von PrestaShop, der die Admin-Token-Prüfung des Frameworks bereits erzwingt.
- Datenschutz: Es werden nur IP-Adresse, Zeitstempel, Blockier-Flag und -Grund gespeichert (kein Nachrichteninhalt, keine Besucher-Identität); Einträge älter als 30 Tage werden automatisch gelöscht.

**Bekannte Einschränkungen (bewusstes Design, keine Fehler):**
- Das Zeit-Token ist zustandslos (nicht an eine Session gebunden, nicht Einmalgebrauch). Ein Bot, der die Seite zuerst lädt, die Mindestzeit abwartet und dann skriptgesteuert absendet, kann die Zeitprüfung allein umgehen — deshalb kombiniert das Modul sie zusätzlich mit Inhalts-Heuristik und Rate-Limiting, statt sich allein auf die Zeitprüfung zu verlassen.
- Rendert das aktive Theme den Hook `displayGDPRConsent` nie innerhalb des `<form>`-Tags des Kontaktformulars, kann das Modul seine Felder/sein Token nicht einhängen — und da ein fehlendes/ungültiges Token als verdächtig gilt, werden dann alle Kontaktformular-Anfragen blockiert. Nach einem Theme-Wechsel unbedingt prüfen (siehe Abschnitt Kompatibilität).
- Das Rate-Limiting erfolgt pro Client-IP-Adresse laut `Tools::getRemoteAddr()`. Hinter einem Reverse Proxy/CDN muss die Behandlung vertrauenswürdiger Proxys/`X-Forwarded-For` in PrestaShop korrekt konfiguriert sein, sonst teilen sich ggf. alle Besucher eine IP-Adresse (Rate-Limiting greift dann gar nicht oder unverhältnismäßig für alle gemeinsam).

### Lizenz

Proprietäres Modul, entwickelt von Harald Huber ([www.harald-huber.com](https://www.harald-huber.com)) — alle Rechte vorbehalten, nicht zur Weiterverbreitung bestimmt.
