<?php
/**
 * Honeypod Antispam.
 *
 * @author    Harald Huber
 * @copyright Harald Huber
 * @link      https://www.harald-huber.com
 * @license   Proprietary - all rights reserved. Not for redistribution.
 *
 * Schuetzt das native PrestaShop-Kontaktformular vor automatisierten
 * Spam-Bots mit mehreren, unabhaengig voneinander wirkenden Schichten:
 *
 *  1. Honeypot-Felder: zusaetzliche Formularfelder, die fuer echte
 *     Besucher per CSS unsichtbar sind, von einfachen Bots aber trotzdem
 *     ausgefuellt werden. Die drei Feldnamen sind im Backend frei
 *     konfigurierbar (mit Standardwerten), zusaetzlich wird das bereits
 *     im Theme vorhandene, native PrestaShop-Honeypot-Feld "url" mit
 *     ausgewertet.
 *  2. Zeitpruefung: Anfragen, die schneller als eine konfigurierbare
 *     Mindestzeit nach dem Laden des Formulars eintreffen, gelten als
 *     automatisiert - unabhaengig davon, ob ein Bot die Honeypot-Felder
 *     erkennt und meidet.
 *  3. Inhalts-Heuristik: Nachrichten mit auffaellig vielen Links oder
 *     mit im Backend hinterlegten Sperrbegriffen gelten als Spam.
 *  4. Rate-Limiting: pro IP-Adresse ist nur eine begrenzte Anzahl an
 *     Anfragen innerhalb eines Zeitfensters erlaubt.
 *
 * Wird eine Anfrage als Spam erkannt, wird sie stillschweigend
 * verworfen, bevor das Kontaktformular-Modul sie verarbeitet (kein
 * Fehler, keine Bestaetigung - der Bot bekommt keinerlei Rueckmeldung).
 */

if (!defined('_PS_VERSION_')) {
    exit;
}

class Honeypod_Antispam extends Module
{
    /**
     * Name des nativen, bereits im Theme vorhandenen PrestaShop-Honeypot-
     * Felds (siehe Contactform::sendMessage() im Kern). Wird zusaetzlich
     * zu den drei konfigurierbaren Feldern ausgewertet, damit auch dieser
     * Fall in der Statistik auftaucht und nicht am Modul vorbei still im
     * Kern haengen bleibt.
     */
    const CORE_HONEYPOT_FIELD = 'url';

    /**
     * Standardwerte fuer die drei konfigurierbaren Honeypot-Feldnamen.
     *
     * @var string[]
     */
    const DEFAULT_HONEYPOT_FIELDS = ['website', 'phone', 'company'];

    /**
     * Feldnamen, die im Kontaktformular bereits durch den Kern belegt
     * sind bzw. die das Modul selbst verwendet. Ein Honeypot-Feld darf
     * niemals einen dieser Namen tragen, sonst wuerde es echte
     * Formulardaten ueberschreiben oder mit dem Zeit-Token kollidieren.
     *
     * @var string[]
     */
    const RESERVED_FIELD_NAMES = [
        'from', 'message', 'id_contact', 'id_order', 'url', 'token',
        'submitmessage', 'fileupload', 'ajax', 'controller', 'fc', 'hpa_ts',
    ];

    /**
     * Name des PrestaShop-Submit-Buttons des Kontaktformulars
     * (Kern-Feldname, siehe contactform.tpl).
     */
    const CONTACT_SUBMIT_FIELD = 'submitMessage';

    /**
     * Name des versteckten Zeit-Tokens (Formular-Renderzeit, signiert).
     */
    const TIMING_FIELD = 'hpa_ts';

    const DEFAULT_MIN_FILL_SECONDS = 4;
    const DEFAULT_MAX_MESSAGE_URLS = 3;
    const DEFAULT_RATE_LIMIT_MAX = 10;
    const DEFAULT_RATE_LIMIT_WINDOW = 3600;

    /**
     * Tabelle (ohne Praefix) fuer Rate-Limiting und Auswertung.
     */
    const ATTEMPT_TABLE = 'honeypod_antispam_attempt';

    /**
     * Verhindert doppelte Verarbeitung, falls mehrere Hooks
     * innerhalb desselben Requests feuern.
     *
     * @var bool
     */
    protected static $handled = false;

    public function __construct()
    {
        $this->name = 'honeypod_antispam';
        $this->tab = 'security_and_fraud';
        $this->version = '1.1.0';
        $this->author = 'Harald Huber';
        $this->need_instance = 0;
        $this->bootstrap = true;

        // Die eingesetzten APIs (Configuration, Tools, HelperForm, Db)
        // sind seit PrestaShop 1.7.0 stabil und unveraendert nutzbar.
        $this->ps_versions_compliancy = [
            'min' => '1.7.0.0',
            'max' => _PS_VERSION_,
        ];

        parent::__construct();

        $this->displayName = $this->trans('Honeypot Antispam (Kontaktformular)', [], 'Modules.Honeypodantispam.Admin');
        $this->description = $this->trans('Schuetzt das Kontaktformular vor Spam-Bots mittels Honeypot-Feldern, Zeitpruefung, Inhalts-Heuristik und Rate-Limiting.', [], 'Modules.Honeypodantispam.Admin');

        $this->confirmUninstall = $this->trans('Moechten Sie das Modul wirklich deinstallieren?', [], 'Modules.Honeypodantispam.Admin');
    }

    /**
     * @return bool
     */
    public function install()
    {
        return parent::install()
            && $this->registerHook('displayGDPRConsent')
            && $this->registerHook('actionDispatcherBefore')
            && $this->registerHook('actionFrontControllerInitBefore')
            && $this->createAttemptTable()
            && $this->installDefaultConfigurationIfMissing();
    }

    /**
     * @return bool
     */
    public function uninstall()
    {
        $configKeys = [
            'HPA_ENABLED', 'HPA_BLOCKED_COUNT', 'HPA_BLOCKED_HONEYPOT',
            'HPA_BLOCKED_TIMING', 'HPA_BLOCKED_CONTENT', 'HPA_BLOCKED_RATE',
            'HPA_FIELD_NAME_1', 'HPA_FIELD_NAME_2', 'HPA_FIELD_NAME_3',
            'HPA_MIN_FILL_SECONDS', 'HPA_MAX_MESSAGE_URLS', 'HPA_BLOCKLIST_KEYWORDS',
            'HPA_RATE_LIMIT_MAX', 'HPA_RATE_LIMIT_WINDOW',
        ];

        foreach ($configKeys as $key) {
            Configuration::deleteByName($key);
        }

        Db::getInstance()->execute('DROP TABLE IF EXISTS `' . _DB_PREFIX_ . self::ATTEMPT_TABLE . '`');

        return parent::uninstall();
    }

    /**
     * Legt die Tabelle fuer Rate-Limiting/Statistik an. Public, da auch
     * vom Upgrade-Skript einer bestehenden Installation aufgerufen.
     *
     * @return bool
     */
    public function createAttemptTable()
    {
        return (bool) Db::getInstance()->execute(
            'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . self::ATTEMPT_TABLE . '` (
                `id_hpa_attempt` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `ip` VARCHAR(45) NOT NULL,
                `date_add` DATETIME NOT NULL,
                `blocked` TINYINT(1) NOT NULL DEFAULT 0,
                `reason` VARCHAR(20) NULL,
                PRIMARY KEY (`id_hpa_attempt`),
                INDEX `idx_ip_date` (`ip`, `date_add`)
            ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8'
        );
    }

    /**
     * Setzt alle Konfigurationswerte, die noch nicht existieren, auf
     * ihren Standardwert. Idempotent nutzbar sowohl bei der
     * Neuinstallation als auch beim Upgrade einer bestehenden
     * Installation (siehe upgrade/upgrade-1.1.0.php). Public, da auch
     * vom Upgrade-Skript aufgerufen.
     *
     * @return bool
     */
    public function installDefaultConfigurationIfMissing()
    {
        $defaults = [
            'HPA_ENABLED' => true,
            'HPA_BLOCKED_COUNT' => 0,
            'HPA_BLOCKED_HONEYPOT' => 0,
            'HPA_BLOCKED_TIMING' => 0,
            'HPA_BLOCKED_CONTENT' => 0,
            'HPA_BLOCKED_RATE' => 0,
            'HPA_FIELD_NAME_1' => self::DEFAULT_HONEYPOT_FIELDS[0],
            'HPA_FIELD_NAME_2' => self::DEFAULT_HONEYPOT_FIELDS[1],
            'HPA_FIELD_NAME_3' => self::DEFAULT_HONEYPOT_FIELDS[2],
            'HPA_MIN_FILL_SECONDS' => self::DEFAULT_MIN_FILL_SECONDS,
            'HPA_MAX_MESSAGE_URLS' => self::DEFAULT_MAX_MESSAGE_URLS,
            'HPA_BLOCKLIST_KEYWORDS' => '',
            'HPA_RATE_LIMIT_MAX' => self::DEFAULT_RATE_LIMIT_MAX,
            'HPA_RATE_LIMIT_WINDOW' => self::DEFAULT_RATE_LIMIT_WINDOW,
        ];

        $success = true;

        foreach ($defaults as $key => $value) {
            if (Configuration::get($key) === false) {
                $success = $this->updateConfigurationValue($key, $value) && $success;
            }
        }

        return $success;
    }

    /**
     * Rendert die versteckten Honeypot-Felder plus das signierte
     * Zeit-Token direkt im Kontaktformular. Der Hook "displayGDPRConsent"
     * wird im contactform-Template dieses Shops sowohl im
     * Standard-Kontaktformular als auch im Widerrufs-Formular innerhalb
     * des <form>-Tags aufgerufen, direkt vor dem Absende-Button - ein
     * zuverlaessiger Einhaengepunkt, ohne das Theme aendern zu muessen.
     *
     * @param array $params
     *
     * @return string
     */
    public function hookDisplayGDPRConsent($params)
    {
        if (!Configuration::get('HPA_ENABLED')) {
            return '';
        }

        $this->context->smarty->assign([
            'hpa_fields' => $this->getConfigurableHoneypotFieldNames(),
            'hpa_timing_field' => self::TIMING_FIELD,
            'hpa_timing_token' => $this->buildTimingToken(),
        ]);

        return $this->fetch('module:' . $this->name . '/views/templates/hook/honeypot-fields.tpl');
    }

    /**
     * Fruehester verlaesslicher Einhaengepunkt vor der eigentlichen
     * Formularverarbeitung durch das contactform-Modul.
     *
     * @param array $params
     */
    public function hookActionDispatcherBefore($params)
    {
        $this->protectContactForm();
    }

    /**
     * Zusaetzlicher Einhaengepunkt (je nach PrestaShop-Version), um die
     * Pruefung zuverlaessig vor der Verarbeitung durch das
     * contactform-Modul auszufuehren.
     *
     * @param array $params
     */
    public function hookActionFrontControllerInitBefore($params)
    {
        $this->protectContactForm();
    }

    /**
     * Prueft, ob es sich um eine Kontaktformular-Anfrage handelt und ob
     * eine der Spamschutz-Schichten anschlaegt. Ist das der Fall, wird
     * die Anfrage stillschweigend entwertet: Das contactform-Modul
     * verarbeitet sie dann gar nicht erst.
     */
    protected function protectContactForm()
    {
        if (self::$handled) {
            return;
        }

        self::$handled = true;

        if (!Configuration::get('HPA_ENABLED')) {
            return;
        }

        if (!Tools::isSubmit(self::CONTACT_SUBMIT_FIELD)) {
            return;
        }

        $ip = $this->getRemoteIp();
        $reason = $this->detectSpam($ip);

        if ($reason === null) {
            $this->logAttempt($ip, false, null);

            return;
        }

        unset($_POST[self::CONTACT_SUBMIT_FIELD]);
        $this->logAttempt($ip, true, $reason);
        $this->incrementBlockedCounters($reason);
    }

    /**
     * Prueft alle Spamschutz-Schichten der Reihe nach, guenstige
     * Pruefungen zuerst.
     *
     * @param string $ip
     *
     * @return string|null Blockiergrund ("honeypot", "timing", "content",
     * "rate_limit") oder null, wenn die Anfrage unauffaellig ist.
     */
    protected function detectSpam($ip)
    {
        foreach ($this->getAllHoneypotFieldNames() as $field) {
            if (trim((string) Tools::getValue($field, '')) !== '') {
                return 'honeypot';
            }
        }

        $elapsed = $this->getElapsedFillSeconds();

        if ($elapsed === null || $elapsed < $this->getMinFillSeconds()) {
            return 'timing';
        }

        if ($this->isMessageContentSpammy((string) Tools::getValue('message', ''))) {
            return 'content';
        }

        // Als letzte, teuerste Pruefung: nur erreicht, wenn die Anfrage
        // jede kostenlose Heuristik bereits unauffaellig durchlaufen hat.
        if ($this->isRateLimited($ip)) {
            return 'rate_limit';
        }

        return null;
    }

    /**
     * Alle Honeypot-Feldnamen: die drei konfigurierbaren plus das
     * native, bereits im Theme vorhandene Kern-Feld.
     *
     * @return string[]
     */
    protected function getAllHoneypotFieldNames()
    {
        $fields = $this->getConfigurableHoneypotFieldNames();
        $fields[] = self::CORE_HONEYPOT_FIELD;

        return $fields;
    }

    /**
     * Die drei im Backend konfigurierbaren Honeypot-Feldnamen. Ungueltige
     * oder leere Werte fallen automatisch auf den jeweiligen
     * Standardwert zurueck.
     *
     * @return string[]
     */
    protected function getConfigurableHoneypotFieldNames()
    {
        $fields = [];

        foreach ([1, 2, 3] as $index) {
            $value = trim((string) Configuration::get('HPA_FIELD_NAME_' . $index));

            if ($value === '' || !$this->isValidFieldName($value)) {
                $value = self::DEFAULT_HONEYPOT_FIELDS[$index - 1];
            }

            $fields[] = $value;
        }

        return array_values(array_unique($fields));
    }

    /**
     * Ein gueltiger Honeypot-Feldname ist ein simpler HTML-Bezeichner
     * und kollidiert nicht mit einem reservierten Kern-/Modul-Feldnamen.
     *
     * @param string $name
     *
     * @return bool
     */
    protected function isValidFieldName($name)
    {
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_\-]{1,32}$/', $name)) {
            return false;
        }

        return !in_array(strtolower($name), self::RESERVED_FIELD_NAMES, true);
    }

    /**
     * Erzeugt das signierte Zeit-Token (Renderzeitpunkt + HMAC), das als
     * verstecktes Feld ins Formular gerendert wird.
     *
     * @return string
     */
    protected function buildTimingToken()
    {
        $timestamp = time();

        return $timestamp . '.' . $this->signTimestamp($timestamp);
    }

    /**
     * @param int|string $timestamp
     *
     * @return string
     */
    protected function signTimestamp($timestamp)
    {
        // _COOKIE_KEY_ ist ein pro Installation einmalig generiertes
        // Geheimnis, das PrestaShop bereits fuer eigene Zwecke nutzt -
        // ausreichend, um das Token faelschungssicher zu signieren, ohne
        // ein zusaetzliches Secret verwalten zu muessen.
        return hash_hmac('sha256', (string) $timestamp, _COOKIE_KEY_ . 'hpa_timing');
    }

    /**
     * Verifiziert das eingesendete Zeit-Token und liefert die seit dem
     * Rendern des Formulars vergangene Zeit in Sekunden.
     *
     * @return int|null null, wenn das Token fehlt, falsch formatiert
     * oder manipuliert ist.
     */
    protected function getElapsedFillSeconds()
    {
        $token = (string) Tools::getValue(self::TIMING_FIELD, '');
        $parts = explode('.', $token, 2);

        if (count($parts) !== 2 || !ctype_digit($parts[0])) {
            return null;
        }

        $timestamp = $parts[0];
        $signature = $parts[1];

        if (!hash_equals($this->signTimestamp($timestamp), $signature)) {
            return null;
        }

        return max(0, time() - (int) $timestamp);
    }

    /**
     * Inhalts-Heuristik: Nachrichten mit auffaellig vielen Links gelten
     * als Spam (typisches Muster bei Backlink-/SEO-Spam), ebenso
     * Nachrichten, die einen im Backend hinterlegten Sperrbegriff
     * enthalten. Die Sperrliste ist standardmaessig leer, damit nie
     * ungeprueft echte Anfragen blockiert werden.
     *
     * @param string $message
     *
     * @return bool
     */
    protected function isMessageContentSpammy($message)
    {
        $urlCount = preg_match_all('#https?://#i', $message);

        if ($urlCount >= $this->getMaxMessageUrls()) {
            return true;
        }

        $haystack = Tools::strtolower($message);

        foreach ($this->getBlocklistKeywords() as $keyword) {
            if ($keyword !== '' && strpos($haystack, $keyword) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Liest die im Backend hinterlegten Sperrbegriffe (ein Begriff pro
     * Zeile) und normalisiert sie fuer den Vergleich.
     *
     * @return string[]
     */
    protected function getBlocklistKeywords()
    {
        $raw = (string) Configuration::get('HPA_BLOCKLIST_KEYWORDS');

        if (trim($raw) === '') {
            return [];
        }

        $lines = preg_split('/[\r\n]+/', Tools::strtolower($raw));
        $keywords = [];

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line !== '') {
                $keywords[] = $line;
            }
        }

        return $keywords;
    }

    /**
     * @param string $ip
     *
     * @return bool
     */
    protected function isRateLimited($ip)
    {
        $window = $this->getRateLimitWindow();
        $max = $this->getRateLimitMax();

        $count = (int) Db::getInstance()->getValue(
            'SELECT COUNT(*) FROM `' . _DB_PREFIX_ . self::ATTEMPT_TABLE . '`
             WHERE `ip` = \'' . pSQL($ip) . '\'
             AND `date_add` > DATE_SUB(NOW(), INTERVAL ' . (int) $window . ' SECOND)'
        );

        return $count >= $max;
    }

    /**
     * Liefert die Client-IP in validierter Form (nie mit SQL-relevanten
     * Zeichen), da sie letztlich aus vom Client beeinflussbaren
     * HTTP-Headern stammt (siehe Tools::getRemoteAddr()).
     *
     * Hinweis fuer den Betrieb: Steht die Seite hinter einem Reverse
     * Proxy/CDN, muss dessen X-Forwarded-For-Weiterleitung in
     * PrestaShop korrekt als vertrauenswuerdig konfiguriert sein - sonst
     * liefert Tools::getRemoteAddr() fuer alle Besucher dieselbe
     * IP-Adresse und das Rate-Limiting greift entweder gar nicht oder
     * (schlimmer) fuer alle Besucher gemeinsam.
     *
     * @return string
     */
    protected function getRemoteIp()
    {
        $ip = Tools::getRemoteAddr();

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    /**
     * Protokolliert jeden Versuch (auch erlaubte), damit das
     * Rate-Limiting korrekt zaehlen kann und die Statistik im Backend
     * eine Aufschluesselung nach Blockiergrund zeigen kann. Raeumt
     * nebenbei sehr alte Eintraege auf, ohne dass es einen Cronjob
     * braucht.
     *
     * @param string $ip
     * @param bool $blocked
     * @param string|null $reason
     */
    protected function logAttempt($ip, $blocked, $reason)
    {
        Db::getInstance()->insert(self::ATTEMPT_TABLE, [
            'ip' => $ip,
            'date_add' => date('Y-m-d H:i:s'),
            'blocked' => (int) $blocked,
            'reason' => $reason !== null ? pSQL($reason) : null,
        ]);

        if (mt_rand(1, 100) === 1) {
            Db::getInstance()->execute(
                'DELETE FROM `' . _DB_PREFIX_ . self::ATTEMPT_TABLE . '`
                 WHERE `date_add` < DATE_SUB(NOW(), INTERVAL 30 DAY)'
            );
        }
    }

    /**
     * @param string $reason
     */
    protected function incrementBlockedCounters($reason)
    {
        $this->updateConfigurationValue('HPA_BLOCKED_COUNT', (int) Configuration::get('HPA_BLOCKED_COUNT') + 1);

        $reasonKeyMap = [
            'honeypot' => 'HPA_BLOCKED_HONEYPOT',
            'timing' => 'HPA_BLOCKED_TIMING',
            'content' => 'HPA_BLOCKED_CONTENT',
            'rate_limit' => 'HPA_BLOCKED_RATE',
        ];

        if (isset($reasonKeyMap[$reason])) {
            $key = $reasonKeyMap[$reason];
            $this->updateConfigurationValue($key, (int) Configuration::get($key) + 1);
        }
    }

    protected function getMinFillSeconds()
    {
        $value = (int) Configuration::get('HPA_MIN_FILL_SECONDS');

        return $value > 0 ? $value : self::DEFAULT_MIN_FILL_SECONDS;
    }

    protected function getMaxMessageUrls()
    {
        $value = (int) Configuration::get('HPA_MAX_MESSAGE_URLS');

        return $value > 0 ? $value : self::DEFAULT_MAX_MESSAGE_URLS;
    }

    protected function getRateLimitMax()
    {
        $value = (int) Configuration::get('HPA_RATE_LIMIT_MAX');

        return $value > 0 ? $value : self::DEFAULT_RATE_LIMIT_MAX;
    }

    protected function getRateLimitWindow()
    {
        $value = (int) Configuration::get('HPA_RATE_LIMIT_WINDOW');

        return $value > 0 ? $value : self::DEFAULT_RATE_LIMIT_WINDOW;
    }

    /**
     * @param string $key
     * @param mixed $value
     *
     * @return bool
     */
    protected function updateConfigurationValue($key, $value)
    {
        return Configuration::updateValue($key, $value);
    }

    /**
     * @return string
     */
    public function getContent()
    {
        $output = '';

        if (Tools::isSubmit('submitHoneypodAntispam')) {
            $output .= $this->processConfigurationSubmit();
        }

        $output .= $this->renderStatistics();

        return $output . $this->renderForm();
    }

    /**
     * Verarbeitet das Absenden des Einstellungsformulars inkl.
     * Validierung der drei Honeypot-Feldnamen.
     *
     * @return string
     */
    protected function processConfigurationSubmit()
    {
        $errors = [];
        $fieldNames = [];

        foreach ([1, 2, 3] as $index) {
            $value = trim((string) Tools::getValue('HPA_FIELD_NAME_' . $index));

            if ($value === '') {
                $value = self::DEFAULT_HONEYPOT_FIELDS[$index - 1];
            } elseif (!$this->isValidFieldName($value)) {
                $errors[] = sprintf(
                    $this->trans('Feldname "%s" ist ungueltig oder reserviert und wurde nicht gespeichert. Erlaubt sind Buchstaben, Zahlen, "_" und "-".', [], 'Modules.Honeypodantispam.Admin'),
                    htmlspecialchars($value, ENT_QUOTES, 'UTF-8')
                );
                $value = (string) Configuration::get('HPA_FIELD_NAME_' . $index);
            }

            $fieldNames[$index] = $value;
        }

        if (count(array_unique($fieldNames)) !== count($fieldNames)) {
            $errors[] = $this->trans('Die drei Honeypot-Feldnamen muessen sich voneinander unterscheiden. Sie wurden nicht gespeichert.', [], 'Modules.Honeypodantispam.Admin');
        } else {
            foreach ($fieldNames as $index => $value) {
                $this->updateConfigurationValue('HPA_FIELD_NAME_' . $index, $value);
            }
        }

        $this->updateConfigurationValue('HPA_ENABLED', (bool) Tools::getValue('HPA_ENABLED'));
        $this->updateConfigurationValue('HPA_MIN_FILL_SECONDS', max(0, (int) Tools::getValue('HPA_MIN_FILL_SECONDS')));
        $this->updateConfigurationValue('HPA_MAX_MESSAGE_URLS', max(1, (int) Tools::getValue('HPA_MAX_MESSAGE_URLS')));
        $this->updateConfigurationValue('HPA_BLOCKLIST_KEYWORDS', (string) Tools::getValue('HPA_BLOCKLIST_KEYWORDS', ''));
        $this->updateConfigurationValue('HPA_RATE_LIMIT_MAX', max(1, (int) Tools::getValue('HPA_RATE_LIMIT_MAX')));
        $this->updateConfigurationValue('HPA_RATE_LIMIT_WINDOW', max(60, (int) Tools::getValue('HPA_RATE_LIMIT_WINDOW')));

        $output = '';

        foreach ($errors as $error) {
            $output .= $this->displayError($error);
        }

        $output .= $this->displayConfirmation(
            $this->trans('Die Einstellungen wurden gespeichert.', [], 'Modules.Honeypodantispam.Admin')
        );

        return $output;
    }

    /**
     * Zeigt die Gesamtzahl blockierter Versuche sowie eine
     * Aufschluesselung der letzten 7 Tage nach Blockiergrund, damit sich
     * die Wirksamkeit tatsaechlich nachvollziehen laesst.
     *
     * @return string
     */
    protected function renderStatistics()
    {
        $recent = Db::getInstance()->getRow(
            'SELECT
                SUM(blocked = 1) AS blocked,
                SUM(reason = \'honeypot\') AS honeypot,
                SUM(reason = \'timing\') AS timing,
                SUM(reason = \'content\') AS content,
                SUM(reason = \'rate_limit\') AS rate_limit
             FROM `' . _DB_PREFIX_ . self::ATTEMPT_TABLE . '`
             WHERE `date_add` > DATE_SUB(NOW(), INTERVAL 7 DAY)'
        );

        if (!is_array($recent)) {
            $recent = [];
        }

        return $this->displayInformation(sprintf(
            $this->trans(
                'Insgesamt blockierte Spam-Versuche: %1$d. Letzte 7 Tage: %2$d blockiert (Honeypot: %3$d, Zeitpruefung: %4$d, Inhalt: %5$d, Rate-Limit: %6$d).',
                [],
                'Modules.Honeypodantispam.Admin'
            ),
            (int) Configuration::get('HPA_BLOCKED_COUNT'),
            (int) $this->arrayGet($recent, 'blocked'),
            (int) $this->arrayGet($recent, 'honeypot'),
            (int) $this->arrayGet($recent, 'timing'),
            (int) $this->arrayGet($recent, 'content'),
            (int) $this->arrayGet($recent, 'rate_limit')
        ));
    }

    /**
     * @param array $array
     * @param string $key
     * @param mixed $default
     *
     * @return mixed
     */
    protected function arrayGet($array, $key, $default = 0)
    {
        return isset($array[$key]) ? $array[$key] : $default;
    }

    /**
     * @return string
     */
    protected function renderForm()
    {
        $fields_form = [
            'form' => [
                'legend' => [
                    'title' => $this->trans('Einstellungen', [], 'Modules.Honeypodantispam.Admin'),
                    'icon' => 'icon-cogs',
                ],
                'input' => [
                    [
                        'type' => 'switch',
                        'label' => $this->trans('Spamschutz aktiv', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_ENABLED',
                        'is_bool' => true,
                        'desc' => $this->trans('Deaktiviert den Spamschutz voruebergehend, ohne das Modul zu deinstallieren.', [], 'Modules.Honeypodantispam.Admin'),
                        'values' => [
                            [
                                'id' => 'hpa_enabled_on',
                                'value' => 1,
                                'label' => $this->trans('Ja', [], 'Admin.Global'),
                            ],
                            [
                                'id' => 'hpa_enabled_off',
                                'value' => 0,
                                'label' => $this->trans('Nein', [], 'Admin.Global'),
                            ],
                        ],
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Honeypot-Feldname 1', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_FIELD_NAME_1',
                        'desc' => sprintf($this->trans('Nur Buchstaben, Zahlen, "_" und "-". Standard: "%s". Leer lassen, um den Standard wiederherzustellen.', [], 'Modules.Honeypodantispam.Admin'), self::DEFAULT_HONEYPOT_FIELDS[0]),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Honeypot-Feldname 2', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_FIELD_NAME_2',
                        'desc' => sprintf($this->trans('Standard: "%s".', [], 'Modules.Honeypodantispam.Admin'), self::DEFAULT_HONEYPOT_FIELDS[1]),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Honeypot-Feldname 3', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_FIELD_NAME_3',
                        'desc' => sprintf($this->trans('Standard: "%s".', [], 'Modules.Honeypodantispam.Admin'), self::DEFAULT_HONEYPOT_FIELDS[2]),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Mindest-Ausfuellzeit (Sekunden)', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_MIN_FILL_SECONDS',
                        'desc' => $this->trans('Anfragen, die schneller als diese Zeitspanne nach dem Laden des Formulars abgeschickt werden, gelten als Bot.', [], 'Modules.Honeypodantispam.Admin'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Max. Links in der Nachricht', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_MAX_MESSAGE_URLS',
                        'desc' => $this->trans('Nachrichten mit mindestens so vielen http(s)-Links gelten als Spam.', [], 'Modules.Honeypodantispam.Admin'),
                    ],
                    [
                        'type' => 'textarea',
                        'label' => $this->trans('Sperrbegriffe', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_BLOCKLIST_KEYWORDS',
                        'desc' => $this->trans('Ein Begriff pro Zeile. Enthaelt die Nachricht einen davon, gilt sie als Spam. Standardmaessig leer, damit nie ungeprueft echte Anfragen blockiert werden - erst nach Sichtung wiederkehrender Spam-Muster befuellen.', [], 'Modules.Honeypodantispam.Admin'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Max. Anfragen pro IP-Adresse', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_RATE_LIMIT_MAX',
                        'desc' => $this->trans('Erlaubte Kontaktformular-Anfragen je IP-Adresse innerhalb des Zeitfensters.', [], 'Modules.Honeypodantispam.Admin'),
                    ],
                    [
                        'type' => 'text',
                        'label' => $this->trans('Zeitfenster fuer Rate-Limit (Sekunden)', [], 'Modules.Honeypodantispam.Admin'),
                        'name' => 'HPA_RATE_LIMIT_WINDOW',
                        'desc' => $this->trans('Zeitraum, ueber den die Anfragen pro IP-Adresse gezaehlt werden, z.B. 3600 = 1 Stunde.', [], 'Modules.Honeypodantispam.Admin'),
                    ],
                ],
                'submit' => [
                    'title' => $this->trans('Speichern', [], 'Admin.Actions'),
                ],
            ],
        ];

        $lang = new Language((int) Configuration::get('PS_LANG_DEFAULT'));

        $helper = new HelperForm();
        $helper->show_toolbar = false;
        $helper->table = $this->table;
        $helper->default_form_language = $lang->id;
        $helper->allow_employee_form_lang = Configuration::get('PS_BO_ALLOW_EMPLOYEE_FORM_LANG') ? Configuration::get('PS_BO_ALLOW_EMPLOYEE_FORM_LANG') : 0;
        $helper->identifier = $this->identifier;
        $helper->submit_action = 'submitHoneypodAntispam';
        $helper->currentIndex = $this->context->link->getAdminLink('AdminModules', false) . '&configure=' . $this->name . '&tab_module=' . $this->tab . '&module_name=' . $this->name;
        $helper->token = Tools::getAdminTokenLite('AdminModules');
        $helper->tpl_vars = [
            'fields_value' => [
                'HPA_ENABLED' => (bool) Configuration::get('HPA_ENABLED'),
                'HPA_FIELD_NAME_1' => Configuration::get('HPA_FIELD_NAME_1'),
                'HPA_FIELD_NAME_2' => Configuration::get('HPA_FIELD_NAME_2'),
                'HPA_FIELD_NAME_3' => Configuration::get('HPA_FIELD_NAME_3'),
                'HPA_MIN_FILL_SECONDS' => (int) Configuration::get('HPA_MIN_FILL_SECONDS'),
                'HPA_MAX_MESSAGE_URLS' => (int) Configuration::get('HPA_MAX_MESSAGE_URLS'),
                'HPA_BLOCKLIST_KEYWORDS' => (string) Configuration::get('HPA_BLOCKLIST_KEYWORDS'),
                'HPA_RATE_LIMIT_MAX' => (int) Configuration::get('HPA_RATE_LIMIT_MAX'),
                'HPA_RATE_LIMIT_WINDOW' => (int) Configuration::get('HPA_RATE_LIMIT_WINDOW'),
            ],
            'languages' => $this->context->controller->getLanguages(),
            'id_language' => $this->context->language->id,
        ];

        return $helper->generateForm([$fields_form]);
    }
}
