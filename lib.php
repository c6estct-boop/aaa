<?php
declare(strict_types=1);

function vexis_config(): array {
    static $config = null;
    if ($config === null) {
        $config = require __DIR__ . '/config.php';
        date_default_timezone_set($config['timezone'] ?? 'UTC');
    }
    return $config;
}

/**
 * All supported plans. "seconds" is the source of truth; "days" is kept for
 * backwards compatibility with older rows / queries.
 * seconds = 0  -> lifetime (unlimited)
 */
function vexis_plans(): array {
    return [
        '1m'  => ['label' => '1 Dakika',   'seconds' => 60],
        '5m'  => ['label' => '5 Dakika',   'seconds' => 300],
        '15m' => ['label' => '15 Dakika',  'seconds' => 900],
        '30m' => ['label' => '30 Dakika',  'seconds' => 1800],
        '1h'  => ['label' => '1 Saat',     'seconds' => 3600],
        '3h'  => ['label' => '3 Saat',     'seconds' => 10800],
        '6h'  => ['label' => '6 Saat',     'seconds' => 21600],
        '12h' => ['label' => '12 Saat',    'seconds' => 43200],
        '1d'  => ['label' => '1 Gun',      'seconds' => 86400],
        '7d'  => ['label' => '7 Gun',      'seconds' => 604800],
        '30d' => ['label' => '30 Gun',     'seconds' => 2592000],
        '90d' => ['label' => '90 Gun',     'seconds' => 7776000],
        '1y'  => ['label' => '1 Yil',      'seconds' => 31536000],
        'lifetime' => ['label' => 'Unlimited', 'seconds' => 0],
        'custom'   => ['label' => 'Ozel Sure', 'seconds' => 0],
    ];
}

function vexis_plan_seconds(string $plan): int {
    $plans = vexis_plans();
    return isset($plans[$plan]) ? (int)$plans[$plan]['seconds'] : 0;
}

/** Human readable duration: 25 sn / 5 dk / 2 sa 10 dk / 3 gun 4 sa */
function vexis_duration_label(int $seconds): string {
    if ($seconds <= 0) {
        return 'Unlimited';
    }
    if ($seconds < 60) {
        return $seconds . ' sn';
    }
    if ($seconds < 3600) {
        $m = intdiv($seconds, 60);
        $s = $seconds % 60;
        return $m . ' dk' . ($s > 0 ? ' ' . $s . ' sn' : '');
    }
    if ($seconds < 86400) {
        $h = intdiv($seconds, 3600);
        $m = intdiv($seconds % 3600, 60);
        return $h . ' sa' . ($m > 0 ? ' ' . $m . ' dk' : '');
    }
    $d = intdiv($seconds, 86400);
    $h = intdiv($seconds % 86400, 3600);
    return $d . ' gun' . ($h > 0 ? ' ' . $h . ' sa' : '');
}

function vexis_plan_label(string $plan, int $seconds): string {
    $plans = vexis_plans();
    if ($plan !== 'custom' && isset($plans[$plan]) && ($plans[$plan]['seconds'] > 0 || $plan === 'lifetime')) {
        return (string)$plans[$plan]['label'];
    }
    if ($seconds <= 0) {
        return 'Unlimited';
    }
    return vexis_duration_label($seconds);
}

function vexis_db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $cfg = vexis_config();
    $driver = strtolower((string)($cfg['db_driver'] ?? 'sqlite'));
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ];

    if ($driver === 'mysql') {
        $my = $cfg['mysql'];
        $dsn = 'mysql:host=' . $my['host'] . ';port=' . (int)$my['port'] . ';dbname=' . $my['name'] . ';charset=utf8mb4';
        $pdo = new PDO($dsn, $my['user'], $my['pass'], $options);
    } else {
        $path = (string)$cfg['sqlite_path'];
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        $pdo = new PDO('sqlite:' . $path, null, null, $options);
        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA busy_timeout = 5000');
    }

    vexis_migrate($pdo, $driver);
    return $pdo;
}

function vexis_migrate(PDO $pdo, string $driver): void {
    if ($driver === 'mysql') {
        $pdo->exec("CREATE TABLE IF NOT EXISTS licenses (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            license_key VARCHAR(32) NOT NULL,
            plan VARCHAR(24) NOT NULL DEFAULT '1y',
            duration_days INT NOT NULL DEFAULT 365,
            duration_seconds BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL,
            activated_at BIGINT NULL,
            expires_at BIGINT NULL,
            hwid VARCHAR(64) NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'active',
            note VARCHAR(160) NOT NULL DEFAULT '',
            last_ip VARCHAR(64) NULL,
            last_seen BIGINT NULL,
            validate_count INT NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            UNIQUE KEY uniq_license_key (license_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        // upgrade older installs that lack duration_seconds
        $col = $pdo->query("SHOW COLUMNS FROM licenses LIKE 'duration_seconds'")->fetch();
        if (!$col) {
            $pdo->exec('ALTER TABLE licenses ADD COLUMN duration_seconds BIGINT NOT NULL DEFAULT 0 AFTER duration_days');
            $pdo->exec('UPDATE licenses SET duration_seconds = duration_days * 86400 WHERE duration_seconds = 0');
        }

        $pdo->exec("CREATE TABLE IF NOT EXISTS events (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            license_key VARCHAR(32) NOT NULL,
            action VARCHAR(32) NOT NULL,
            detail VARCHAR(255) NOT NULL DEFAULT '',
            ip VARCHAR(64) NOT NULL DEFAULT '',
            created_at BIGINT NOT NULL,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS bans (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(64) NOT NULL,
            reason VARCHAR(120) NOT NULL DEFAULT '',
            created_at BIGINT NOT NULL,
            hits INT NOT NULL DEFAULT 1,
            PRIMARY KEY (id),
            UNIQUE KEY uniq_ban_ip (ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS presence (
            steam_id VARCHAR(24) NOT NULL,
            license_key VARCHAR(32) NOT NULL,
            name VARCHAR(64) NOT NULL DEFAULT '',
            hwid VARCHAR(64) NOT NULL DEFAULT '',
            skins TEXT NOT NULL,
            updated_at BIGINT NOT NULL,
            PRIMARY KEY (steam_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        $pdo->exec("CREATE TABLE IF NOT EXISTS chat (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            license_key VARCHAR(32) NOT NULL DEFAULT '',
            steam_id VARCHAR(24) NOT NULL DEFAULT '',
            name VARCHAR(64) NOT NULL DEFAULT '',
            message VARCHAR(512) NOT NULL,
            created_at BIGINT NOT NULL,
            PRIMARY KEY (id),
            KEY idx_chat_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        return;
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL UNIQUE,
        plan TEXT NOT NULL DEFAULT '1y',
        duration_days INTEGER NOT NULL DEFAULT 365,
        duration_seconds INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        activated_at INTEGER NULL,
        expires_at INTEGER NULL,
        hwid TEXT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        note TEXT NOT NULL DEFAULT '',
        last_ip TEXT NULL,
        last_seen INTEGER NULL,
        validate_count INTEGER NOT NULL DEFAULT 0
    )");

    // upgrade older sqlite installs that lack duration_seconds
    $cols = $pdo->query('PRAGMA table_info(licenses)')->fetchAll();
    $has_seconds = false;
    foreach ($cols as $c) {
        if (($c['name'] ?? '') === 'duration_seconds') {
            $has_seconds = true;
            break;
        }
    }
    if (!$has_seconds) {
        $pdo->exec('ALTER TABLE licenses ADD COLUMN duration_seconds INTEGER NOT NULL DEFAULT 0');
        $pdo->exec('UPDATE licenses SET duration_seconds = duration_days * 86400 WHERE duration_seconds = 0');
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        ip TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE,
        reason TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        hits INTEGER NOT NULL DEFAULT 1
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS presence (
        steam_id TEXT PRIMARY KEY,
        license_key TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        hwid TEXT NOT NULL DEFAULT '',
        skins TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS chat (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL DEFAULT '',
        steam_id TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL DEFAULT '',
        message TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )");
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_chat_created ON chat(created_at)');
}

function vexis_json($payload, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function vexis_fail(string $error, string $message, int $status = 200): void {
    vexis_json([
        'ok' => false,
        'error' => $error,
        'message' => $message,
        'server_time' => time(),
    ], $status);
}

// ---------------------------------------------------------------------------
// Text protocol (presence / chat). Kept line-based so the injected client does
// not need a full JSON parser. Format:
//   OK\nPEER <steam_id> <name_b64> <skins_b64>\nEND\n
//   OK\nMSG <id> <created_at> <steam_id> <name_b64> <text_b64>\nEND\n
//   ERR <code> <message>
// ---------------------------------------------------------------------------
function vexis_text_headers(): void {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
}

function vexis_text_fail(string $error, string $message, int $status = 200): void {
    http_response_code($status);
    vexis_text_headers();
    echo 'ERR ' . $error . ' ' . str_replace(["\r", "\n"], ' ', $message);
    exit;
}

function vexis_b64_encode(string $value): string {
    return base64_encode($value);
}

function vexis_b64_decode(string $value): string {
    if ($value === '') {
        return '';
    }
    // PHP form decoding turns '+' into spaces; restore them before decoding.
    $value = strtr($value, ' ', '+');
    $decoded = base64_decode($value, true);
    return $decoded === false ? '' : $decoded;
}

/**
 * Validates key+hwid for presence/chat. Returns [row, error, message].
 * Unlike validate, this never starts a new activation by itself: the loader
 * must have validated the key at least once (which writes the HWID).
 */
function vexis_license_auth(PDO $db, array $input): array {
    $key = vexis_normalize_key((string)($input['key'] ?? ''));
    $hwid = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', (string)($input['hwid'] ?? '')));

    if ($key === '' || strlen($hwid) < 8) {
        return [null, 'invalid_key', 'Lisans anahtari gecersiz.'];
    }

    $stmt = $db->prepare('SELECT * FROM licenses WHERE license_key = ? LIMIT 1');
    $stmt->execute([$key]);
    $row = $stmt->fetch();

    if (!$row) {
        return [null, 'unknown_key', 'Lisans bulunamadi.'];
    }
    if (strtolower((string)$row['status']) === 'revoked') {
        return [null, 'revoked', 'Lisans iptal edilmis.'];
    }

    $stored = strtoupper(trim((string)($row['hwid'] ?? '')));
    if ($stored === '' || !hash_equals($stored, $hwid)) {
        return [null, 'hwid_mismatch', 'HWID farkli: bu lisans baska bir bilgisayara bagli.'];
    }

    $expires_at = $row['expires_at'] !== null ? (int)$row['expires_at'] : null;
    if ($expires_at !== null && $expires_at <= time()) {
        return [null, 'expired', 'Lisans suresi bitmis.'];
    }

    return [$row, '', ''];
}

function vexis_input(): array {
    $data = [];
    foreach ($_GET as $k => $v) { $data[$k] = $v; }
    foreach ($_POST as $k => $v) { $data[$k] = $v; }

    $content_type = (string)($_SERVER['CONTENT_TYPE'] ?? '');
    if (stripos($content_type, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        $decoded = json_decode((string)$raw, true);
        if (is_array($decoded)) {
            $data = array_merge($data, $decoded);
        }
    }
    return $data;
}

function vexis_client_ip(): string {
    // Render / Cloudflare sit behind a proxy: REMOTE_ADDR is the proxy, the real
    // visitor is in CF-Connecting-IP or X-Forwarded-For. Prefer those.
    $candidates = [];
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $candidates[] = (string)$_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']) as $part) {
            $candidates[] = trim($part);
        }
    }
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        $candidates[] = (string)$_SERVER['REMOTE_ADDR'];
    }
    foreach ($candidates as $candidate) {
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return substr($candidate, 0, 64);
        }
    }
    return '0.0.0.0';
}

function vexis_ban_message(): string {
    $cfg = vexis_config();
    return (string)($cfg['ban_message'] ?? 'invalid api request BANNED !');
}

function vexis_banned(PDO $db, string $ip): bool {
    $cfg = vexis_config();
    if (empty($cfg['ban_enabled'])) {
        return false;
    }
    try {
        $stmt = $db->prepare('SELECT 1 FROM bans WHERE ip = ? LIMIT 1');
        $stmt->execute([$ip]);
        return (bool)$stmt->fetchColumn();
    } catch (Throwable $e) {
        return false;
    }
}

function vexis_ban_ip(PDO $db, string $ip, string $reason = ''): void {
    $cfg = vexis_config();
    if (empty($cfg['ban_enabled'])) {
        return;
    }
    $ip = substr($ip, 0, 64);
    $reason = substr($reason, 0, 120);
    $now = time();
    try {
        $driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);
        if ($driver === 'mysql') {
            $stmt = $db->prepare('INSERT INTO bans (ip, reason, created_at, hits) VALUES (?, ?, ?, 1)
                ON DUPLICATE KEY UPDATE hits = hits + 1, reason = VALUES(reason)');
            $stmt->execute([$ip, $reason, $now]);
        } else {
            $stmt = $db->prepare('INSERT INTO bans (ip, reason, created_at, hits) VALUES (?, ?, ?, 1)
                ON CONFLICT(ip) DO UPDATE SET hits = hits + 1, reason = excluded.reason');
            $stmt->execute([$ip, $reason, $now]);
        }
    } catch (Throwable $e) {
    }
}

function vexis_deny_banned(): void {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo vexis_ban_message();
    exit;
}

function vexis_require_valid_request(PDO $db, array $input): void {
    $ip = vexis_client_ip();

    // already banned -> always deny
    if (vexis_banned($db, $ip)) {
        vexis_deny_banned();
    }

    // empty / meaningless requests
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        vexis_ban_ip($db, $ip, 'bad_method');
        vexis_deny_banned();
    }
    $raw = file_get_contents('php://input');
    if (($raw === false || trim((string)$raw) === '') && empty($_POST)) {
        vexis_ban_ip($db, $ip, 'empty_request');
        vexis_deny_banned();
    }

    $cfg = vexis_config();
    $expected = (string)($cfg['api_secret'] ?? '');
    $provided = (string)($input['sig'] ?? $input['token'] ?? $input['secret'] ?? '');
    if ($expected === '' || $provided === '' || !hash_equals($expected, $provided)) {
        vexis_ban_ip($db, $ip, 'bad_signature');
        vexis_deny_banned();
    }

    $action = strtolower(trim((string)($input['action'] ?? '')));
    $allowed = ['validate', 'presence', 'chat_poll', 'chat_send'];
    if (!in_array($action, $allowed, true)) {
        vexis_ban_ip($db, $ip, 'bad_action');
        vexis_deny_banned();
    }
}

function vexis_normalize_key(string $raw): string {
    $clean = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $raw));
    if (strlen($clean) !== 19 || substr($clean, 0, 5) !== 'VEXIS') {
        return '';
    }
    return substr($clean, 0, 5) . '-' . substr($clean, 5, 4) . '-' . substr($clean, 9, 5) . '-' .
        substr($clean, 14, 5);
}

function vexis_generate_key(): string {
    // no I / O / 0 / 1 so keys are easy to read out loud
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $pick = static function (int $length) use ($alphabet): string {
        $out = '';
        $max = strlen($alphabet) - 1;
        for ($i = 0; $i < $length; ++$i) {
            $out .= $alphabet[random_int(0, $max)];
        }
        return $out;
    };
    return 'VEXIS-' . $pick(4) . '-' . $pick(5) . '-' . $pick(5);
}

function vexis_log(PDO $db, string $key, string $action, string $detail = ''): void {
    try {
        $stmt = $db->prepare('INSERT INTO events (license_key, action, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)');
        $stmt->execute([$key, $action, substr($detail, 0, 255), vexis_client_ip(), time()]);
    } catch (Throwable $ignored) {
    }
}

function vexis_remaining_label(?int $expires_at): string {
    if ($expires_at === null) {
        return 'Unlimited';
    }
    $left = $expires_at - time();
    if ($left <= 0) {
        return 'Expired';
    }
    if ($left < 60) {
        return $left . ' sn';
    }
    if ($left < 3600) {
        return intdiv($left, 60) . ' dk ' . ($left % 60) . ' sn';
    }
    $days = intdiv($left, 86400);
    $hours = intdiv($left % 86400, 3600);
    if ($days > 0) {
        return $days . 'g ' . $hours . 's';
    }
    $mins = intdiv($left % 3600, 60);
    return $hours . 's ' . $mins . 'dk';
}

/** Seconds for a row, falling back to legacy duration_days. */
function vexis_row_seconds(array $row): int {
    $seconds = (int)($row['duration_seconds'] ?? 0);
    if ($seconds <= 0 && (int)($row['duration_days'] ?? 0) > 0) {
        $seconds = (int)$row['duration_days'] * 86400;
    }
    return $seconds;
}
