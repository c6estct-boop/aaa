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

function vexis_plans(): array {
    return [
        '1d' => ['label' => '1 Gun', 'days' => 1],
        '7d' => ['label' => '7 Gun', 'days' => 7],
        '30d' => ['label' => '30 Gun', 'days' => 30],
        '90d' => ['label' => '90 Gun', 'days' => 90],
        '1y' => ['label' => '1 Yil', 'days' => 365],
        'lifetime' => ['label' => 'Unlimited', 'days' => 0],
    ];
}

function vexis_plan_label(string $plan, int $days): string {
    $plans = vexis_plans();
    if (isset($plans[$plan])) {
        return $plans[$plan]['label'];
    }
    if ($days > 0) {
        return $days . ' Gun';
    }
    return $plan;
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
        return;
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL UNIQUE,
        plan TEXT NOT NULL DEFAULT '1y',
        duration_days INTEGER NOT NULL DEFAULT 365,
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
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    return substr($ip, 0, 64);
}

function vexis_ban_message(): string {
    $cfg = vexis_config();
    return (string)($cfg['ban_message'] ?? 'invalid api request BANNED !');
}

function vexis_banned(PDO $db, string $ip): bool {
    try {
        $stmt = $db->prepare('SELECT 1 FROM bans WHERE ip = ? LIMIT 1');
        $stmt->execute([$ip]);
        return (bool)$stmt->fetchColumn();
    } catch (Throwable $e) {
        return false;
    }
}

function vexis_ban_ip(PDO $db, string $ip, string $reason = ''): void {
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
    if ($action !== 'validate') {
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
    $days = intdiv($left, 86400);
    $hours = intdiv($left % 86400, 3600);
    if ($days > 0) {
        return $days . 'g ' . $hours . 's';
    }
    $mins = intdiv($left % 3600, 60);
    return $hours . 's ' . $mins . 'dk';
}