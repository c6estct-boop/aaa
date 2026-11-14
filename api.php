<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';

$input = vexis_input();

try {
    $db = vexis_db();
} catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'server error';
    exit;
}

// Hard gate: bans empty/unsigned/invalid requests with "invalid api request BANNED !"
vexis_require_valid_request($db, $input);

$action = strtolower(trim((string)($input['action'] ?? '')));

// ---------------------------------------------------------------------------
// Presence: online users + compact skin blob (text protocol, see lib.php)
// ---------------------------------------------------------------------------
if ($action === 'presence') {
    [$lic, $auth_error, $auth_message] = vexis_license_auth($db, $input);
    if (!$lic) {
        vexis_text_fail($auth_error, $auth_message);
    }

    $steam_id = preg_replace('/[^0-9]/', '', (string)($input['steam_id'] ?? ''));
    if ($steam_id === '' || strlen($steam_id) > 20) {
        vexis_text_fail('bad_steam', 'SteamID okunamadi.');
    }

    $name = vexis_b64_decode((string)($input['name'] ?? ''));
    $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name) ?? '';
    if (preg_match('/^.{0,48}/us', $name, $nm)) {
        $name = $nm[0];
    }

    $skins = strtr((string)($input['skins'] ?? ''), ' ', '+');
    if (strlen($skins) > 12000) {
        vexis_text_fail('bad_skins', 'Skin verisi cok buyuk.');
    }

    $now = time();
    $driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver === 'mysql') {
        $upsert = $db->prepare('INSERT INTO presence (steam_id, license_key, name, hwid, skins, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE license_key = VALUES(license_key), name = VALUES(name),
                hwid = VALUES(hwid), skins = VALUES(skins), updated_at = VALUES(updated_at)');
    } else {
        $upsert = $db->prepare('INSERT INTO presence (steam_id, license_key, name, hwid, skins, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(steam_id) DO UPDATE SET license_key = excluded.license_key, name = excluded.name,
                hwid = excluded.hwid, skins = excluded.skins, updated_at = excluded.updated_at');
    }
    $upsert->execute([$steam_id, (string)$lic['license_key'], $name,
        strtoupper((string)($input['hwid'] ?? '')), $skins, $now]);

    // drop clients that stopped posting
    $db->prepare('DELETE FROM presence WHERE updated_at < ?')->execute([$now - 30]);

    $peers = $db->prepare('SELECT steam_id, name, skins FROM presence
        WHERE updated_at >= ? AND steam_id <> ?
        ORDER BY updated_at DESC LIMIT 64');
    $peers->execute([$now - 20, $steam_id]);

    vexis_text_headers();
    echo "OK\n";
    foreach ($peers->fetchAll() as $peer) {
        echo 'PEER ' . $peer['steam_id'] . ' ' . vexis_b64_encode((string)$peer['name']) . ' ' .
            (string)$peer['skins'] . "\n";
    }
    echo "END\n";
    exit;
}

// ---------------------------------------------------------------------------
// Chat / IRC poll
// ---------------------------------------------------------------------------
if ($action === 'chat_poll') {
    [$lic, $auth_error, $auth_message] = vexis_license_auth($db, $input);
    if (!$lic) {
        vexis_text_fail($auth_error, $auth_message);
    }

    $since = max(0, (int)($input['since'] ?? 0));
    $max_id = (int)($db->query('SELECT COALESCE(MAX(id), 0) FROM chat')->fetchColumn() ?: 0);
    $reset = false;
    if ($since > $max_id) {
        // database was reset (e.g. ephemeral free hosting); replay history
        $since = 0;
        $reset = true;
    }
    if ($since <= 0) {
        $stmt = $db->query('SELECT * FROM chat ORDER BY id DESC LIMIT 30');
        $messages = array_reverse($stmt->fetchAll());
    } else {
        $stmt = $db->prepare('SELECT * FROM chat WHERE id > ? ORDER BY id ASC LIMIT 60');
        $stmt->execute([$since]);
        $messages = $stmt->fetchAll();
    }

    vexis_text_headers();
    echo "OK\n";
    if ($reset) {
        echo "RESET\n";
    }
    foreach ($messages as $message) {
        $steam = preg_replace('/[^0-9]/', '', (string)$message['steam_id']);
        echo 'MSG ' . (int)$message['id'] . ' ' . (int)$message['created_at'] . ' ' .
            ($steam !== '' ? $steam : '0') . ' ' .
            vexis_b64_encode((string)$message['name']) . ' ' .
            vexis_b64_encode((string)$message['message']) . "\n";
    }
    echo "END\n";
    exit;
}

// ---------------------------------------------------------------------------
// Chat / IRC send
// ---------------------------------------------------------------------------
if ($action === 'chat_send') {
    [$lic, $auth_error, $auth_message] = vexis_license_auth($db, $input);
    if (!$lic) {
        vexis_text_fail($auth_error, $auth_message);
    }

    $text = trim((string)($input['message'] ?? ''));
    $text = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $text) ?? '';
    if (preg_match('/^.{0,240}/us', $text, $tm)) {
        $text = $tm[0];
    }
    if (trim($text) === '') {
        vexis_text_fail('empty', 'Mesaj bos.');
    }

    $name = vexis_b64_decode((string)($input['name'] ?? ''));
    $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name) ?? '';
    if (preg_match('/^.{0,48}/us', $name, $nm)) {
        $name = $nm[0];
    }

    $steam_id = preg_replace('/[^0-9]/', '', (string)($input['steam_id'] ?? ''));
    $now = time();

    // very light flood protection: 1 message per second per license
    $last = $db->prepare('SELECT created_at FROM chat WHERE license_key = ? ORDER BY id DESC LIMIT 1');
    $last->execute([(string)$lic['license_key']]);
    $last_at = (int)($last->fetchColumn() ?: 0);
    if ($last_at > 0 && $now - $last_at < 1) {
        vexis_text_fail('rate_limited', 'Cok hizli mesaj gonderiyorsun.');
    }

    $insert = $db->prepare('INSERT INTO chat (license_key, steam_id, name, message, created_at)
        VALUES (?, ?, ?, ?, ?)');
    $insert->execute([(string)$lic['license_key'], $steam_id, $name, $text, $now]);

    vexis_text_headers();
    echo 'OK ' . (int)$db->lastInsertId();
    exit;
}

$key = vexis_normalize_key((string)($input['key'] ?? ''));
$hwid = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', (string)($input['hwid'] ?? '')));

if ($key === '') {
    vexis_fail('invalid_key', 'Lisans anahtari gecersiz. Format: VEXIS-XXXX-XXXXX-XXXXX');
}
if (strlen($hwid) < 8) {
    vexis_fail('bad_hwid', 'HWID okunamadi.');
}

$stmt = $db->prepare('SELECT * FROM licenses WHERE license_key = ? LIMIT 1');
$stmt->execute([$key]);
$row = $stmt->fetch();

if (!$row) {
    vexis_fail('unknown_key', 'Lisans bulunamadi.');
}
if (strtolower((string)$row['status']) === 'revoked') {
    vexis_fail('revoked', 'Lisans iptal edilmis.');
}

$now = time();
$seconds = vexis_row_seconds($row);
$lifetime = $seconds <= 0;

$expires_at = $row['expires_at'] !== null ? (int)$row['expires_at'] : null;
$activated_at = $row['activated_at'] !== null ? (int)$row['activated_at'] : null;
$stored_hwid = trim((string)($row['hwid'] ?? ''));

if ($expires_at !== null && $expires_at <= $now) {
    vexis_log($db, $key, 'expired', 'expired_at=' . $expires_at);
    vexis_fail('expired', 'Lisans suresi bitmis.');
}

if ($stored_hwid === '') {
    // first launch: start the clock and lock the key to this machine (HWID lock)
    $activated_at = $now;
    $expires_at = $lifetime ? null : $now + $seconds;

    $update = $db->prepare('UPDATE licenses SET hwid = ?, activated_at = ?, expires_at = ?, last_ip = ?, last_seen = ?, '
        . 'validate_count = validate_count + 1 WHERE id = ?');
    $update->execute([$hwid, $activated_at, $expires_at, vexis_client_ip(), $now, (int)$row['id']]);
    vexis_log($db, $key, 'activated', 'hwid=' . $hwid . ' seconds=' . $seconds);
} elseif (!hash_equals(strtoupper($stored_hwid), $hwid)) {
    vexis_log($db, $key, 'hwid_mismatch', 'hwid=' . $hwid);
    vexis_fail('hwid_mismatch', 'HWID farkli: bu lisans baska bir bilgisayara bagli.');
} else {
    $update = $db->prepare('UPDATE licenses SET last_ip = ?, last_seen = ?, validate_count = validate_count + 1 '
        . 'WHERE id = ?');
    $update->execute([vexis_client_ip(), $now, (int)$row['id']]);
}

$plan = (string)$row['plan'];
$remaining = $expires_at !== null ? max(0, $expires_at - $now) : 0;

vexis_json([
    'ok' => true,
    'online' => true,
    'message' => 'Lisans aktif.',
    'key' => $key,
    'plan' => $plan,
    'plan_label' => vexis_plan_label($plan, $seconds),
    'duration_seconds' => $seconds,
    'lifetime' => $lifetime,
    'activated_at' => $activated_at,
    'expires_at' => $expires_at,
    'remaining' => $remaining,
    'server_time' => $now,
]);
