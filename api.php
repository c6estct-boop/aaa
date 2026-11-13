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

$key = vexis_normalize_key((string)($input['key'] ?? ''));
$hwid = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', (string)($input['hwid'] ?? '')));

if ($key === '') {
    vexis_fail('invalid_key', 'Lisans anahtari gecersiz. Format: VEXIS-XXXX-XXXXX-XXXXX');
}
if (strlen($hwid) < 8) {
    vexis_fail('bad_hwid', 'Donanim kimligi okunamadi.');
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
$expires_at = $row['expires_at'] !== null ? (int)$row['expires_at'] : null;
$activated_at = $row['activated_at'] !== null ? (int)$row['activated_at'] : null;
$stored_hwid = trim((string)($row['hwid'] ?? ''));

if ($expires_at !== null && $expires_at <= $now) {
    vexis_fail('expired', 'Lisans suresi dolmus.');
}

if ($stored_hwid === '') {
    // first launch: start the clock and lock the key to this machine (HWID lock)
    $days = (int)$row['duration_days'];
    $lifetime = $days <= 0;
    $activated_at = $now;
    $expires_at = $lifetime ? null : $now + $days * 86400;

    $update = $db->prepare('UPDATE licenses SET hwid = ?, activated_at = ?, expires_at = ?, last_ip = ?, last_seen = ?, '
        . 'validate_count = validate_count + 1 WHERE id = ?');
    $update->execute([$hwid, $activated_at, $expires_at, vexis_client_ip(), $now, (int)$row['id']]);
    vexis_log($db, $key, 'activated', 'hwid=' . $hwid);
} elseif (!hash_equals(strtoupper($stored_hwid), $hwid)) {
    vexis_log($db, $key, 'hwid_mismatch', 'hwid=' . $hwid);
    vexis_fail('hwid_mismatch', 'Lisans baska bir bilgisayara bagli. HWID sifirlama isteyin.');
} else {
    $update = $db->prepare('UPDATE licenses SET last_ip = ?, last_seen = ?, validate_count = validate_count + 1 '
        . 'WHERE id = ?');
    $update->execute([vexis_client_ip(), $now, (int)$row['id']]);
}

$plan = (string)$row['plan'];
$days = (int)$row['duration_days'];
$lifetime = $days <= 0;

vexis_json([
    'ok' => true,
    'message' => 'Lisans aktif.',
    'key' => $key,
    'plan' => $plan,
    'plan_label' => vexis_plan_label($plan, $days),
    'lifetime' => $lifetime,
    'activated_at' => $activated_at,
    'expires_at' => $expires_at,
    'remaining' => $expires_at !== null ? max(0, $expires_at - $now) : 0,
    'server_time' => $now,
]);