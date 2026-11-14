<?php
declare(strict_types=1);

require __DIR__ . '/lib.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => !empty($_SERVER['HTTPS']),
    ]);
    session_start();
}

$config = vexis_config();
$authed = !empty($_SESSION['vexis_admin']);
$error = '';
$flash = '';

if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: admin.php');
    exit;
}

if (!$authed && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    if (hash_equals((string)$config['admin_password'], (string)($_POST['password'] ?? ''))) {
        session_regenerate_id(true);
        $_SESSION['vexis_admin'] = true;
        $authed = true;
        header('Location: admin.php');
        exit;
    }
    $error = 'Sifre yanlis.';
}

function h($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function vexis_dt($timestamp): string {
    if ($timestamp === null || (int)$timestamp <= 0) {
        return '-';
    }
    return date('d.m.Y H:i', (int)$timestamp);
}

function vexis_row_state(array $row, int $now): array {
    if (($row['status'] ?? '') === 'revoked') {
        return ['Revoked', 'bad'];
    }
    if (empty($row['hwid'])) {
        return ['Unused', 'muted'];
    }
    if ($row['expires_at'] !== null && (int)$row['expires_at'] <= $now) {
        return ['Expired', 'bad'];
    }
    return ['Active', 'good'];
}

function vexis_event_meta(string $action): array {
    $map = [
        'activated' => ['Aktivasyon', 'good'],
        'expired' => ['Suresi Bitti', 'bad'],
        'hwid_mismatch' => ['HWID Farkli', 'bad'],
        'revoked' => ['Iptal', 'bad'],
        'created' => ['Olusturuldu', 'muted'],
    ];
    if (isset($map[$action])) {
        return $map[$action];
    }
    return [$action !== '' ? $action : '-', 'muted'];
}

$db = null;
$now = time();
$stats = ['total' => 0, 'unused' => 0, 'active' => 0, 'expired' => 0, 'revoked' => 0];
$q = '';
$state_filter = '';
$rows = [];
$bans = [];
$events = [];
$page = 1;
$pages = 1;
$total_rows = 0;
$query_base = 'admin.php?q=&state=&page=';
$csrf = '';

if ($authed) {
    $db = vexis_db();
    $flash = (string)($_SESSION['vexis_flash'] ?? '');
    unset($_SESSION['vexis_flash']);
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    $csrf = (string)$_SESSION['csrf'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
        $ok = true;
        $message = '';
        if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
            $error = 'Guvenlik dogrulamasi basarisiz, sayfayi yenileyip tekrar dene.';
            $ok = false;
        } else {
            $action = (string)$_POST['action'];
            $id = (int)($_POST['id'] ?? 0);
            try {
                if ($action === 'create') {
                    $plans = vexis_plans();
                    $plan = (string)($_POST['plan'] ?? '1y');
                    $seconds = 0;

                    if ($plan === 'custom') {
                        $value = max(1, min(1000000, (int)($_POST['custom_value'] ?? 30)));
                        $unit = (string)($_POST['custom_unit'] ?? 'minutes');
                        $mult = 60;
                        if ($unit === 'seconds') { $mult = 1; }
                        elseif ($unit === 'hours') { $mult = 3600; }
                        elseif ($unit === 'days') { $mult = 86400; }
                        $seconds = $value * $mult;
                    } elseif ($plan === 'lifetime') {
                        $seconds = 0;
                    } elseif (isset($plans[$plan])) {
                        $seconds = (int)$plans[$plan]['seconds'];
                    } else {
                        $plan = '1y';
                        $seconds = 31536000;
                    }

                    $days = $seconds > 0 ? max(1, (int)ceil($seconds / 86400)) : 0;
                    $count = max(1, min(50, (int)($_POST['count'] ?? 1)));
                    $note = trim((string)($_POST['note'] ?? ''));
                    $note = function_exists('mb_substr') ? mb_substr($note, 0, 120, 'UTF-8') : substr($note, 0, 120);

                    $insert = $db->prepare('INSERT INTO licenses (license_key, plan, duration_days, duration_seconds, created_at, status, note) VALUES (?, ?, ?, ?, ?, ?, ?)');
                    $made = 0;
                    for ($i = 0; $i < $count; ++$i) {
                        $inserted = false;
                        for ($try = 0; $try < 10 && !$inserted; ++$try) {
                            $candidate = vexis_generate_key();
                            try {
                                $insert->execute([$candidate, $plan, $days, $seconds, $now, 'active', $note]);
                                $inserted = true;
                                ++$made;
                            } catch (PDOException $e) {
                                $msg = $e->getMessage();
                                if (stripos($msg, 'unique') === false && stripos($msg, 'duplicate') === false) {
                                    throw $e;
                                }
                            }
                        }
                        if (!$inserted) {
                            throw new RuntimeException('benzersiz anahtar uretilemedi');
                        }
                    }
                    $message = $made . ' lisans olusturuldu (' . vexis_duration_label($seconds) . ').';
                } elseif ($action === 'revoke' && $id > 0) {
                    $db->prepare("UPDATE licenses SET status = 'revoked' WHERE id = ?")->execute([$id]);
                    $message = 'Lisans iptal edildi.';
                } elseif ($action === 'activate' && $id > 0) {
                    $db->prepare("UPDATE licenses SET status = 'active' WHERE id = ?")->execute([$id]);
                    $message = 'Lisans tekrar aktif.';
                } elseif ($action === 'reset' && $id > 0) {
                    $db->prepare('UPDATE licenses SET hwid = NULL, activated_at = NULL, expires_at = NULL, last_seen = NULL, '
                        . "validate_count = 0, status = 'active' WHERE id = ?")->execute([$id]);
                    $message = 'HWID ve sure sifirlandi; lisans ilk kullanimda yeniden baslayacak.';
                } elseif ($action === 'extend' && $id > 0) {
                    $db->prepare('UPDATE licenses SET expires_at = expires_at + 2592000 WHERE id = ? AND expires_at IS NOT NULL')
                        ->execute([$id]);
                    $message = 'Suresi 30 gun uzatildi.';
                } elseif ($action === 'delete' && $id > 0) {
                    $db->prepare('DELETE FROM licenses WHERE id = ?')->execute([$id]);
                    $message = 'Lisans silindi.';
                } elseif ($action === 'unban' && $id > 0) {
                    $db->prepare('DELETE FROM bans WHERE id = ?')->execute([$id]);
                    $message = 'IP ban kaldirildi.';
                } elseif ($action === 'unban_all') {
                    $db->exec('DELETE FROM bans');
                    $message = 'Tum banlar temizlendi.';
                } else {
                    $message = 'Bilinmeyen islem.';
                }
            } catch (Throwable $e) {
                $error = 'Islem hatasi: ' . $e->getMessage();
                $ok = false;
            }
        }
        if ($ok) {
            $_SESSION['vexis_flash'] = $message;
            header('Location: admin.php');
            exit;
        }
    }

    $stats = $db->query("SELECT COUNT(*) AS total,
        COALESCE(SUM(CASE WHEN hwid IS NULL THEN 1 ELSE 0 END), 0) AS unused,
        COALESCE(SUM(CASE WHEN hwid IS NOT NULL AND status = 'active' AND (expires_at IS NULL OR expires_at > $now) THEN 1 ELSE 0 END), 0) AS active,
        COALESCE(SUM(CASE WHEN expires_at IS NOT NULL AND expires_at <= $now THEN 1 ELSE 0 END), 0) AS expired,
        COALESCE(SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END), 0) AS revoked
        FROM licenses")->fetch();

    $q = trim((string)($_GET['q'] ?? ''));
    $state_filter = (string)($_GET['state'] ?? '');
    $where = [];
    $params = [];
    if ($q !== '') {
        $where[] = '(license_key LIKE ? OR hwid LIKE ? OR note LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like);
    }
    if ($state_filter === 'unused') {
        $where[] = 'hwid IS NULL';
    } elseif ($state_filter === 'active') {
        $where[] = 'hwid IS NOT NULL AND status = ? AND (expires_at IS NULL OR expires_at > ?)';
        array_push($params, 'active', $now);
    } elseif ($state_filter === 'expired') {
        $where[] = 'expires_at IS NOT NULL AND expires_at <= ?';
        $params[] = $now;
    } elseif ($state_filter === 'revoked') {
        $where[] = 'status = ?';
        $params[] = 'revoked';
    }
    $where_sql = $where ? ' WHERE ' . implode(' AND ', $where) : '';

    $per_page = 20;
    $count_stmt = $db->prepare('SELECT COUNT(*) FROM licenses' . $where_sql);
    $count_stmt->execute($params);
    $total_rows = (int)$count_stmt->fetchColumn();
    $pages = max(1, (int)ceil($total_rows / $per_page));
    $page = min($pages, max(1, (int)($_GET['page'] ?? 1)));
    $offset = ($page - 1) * $per_page;

    $list = $db->prepare('SELECT * FROM licenses' . $where_sql . ' ORDER BY id DESC LIMIT ' . $per_page . ' OFFSET ' . $offset);
    $list->execute($params);
    $rows = $list->fetchAll();
    $query_base = 'admin.php?q=' . urlencode($q) . '&state=' . urlencode($state_filter) . '&page=';

    $bans = $db->query('SELECT * FROM bans ORDER BY created_at DESC LIMIT 200')->fetchAll();
    $events = $db->query('SELECT * FROM events ORDER BY id DESC LIMIT 40')->fetchAll();
}
?>
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vexis License Panel</title>
<style>
    :root {
        --bg: #04060b;
        --bg-soft: #070b14;
        --panel: rgba(12, 17, 28, 0.82);
        --panel-solid: #0b1120;
        --panel-2: #0e1526;
        --line: rgba(148, 163, 184, 0.14);
        --line-strong: rgba(148, 163, 184, 0.26);
        --text: #e8eefc;
        --muted: #93a4be;
        --accent: #22d3ee;
        --accent-2: #8b5cf6;
        --accent-soft: rgba(34, 211, 238, 0.12);
        --good: #34d399;
        --bad: #fb7185;
        --warn: #fbbf24;
        --radius: 18px;
        --shadow: 0 18px 50px rgba(0, 0, 0, 0.55);
    }

    * { box-sizing: border-box; }

    html { color-scheme: dark; }

    body {
        margin: 0;
        min-height: 100vh;
        color: var(--text);
        font: 14px/1.55 "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
        background: var(--bg);
        overflow-x: hidden;
    }

    body::before,
    body::after {
        content: "";
        position: fixed;
        z-index: -2;
        width: 720px;
        height: 720px;
        border-radius: 50%;
        filter: blur(120px);
        opacity: 0.5;
        pointer-events: none;
    }
    body::before {
        top: -280px;
        left: -160px;
        background: radial-gradient(circle, rgba(34, 211, 238, 0.35), transparent 68%);
        animation: drift 18s ease-in-out infinite alternate;
    }
    body::after {
        right: -220px;
        bottom: -320px;
        background: radial-gradient(circle, rgba(139, 92, 246, 0.32), transparent 68%);
        animation: drift 22s ease-in-out infinite alternate-reverse;
    }

    .grid-bg {
        position: fixed;
        inset: 0;
        z-index: -1;
        pointer-events: none;
        background-image:
            linear-gradient(rgba(148, 163, 184, 0.045) 1px, transparent 1px),
            linear-gradient(90deg, rgba(148, 163, 184, 0.045) 1px, transparent 1px);
        background-size: 54px 54px;
        mask-image: radial-gradient(ellipse at 50% 0%, #000 25%, transparent 78%);
        -webkit-mask-image: radial-gradient(ellipse at 50% 0%, #000 25%, transparent 78%);
    }

    @keyframes drift {
        from { transform: translate3d(0, 0, 0) scale(1); }
        to   { transform: translate3d(60px, 40px, 0) scale(1.08); }
    }
    @keyframes rise {
        from { opacity: 0; transform: translateY(10px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.55); }
        50% { box-shadow: 0 0 0 7px rgba(52, 211, 153, 0); }
    }

    a { color: var(--accent); text-decoration: none; transition: color 0.2s ease; }
    a:hover { color: #67e8f9; }

    .wrap { max-width: 1280px; margin: 0 auto; padding: 34px 22px 70px; animation: rise 0.4s ease-out; }

    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 26px; }

    .brand { display: flex; align-items: center; gap: 12px; font-size: 18px; font-weight: 800; letter-spacing: 0.05em; }

    .logo {
        width: 38px; height: 38px; border-radius: 12px;
        display: grid; place-items: center;
        background: linear-gradient(135deg, var(--accent), var(--accent-2));
        box-shadow: 0 8px 24px rgba(34, 211, 238, 0.35);
        color: #04101a; font-size: 19px; font-weight: 900;
    }

    .gradient-text {
        background: linear-gradient(100deg, #ffffff 10%, var(--accent) 55%, var(--accent-2) 100%);
        -webkit-background-clip: text;
        background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .top-right { display: flex; align-items: center; gap: 12px; }

    .status {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 8px 14px; border-radius: 999px;
        border: 1px solid rgba(52, 211, 153, 0.28);
        background: rgba(52, 211, 153, 0.08);
        color: var(--good); font-size: 12px; font-weight: 700; letter-spacing: 0.03em;
    }
    .status i {
        width: 8px; height: 8px; border-radius: 50%;
        background: var(--good); animation: pulse 2.2s infinite;
    }

    .panel {
        position: relative;
        background: var(--panel);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--line);
        border-radius: var(--radius);
        padding: 24px;
        box-shadow: var(--shadow);
    }

    .panel + .panel { margin-top: 20px; }

    .panel-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 18px; }
    .panel-head h2 { margin: 0; }

    h1 { font-size: 26px; margin: 0 0 6px; font-weight: 800; letter-spacing: -0.02em; }
    h2 { font-size: 12px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); font-weight: 800; }

    .muted { color: var(--muted); }
    .small { font-size: 12px; }

    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(172px, 1fr)); gap: 16px; margin-bottom: 20px; }

    .stat {
        padding: 20px;
        display: flex; align-items: center; gap: 16px;
        background:
            linear-gradient(160deg, rgba(34, 211, 238, 0.06), transparent 45%),
            var(--panel);
        overflow: hidden;
        transition: transform 0.22s ease, border-color 0.22s ease;
    }
    .stat::after {
        content: ""; position: absolute; inset: 0 0 auto 0; height: 2px;
        background: linear-gradient(90deg, var(--accent), var(--accent-2));
        opacity: 0.75;
    }
    .stat:hover { transform: translateY(-3px); border-color: var(--line-strong); }
    .stat .icon {
        width: 44px; height: 44px; border-radius: 13px; flex: 0 0 auto;
        display: grid; place-items: center;
        background: var(--accent-soft);
        border: 1px solid rgba(34, 211, 238, 0.22);
        color: var(--accent);
    }
    .stat .icon svg { width: 21px; height: 21px; }
    .stat .n { font-size: 27px; font-weight: 800; line-height: 1.1; letter-spacing: -0.02em; }
    .stat .l { color: var(--muted); font-size: 11px; letter-spacing: 0.09em; text-transform: uppercase; font-weight: 700; margin-top: 3px; }

    label {
        display: block; font-size: 11px; font-weight: 700; color: var(--muted);
        margin: 0 0 7px; letter-spacing: 0.07em; text-transform: uppercase;
    }

    input, select {
        width: 100%; padding: 11px 14px; border-radius: 11px;
        border: 1px solid var(--line);
        background: var(--panel-2);
        color: var(--text); outline: none; font: inherit;
        transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
    }
    input::placeholder { color: rgba(147, 164, 190, 0.55); }
    input:focus, select:focus {
        border-color: rgba(34, 211, 238, 0.65);
        box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.15);
        background: #0f1728;
    }

    select option { background: #0b1120; color: var(--text); }

    .row { display: grid; grid-template-columns: 1.25fr .55fr .9fr 1.35fr auto; gap: 12px; align-items: end; }

    .btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 7px;
        padding: 11px 20px; border-radius: 11px; border: 1px solid transparent;
        background: linear-gradient(135deg, var(--accent), var(--accent-2));
        color: #04121b; font: inherit; font-weight: 800; cursor: pointer;
        white-space: nowrap;
        box-shadow: 0 10px 26px rgba(34, 211, 238, 0.28);
        transition: transform 0.18s ease, box-shadow 0.18s ease, filter 0.18s ease;
    }
    .btn:hover { transform: translateY(-2px); filter: brightness(1.06); box-shadow: 0 14px 32px rgba(34, 211, 238, 0.36); }
    .btn:active { transform: translateY(0); }
    .btn.small { padding: 7px 13px; font-size: 12px; border-radius: 9px; }

    .btn.ghost {
        background: rgba(148, 163, 184, 0.06);
        border-color: var(--line);
        color: var(--text);
        box-shadow: none;
    }
    .btn.ghost:hover { background: rgba(148, 163, 184, 0.13); border-color: var(--line-strong); }

    .btn.danger {
        background: rgba(251, 113, 133, 0.12);
        border-color: rgba(251, 113, 133, 0.4);
        color: var(--bad);
        box-shadow: none;
    }
    .btn.danger:hover { background: var(--bad); color: #1a0508; border-color: var(--bad); }

    .table-wrap { overflow-x: auto; border-radius: 14px; border: 1px solid var(--line); }

    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 13px 14px; text-align: left; vertical-align: middle; border-bottom: 1px solid var(--line); }
    th {
        font-size: 10.5px; letter-spacing: 0.1em; text-transform: uppercase;
        color: var(--muted); font-weight: 800; background: rgba(148, 163, 184, 0.04);
        white-space: nowrap;
    }
    tbody tr { transition: background-color 0.15s ease; }
    tbody tr:hover { background: rgba(34, 211, 238, 0.045); }
    tbody tr:last-child td { border-bottom: none; }

    .key {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12.5px; font-weight: 700; letter-spacing: 0.02em;
        color: #a5f3fc;
        background: rgba(34, 211, 238, 0.08);
        border: 1px solid rgba(34, 211, 238, 0.22);
        padding: 5px 9px; border-radius: 8px;
        display: inline-block;
        word-break: break-all;
    }

    .tag {
        display: inline-flex; align-items: center; gap: 6px;
        padding: 5px 11px; border-radius: 999px;
        font-size: 11px; font-weight: 800; letter-spacing: 0.03em;
        border: 1px solid transparent;
        white-space: nowrap;
    }
    .tag::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
    .tag.good { color: var(--good); background: rgba(52, 211, 153, 0.1); border-color: rgba(52, 211, 153, 0.3); }
    .tag.bad { color: var(--bad); background: rgba(251, 113, 133, 0.1); border-color: rgba(251, 113, 133, 0.3); }
    .tag.muted { color: var(--muted); background: rgba(148, 163, 184, 0.08); border-color: var(--line); }

    .plan-pill {
        display: inline-block; padding: 4px 10px; border-radius: 8px;
        font-size: 11.5px; font-weight: 700;
        color: #c4b5fd; background: rgba(139, 92, 246, 0.12);
        border: 1px solid rgba(139, 92, 246, 0.3);
        white-space: nowrap;
    }

    .hwid { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11.5px; color: var(--muted); word-break: break-all; }

    .actions { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
    .actions form { margin: 0; }

    .toolbar { display: flex; gap: 12px; align-items: end; margin-bottom: 18px; flex-wrap: wrap; }
    .toolbar form { display: flex; gap: 10px; align-items: end; flex: 1; }
    .toolbar .grow { flex: 1; min-width: 200px; }

    .pager { display: flex; gap: 6px; justify-content: center; margin-top: 20px; flex-wrap: wrap; }
    .pager .current {
        background: linear-gradient(135deg, var(--accent), var(--accent-2));
        color: #04121b; border-color: transparent;
    }

    .flash, .err {
        padding: 13px 17px; border-radius: 13px; margin-bottom: 16px;
        font-weight: 700; animation: rise 0.3s ease-out;
        display: flex; align-items: center; gap: 10px;
    }
    .flash { border: 1px solid rgba(52, 211, 153, 0.32); background: rgba(52, 211, 153, 0.09); color: var(--good); }
    .err { border: 1px solid rgba(251, 113, 133, 0.32); background: rgba(251, 113, 133, 0.09); color: var(--bad); }

    .login { max-width: 420px; margin: 15vh auto 0; padding: 32px; }
    .login .logo { width: 52px; height: 52px; border-radius: 16px; font-size: 26px; margin-bottom: 18px; }
    .login h1 { font-size: 24px; }
    .login .btn { width: 100%; margin-top: 18px; }
    .login .field { margin-top: 18px; }

    .hint { font-size: 12px; color: var(--muted); margin-top: 12px; }
    .break { word-break: break-all; }

    .empty { text-align: center; color: var(--muted); padding: 36px 12px; }

    .countdown { font-variant-numeric: tabular-nums; font-size: 11.5px; color: var(--muted); }
    .countdown.soon { color: var(--warn); font-weight: 700; }
    .countdown.over { color: var(--bad); font-weight: 700; }

    ::-webkit-scrollbar { width: 11px; height: 11px; }
    ::-webkit-scrollbar-track { background: #070b14; }
    ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 8px; border: 3px solid #070b14; }
    ::-webkit-scrollbar-thumb:hover { background: #334155; }

    @media (max-width: 980px) {
        .row { grid-template-columns: 1fr 1fr; }
        .hide-sm { display: none; }
    }
    @media (max-width: 620px) {
        .row { grid-template-columns: 1fr; }
        .topbar { flex-direction: column; align-items: flex-start; }
        .wrap { padding: 24px 14px 50px; }
        .panel { padding: 18px; }
    }
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="wrap">
    <div class="topbar">
        <div class="brand">
            <span class="logo">V</span>
            <span><span class="gradient-text">VEXIS</span> <span class="muted" style="font-weight:500;letter-spacing:0;font-size:13px">/ license panel</span></span>
        </div>
        <div class="top-right">
            <span class="status"><i></i> API Online</span>
            <?php if ($authed): ?>
                <a class="btn ghost small" href="admin.php?logout=1">Cikis</a>
            <?php endif; ?>
        </div>
    </div>

    <?php if (!$authed): ?>
        <div class="panel login">
            <div class="logo">V</div>
            <h1 class="gradient-text">Panel Girisi</h1>
            <p class="muted" style="margin:4px 0 0">Lisans olusturmak ve yonetmek icin sifre gir.</p>
            <?php if ($error !== ''): ?><div class="err"><?= h($error) ?></div><?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="login" value="1">
                <div class="field">
                    <label for="password">Sifre</label>
                    <input type="password" id="password" name="password" autofocus placeholder="admin sifresi">
                </div>
                <button class="btn" type="submit">Giris Yap</button>
            </form>
        </div>
    <?php else: ?>

    <?php if ($flash !== ''): ?><div class="flash"><?= h($flash) ?></div><?php endif; ?>
    <?php if ($error !== ''): ?><div class="err"><?= h($error) ?></div><?php endif; ?>

    <div class="stats">
        <div class="panel stat">
            <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h16v3a2 2 0 0 0 0 4v3H4v-3a2 2 0 0 0 0-4V7Z"/></svg></div>
            <div><div class="n"><?= (int)$stats['total'] ?></div><div class="l">Toplam</div></div>
        </div>
        <div class="panel stat">
            <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-4 4 2 2m-5-1 2 2"/></svg></div>
            <div><div class="n"><?= (int)$stats['unused'] ?></div><div class="l">Kullanilmadi</div></div>
        </div>
        <div class="panel stat">
            <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="m5 13 4 4L19 7"/></svg></div>
            <div><div class="n"><?= (int)$stats['active'] ?></div><div class="l">Aktif</div></div>
        </div>
        <div class="panel stat">
            <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg></div>
            <div><div class="n"><?= (int)$stats['expired'] ?></div><div class="l">Suresi Dolan</div></div>
        </div>
        <div class="panel stat">
            <div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3 5 6v5c0 4.2 2.9 7.6 7 9 4.1-1.4 7-4.8 7-9V6l-7-3Z"/><path d="M9.5 9.5h5"/></svg></div>
            <div><div class="n"><?= (int)count($bans) ?></div><div class="l">Banli IP</div></div>
        </div>
    </div>

    <div class="panel">
        <div class="panel-head">
            <h2>Lisans Olustur</h2>
            <span class="muted small">Saniye / dakika / saat / gun desteklenir</span>
        </div>
        <form method="post" class="row">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <input type="hidden" name="action" value="create">
            <div>
                <label for="plan">Sure</label>
                <select id="plan" name="plan">
                    <optgroup label="Dakika">
                        <option value="1m">1 Dakika</option>
                        <option value="5m">5 Dakika</option>
                        <option value="15m">15 Dakika</option>
                        <option value="30m">30 Dakika</option>
                    </optgroup>
                    <optgroup label="Saat">
                        <option value="1h">1 Saat</option>
                        <option value="3h">3 Saat</option>
                        <option value="6h">6 Saat</option>
                        <option value="12h">12 Saat</option>
                    </optgroup>
                    <optgroup label="Gun">
                        <option value="1d">1 Gun</option>
                        <option value="7d">7 Gun</option>
                        <option value="30d">30 Gun</option>
                        <option value="90d">90 Gun</option>
                        <option value="1y" selected>1 Yil</option>
                    </optgroup>
                    <optgroup label="Diger">
                        <option value="lifetime">Unlimited</option>
                        <option value="custom">Ozel Sure</option>
                    </optgroup>
                </select>
            </div>
            <div>
                <label for="count">Adet</label>
                <input type="number" id="count" name="count" min="1" max="50" value="1">
            </div>
            <div id="custom_wrap" style="display:none">
                <label for="custom_value">Ozel</label>
                <div style="display:flex;gap:8px">
                    <input type="number" id="custom_value" name="custom_value" min="1" max="1000000" value="30" style="flex:1">
                    <select id="custom_unit" name="custom_unit" style="flex:1">
                        <option value="seconds">Saniye</option>
                        <option value="minutes" selected>Dakika</option>
                        <option value="hours">Saat</option>
                        <option value="days">Gun</option>
                    </select>
                </div>
            </div>
            <div>
                <label for="note">Not (opsiyonel)</label>
                <input type="text" id="note" name="note" maxlength="120" placeholder="ornek: ali / discord">
            </div>
            <div>
                <button class="btn" type="submit">Olustur</button>
            </div>
        </form>
        <div class="hint">Anahtar formati: <span class="key">VEXIS-XXXX-XXXXX-XXXXX</span> &middot; Ilk aktivasyonda HWID'ye kilitlenir, sure o anda baslar.</div>
    </div>

    <div class="panel">
        <div class="toolbar">
            <form method="get">
                <div class="grow">
                    <label for="q">Ara</label>
                    <input type="text" id="q" name="q" value="<?= h($q) ?>" placeholder="key, hwid veya not">
                </div>
                <div>
                    <label for="state">Durum</label>
                    <select id="state" name="state">
                        <option value="">Hepsi</option>
                        <option value="unused" <?= $state_filter === 'unused' ? 'selected' : '' ?>>Kullanilmadi</option>
                        <option value="active" <?= $state_filter === 'active' ? 'selected' : '' ?>>Aktif</option>
                        <option value="expired" <?= $state_filter === 'expired' ? 'selected' : '' ?>>Suresi Dolan</option>
                        <option value="revoked" <?= $state_filter === 'revoked' ? 'selected' : '' ?>>Iptal</option>
                    </select>
                </div>
                <button class="btn ghost" type="submit">Filtrele</button>
            </form>
            <a class="btn ghost small" href="admin.php">Temizle</a>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>Lisans</th>
                    <th>Plan</th>
                    <th>Durum</th>
                    <th class="hide-sm">HWID</th>
                    <th>Bitis</th>
                    <th class="hide-sm">Son Gorulme</th>
                    <th class="hide-sm">Not</th>
                    <th style="text-align:right">Islem</th>
                </tr>
                </thead>
                <tbody>
                <?php if (!$rows): ?>
                    <tr><td colspan="8" class="empty">Kayit yok.</td></tr>
                <?php endif; ?>
                <?php foreach ($rows as $row): ?>
                    <?php
                    [$state_label, $state_class] = vexis_row_state($row, $now);
                    $row_seconds = vexis_row_seconds($row);
                    $plan_label = vexis_plan_label((string)$row['plan'], $row_seconds);
                    if ($row['expires_at'] === null) {
                        $expires_html = $row_seconds <= 0
                            ? '<span class="tag muted">Unlimited</span>'
                            : '<span class="muted small">bekliyor</span>';
                    } else {
                        $exp = (int)$row['expires_at'];
                        $expires_html = '<div>' . h(vexis_dt($exp)) . '</div>' .
                            '<div class="countdown' . ($exp <= $now ? ' over' : (($exp - $now) < 3600 ? ' soon' : '')) . '" data-expires="' . $exp . '">' .
                            h(vexis_remaining_label($exp)) . '</div>';
                    }
                    ?>
                    <tr>
                        <td>
                            <div class="key"><?= h($row['license_key']) ?></div>
                            <button class="btn ghost small copy" type="button" data-key="<?= h($row['license_key']) ?>" style="margin-top:6px">Kopyala</button>
                        </td>
                        <td><span class="plan-pill"><?= h($plan_label) ?></span></td>
                        <td><span class="tag <?= h($state_class) ?>"><?= h($state_label) ?></span></td>
                        <td class="hide-sm"><span class="hwid"><?= $row['hwid'] ? h($row['hwid']) : '-' ?></span></td>
                        <td><?= $expires_html ?></td>
                        <td class="hide-sm muted small"><?= h(vexis_dt($row['last_seen'])) ?></td>
                        <td class="hide-sm muted small"><?= $row['note'] ? h($row['note']) : '-' ?></td>
                        <td>
                            <div class="actions">
                                <form method="post">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="action" value="<?= $row['status'] === 'revoked' ? 'activate' : 'revoke' ?>">
                                    <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                    <button class="btn ghost small" type="submit"><?= $row['status'] === 'revoked' ? 'Aktif Et' : 'Iptal' ?></button>
                                </form>
                                <form method="post">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="action" value="reset">
                                    <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                    <button class="btn ghost small" type="submit">HWID Sifirla</button>
                                </form>
                                <form method="post">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="action" value="extend">
                                    <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                    <button class="btn ghost small" type="submit">+30 Gun</button>
                                </form>
                                <form method="post" onsubmit="return confirm('Lisans silinsin mi?')">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                    <button class="btn danger small" type="submit">Sil</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if ($pages > 1): ?>
            <div class="pager">
                <?php for ($p = 1; $p <= $pages; ++$p): ?>
                    <?php if ($p === $page): ?>
                        <span class="btn small current" style="cursor:default"><?= $p ?></span>
                    <?php else: ?>
                        <a class="btn ghost small" href="<?= h($query_base . $p) ?>"><?= $p ?></a>
                    <?php endif; ?>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="panel">
        <div class="panel-head">
            <h2>Son Hareketler</h2>
            <span class="muted small">Son 40 dogrulama olayi</span>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>Zaman</th>
                    <th>Lisans</th>
                    <th>Olay</th>
                    <th class="hide-sm">Detay</th>
                    <th class="hide-sm">IP</th>
                </tr>
                </thead>
                <tbody>
                <?php if (!$events): ?>
                    <tr><td colspan="5" class="empty">Henuz olay yok. Loader ilk dogrulamayi yaptiginda burada gorunur.</td></tr>
                <?php endif; ?>
                <?php foreach ($events as $event): ?>
                    <?php [$event_label, $event_class] = vexis_event_meta((string)$event['action']); ?>
                    <tr>
                        <td class="muted small"><?= h(vexis_dt($event['created_at'])) ?></td>
                        <td><span class="key"><?= h($event['license_key']) ?></span></td>
                        <td><span class="tag <?= h($event_class) ?>"><?= h($event_label) ?></span></td>
                        <td class="hide-sm muted small break"><?= $event['detail'] ? h($event['detail']) : '-' ?></td>
                        <td class="hide-sm muted small"><?= h($event['ip']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="panel">
        <div class="panel-head">
            <h2>Banli IP'ler (API)</h2>
            <?php if ($bans): ?>
                <form method="post" onsubmit="return confirm('Tum banlar kaldirilsin mi?')" style="margin:0">
                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="unban_all">
                    <button class="btn danger small" type="submit">Tumunu Kaldir</button>
                </form>
            <?php endif; ?>
        </div>
        <div class="hint" style="margin-top:0;margin-bottom:14px">Bos / imzasiz / gecersiz istek atan IP'ler otomatik banlanir ve <span class="key"><?= h(vexis_ban_message()) ?></span> yaniti alir.</div>
        <div class="table-wrap">
            <table>
                <thead>
                <tr>
                    <th>IP</th>
                    <th>Sebep</th>
                    <th>Hit</th>
                    <th>Tarih</th>
                    <th style="text-align:right">Islem</th>
                </tr>
                </thead>
                <tbody>
                <?php if (!$bans): ?>
                    <tr><td colspan="5" class="empty">Ban yok.</td></tr>
                <?php endif; ?>
                <?php foreach ($bans as $ban): ?>
                    <tr>
                        <td><span class="key"><?= h($ban['ip']) ?></span></td>
                        <td><span class="tag bad"><?= h($ban['reason'] ?: 'banned') ?></span></td>
                        <td><?= (int)($ban['hits'] ?? 1) ?></td>
                        <td class="muted small"><?= h(vexis_dt($ban['created_at'])) ?></td>
                        <td>
                            <div class="actions">
                                <form method="post">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="action" value="unban">
                                    <input type="hidden" name="id" value="<?= (int)$ban['id'] ?>">
                                    <button class="btn ghost small" type="submit">Kaldir</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // live countdown for licence expiry cells
        (function () {
            function fmt(left) {
                if (left <= 0) return 'suresi bitti';
                var d = Math.floor(left / 86400);
                var h = Math.floor((left % 86400) / 3600);
                var m = Math.floor((left % 3600) / 60);
                var s = left % 60;
                if (d > 0) return d + 'g ' + h + 's ' + m + 'dk';
                if (h > 0) return h + 's ' + m + 'dk ' + s + 'sn';
                if (m > 0) return m + 'dk ' + s + 'sn';
                return s + 'sn';
            }
            function tick() {
                var now = Math.floor(Date.now() / 1000);
                document.querySelectorAll('[data-expires]').forEach(function (el) {
                    var exp = parseInt(el.getAttribute('data-expires'), 10) || 0;
                    var left = exp - now;
                    el.textContent = fmt(left);
                    el.classList.toggle('over', left <= 0);
                    el.classList.toggle('soon', left > 0 && left < 3600);
                });
            }
            tick();
            setInterval(tick, 1000);
        })();

        // custom plan field
        (function () {
            var plan = document.getElementById('plan');
            var wrap = document.getElementById('custom_wrap');
            if (!plan || !wrap) return;
            function sync() {
                var custom = plan.value === 'custom';
                wrap.style.display = custom ? 'block' : 'none';
            }
            plan.addEventListener('change', sync);
            sync();
        })();

        // copy key + toast
        (function () {
            function toast(text) {
                var el = document.createElement('div');
                el.textContent = text;
                el.style.cssText = 'position:fixed;left:50%;bottom:26px;transform:translateX(-50%);' +
                    'background:linear-gradient(135deg,#22d3ee,#8b5cf6);color:#04121b;font-weight:800;' +
                    'padding:10px 18px;border-radius:10px;z-index:9999;box-shadow:0 12px 30px rgba(34,211,238,.35)';
                document.body.appendChild(el);
                setTimeout(function () { el.remove(); }, 1500);
            }
            document.addEventListener('click', function (event) {
                var button = event.target.closest('.copy');
                if (!button) return;
                var key = button.getAttribute('data-key') || '';
                var done = function () { toast('Kopyalandi'); };
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(key).then(done, done);
                } else {
                    var area = document.createElement('textarea');
                    area.value = key;
                    document.body.appendChild(area);
                    area.select();
                    document.execCommand('copy');
                    document.body.removeChild(area);
                    done();
                }
            });
        })();
    </script>

    <?php endif; ?>
</div>
</body>
</html>
