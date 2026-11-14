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

$db = null;
$now = time();
$stats = ['total' => 0, 'unused' => 0, 'active' => 0, 'expired' => 0, 'revoked' => 0];
$q = '';
$state_filter = '';
$rows = [];
$bans = [];
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
                    if ($plan === 'custom') {
                        $days = max(1, min(3650, (int)($_POST['custom_days'] ?? 30)));
                    } elseif (isset($plans[$plan])) {
                        $days = (int)$plans[$plan]['days'];
                    } else {
                        $plan = '1y';
                        $days = 365;
                    }
                    $count = max(1, min(50, (int)($_POST['count'] ?? 1)));
                    $note = trim((string)($_POST['note'] ?? ''));
                    $note = function_exists('mb_substr') ? mb_substr($note, 0, 120, 'UTF-8') : substr($note, 0, 120);

                    $insert = $db->prepare('INSERT INTO licenses (license_key, plan, duration_days, created_at, status, note) VALUES (?, ?, ?, ?, ?, ?)');
                    $made = 0;
                    for ($i = 0; $i < $count; ++$i) {
                        $inserted = false;
                        for ($try = 0; $try < 10 && !$inserted; ++$try) {
                            $candidate = vexis_generate_key();
                            try {
                                $insert->execute([$candidate, $plan, $days, $now, 'active', $note]);
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
                    $message = $made . ' lisans olusturuldu.';
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
        --bg: #040608;
        --panel: rgba(13, 17, 23, 0.85);
        --panel-secondary: #161b22;
        --line: rgba(255, 255, 255, 0.08);
        --text: #e6edf3;
        --muted: #8b949e;
        
        --accent: #f59e0b; /* Sıcak Hardal / Turuncu Vurgu */
        --accent-hover: #d97706;
        --accent-glow: rgba(245, 158, 11, 0.25);
        
        --good: #2ea043;
        --bad: #f85149;
    }

    /* Özel Havalı İmleç (Custom Mouse Cursor) */
    body, button, input, select, a {
        cursor: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='%23f59e0b' stroke='%230d1117' stroke-width='2'%3E%3Cpolygon points='3 3 21 12 12 21 9 12 3 3'/%3E%3C/svg%3E"), auto !important;
    }

    * { box-sizing: border-box; }
    
    body {
        margin: 0;
        min-height: 100vh;
        background-color: var(--bg);
        background-image: 
            radial-gradient(circle at 15% 10%, rgba(245, 158, 11, 0.06) 0%, transparent 45%),
            radial-gradient(circle at 85% 90%, rgba(46, 160, 67, 0.04) 0%, transparent 45%);
        color: var(--text);
        font: 14px/1.5 "Inter", "Segoe UI", system-ui, sans-serif;
        animation: fadeIn 0.4s ease-out;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-4px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* Gradyan Yazı Efektleri */
    .gradient-text {
        background: linear-gradient(135deg, #ffffff, var(--accent));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
    }

    a { color: var(--accent); text-decoration: none; transition: 0.2s; }
    a:hover { color: var(--accent-hover); }
    
    .wrap { max-width: 1260px; margin: 0 auto; padding: 32px 20px 60px; }
    
    .topbar { 
        display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 24px; 
    }

    .brand { display: flex; align-items: center; gap: 12px; font-weight: 700; letter-spacing: 0.06em; font-size: 17px; color: #fff; }
    
    .brand .dot { 
        width: 10px; height: 10px; border-radius: 50%; 
        background: var(--accent); 
        box-shadow: 0 0 12px var(--accent); 
        animation: pulse-dot 2s infinite ease-in-out;
    }
    @keyframes pulse-dot {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(245, 158, 11, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(245, 158, 11, 0); }
    }

    .muted { color: var(--muted); }
    
    /* Siyahımsı Cam Efektli (Glassmorphism) Paneller */
    .panel { 
        background: var(--panel); 
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--line); 
        border-radius: 16px; 
        padding: 24px; 
        box-shadow: 0 12px 30px rgba(0, 0, 0, 0.5);
        transition: transform 0.25s ease, border-color 0.25s ease;
    }
    .panel:hover {
        border-color: rgba(255, 255, 255, 0.15);
        transform: translateY(-2px);
    }

    .grid { display: grid; gap: 16px; }
    .stats { grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); margin-bottom: 20px; }
    
    .stat { 
        padding: 18px 20px; 
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.9) 0%, rgba(13, 17, 23, 0.9) 100%);
        border-left: 4px solid var(--accent);
    }
    .stat .n { font-size: 28px; font-weight: 800; color: #fff; letter-spacing: -0.02em; }
    .stat .l { color: var(--muted); font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase; margin-top: 4px; font-weight: 600; }
    
    h1 { font-size: 24px; margin: 0 0 6px; font-weight: 800; color: #fff; }
    h2 { font-size: 12px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); margin: 0 0 14px; font-weight: 700; }
    
    label { display: block; font-size: 11px; font-weight: 600; color: var(--muted); margin: 0 0 6px; letter-spacing: 0.04em; text-transform: uppercase; }
    
    input, select {
        width: 100%; padding: 11px 14px; border-radius: 10px; border: 1px solid var(--line);
        background: var(--panel-secondary); color: var(--text); outline: none; font: inherit;
        transition: all 0.2s ease;
    }
    input:focus, select:focus { 
        border-color: var(--accent); 
        box-shadow: 0 0 0 3px var(--accent-glow); 
    }

    .row { display: grid; grid-template-columns: 1.4fr .8fr .7fr 1.2fr auto; gap: 12px; align-items: end; }
    
    /* Vurgu Butonları (Hardal/Turuncu CTA) */
    .btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 6px;
        padding: 11px 20px; border-radius: 10px; border: 1px solid var(--accent);
        background: var(--accent); color: #0d1117; font: inherit; font-weight: 700; cursor: pointer;
        white-space: nowrap; transition: all 0.2s ease;
        box-shadow: 0 4px 14px rgba(245, 158, 11, 0.3);
    }
    .btn:hover { 
        background: var(--accent-hover); 
        border-color: var(--accent-hover);
        color: #fff;
        transform: translateY(-2px);
        box-shadow: 0 6px 18px rgba(245, 158, 11, 0.4);
    }
    .btn:active { transform: translateY(0); }
    .btn.small { padding: 7px 14px; font-size: 12px; font-weight: 600; }
    
    .btn.ghost { 
        border-color: var(--line); 
        background: rgba(255, 255, 255, 0.03); 
        color: var(--muted); 
        box-shadow: none;
    }
    .btn.ghost:hover { 
        background: rgba(255, 255, 255, 0.08); 
        color: #fff; 
        border-color: rgba(255, 255, 255, 0.2);
    }
    
    .btn.danger { 
        border-color: var(--bad); 
        background: rgba(248, 81, 73, 0.15); 
        color: var(--bad); 
        box-shadow: 0 4px 14px rgba(248, 81, 73, 0.2);
    }
    .btn.danger:hover { 
        background: var(--bad); 
        border-color: var(--bad);
        color: #fff;
        box-shadow: 0 6px 18px rgba(248, 81, 73, 0.35); 
    }

    table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 8px; }
    th, td { padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--line); vertical-align: middle; }
    th { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); font-weight: 700; }
    
    tbody tr { transition: background-color 0.15s ease; }
    tbody tr:hover { background: rgba(255, 255, 255, 0.02); }
    
    .key { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; color: #fde047; font-weight: 600; background: var(--panel-secondary); padding: 4px 8px; border-radius: 6px; display: inline-block; border: 1px solid var(--line); }
    
    .tag { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; border: 1px solid transparent; letter-spacing: 0.02em; }
    .tag.good { color: #3fb950; background: rgba(46, 160, 67, 0.15); border-color: rgba(46, 160, 67, 0.3); }
    .tag.bad { color: #f85149; background: rgba(248, 81, 73, 0.15); border-color: rgba(248, 81, 73, 0.3); }
    .tag.muted { color: var(--muted); background: rgba(255, 255, 255, 0.04); border-color: var(--line); }

    .actions { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
    
    .toolbar { display: flex; gap: 12px; align-items: end; margin: 20px 0 8px; flex-wrap: wrap; }
    .toolbar form { display: flex; gap: 10px; align-items: end; flex: 1; }
    .toolbar .grow { flex: 1; }
    
    .pager { display: flex; gap: 6px; justify-content: center; margin-top: 20px; flex-wrap: wrap; }
    
    .flash { 
        padding: 12px 16px; border: 1px solid rgba(46, 160, 67, 0.3); background: rgba(46, 160, 67, 0.1); 
        border-radius: 12px; margin-bottom: 16px; color: #3fb950; font-weight: 600;
        animation: fadeIn 0.3s ease-out;
    }
    .err { 
        padding: 12px 16px; border: 1px solid rgba(248, 81, 73, 0.3); background: rgba(248, 81, 73, 0.1); 
        border-radius: 12px; margin-bottom: 16px; color: #f85149; font-weight: 600;
        animation: fadeIn 0.3s ease-out;
    }
    
    .login { max-width: 400px; margin: 15vh auto 0; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
    .login h1 { margin-bottom: 8px; }
    .login .btn { width: 100%; margin-top: 16px; }
    
    .break { word-break: break-all; }
    .hint { font-size: 12px; color: var(--muted); margin-top: 10px; }

    @media (max-width: 900px) {
        .row { grid-template-columns: 1fr 1fr; }
        .hide-sm { display: none; }
    }
</style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <div class="brand"><span class="dot"></span> <span class="gradient-text">VEXIS</span> <span class="muted" style="font-weight:400;letter-spacing:0">/ license panel</span></div>
        <?php if ($authed): ?>
            <a class="btn ghost small" href="admin.php?logout=1">Çıkış</a>
        <?php endif; ?>
    </div>

    <?php if (!$authed): ?>
        <div class="panel login">
            <h1 class="gradient-text">Panel Girişi</h1>
            <p class="muted" style="margin-top:0">Lisans oluşturmak ve yönetmek için şifre gir.</p>
            <?php if ($error !== ''): ?><div class="err"><?= h($error) ?></div><?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="login" value="1">
                <label for="password">Şifre</label>
                <input type="password" id="password" name="password" autofocus>
                <button class="btn" type="submit">Giriş Yap</button>
            </form>
        </div>
    <?php else: ?>

    <?php if ($flash !== ''): ?><div class="flash"><?= h($flash) ?></div><?php endif; ?>
    <?php if ($error !== ''): ?><div class="err"><?= h($error) ?></div><?php endif; ?>

    <div class="grid stats">
        <div class="panel stat"><div class="n"><?= (int)$stats['total'] ?></div><div class="l">Toplam</div></div>
        <div class="panel stat"><div class="n"><?= (int)$stats['unused'] ?></div><div class="l">Kullanılmadı</div></div>
        <div class="panel stat"><div class="n"><?= (int)$stats['active'] ?></div><div class="l">Aktif</div></div>
        <div class="panel stat"><div class="n"><?= (int)$stats['expired'] ?></div><div class="l">Süresi Dolan</div></div>
        <div class="panel stat"><div class="n"><?= (int)count($bans) ?></div><div class="l">Banlı IP</div></div>
    </div>

    <div class="panel" style="margin-bottom:20px">
        <h2>Lisans Oluştur</h2>
        <form method="post" class="row">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <input type="hidden" name="action" value="create">
            <div>
                <label for="plan">Süre</label>
                <select id="plan" name="plan" onchange="document.getElementById('custom_days_wrap').style.display = this.value === 'custom' ? 'block' : 'none'">
                    <option value="1d">1 Gün</option>
                    <option value="7d">7 Gün</option>
                    <option value="30d">30 Gün</option>
                    <option value="90d">90 Gün</option>
                    <option value="1y" selected>1 Yıl</option>
                    <option value="lifetime">Unlimited</option>
                    <option value="custom">Özel Gün</option>
                </select>
            </div>
            <div>
                <label for="count">Adet</label>
                <input type="number" id="count" name="count" min="1" max="50" value="1">
            </div>
            <div id="custom_days_wrap" style="display:none">
                <label for="custom_days">Gün</label>
                <input type="number" id="custom_days" name="custom_days" min="1" max="3650" value="30">
            </div>
            <div>
                <label for="note">Not (opsiyonel)</label>
                <input type="text" id="note" name="note" maxlength="120" placeholder="ornek: ali / discord">
            </div>
            <div>
                <button class="btn" type="submit">Oluştur</button>
            </div>
        </form>
        <div class="hint">Anahtar formatı: <span class="key">VEXIS-XXXX-XXXXX-XXXXX</span>. İlk aktivasyonda HWID'ye kilitlenir.</div>
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
                        <option value="unused" <?= $state_filter === 'unused' ? 'selected' : '' ?>>Kullanılmadı</option>
                        <option value="active" <?= $state_filter === 'active' ? 'selected' : '' ?>>Aktif</option>
                        <option value="expired" <?= $state_filter === 'expired' ? 'selected' : '' ?>>Süresi Dolan</option>
                        <option value="revoked" <?= $state_filter === 'revoked' ? 'selected' : '' ?>>İptal</option>
                    </select>
                </div>
                <button class="btn ghost" type="submit">Filtrele</button>
            </form>
            <a class="btn ghost small" href="admin.php" style="display:inline-flex;align-items:center;height:38px;">Temizle</a>
        </div>

        <table>
            <thead>
            <tr>
                <th>Lisans</th>
                <th>Plan</th>
                <th>Durum</th>
                <th class="hide-sm">HWID</th>
                <th>Bitiş</th>
                <th class="hide-sm">Son Görülme</th>
                <th class="hide-sm">Not</th>
                <th style="text-align:right">İşlem</th>
            </tr>
            </thead>
            <tbody>
            <?php if (!$rows): ?>
                <tr><td colspan="8" class="muted" style="text-align:center;padding:32px">Kayıt yok.</td></tr>
            <?php endif; ?>
            <?php foreach ($rows as $row): ?>
                <?php
                [$state_label, $state_class] = vexis_row_state($row, $now);
                $expires_label = $row['expires_at'] === null
                    ? (((int)$row['duration_days'] <= 0) ? 'Unlimited' : '-')
                    : h(vexis_dt($row['expires_at'])) . '<br><span class="muted" style="font-size:11px">' . h(vexis_remaining_label((int)$row['expires_at'])) . '</span>';
                ?>
                <tr>
                    <td>
                        <div class="key"><?= h($row['license_key']) ?></div>
                        <button class="btn ghost small copy" type="button" data-key="<?= h($row['license_key']) ?>" style="margin-top:6px">Kopyala</button>
                    </td>
                    <td><?= h(vexis_plan_label((string)$row['plan'], (int)$row['duration_days'])) ?></td>
                    <td><span class="tag <?= h($state_class) ?>"><?= h($state_label) ?></span></td>
                    <td class="hide-sm break"><span class="muted" style="font-size:12px"><?= $row['hwid'] ? h($row['hwid']) : '-' ?></span></td>
                    <td><?= $expires_label ?></td>
                    <td class="hide-sm muted" style="font-size:12px"><?= h(vexis_dt($row['last_seen'])) ?></td>
                    <td class="hide-sm muted" style="font-size:12px"><?= $row['note'] ? h($row['note']) : '-' ?></td>
                    <td>
                        <div class="actions">
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                <input type="hidden" name="action" value="<?= $row['status'] === 'revoked' ? 'activate' : 'revoke' ?>">
                                <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                <button class="btn ghost small" type="submit"><?= $row['status'] === 'revoked' ? 'Aktif Et' : 'İptal' ?></button>
                            </form>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                <input type="hidden" name="action" value="reset">
                                <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                <button class="btn ghost small" type="submit">HWID Sıfırla</button>
                            </form>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                <input type="hidden" name="action" value="extend">
                                <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                <button class="btn ghost small" type="submit">+30 Gün</button>
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

        <?php if ($pages > 1): ?>
            <div class="pager">
                <?php for ($p = 1; $p <= $pages; ++$p): ?>
                    <?php if ($p === $page): ?>
                        <span class="btn small" style="cursor:default; background:var(--accent); color:#0d1117; border-color:var(--accent);"><?= $p ?></span>
                    <?php else: ?>
                        <a class="btn ghost small" href="<?= h($query_base . $p) ?>"><?= $p ?></a>
                    <?php endif; ?>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="panel" style="margin-top:20px">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px">
            <h2 style="margin:0">Banlı IP'ler (API)</h2>
            <?php if ($bans): ?>
            <form method="post" onsubmit="return confirm('Tüm banlar kaldırılsın mı?')">
                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="unban_all">
                <button class="btn danger small" type="submit">Tümünü Kaldır</button>
            </form>
            <?php endif; ?>
        </div>
        <div class="hint" style="margin-top:0;margin-bottom:12px">Boş / imzasız / geçersiz istek atan IP'ler otomatik banlanır ve <span class="key"><?= h(vexis_ban_message()) ?></span> yanıtı alır.</div>
        <table>
            <thead>
            <tr>
                <th>IP</th>
                <th>Sebep</th>
                <th>Hit</th>
                <th>Tarih</th>
                <th style="text-align:right">İşlem</th>
            </tr>
            </thead>
            <tbody>
            <?php if (!$bans): ?>
                <tr><td colspan="5" class="muted" style="text-align:center;padding:20px">Ban yok.</td></tr>
            <?php endif; ?>
            <?php foreach ($bans as $ban): ?>
                <tr>
                    <td class="key"><?= h($ban['ip']) ?></td>
                    <td><span class="tag bad"><?= h($ban['reason'] ?: 'banned') ?></span></td>
                    <td><?= (int)($ban['hits'] ?? 1) ?></td>
                    <td class="muted" style="font-size:12px"><?= h(vexis_dt($ban['created_at'])) ?></td>
                    <td>
                        <div class="actions">
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                <input type="hidden" name="action" value="unban">
                                <input type="hidden" name="id" value="<?= (int)$ban['id'] ?>">
                                <button class="btn ghost small" type="submit">Kaldır</button>
                            </form>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <script>
        document.addEventListener('click', function (event) {
            var button = event.target.closest('.copy');
            if (!button) return;
            var key = button.getAttribute('data-key') || '';
            var done = function () {
                var old = button.textContent;
                button.textContent = 'Kopyalandı';
                button.style.borderColor = 'var(--good)';
                button.style.color = 'var(--good)';
                setTimeout(function () { 
                    button.textContent = old; 
                    button.style.borderColor = '';
                    button.style.color = '';
                }, 1400);
            };
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
    </script>

    <?php endif; ?>
</div>
</body>
</html>
