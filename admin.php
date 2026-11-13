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
        --bg: #07090c;
        --panel: #0e1218;
        --panel-2: #121821;
        --line: rgba(255, 255, 255, .08);
        --text: #e7edf5;
        --muted: #8b97a8;
        --accent: #37b1da;
        --good: #4fd48b;
        --bad: #ff6b6b;
    }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        min-height: 100vh;
        background: radial-gradient(1200px 600px at 20% -10%, rgba(55, 177, 218, .12), transparent 60%), var(--bg);
        color: var(--text);
        font: 14px/1.45 "Segoe UI", system-ui, sans-serif;
    }
    a { color: var(--accent); text-decoration: none; }
    .wrap { max-width: 1220px; margin: 0 auto; padding: 28px 20px 60px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 22px; }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; letter-spacing: .08em; font-size: 15px; }
    .brand .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 14px var(--accent); }
    .muted { color: var(--muted); }
    .panel { background: linear-gradient(180deg, rgba(255,255,255,.03), transparent), var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 18px; }
    .grid { display: grid; gap: 14px; }
    .stats { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); margin-bottom: 16px; }
    .stat { padding: 14px 16px; }
    .stat .n { font-size: 24px; font-weight: 700; }
    .stat .l { color: var(--muted); font-size: 12px; letter-spacing: .04em; text-transform: uppercase; }
    h1 { font-size: 20px; margin: 0 0 4px; }
    h2 { font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin: 0 0 12px; }
    label { display: block; font-size: 12px; color: var(--muted); margin: 0 0 6px; }
    input, select {
        width: 100%; padding: 10px 12px; border-radius: 9px; border: 1px solid var(--line);
        background: var(--panel-2); color: var(--text); outline: none; font: inherit;
    }
    input:focus, select:focus { border-color: rgba(55, 177, 218, .65); }
    .row { display: grid; grid-template-columns: 1.4fr .8fr .7fr 1.2fr auto; gap: 10px; align-items: end; }
    .btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 6px;
        padding: 10px 16px; border-radius: 9px; border: 1px solid rgba(55, 177, 218, .45);
        background: rgba(55, 177, 218, .14); color: #dff6ff; font: inherit; font-weight: 600; cursor: pointer;
        white-space: nowrap;
    }
    .btn:hover { background: rgba(55, 177, 218, .24); }
    .btn.small { padding: 6px 10px; font-size: 12px; font-weight: 500; }
    .btn.ghost { border-color: var(--line); background: transparent; color: var(--muted); }
    .btn.danger { border-color: rgba(255, 107, 107, .35); background: rgba(255, 107, 107, .10); color: #ffc4c4; }
    table { width: 100%; border-collapse: collapse; margin-top: 6px; }
    th, td { padding: 10px 8px; text-align: left; border-bottom: 1px solid var(--line); vertical-align: middle; }
    th { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); font-weight: 600; }
    tbody tr:hover { background: rgba(255, 255, 255, .02); }
    .key { font-family: Consolas, "Courier New", monospace; font-size: 12.5px; color: #c8f0ff; }
    .tag { display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1px solid transparent; }
    .tag.good { color: var(--good); background: rgba(79, 212, 139, .10); border-color: rgba(79, 212, 139, .28); }
    .tag.bad { color: var(--bad); background: rgba(255, 107, 107, .10); border-color: rgba(255, 107, 107, .28); }
    .tag.muted { color: var(--muted); background: rgba(255, 255, 255, .04); border-color: var(--line); }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
    .toolbar { display: flex; gap: 10px; align-items: end; margin: 18px 0 6px; flex-wrap: wrap; }
    .toolbar form { display: flex; gap: 8px; align-items: end; flex: 1; }
    .toolbar .grow { flex: 1; }
    .pager { display: flex; gap: 8px; justify-content: center; margin-top: 16px; flex-wrap: wrap; }
    .flash { padding: 10px 14px; border: 1px solid rgba(79, 212, 139, .3); background: rgba(79, 212, 139, .08); border-radius: 10px; margin-bottom: 14px; color: #c9ffe0; }
    .err { padding: 10px 14px; border: 1px solid rgba(255, 107, 107, .3); background: rgba(255, 107, 107, .08); border-radius: 10px; margin-bottom: 14px; color: #ffd2d2; }
    .login { max-width: 380px; margin: 12vh auto 0; }
    .login h1 { margin-bottom: 16px; }
    .login .btn { width: 100%; margin-top: 14px; }
    .hint { margin-top: 12px; font-size: 12px; color: var(--muted); }
    .break { word-break: break-all; }
    @media (max-width: 900px) {
        .row { grid-template-columns: 1fr 1fr; }
        .hide-sm { display: none; }
    }
</style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <div class="brand"><span class="dot"></span> VEXIS <span class="muted" style="font-weight:400;letter-spacing:0">/ license panel</span></div>
        <?php if ($authed): ?>
            <a class="btn ghost small" href="admin.php?logout=1">Cikis</a>
        <?php endif; ?>
    </div>

    <?php if (!$authed): ?>
        <div class="panel login">
            <h1>Panel girisi</h1>
            <p class="muted" style="margin-top:0">Lisans olusturmak ve yonetmek icin sifre gir.</p>
            <?php if ($error !== ''): ?><div class="err"><?= h($error) ?></div><?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="login" value="1">
                <label for="password">Sifre</label>
                <input type="password" id="password" name="password" autofocus>
                <button class="btn" type="submit">Giris yap</button>
            </form>
            <div class="hint">Sifre: <code>api/config.php</code> icindeki <code>admin_password</code>.</div>
        </div>
    <?php else: ?>

    <?php if ($flash !== ''): ?><div class="flash"><?= h($flash) ?></div><?php endif; ?>
    <?php if ($error !== ''): ?><div class="err"><?= h($error) ?></div><?php endif; ?>

    <div class="grid stats">
        <div class="panel stat"><div class="n"><?= (int)$stats['total'] ?></div><div class="l">Toplam</div></div>
        <div class="panel stat"><div class="n"><?= (int)$stats['unused'] ?></div><div class="l">Kullanilmadi</div></div>
        <div class="panel stat"><div class="n"><?= (int)$stats['active'] ?></div><div class="l">Aktif</div></div>
        <div class="panel stat"><div class="n"><?= (int)$stats['expired'] ?></div><div class="l">Suresi dolan</div></div>
        <div class="panel stat"><div class="n"><?= (int)count($bans) ?></div><div class="l">Banli IP</div></div>
    </div>

    <div class="panel" style="margin-bottom:16px">
        <h2>Lisans olustur</h2>
        <form method="post" class="row">
            <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
            <input type="hidden" name="action" value="create">
            <div>
                <label for="plan">Sure</label>
                <select id="plan" name="plan" onchange="document.getElementById('custom_days_wrap').style.display = this.value === 'custom' ? 'block' : 'none'">
                    <option value="1d">1 Gun</option>
                    <option value="7d">7 Gun</option>
                    <option value="30d">30 Gun</option>
                    <option value="90d">90 Gun</option>
                    <option value="1y" selected>1 Yil</option>
                    <option value="lifetime">Unlimited</option>
                    <option value="custom">Ozel gun</option>
                </select>
            </div>
            <div>
                <label for="count">Adet</label>
                <input type="number" id="count" name="count" min="1" max="50" value="1">
            </div>
            <div id="custom_days_wrap" style="display:none">
                <label for="custom_days">Gun</label>
                <input type="number" id="custom_days" name="custom_days" min="1" max="3650" value="30">
            </div>
            <div>
                <label for="note">Not (opsiyonel)</label>
                <input type="text" id="note" name="note" maxlength="120" placeholder="ornek: ali / discord">
            </div>
            <div>
                <button class="btn" type="submit">Olustur</button>
            </div>
        </form>
        <div class="hint">Anahtar formati: <span class="key">VEXIS-XXXX-XXXXX-XXXXX</span>. Ilk aktivasyonda HWID'ye kilitlenir.</div>
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
                        <option value="expired" <?= $state_filter === 'expired' ? 'selected' : '' ?>>Suresi dolan</option>
                        <option value="revoked" <?= $state_filter === 'revoked' ? 'selected' : '' ?>>Iptal</option>
                    </select>
                </div>
                <button class="btn ghost" type="submit">Filtrele</button>
            </form>
            <a class="btn ghost small" href="admin.php">Temizle</a>
        </div>

        <table>
            <thead>
            <tr>
                <th>Lisans</th>
                <th>Plan</th>
                <th>Durum</th>
                <th class="hide-sm">HWID</th>
                <th>Bitis</th>
                <th class="hide-sm">Son gorulme</th>
                <th class="hide-sm">Not</th>
                <th style="text-align:right">Islem</th>
            </tr>
            </thead>
            <tbody>
            <?php if (!$rows): ?>
                <tr><td colspan="8" class="muted" style="text-align:center;padding:26px">Kayit yok.</td></tr>
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
                                <button class="btn ghost small" type="submit"><?= $row['status'] === 'revoked' ? 'Aktif et' : 'Iptal' ?></button>
                            </form>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                <input type="hidden" name="action" value="reset">
                                <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                <button class="btn ghost small" type="submit">HWID sifirla</button>
                            </form>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                <input type="hidden" name="action" value="extend">
                                <input type="hidden" name="id" value="<?= (int)$row['id'] ?>">
                                <button class="btn ghost small" type="submit">+30 gun</button>
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
                        <span class="btn small" style="cursor:default"><?= $p ?></span>
                    <?php else: ?>
                        <a class="btn ghost small" href="<?= h($query_base . $p) ?>"><?= $p ?></a>
                    <?php endif; ?>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
    </div>

    <div class="panel" style="margin-top:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px">
            <h2 style="margin:0">Banli IP'ler (API)</h2>
            <?php if ($bans): ?>
            <form method="post" onsubmit="return confirm('Tum banlar kaldirilsin mi?')">
                <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                <input type="hidden" name="action" value="unban_all">
                <button class="btn danger small" type="submit">Tumunu kaldir</button>
            </form>
            <?php endif; ?>
        </div>
        <div class="hint" style="margin-top:0;margin-bottom:10px">Bos / imzasiz / gecersiz istek atan IP'ler otomatik banlanir ve <span class="key"><?= h(vexis_ban_message()) ?></span> yaniti alir.</div>
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
                <tr><td colspan="5" class="muted" style="text-align:center;padding:18px">Ban yok.</td></tr>
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
                                <button class="btn ghost small" type="submit">Kaldir</button>
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
                button.textContent = 'Kopyalandi';
                setTimeout(function () { button.textContent = old; }, 1200);
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