<?php
/*
 * Single-file access-key API.
 * IMPORTANT: Change the password below before putting this file online.
 * All keys last exactly 24 hours. No environment variables or PHP packages required.
 */
$ADMIN_PASSWORD = 'MeraKeyApi-2026!Blue';
$volumePath = getenv('RAILWAY_VOLUME_MOUNT_PATH');
$STORE_FILE = ($volumePath !== false && $volumePath !== '')
    ? rtrim($volumePath, '/') . '/.key_store.php'
    : __DIR__ . '/.key_store.php';

header('Content-Type: application/json; charset=utf-8');

function reply(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
function request_data(): array {
    $data = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($data)) reply(400, ['ok'=>false, 'error'=>'Send JSON in the request body']);
    return $data;
}
function with_store(bool $write, callable $callback) {
    global $STORE_FILE;
    $fh = @fopen($STORE_FILE, 'c+');
    if (!$fh) reply(500, ['ok'=>false, 'error'=>'Cannot write key storage; make this folder writable']);
    if (!flock($fh, LOCK_EX)) { fclose($fh); reply(500, ['ok'=>false, 'error'=>'Storage lock failed']); }
    rewind($fh);
    $contents = stream_get_contents($fh);
    // The file starts with a PHP guard, so directly opening it over the web reveals no key data.
    $guard = "<?php http_response_code(404); exit; ?>\n";
    $json = str_starts_with($contents, $guard) ? substr($contents, strlen($guard)) : '';
    $records = $json !== '' ? json_decode($json, true) : [];
    if (!is_array($records)) $records = [];
    $result = $callback($records);
    if ($write) {
        rewind($fh);
        ftruncate($fh, 0);
        fwrite($fh, $guard . json_encode($records, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        fflush($fh);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}
function require_admin(array $data): void {
    global $ADMIN_PASSWORD;
    if ($ADMIN_PASSWORD === 'CHANGE_THIS_TO_YOUR_OWN_PASSWORD' || strlen($ADMIN_PASSWORD) < 10) {
        reply(500, ['ok'=>false, 'error'=>'Set your own admin password in index.php first']);
    }
    $given = (string)($data['password'] ?? '');
    if (!hash_equals($ADMIN_PASSWORD, $given)) reply(401, ['ok'=>false, 'error'=>'Wrong admin password']);
}
function now_utc(): DateTimeImmutable { return new DateTimeImmutable('now', new DateTimeZone('UTC')); }
function key_hash(string $key): string { return hash('sha256', $key); }

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
if ($method === 'GET' && ($path === '/health' || $path === '/')) reply(200, ['ok'=>true, 'message'=>'Key API is running']);

// Create a generated key or custom key. POST JSON: {"password":"...", "custom_key":"..."}
if ($method === 'POST' && ($path === '/create' || $path === '/v1/admin/keys')) {
    $data = request_data();
    require_admin($data);
    $key = isset($data['custom_key']) ? trim((string)$data['custom_key']) : rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
    if (!preg_match('/^[A-Za-z0-9_-]{8,64}$/', $key)) reply(400, ['ok'=>false, 'error'=>'Custom key must be 8-64 letters, numbers, _ or -']);
    $created = now_utc();
    $expires = $created->modify('+24 hours');
    $createdText = $created->format('Y-m-d\TH:i:s\Z');
    $expiresText = $expires->format('Y-m-d\TH:i:s\Z');
    $record = with_store(true, function (&$records) use ($key, $createdText, $expiresText, $data) {
        $hash = key_hash($key);
        foreach ($records as $item) if (($item['hash'] ?? '') === $hash) return null;
        $id = 1;
        foreach ($records as $item) $id = max($id, (int)($item['id'] ?? 0) + 1);
        $records[] = ['id'=>$id, 'hash'=>$hash, 'created_at'=>$createdText, 'expires_at'=>$expiresText, 'hwid'=>null, 'label'=>substr(trim((string)($data['label'] ?? '')),0,100), 'revoked'=>false];
        return ['id'=>$id];
    });
    if ($record === null) reply(409, ['ok'=>false, 'error'=>'That key already exists']);
    reply(201, ['ok'=>true, 'id'=>$record['id'], 'key'=>$key, 'created_at'=>$createdText, 'expires_at'=>$expiresText, 'duration_hours'=>24]);
}

// Compatible with the Android app: POST /v1/auth/key-login JSON {"key":"...", "hwid":"..."}
if ($method === 'POST' && ($path === '/v1/auth/key-login' || $path === '/verify')) {
    $data = request_data();
    $key = trim((string)($data['key'] ?? ''));
    $hwid = trim((string)($data['hwid'] ?? ''));
    if ($key === '' || strlen($key)>200 || $hwid === '' || strlen($hwid)>200) reply(400, ['ok'=>false, 'valid'=>false, 'error'=>'key and hwid are required']);
    $result = with_store(true, function (&$records) use ($key, $hwid) {
        $hash = key_hash($key);
        foreach ($records as &$item) {
            if (($item['hash'] ?? '') !== $hash) continue;
            if (!empty($item['revoked'])) return ['ok'=>false,'valid'=>false,'error'=>'Key was not accepted.'];
            if (new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) <= now_utc()) return ['ok'=>false,'valid'=>false,'error'=>'Key has expired.'];
            if ($item['hwid'] !== null && !hash_equals((string)$item['hwid'], $hwid)) return ['ok'=>false,'valid'=>false,'error'=>'Key is already linked to another device.'];
            if ($item['hwid'] === null) $item['hwid'] = $hwid;
            return ['ok'=>true,'valid'=>true,'expires_at'=>$item['expires_at']];
        }
        unset($item);
        return ['ok'=>false,'valid'=>false,'error'=>'Key was not accepted.'];
    });
    reply(200, $result);
}

// List keys (raw keys are never saved or shown).
if ($method === 'POST' && $path === '/list') {
    $data = request_data(); require_admin($data);
    $rows = with_store(false, function (&$records) {
        foreach ($records as &$item) {
            $item['expired'] = new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) <= now_utc();
            unset($item['hash']);
        }
        unset($item);
        return $records;
    });
    reply(200, ['ok'=>true, 'keys'=>$rows]);
}

// Revoke key: POST /revoke JSON {"password":"...", "id":1}
if ($method === 'POST' && $path === '/revoke') {
    $data = request_data(); require_admin($data);
    $id = (int)($data['id'] ?? 0);
    if ($id < 1) reply(400, ['ok'=>false, 'error'=>'A valid key id is required']);
    $found = with_store(true, function (&$records) use ($id) {
        foreach ($records as &$item) if ((int)$item['id'] === $id) { $item['revoked'] = true; unset($item); return true; }
        unset($item); return false;
    });
    if (!$found) reply(404, ['ok'=>false, 'error'=>'Key not found']);
    reply(200, ['ok'=>true, 'revoked'=>true, 'id'=>$id]);
}
reply(404, ['ok'=>false, 'error'=>'Endpoint not found']);
