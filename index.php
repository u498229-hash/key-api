<?php
/*
 * Single-file access-key API.
 * Public key creation is enabled; anyone who knows the endpoint can create keys.
 * All keys last exactly 24 hours. No environment variables or PHP packages required.
 */
$volumePath = getenv('RAILWAY_VOLUME_MOUNT_PATH');
$STORE_FILE = ($volumePath !== false && $volumePath !== '')
    ? rtrim($volumePath, '/') . '/.key_store.php'
    : __DIR__ . '/.key_store.php';

header('Content-Type: application/json; charset=utf-8');

// Admin password for the key list / revoke / device reset tools on /admin. Change it to any password you like.
$ADMIN_TOKEN = 'ADMIN';

// Secret used to sign the /connect token. Keep it the same as the secret string inside the app's Login() code.
// (This value is the one already present in your PRABIR__LOGIN_X999.h. For better safety change it here AND in the .h.)
$CONNECT_SECRET = 'Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E';

// How many times one key may move to a new device by itself (app reinstalled / new phone). 0 = first device only.
$MAX_DEVICE_CHANGES = 1;

// While a key is in use on one device, a different device is blocked until the first device has been silent
// (no successful /verify) for this many minutes. The app should call /verify on every launch (and ideally every
// few minutes while running) so the first device stays protected.
$TAKEOVER_WAIT_MINUTES = 30;

// Expired keys are deleted automatically as soon as they expire (0). Set 1 to keep them one more day.
$PURGE_DAYS = 0;

function reply(int $status, array $data): never {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
function request_data(): array {
    $raw = file_get_contents('php://input') ?: '';
    if (trim($raw) === '') return [];
    $data = json_decode($raw, true);
    if (!is_array($data)) reply(400, ['ok'=>false, 'error'=>'Send a valid JSON object']);
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
        // Automatic cleanup of expired keys (runs on every create / verify).
        global $PURGE_DAYS;
        $cut = now_utc()->modify('-' . (int)$PURGE_DAYS . ' days');
        $records = array_values(array_filter($records, function ($item) use ($cut) {
            try { return new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) > $cut; } catch (Throwable $e) { return false; }
        }));
        rewind($fh);
        ftruncate($fh, 0);
        fwrite($fh, $guard . json_encode($records, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        fflush($fh);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}
function admin_ok(): bool {
    global $ADMIN_TOKEN;
    $given = (string)($_SERVER['HTTP_X_API_KEY'] ?? $_GET['token'] ?? '');
    return $ADMIN_TOKEN !== '' && hash_equals($ADMIN_TOKEN, $given);
}
function now_utc(): DateTimeImmutable { return new DateTimeImmutable('now', new DateTimeZone('UTC')); }
function key_hash(string $key): string { return hash('sha256', $key); }

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

// Simple same-origin admin page for creating keys from a mobile browser.
if ($method === 'GET' && ($path === '/admin' || $path === '/admin/')) {
    header('Content-Type: text/html; charset=utf-8');
    echo <<<'HTML'
<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Key Admin</title>
<style>body{font:16px system-ui;max-width:520px;margin:32px auto;padding:0 16px;color:#17202a}input,button{box-sizing:border-box;width:100%;padding:13px;margin:8px 0;border:1px solid #bbb;border-radius:8px;font-size:16px}button{background:#1769e0;color:white;border:0;font-weight:700}small{color:#555}pre{white-space:pre-wrap;word-break:break-word;background:#f2f4f7;padding:12px;border-radius:8px}</style>
<h2>Create an access key</h2><p>Generated keys look like ALONE-CHEATS-ABC. Each key lasts 24 hours and binds to the first device that verifies it.</p>
<form id="f"><label>Custom key (leave empty to generate one)</label><input id="k" maxlength="64" placeholder="Example: ALONE-CHEATS-ABC"><label>Label (optional)</label><input id="l" maxlength="100" placeholder="Who is this for?"><button>Create key</button></form><pre id="out" hidden></pre>
<hr><h2>Manage keys</h2><p><small>Enter the admin password (ADMIN_TOKEN). Keys are stored hashed, so each row shows the key id, label and the last 3 letters.</small></p>
<input id="at" type="password" autocomplete="off" placeholder="Admin password"><button id="ld" type="button">Load keys</button><div id="keys"></div>
<input id="dk" placeholder="Or type a full key to delete, e.g. ALONE-CHEATS-ABCDEF" autocomplete="off"><button id="dkb" type="button" style="background:#c62828">Delete this key</button><pre id="dout" hidden></pre>
<style>.row{border:1px solid #ddd;border-radius:8px;padding:10px;margin:8px 0;font-size:14px;word-break:break-word}.row button{width:auto;display:inline-block;padding:8px 12px;margin:6px 6px 0 0;font-size:14px}.row .bad{background:#c62828}</style>
<script>(function(){const tk=document.getElementById('at'),box=document.getElementById('keys');async function api(p){const r=await fetch(p,{headers:{'X-API-KEY':tk.value}});return r.json();}async function load(){box.textContent='Loading…';let j;try{j=await api('/list');}catch(e){box.textContent='Could not connect';return;}if(!j.ok){box.textContent=j.error||'Error';return;}box.textContent='';if(!j.keys.length){box.textContent='No keys.';return;}j.keys.forEach(k=>{const d=document.createElement('div');d.className='row';const st=k.revoked?'REVOKED':(k.expired?'EXPIRED':(k.device_linked?'Device linked':'Not used yet'));d.textContent='#'+k.id+(k.hint?' ...'+k.hint:'')+(k.label?' · '+k.label:'')+' · '+st+' · device changes: '+k.device_changes+' · expires '+k.expires_at;d.appendChild(document.createElement('br'));const b1=document.createElement('button');b1.type='button';b1.textContent='Reset device';b1.onclick=async()=>{if(!confirm('Unlink key #'+k.id+' from its device?'))return;await api('/reset?id='+k.id);load();};const b2=document.createElement('button');b2.type='button';b2.className='bad';b2.textContent='Revoke';b2.onclick=async()=>{if(!confirm('Revoke key #'+k.id+'? It will stop working.'))return;await api('/revoke?id='+k.id);load();};const b3=document.createElement('button');b3.type='button';b3.className='bad';b3.textContent='Delete';b3.onclick=async()=>{if(!confirm('DELETE key #'+k.id+' permanently?'))return;await api('/delete?id='+k.id);load();};d.appendChild(b1);d.appendChild(b2);d.appendChild(b3);box.appendChild(d);});}document.getElementById('ld').onclick=load;document.getElementById('dkb').onclick=async()=>{const k=document.getElementById('dk').value.trim(),o=document.getElementById('dout');if(!k)return;if(!confirm('Delete key '+k+' permanently?'))return;o.hidden=false;try{const j=await api('/delete?key='+encodeURIComponent(k));o.textContent=j.ok?'Deleted.':(j.error||'Key not found.');if(j.ok){document.getElementById('dk').value='';if(box.childNodes.length)load();}}catch(e){o.textContent='Could not connect';}};})();</script>
<script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const o=document.getElementById('out');o.hidden=false;o.textContent='Creating…';const d={label:document.getElementById('l').value};const k=document.getElementById('k').value.trim();if(k)d.custom_key=k;try{const r=await fetch('/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});const j=await r.json();o.textContent=JSON.stringify(j,null,2);}catch(err){o.textContent='Could not connect: '+err;}});</script></html>
HTML;
    exit;
}
if ($method === 'GET' && ($path === '/health' || $path === '/')) reply(200, ['ok'=>true, 'message'=>'Key API is running']);

// Public creation: POST /create with empty body for a generated key, or custom_key for your own.
// GET /create also works now (generated key, or ?custom_key=...&label=...). POST works exactly as before.
if (($method === 'POST' && ($path === '/create' || $path === '/v1/admin/keys')) || ($method === 'GET' && $path === '/create')) {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    $data = $method === 'GET' ? $_GET : request_data();
    $generated = !isset($data['custom_key']) || trim((string)$data['custom_key']) === '';
    $key = $generated ? '' : trim((string)$data['custom_key']);
    if (!$generated && !preg_match('/^[A-Za-z0-9_-]{8,64}$/', $key)) reply(400, ['ok'=>false, 'error'=>'Custom key must be 8-64 letters, numbers, _ or -']);
    $created = now_utc();
    $expires = $created->modify('+24 hours');
    $createdText = $created->format('Y-m-d\TH:i:s\Z');
    $expiresText = $expires->format('Y-m-d\TH:i:s\Z');
    $record = with_store(true, function (&$records) use (&$key, $generated, $createdText, $expiresText, $data) {
        // Expired keys no longer need to occupy one of the three-letter generated-key slots.
        $now = now_utc();
        $records = array_values(array_filter($records, function ($item) use ($now) {
            return new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) > $now;
        }));
        if ($generated) {
            $used = [];
            foreach ($records as $item) $used[$item['hash'] ?? ''] = true;
            for ($i = 0; $i < 17576; $i++) {
                $candidate = 'ALONE-CHEATS-' . chr(random_int(65, 90)) . chr(random_int(65, 90)) . chr(random_int(65, 90));
                if (!isset($used[key_hash($candidate)])) { $key = $candidate; break; }
            }
            if ($key === '') return null;
        }
        $hash = key_hash($key);
        foreach ($records as $item) if (($item['hash'] ?? '') === $hash) return null;
        $id = 1;
        foreach ($records as $item) $id = max($id, (int)($item['id'] ?? 0) + 1);
        $records[] = ['id'=>$id, 'hash'=>$hash, 'created_at'=>$createdText, 'expires_at'=>$expiresText, 'hwid'=>null, 'hint'=>substr($key, -3), 'label'=>substr(trim((string)($data['label'] ?? '')),0,100), 'revoked'=>false];
        return ['id'=>$id];
    });
    if ($record === null) reply(409, ['ok'=>false, 'error'=>'That key already exists or no generated key is available; try again later']);
    reply(201, ['ok'=>true, 'id'=>$record['id'], 'key'=>$key, 'created_at'=>$createdText, 'expires_at'=>$expiresText, 'duration_hours'=>24]);
}

// Admin tools (need ADMIN_TOKEN): GET /list, /revoke?id=N, /reset?id=N, /delete?id=N or /delete?key=KEY  (password in header X-API-KEY or ?token=)
if (in_array($path, ['/list', '/revoke', '/reset', '/delete'], true) && in_array($method, ['GET', 'POST'], true)) {
    header('Cache-Control: no-store');
    if ($ADMIN_TOKEN === '') reply(403, ['ok'=>false, 'error'=>'Admin tools are disabled: set the ADMIN_TOKEN environment variable']);
    if (!admin_ok()) reply(403, ['ok'=>false, 'error'=>'Wrong admin password']);
    if ($path === '/list') {
        $rows = with_store(false, function (&$records) {
            $now = now_utc();
            $out = [];
            foreach ($records as $item) {
                try { $expired = new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) <= $now; } catch (Throwable $e) { $expired = true; }
                $out[] = ['id'=>$item['id'] ?? null, 'hint'=>$item['hint'] ?? '', 'label'=>$item['label'] ?? '', 'created_at'=>$item['created_at'] ?? '', 'expires_at'=>$item['expires_at'] ?? '', 'device_linked'=>($item['hwid'] ?? null) !== null, 'device_changes'=>(int)($item['rebinds'] ?? 0), 'revoked'=>!empty($item['revoked']), 'expired'=>$expired];
            }
            return $out;
        });
        reply(200, ['ok'=>true, 'count'=>count($rows), 'keys'=>$rows]);
    }
    if ($path === '/delete') {
        // Permanently delete one key: by id (?id=N) or by the full key text (?key=ALONE-CHEATS-XXXXXX).
        $id = (int)($_GET['id'] ?? 0);
        $byKey = trim((string)($_GET['key'] ?? ''));
        $hash = $byKey !== '' ? key_hash($byKey) : '';
        $done = with_store(true, function (&$records) use ($id, $hash) {
            foreach ($records as $i => $item) {
                $match = $hash !== '' ? (($item['hash'] ?? '') === $hash) : ($id > 0 && (int)($item['id'] ?? 0) === $id);
                if ($match) { array_splice($records, $i, 1); return true; }
            }
            return false;
        });
        reply($done ? 200 : 404, ['ok'=>$done, 'deleted'=>$done]);
    }
    $id = (int)($_GET['id'] ?? 0);
    $reset = $path === '/reset';
    $done = with_store(true, function (&$records) use ($id, $reset) {
        foreach ($records as &$item) {
            if ((int)($item['id'] ?? 0) !== $id) continue;
            if ($reset) { $item['hwid'] = null; $item['rebinds'] = 0; unset($item['last_seen']); } else { $item['revoked'] = true; }
            return true;
        }
        return false;
    });
    reply($done ? 200 : 404, ['ok'=>$done, ($reset ? 'reset_id' : 'revoked_id')=>$done ? $id : null]);
}

// Shared key check used by /verify, /v1/auth/key-login and /connect.
function verify_key(string $key, string $hwid): array {
    global $MAX_DEVICE_CHANGES, $TAKEOVER_WAIT_MINUTES;
    return with_store(true, function (&$records) use ($key, $hwid, $MAX_DEVICE_CHANGES, $TAKEOVER_WAIT_MINUTES) {
        $hash = key_hash($key);
        foreach ($records as &$item) {
            if (($item['hash'] ?? '') !== $hash) continue;
            if (!empty($item['revoked'])) return ['ok'=>false,'valid'=>false,'error'=>'Key was not accepted.'];
            if (new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) <= now_utc()) return ['ok'=>false,'valid'=>false,'error'=>'Key has expired.'];
            $nowT = now_utc();
            if ($item['hwid'] !== null && !hash_equals((string)$item['hwid'], $hwid)) {
                // A different device is asking for a key that is already linked.
                $changes = (int)($item['rebinds'] ?? 0);
                if ($changes >= $MAX_DEVICE_CHANGES) return ['ok'=>false,'valid'=>false,'error'=>'Key is already linked to another device.'];
                // Still in use on the first device? Then block the new device.
                try { $lastSeen = new DateTimeImmutable($item['last_seen'] ?? $item['created_at'], new DateTimeZone('UTC')); }
                catch (Throwable $e) { $lastSeen = $nowT->modify('-1 year'); }
                $idleSeconds = $nowT->getTimestamp() - $lastSeen->getTimestamp();
                $needSeconds = max(0, (int)$TAKEOVER_WAIT_MINUTES) * 60;
                if ($idleSeconds < $needSeconds) {
                    $left = (int)ceil(($needSeconds - $idleSeconds) / 60);
                    return ['ok'=>false,'valid'=>false,'error'=>'Key is currently in use on another device.','retry_after_minutes'=>$left];
                }
                // First device has been inactive: allow a limited number of device changes (reinstall / new phone).
                $item['hwid'] = $hwid;
                $item['rebinds'] = $changes + 1;
                $item['last_seen'] = $nowT->format('Y-m-d\TH:i:s\Z');
                return ['ok'=>true,'valid'=>true,'expires_at'=>$item['expires_at'],'device_changed'=>true,'device_changes_left'=>$MAX_DEVICE_CHANGES - $changes - 1];
            }
            if ($item['hwid'] === null) $item['hwid'] = $hwid;
            $item['last_seen'] = $nowT->format('Y-m-d\TH:i:s\Z');
            return ['ok'=>true,'valid'=>true,'expires_at'=>$item['expires_at']];
        }
        unset($item);
        return ['ok'=>false,'valid'=>false,'error'=>'Key was not accepted.'];
    });
}

// Compatible with the Android app: POST /v1/auth/key-login JSON {"key":"...", "hwid":"..."}
if ($method === 'POST' && ($path === '/v1/auth/key-login' || $path === '/verify')) {
    $data = request_data();
    $key = trim((string)($data['key'] ?? ''));
    $hwid = trim((string)($data['hwid'] ?? ''));
    if ($key === '' || strlen($key)>200 || $hwid === '' || strlen($hwid)>200) reply(400, ['ok'=>false, 'valid'=>false, 'error'=>'key and hwid are required']);
    reply(200, verify_key($key, $hwid));
}

// Loader-style login: POST /connect (form data: game, user_key, serial).
// Answers {"status":true,"data":{"token":md5("GAME-KEY-SERIAL-SECRET"),"rng":unix_time}} or {"status":false,"reason":"..."}.
// $CONNECT_SECRET must be the same string as the secret inside the app's Login() code.
if ($method === 'POST' && $path === '/connect') {
    $game = substr(trim((string)($_POST['game'] ?? '')), 0, 40);
    $key = trim((string)($_POST['user_key'] ?? ''));
    $serial = trim((string)($_POST['serial'] ?? ''));
    if ($game === '' || $key === '' || strlen($key) > 200 || $serial === '' || strlen($serial) > 200) reply(200, ['status'=>false, 'reason'=>'Missing game, user_key or serial']);
    $r = verify_key($key, $serial);
    if (empty($r['ok'])) reply(200, ['status'=>false, 'reason'=>$r['error'] ?? 'Key was not accepted.']);
    global $CONNECT_SECRET;
    reply(200, ['status'=>true, 'data'=>['token'=>md5($game . '-' . $key . '-' . $serial . '-' . $CONNECT_SECRET), 'rng'=>time(), 'expires_at'=>$r['expires_at'] ?? '']]);
}

reply(404, ['ok'=>false, 'error'=>'Endpoint not found']);
