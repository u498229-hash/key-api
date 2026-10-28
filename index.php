<?php
/*
 * Single-file access-key API.
 * Public key creation is enabled; anyone who knows the endpoint can create keys.
 * Creation supports custom duration and device limits. No environment variables or PHP packages required.
 */
$volumePath = getenv('RAILWAY_VOLUME_MOUNT_PATH');
$STORE_FILE = ($volumePath !== false && $volumePath !== '')
    ? rtrim($volumePath, '/') . '/.key_store.php'
    : __DIR__ . '/.key_store.php';

header('Content-Type: application/json; charset=utf-8');

// Admin password for the key list / revoke / device reset tools on /admin. Change it to any password you like.
$ADMIN_TOKEN = 'ADMIN';

// How many times one key may move to a new device by itself (app reinstalled / new phone). 0 = first device only.
$MAX_DEVICE_CHANGES = 1;

// While a key is in use on one device, a different device is blocked until the first device has been silent
// (no successful /verify) for this many minutes. The app should call /verify on every launch (and ideally every
// few minutes while running) so the first device stays protected.
$TAKEOVER_WAIT_MINUTES = 30;

// Expired keys are deleted automatically as soon as they expire (0). Set 1 to keep them one more day.
$PURGE_DAYS = 0;

function reply(int $status, array $data): never {
    if (isset($data['error']) && !isset($data['detail'])) $data['detail'] = $data['error'];
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
            // A first-login timer has no expiry until its first successful verify.
            if (empty($item['expires_at'])) return true;
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
    <h2>Create an access key</h2><p>Generated keys can have a custom duration and device limit.</p>
<form id="f"><label>Custom key (leave empty to generate one)</label><input id="k" maxlength="64" placeholder="Example: ALONE-CHEATS-ABC"><label>Duration</label><input id="h" type="number" min="1" value="24"><label>Unit</label><select id="u" style="box-sizing:border-box;width:100%;padding:13px;margin:8px 0;border:1px solid #bbb;border-radius:8px;font-size:16px"><option value="minutes">Minutes</option><option value="hours" selected>Hours</option><option value="days">Days</option><option value="months">Months</option></select><label>Devices</label><input id="dv" type="number" min="1" value="1"><label>Label (optional)</label><input id="l" maxlength="100" placeholder="Who is this for?"><button>Create key</button></form><pre id="out" hidden></pre>
<hr><h2>Manage keys</h2><p><small>Enter the admin password (ADMIN_TOKEN). Keys are stored hashed, so each row shows the key id, label and the last 3 letters.</small></p>
<input id="at" type="password" autocomplete="off" placeholder="Admin password"><button id="ld" type="button">Load keys</button><div id="keys"></div>
<input id="dk" placeholder="Or type a full key to delete, e.g. ALONE-CHEATS-ABCDEF" autocomplete="off"><button id="dkb" type="button" style="background:#c62828">Delete this key</button><pre id="dout" hidden></pre>
<style>.row{border:1px solid #ddd;border-radius:8px;padding:10px;margin:8px 0;font-size:14px;word-break:break-word}.row button{width:auto;display:inline-block;padding:8px 12px;margin:6px 6px 0 0;font-size:14px}.row .bad{background:#c62828}</style>
<script>(function(){const tk=document.getElementById('at'),box=document.getElementById('keys');async function api(p){const r=await fetch(p,{headers:{'X-API-KEY':tk.value}});return r.json();}async function load(){box.textContent='Loading…';let j;try{j=await api('/list');}catch(e){box.textContent='Could not connect';return;}if(!j.ok){box.textContent=j.error||'Error';return;}box.textContent='';if(!j.keys.length){box.textContent='No keys.';return;}j.keys.forEach(k=>{const d=document.createElement('div');d.className='row';const st=k.revoked?'REVOKED':(k.status==='blocked'?'BLOCKED':(k.status==='disabled'?'DISABLED':(k.expired?'EXPIRED':(k.started_at?'ACTIVE':'NOT STARTED'))));const fmt=v=>v?new Date(v).toLocaleString():'—';const used=Number(k.devices_used||0),limit=Number(k.max_devices||1),remain=k.expires_at?Math.max(0,new Date(k.expires_at)-Date.now()):0;const left=remain?((Math.floor(remain/3600000)+'h '+Math.floor((remain%3600000)/60000)+'m')):'—';d.innerHTML='<strong>#'+k.id+(k.hint?' ...'+k.hint:'')+'</strong>'+(k.label?' · '+k.label:'')+'<br><b>Status:</b> '+st+' · <b>Devices:</b> '+used+'/'+limit+'<br><b>Duration:</b> '+(k.duration||'—')+' '+(k.duration_unit||'')+' · <b>Remaining:</b> '+left+'<br><b>Timer started:</b> '+fmt(k.started_at)+'<br><b>Expires:</b> '+fmt(k.expires_at)+'<br><b>Device changes:</b> '+(k.device_changes||0);d.appendChild(document.createElement('br'));const b1=document.createElement('button');b1.type='button';b1.textContent='Reset device';b1.onclick=async()=>{if(!confirm('Unlink key #'+k.id+' from its device?'))return;await api('/reset?id='+k.id);load();};const b2=document.createElement('button');b2.type='button';b2.className='bad';b2.textContent='Revoke';b2.onclick=async()=>{if(!confirm('Revoke key #'+k.id+'? It will stop working.'))return;await api('/revoke?id='+k.id);load();};const b3=document.createElement('button');b3.type='button';b3.className='bad';b3.textContent='Delete';b3.onclick=async()=>{if(!confirm('DELETE key #'+k.id+' permanently?'))return;await api('/delete?id='+k.id);load();};d.appendChild(b1);d.appendChild(b2);d.appendChild(b3);box.appendChild(d);});}document.getElementById('ld').onclick=load;document.getElementById('dkb').onclick=async()=>{const k=document.getElementById('dk').value.trim(),o=document.getElementById('dout');if(!k)return;if(!confirm('Delete key '+k+' permanently?'))return;o.hidden=false;try{const j=await api('/delete?key='+encodeURIComponent(k));o.textContent=j.ok?'Deleted.':(j.error||'Key not found.');if(j.ok){document.getElementById('dk').value='';if(box.childNodes.length)load();}}catch(e){o.textContent='Could not connect';}};})();</script>
<script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const o=document.getElementById('out');o.hidden=false;o.textContent='Creating…';const d={duration:Number(document.getElementById('h').value),unit:document.getElementById('u').value,devices:Number(document.getElementById('dv').value),label:document.getElementById('l').value};const k=document.getElementById('k').value.trim();if(k)d.custom_key=k;try{const r=await fetch('/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});const j=await r.json();o.textContent=JSON.stringify(j,null,2);}catch(err){o.textContent='Could not connect: '+err;}});</script></html>
HTML;
    exit;
}
if ($method === 'GET' && ($path === '/health' || $path === '/')) reply(200, ['ok'=>true, 'message'=>'Key API is running']);

// Public creation: /create or /createhours with custom_key (or key), hours and devices.
// Compact form is also supported: /createhours5?key=MY-KEY&devices=100
$compactHours = null;
$compactDevices = null;
if (preg_match('#^/createhours([0-9]+)(?:devices?|/devices?)([0-9]+)$#', $path, $m)) {
    $compactHours = (int)$m[1];
    $compactDevices = (int)$m[2];
} elseif (preg_match('#^/createhours([0-9]+)$#', $path, $m)) {
    $compactHours = (int)$m[1];
}
$isCreateEndpoint = $path === '/create' || $path === '/createhours' || $path === '/v1/admin/keys' || $compactHours !== null;
if (($method === 'POST' && $isCreateEndpoint) || ($method === 'GET' && $isCreateEndpoint && $path !== '/v1/admin/keys')) {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    $data = $method === 'GET' ? $_GET : request_data();
    $requestedKey = isset($data['custom_key']) ? $data['custom_key'] : ($data['key'] ?? '');
    $generated = trim((string)$requestedKey) === '';
    $key = $generated ? '' : trim((string)$requestedKey);
    if (!$generated && !preg_match('/^[A-Za-z0-9_-]{8,64}$/', $key)) reply(400, ['ok'=>false, 'error'=>'Custom key must be 8-64 letters, numbers, _ or -']);
    $hours = filter_var($compactHours ?? ($data['hours'] ?? 24), FILTER_VALIDATE_INT);
    $devices = filter_var($compactDevices ?? ($data['devices'] ?? 1), FILTER_VALIDATE_INT);
    if ($hours === false || $hours < 1) reply(400, ['ok'=>false, 'error'=>'hours must be a positive integer']);
    if ($devices === false || $devices < 1) reply(400, ['ok'=>false, 'error'=>'devices must be a positive integer']);
    $unit = strtolower(trim((string)($data['unit'] ?? $data['duration_unit'] ?? 'hours')));
    if ($unit === 'hour') $unit = 'hours';
    if ($unit === 'minute') $unit = 'minutes';
    if ($unit === 'day') $unit = 'days';
    if ($unit === 'month') $unit = 'months';
    if (!in_array($unit, ['minutes', 'hours', 'days', 'months'], true)) reply(400, ['ok'=>false, 'error'=>'unit must be minutes, hours, days, or months']);
    $duration = filter_var($data['duration'] ?? ($compactHours ?? ($data['hours'] ?? 24)), FILTER_VALIDATE_INT);
    if ($duration === false || $duration < 1) reply(400, ['ok'=>false, 'error'=>'duration must be a positive integer']);
    $created = now_utc();
    $expires = null; // Timer starts on first successful login.
    $createdText = $created->format('Y-m-d\TH:i:s\Z');
    $expiresText = null;
    $record = with_store(true, function (&$records) use (&$key, $generated, $createdText, $expiresText, $data, $devices, $duration, $unit) {
        // Expired keys no longer need to occupy one of the three-letter generated-key slots.
        $now = now_utc();
        $records = array_values(array_filter($records, function ($item) use ($now) {
            if (empty($item['expires_at'])) return true;
            try { return new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) > $now; } catch (Throwable $e) { return false; }
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
        $records[] = ['id'=>$id, 'hash'=>$hash, 'created_at'=>$createdText, 'started_at'=>null, 'expires_at'=>$expiresText, 'duration'=>$duration, 'duration_unit'=>$unit, 'status'=>'active', 'hwid'=>null, 'device_hwids'=>[], 'max_devices'=>$devices, 'hint'=>substr($key, -3), 'label'=>substr(trim((string)($data['label'] ?? '')),0,100), 'revoked'=>false];
        return ['id'=>$id];
    });
    if ($record === null) reply(409, ['ok'=>false, 'error'=>'That key already exists or no generated key is available; try again later']);
    reply(201, ['ok'=>true, 'id'=>$record['id'], 'key'=>$key, 'created_at'=>$createdText, 'expires_at'=>$expiresText, 'duration'=>$duration, 'duration_unit'=>$unit, 'timer'=>'starts_on_first_login', 'max_devices'=>$devices]);
}

// Admin tools (need ADMIN_TOKEN): list, reset, revoke, block, disable, enable, delete.
if (in_array($path, ['/list', '/revoke', '/reset', '/block', '/disable', '/enable', '/delete'], true) && in_array($method, ['GET', 'POST'], true)) {
    header('Cache-Control: no-store');
    if ($ADMIN_TOKEN === '') reply(403, ['ok'=>false, 'error'=>'Admin tools are disabled: set the ADMIN_TOKEN environment variable']);
    if (!admin_ok()) reply(403, ['ok'=>false, 'error'=>'Wrong admin password']);
    if ($path === '/list') {
        $rows = with_store(false, function (&$records) {
            $now = now_utc();
            $out = [];
            foreach ($records as $item) {
                try { $expired = !empty($item['expires_at']) && new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) <= $now; } catch (Throwable $e) { $expired = true; }
                $out[] = ['id'=>$item['id'] ?? null, 'hint'=>$item['hint'] ?? '', 'label'=>$item['label'] ?? '', 'status'=>$item['status'] ?? (!empty($item['revoked']) ? 'revoked' : 'active'), 'created_at'=>$item['created_at'] ?? '', 'started_at'=>$item['started_at'] ?? null, 'expires_at'=>$item['expires_at'] ?? null, 'duration'=>$item['duration'] ?? null, 'duration_unit'=>$item['duration_unit'] ?? null, 'device_linked'=>($item['hwid'] ?? null) !== null, 'devices_used'=>is_array($item['device_hwids'] ?? null) ? count($item['device_hwids']) : (($item['hwid'] ?? null) !== null ? 1 : 0), 'max_devices'=>(int)($item['max_devices'] ?? 1), 'device_changes'=>(int)($item['rebinds'] ?? 0), 'revoked'=>!empty($item['revoked']), 'expired'=>$expired];
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
    $newStatus = $path === '/block' ? 'blocked' : ($path === '/disable' ? 'disabled' : ($path === '/enable' ? 'active' : null));
    $done = with_store(true, function (&$records) use ($id, $reset, $newStatus) {
        foreach ($records as &$item) {
            if ((int)($item['id'] ?? 0) !== $id) continue;
            if ($reset) { $item['hwid'] = null; $item['device_hwids'] = []; $item['rebinds'] = 0; if (array_key_exists('duration', $item)) { $item['started_at'] = null; $item['expires_at'] = null; $item['status'] = 'active'; } unset($item['last_seen']); } else { $item['revoked'] = true; $item['status'] = 'revoked'; }
            if ($newStatus !== null) $item['status'] = $newStatus;
            return true;
        }
        return false;
    });
    $resultField = $reset ? 'reset_id' : ($newStatus !== null ? 'status_id' : 'revoked_id');
    $payload = ['ok'=>$done, $resultField=>$done ? $id : null];
    if ($newStatus !== null) $payload['status'] = $done ? $newStatus : null;
    reply($done ? 200 : 404, $payload);
}

// Compatible with the Android app: POST /v1/auth/key-login JSON {"key":"...", "hwid":"..."}
if (($path === '/v1/auth/key-login' || $path === '/verify') && $method === 'OPTIONS') {
    header('Allow: POST, OPTIONS');
    reply(204, []);
}
if (($path === '/v1/auth/key-login' || $path === '/verify') && $method !== 'POST') {
    header('Allow: POST, OPTIONS');
    reply(405, ['ok'=>false, 'valid'=>false, 'error'=>'Method not allowed; use POST']);
}
if ($method === 'POST' && ($path === '/v1/auth/key-login' || $path === '/verify')) {
    $data = request_data();
    $key = trim((string)($data['key'] ?? ''));
    $hwid = trim((string)($data['hwid'] ?? ''));
    if ($key === '' || strlen($key)>200 || $hwid === '' || strlen($hwid)>200) reply(400, ['ok'=>false, 'valid'=>false, 'error'=>'key and hwid are required']);
    $result = with_store(true, function (&$records) use ($key, $hwid, $MAX_DEVICE_CHANGES, $TAKEOVER_WAIT_MINUTES) {
        $hash = key_hash($key);
        foreach ($records as &$item) {
            if (($item['hash'] ?? '') !== $hash) continue;
            if (!empty($item['revoked'])) return ['ok'=>false,'valid'=>false,'error'=>'Key was not accepted.'];
            $nowT = now_utc();
            $status = (string)($item['status'] ?? 'active');
            if ($status === 'blocked') return ['ok'=>false,'valid'=>false,'error'=>'Key is blocked.'];
            if ($status === 'disabled') return ['ok'=>false,'valid'=>false,'error'=>'Key is disabled.'];
            if (empty($item['expires_at']) && !empty($item['duration'])) {
                $amount = max(1, (int)$item['duration']);
                $unit = (string)($item['duration_unit'] ?? 'hours');
                try {
                    $item['started_at'] = $nowT->format('Y-m-d\TH:i:s\Z');
                    $item['expires_at'] = $nowT->modify('+' . $amount . ' ' . $unit)->format('Y-m-d\TH:i:s\Z');
                } catch (Throwable $e) {
                    return ['ok'=>false,'valid'=>false,'error'=>'Key duration is invalid.'];
                }
            }
            if (!empty($item['expires_at']) && new DateTimeImmutable($item['expires_at'], new DateTimeZone('UTC')) <= $nowT) {
                $item['status'] = 'expired';
                return ['ok'=>false,'valid'=>false,'error'=>'Key has expired.'];
            }
            // New keys use an exact device limit. Legacy records without
            // max_devices keep the original one-device/rebind behavior below.
            $isNewDeviceLimitKey = array_key_exists('max_devices', $item);
            $maxDevices = max(1, (int)($item['max_devices'] ?? 1));
            if ($isNewDeviceLimitKey) {
                $knownDevices = is_array($item['device_hwids'] ?? null) ? $item['device_hwids'] : [];
                if (in_array($hwid, $knownDevices, true)) {
                    $item['last_seen'] = $nowT->format('Y-m-d\TH:i:s\Z');
                    return ['ok'=>true,'valid'=>true,'expires_at'=>$item['expires_at'],'devices_used'=>count($knownDevices),'max_devices'=>$maxDevices];
                }
                if (count($knownDevices) >= $maxDevices) return ['ok'=>false,'valid'=>false,'error'=>'Maximum device limit reached.'];
                $knownDevices[] = $hwid;
                $item['device_hwids'] = $knownDevices;
                if ($item['hwid'] === null) $item['hwid'] = $hwid;
                $item['last_seen'] = $nowT->format('Y-m-d\TH:i:s\Z');
                return ['ok'=>true,'valid'=>true,'expires_at'=>$item['expires_at'],'devices_used'=>count($knownDevices),'max_devices'=>$maxDevices];
            }
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
    // Match conventional license APIs: invalid, expired, revoked, or over-limit
    // credentials return HTTP 403 while retaining the JSON valid=false response.
    reply(!empty($result['valid']) ? 200 : 403, $result);
}

reply(404, ['ok'=>false, 'error'=>'Endpoint not found']);
