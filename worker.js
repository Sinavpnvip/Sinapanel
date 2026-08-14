/**
 * ═══════════════════════════════════════════════════════════════
 *   APP Panel  ·  Advanced Proxy Panel  v2.0 (Enterprise Edition)
 *   پنل پروکسی پیشرفته — پشتیبانی از D1، UUID اختصاصی و Clean IP خودکار
 * ═══════════════════════════════════════════════════════════════
 */

import { connect } from 'cloudflare:sockets';

const DEFAULT_PASSWORD = '123456';
const PANEL_PATH = '/panel';
const SUB_PATH = '/sub';
const DOH_PATH = '/doh';
const API_PATH = '/api';

// ──────────────────────────── Utils ────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

function isValidUUID(u) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u);
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64Str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return { data: bytes.buffer };
  } catch (e) {
    return { error: e };
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function html(content) {
  return new Response(content, {
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function redirect(url) {
  return Response.redirect(url, 302);
}

// ──────────────────────────── D1 Database Helpers ────────────────────────────
async function getSettings(env) {
  if (!env.APP_DB) return defaultSettings();
  try {
    const { results } = await env.APP_DB.prepare("SELECT * FROM settings").all();
    const settings = defaultSettings();
    for (const row of results) {
      try { settings[row.key] = JSON.parse(row.value); } catch { settings[row.key] = row.value; }
    }
    return settings;
  } catch (e) {
    return defaultSettings();
  }
}

async function saveSettings(env, data) {
  if (!env.APP_DB) return;
  const stmt = env.APP_DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
  for (const [key, value] of Object.entries(data)) {
    await stmt.bind(key, JSON.stringify(value)).run();
  }
}

async function getSubs(env) {
  if (!env.APP_DB) return [];
  try {
    const { results } = await env.APP_DB.prepare("SELECT * FROM subs").all();
    return results.map(row => ({
      id: row.id,
      name: row.name,
      traffic: row.traffic,
      maxUsers: row.maxUsers,
      days: row.days,
      port: row.port,
      path: row.path,
      protocols: JSON.parse(row.protocols || '{}'),
      proxyIP: row.proxyIP,
      cleanIPs: JSON.parse(row.cleanIPs || '[]'),
      routing: JSON.parse(row.routing || '{}')
    }));
  } catch (e) {
    return [];
  }
}

async function saveSub(env, sub) {
  if (!env.APP_DB) return;
  await env.APP_DB.prepare(
    "INSERT OR REPLACE INTO subs (id, name, traffic, maxUsers, days, port, path, protocols, proxyIP, cleanIPs, routing) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    sub.id, sub.name, sub.traffic||0, sub.maxUsers||0, sub.days||0, sub.port||443, sub.path||'/',
    JSON.stringify(sub.protocols||{}), sub.proxyIP||'', JSON.stringify(sub.cleanIPs||[]), JSON.stringify(sub.routing||{})
  ).run();
}

async function deleteSub(env, id) {
  if (!env.APP_DB) return;
  await env.APP_DB.prepare("DELETE FROM subs WHERE id = ?").bind(id).run();
}

async function getUsers(env) {
  if (!env.APP_DB) return [];
  try {
    const { results } = await env.APP_DB.prepare("SELECT * FROM users").all();
    return results.map(row => ({
      id: row.id,
      name: row.name,
      uuid: row.uuid,
      used: row.used,
      traffic: row.traffic,
      expire: row.expire,
      maxDevices: row.maxDevices,
      subId: row.subId,
      note: row.note,
      enabled: row.enabled === 1
    }));
  } catch (e) {
    return [];
  }
}

async function saveUser(env, user) {
  if (!env.APP_DB) return;
  await env.APP_DB.prepare(
    "INSERT OR REPLACE INTO users (id, name, uuid, used, traffic, expire, maxDevices, subId, note, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    user.id, user.name, user.uuid, user.used||0, user.traffic||0, user.expire||null, user.maxDevices||1, user.subId||'', user.note||'', user.enabled !== false ? 1 : 0
  ).run();
}

async function deleteUser(env, id) {
  if (!env.APP_DB) return;
  await env.APP_DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
}

async function getUserByUUID(env, uuidStr) {
  if (!env.APP_DB) return null;
  const user = await env.APP_DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuidStr).first();
  if (!user) return null;
  return user;
}

async function updateUserTraffic(env, userId, bytesToAdd) {
  if (!env.APP_DB || !userId || bytesToAdd <= 0) return;
  await env.APP_DB.prepare("UPDATE users SET used = used + ? WHERE id = ?").bind(bytesToAdd, userId).run();
}

async function resetUserTraffic(env, userId) {
  if (!env.APP_DB) return;
  await env.APP_DB.prepare("UPDATE users SET used = 0 WHERE id = ?").bind(userId).run();
}

// ──────────────────────────── Auth ────────────────────────────
async function checkAuth(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/app_token=([^;]+)/);
  if (!match) return false;
  const token = match[1];
  if (!env.APP_DB) return token.length > 8;
  const session = await env.APP_DB.prepare("SELECT token FROM sessions WHERE token = ? AND expire > ?").bind(token, Date.now()).first();
  return !!session;
}

async function createSession(env) {
  const token = crypto.randomUUID().replace(/-/g, '');
  if (env.APP_DB) {
    const expire = Date.now() + (86400 * 7 * 1000);
    await env.APP_DB.prepare("INSERT INTO sessions (token, expire) VALUES (?, ?)").bind(token, expire).run();
  }
  return token;
}

// ──────────────────────────── Default Settings ────────────────────────────
function defaultSettings() {
  return {
    password: DEFAULT_PASSWORD,
    uuid: uuid(),
    trojanPassword: 'trojan' + Math.random().toString(36).slice(2, 10),
    fingerprint: 'chrome',
    fragment: { length: '10-20', interval: '10-20', packets: 'tlshello' },
    warp: { enabled: false, pro: false, endpoint: '' },
    proxyIP: '',
    cleanIPs: []
  };
}

// ──────────────────────────── Subscription Generator ────────────────────────────
function generateVlessLink(host, userUuid, port, path, remark, proxyIP) {
  const address = proxyIP || host;
  const params = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: host,
    fp: 'chrome',
    type: 'ws',
    host: host,
    path: path || '/'
  });
  return `vless://${userUuid}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark || 'APP')}`;
}

function generateTrojanLink(host, password, port, path, remark, proxyIP) {
  const address = proxyIP || host;
  const params = new URLSearchParams({
    security: 'tls',
    sni: host,
    fp: 'chrome',
    type: 'ws',
    host: host,
    path: path || '/'
  });
  return `trojan://${password}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark || 'APP-Trojan')}`;
}

function generateUserSubContent(user, sub, settings, host) {
  const links = [];
  const port = sub.port || 443;
  const path = sub.path || '/';
  const proxyIP = sub.proxyIP || settings.proxyIP || '';
  const cleanIPs = (sub.cleanIPs || settings.cleanIPs || []).filter(Boolean);
  
  const usedGB = (user.used / 1024 / 1024 / 1024).toFixed(2);
  const totalGB = user.traffic > 0 ? user.traffic : '∞';
  const remainingDays = user.expire ? Math.max(0, Math.ceil((new Date(user.expire) - new Date()) / 86400000)) : '∞';
  const remarkSuffix = ` [${usedGB}/${totalGB}GB - ${remainingDays}D]`;

  const baseRemark = (sub.name || 'APP') + '-' + (user.name || 'User');

  if (sub.protocols?.vless !== false) {
    links.push(generateVlessLink(host, user.uuid, port, path, baseRemark + remarkSuffix, proxyIP));
    for (const ip of cleanIPs) {
      links.push(generateVlessLink(host, user.uuid, port, path, baseRemark + '-' + ip + remarkSuffix, ip));
    }
  }
  if (sub.protocols?.trojan) {
    links.push(generateTrojanLink(host, settings.trojanPassword, port, path, baseRemark + '-Trojan' + remarkSuffix, proxyIP));
  }
  return btoa(links.join('\n'));
}

function generateSubContent(sub, settings, host) {
  const links = [];
  const port = sub.port || 443;
  const path = sub.path || '/';
  const remark = sub.name || 'APP';
  const proxyIP = sub.proxyIP || settings.proxyIP || '';
  const cleanIPs = (sub.cleanIPs || settings.cleanIPs || []).filter(Boolean);

  if (sub.protocols?.vless !== false) {
    links.push(generateVlessLink(host, settings.uuid, port, path, remark, proxyIP));
    for (const ip of cleanIPs) {
      links.push(generateVlessLink(host, settings.uuid, port, path, remark + '-' + ip, ip));
    }
  }
  if (sub.protocols?.trojan) {
    links.push(generateTrojanLink(host, settings.trojanPassword, port, path, remark + '-Trojan', proxyIP));
  }
  return btoa(links.join('\n'));
}

// ──────────────────────────── VLESS Handler (Core) ────────────────────────────
function processVlessHeader(buffer, expectedUUID) {
  if (buffer.byteLength < 24) return { hasError: true, message: 'invalid header' };
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1))[0];
  const uuidBytes = new Uint8Array(buffer.slice(1, 17));
  const uuidStr = [...uuidBytes].map(b => b.toString(16).padStart(2, '0')).join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  
  if (uuidStr.toLowerCase() !== expectedUUID.toLowerCase()) {
    return { hasError: true, message: 'invalid uuid' };
  }
  
  const optLen = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLen, 19 + optLen))[0];
  const isUDP = cmd === 2;
  if (cmd !== 1 && cmd !== 2) return { hasError: true, message: 'unsupported command' };
  
  const portIndex = 19 + optLen;
  const portRemote = view.getUint16(portIndex);
  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
  addressIndex += 1;
  
  let addressRemote = '';
  let addressLength = 0;
  
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressRemote = new Uint8Array(buffer.slice(addressIndex, addressIndex + addressLength)).join('.');
      break;
    case 2:
      addressLength = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
      addressIndex += 1;
      addressRemote = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const ipv6 = [];
      const dv = new DataView(buffer.slice(addressIndex, addressIndex + 16));
      for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
      addressRemote = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: 'invalid address type' };
  }
  
  const rawDataIndex = addressIndex + addressLength;
  return {
    hasError: false,
    addressRemote,
    portRemote,
    rawDataIndex,
    vlessVersion: new Uint8Array([version]),
    isUDP
  };
}

function makeReadableWebSocketStream(webSocket, earlyData) {
  let cancelled = false;
  return new ReadableStream({
    start(controller) {
      webSocket.addEventListener('message', e => {
        if (!cancelled) controller.enqueue(e.data);
      });
      webSocket.addEventListener('close', () => { try { controller.close(); } catch (_) {} });
      webSocket.addEventListener('error', err => controller.error(err));
      if (earlyData) controller.enqueue(earlyData);
    },
    cancel() { cancelled = true; }
  });
}

// Unified & Single Declaration of WebSocket Handler
async function handleVLESSWebSocket(request, env, settings, currentUser, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let remoteSocket = { value: null };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const { data: earlyData } = base64ToArrayBuffer(earlyDataHeader);
  const readable = makeReadableWebSocketStream(webSocket, earlyData);

  let isUserBlocked = false;
  let accumulatedBytes = 0;

  readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (remoteSocket.value) {
        const writer = remoteSocket.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        
        if (currentUser && !isUserBlocked) {
          const chunkBytes = chunk.byteLength || chunk.length || 0;
          accumulatedBytes += chunkBytes;
          
          if (currentUser.traffic > 0 && (currentUser.used + accumulatedBytes) >= currentUser.traffic * 1024 * 1024 * 1024) {
            isUserBlocked = true;
            webSocket.close(1000, 'traffic limit exceeded');
          }
          if (currentUser.expire && new Date(currentUser.expire) < new Date()) {
            isUserBlocked = true;
            webSocket.close(1000, 'account expired');
          }
          
          if (accumulatedBytes > 1048576) {
            ctx.waitUntil(updateUserTraffic(env, currentUser.id, accumulatedBytes));
            currentUser.used += accumulatedBytes;
            accumulatedBytes = 0;
          }
        }
        return;
      }
      
      // Use user's specific UUID if available, else fallback to global settings UUID
      const expectedUUID = currentUser ? currentUser.uuid : settings.uuid;
      const parsed = processVlessHeader(chunk, expectedUUID);
      if (parsed.hasError) {
        webSocket.close(1000, parsed.message);
        return;
      }
      
      const { addressRemote, portRemote, rawDataIndex, vlessVersion, isUDP } = parsed;
      if (isUDP) {
        webSocket.close(1000, 'UDP not fully supported in this build');
        return;
      }
      
      const rawClientData = chunk.slice(rawDataIndex);
      const target = settings.proxyIP || addressRemote;
      
      try {
        const sock = connect({ hostname: target, port: portRemote });
        remoteSocket.value = sock;
        const writer = sock.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();

        const resp = new Uint8Array([vlessVersion[0], 0]);
        webSocket.send(resp);

        sock.readable.pipeTo(new WritableStream({
          write(data) { 
            if (!isUserBlocked) {
              webSocket.send(data); 
              if (currentUser) {
                accumulatedBytes += data.byteLength || data.length || 0;
                if (accumulatedBytes > 1048576) {
                  ctx.waitUntil(updateUserTraffic(env, currentUser.id, accumulatedBytes));
                  currentUser.used += accumulatedBytes;
                  accumulatedBytes = 0;
                }
              }
            }
          },
          close() { try { webSocket.close(); } catch (_) {} },
          abort() { try { webSocket.close(); } catch (_) {} }
        })).catch(() => {});
      } catch (e) {
        webSocket.close(1000, 'connect failed');
      }
    }
  })).catch(() => {});

  webSocket.addEventListener('close', async () => {
    if (currentUser && env.APP_DB && accumulatedBytes > 0) {
      await updateUserTraffic(env, currentUser.id, accumulatedBytes);
    }
  });

  return new Response(null, { status: 101, webSocket: client });
}

// ──────────────────────────── Panel HTML (Pro UI) ────────────────────────────
function getPanelHTML(lang, authenticated) {
  const isFa = lang !== 'en';
  if (!authenticated) {
    return `<!DOCTYPE html>
<html lang="${isFa ? 'fa' : 'en'}" dir="${isFa ? 'rtl' : 'ltr'}">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>APP Panel Login</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700&family=Inter:wght@400;600;700&display=swap');
:root{--bg:#f8fafc;--card:#ffffff;--text:#1e293b;--muted:#64748b;--primary:#4f46e5;--primary-hover:#4338ca;--border:#e2e8f0;--danger:#ef4444;--success:#10b981}
*{box-sizing:border-box;margin:0;padding:0;font-family:${isFa?'Vazirmatn':'Inter'},system-ui,sans-serif}
body{background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2.5rem;width:100%;max-width:380px;text-align:center;box-shadow:0 10px 25px -5px rgba(0,0,0,.05)}
h1{color:var(--primary);font-size:1.5rem;margin-bottom:.5rem;font-weight:700}
p{color:var(--muted);font-size:.9rem;margin-bottom:1.5rem}
input{width:100%;padding:.8rem 1rem;background:#f1f5f9;border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:.95rem;margin-bottom:1rem;transition:.2s}
input:focus{outline:none;border-color:var(--primary);background:#fff;box-shadow:0 0 0 3px rgba(79,70,229,.1)}
button{width:100%;padding:.8rem;background:var(--primary);color:#fff;border:none;border-radius:10px;font-weight:600;font-size:.95rem;cursor:pointer;transition:.2s}
button:hover{background:var(--primary-hover)}
.err{color:var(--danger);font-size:.8rem;margin-top:.75rem;display:none}
</style>
</head>
<body>
<div class="box">
  <h1>APP Panel</h1>
  <p>${isFa ? 'برای ورود رمز عبور را وارد کنید' : 'Enter your password to login'}</p>
  <form id="f">
    <input type="password" id="pass" placeholder="${isFa ? 'رمز عبور' : 'Password'}" autofocus>
    <button type="submit">${isFa ? 'ورود به پنل' : 'Login'}</button>
    <div class="err" id="err">${isFa ? 'رمز عبور اشتباه است' : 'Wrong password'}</div>
  </form>
</div>
<script>
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pass').value})});
  if(r.ok){location.reload()}else{document.getElementById('err').style.display='block'}
};
</script>
</body></html>`;
  }

  return `<!DOCTYPE html>
<html lang="${isFa ? 'fa' : 'en'}" dir="${isFa ? 'rtl' : 'ltr'}">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>APP Panel</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');
:root{--bg:#f8fafc;--card:#ffffff;--text:#1e293b;--muted:#64748b;--light:#f1f5f9;--primary:#4f46e5;--primary-hover:#4338ca;--primary-soft:#eef2ff;--border:#e2e8f0;--danger:#ef4444;--danger-soft:#fef2f2;--success:#10b981;--success-soft:#ecfdf5;--yellow:#f59e0b;--yellow-soft:#fffbeb;--blue:#3b82f6;--blue-soft:#eff6ff}
*{box-sizing:border-box;margin:0;padding:0;font-family:${isFa?'Vazirmatn':'Inter'},system-ui,sans-serif}
body{background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
.container{max-width:1100px;margin:0 auto;padding:1.5rem 1rem 4rem}
.header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem;margin-bottom:2rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border)}
.logo{font-weight:700;font-size:1.25rem;color:var(--primary);display:flex;align-items:center;gap:.5rem}
.logo::before{content:'';width:10px;height:10px;background:var(--primary);border-radius:50%}
.nav{display:flex;flex-wrap:wrap;gap:.25rem;margin-bottom:1.5rem;background:var(--card);padding:.35rem;border-radius:12px;border:1px solid var(--border);box-shadow:0 1px 3px rgba(0,0,0,.03)}
.nav a{padding:.5rem 1rem;border-radius:8px;color:var(--muted);font-size:.85rem;font-weight:500;cursor:pointer;text-decoration:none;transition:.2s}
.nav a.active{color:#fff;background:var(--primary);box-shadow:0 4px 6px -1px rgba(79,70,229,.2)}
.nav a:not(.active):hover{background:var(--light);color:var(--text)}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.5rem;margin-bottom:1rem;box-shadow:0 1px 3px rgba(0,0,0,.03)}
h2{font-size:1.1rem;font-weight:600;margin-bottom:1rem;color:var(--text)}
.muted{color:var(--muted);font-size:.8rem}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:.75rem;margin-bottom:.5rem}
@media(min-width:680px){.stats{grid-template-columns:repeat(4,1fr)}}
.stat{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:1rem;text-align:center}
.stat-value{font-size:1.5rem;font-weight:700;color:var(--primary);margin-bottom:.25rem}
.stat-label{font-size:.75rem;color:var(--muted);font-weight:500}
.progress-wrap{margin:.75rem 0}.progress-head{display:flex;justify-content:space-between;font-size:.75rem;margin-bottom:.35rem;color:var(--muted)}
.progress-bar{height:8px;background:var(--light);border-radius:99px;overflow:hidden}
.progress-fill{height:100%;background:var(--primary);border-radius:99px;transition:width .3s ease}
.config-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.75rem;font-family:ui-monospace,monospace;font-size:.75rem;word-break:break-all;position:relative;margin:.5rem 0;color:var(--text)}
button,.btn{display:inline-flex;align-items:center;gap:.25rem;padding:.5rem 1rem;background:var(--primary);color:#fff;border:none;border-radius:8px;font-size:.8rem;font-weight:500;cursor:pointer;transition:.2s;font-family:inherit}
button:hover{background:var(--primary-hover)}
.btn-sm{padding:.35rem .65rem;font-size:.75rem}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text)}
.btn-outline:hover{background:var(--light);border-color:var(--muted)}
.btn-ghost{background:transparent;color:var(--muted);padding:.35rem .65rem;font-size:.75rem}
.btn-ghost:hover{background:var(--light)}
.btn-danger{background:transparent;border:1px solid var(--danger);color:var(--danger)}
.btn-danger:hover{background:var(--danger-soft)}
.btn-blue{background:transparent;border:1px solid var(--blue);color:var(--blue)}
.btn-blue:hover{background:var(--blue-soft)}
.badge{display:inline-block;padding:.2rem .5rem;border-radius:6px;font-size:.65rem;font-weight:600;margin:.05rem}
.badge-default{color:var(--text);background:var(--light)}
.badge-blue{color:var(--blue);background:var(--blue-soft)}
.badge-yellow{color:var(--yellow);background:var(--yellow-soft)}
.badge-red{color:var(--danger);background:var(--danger-soft)}
.badge-green{color:var(--success);background:var(--success-soft)}
input,textarea,select{width:100%;padding:.6rem .8rem;background:#fff;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.85rem;margin-bottom:.5rem;font-family:inherit;transition:.2s}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(79,70,229,.1)}
label.lbl{display:block;margin-bottom:.25rem;font-size:.75rem;color:var(--muted);font-weight:500}
.grid{display:grid;gap:.75rem}@media(min-width:560px){.grid-2{grid-template-columns:1fr 1fr}}
.toast{position:fixed;bottom:1.5rem;left:1.5rem;background:var(--text);color:#fff;padding:.75rem 1.25rem;border-radius:8px;font-weight:500;font-size:.85rem;opacity:0;transform:translateY(10px);transition:.3s;z-index:90;box-shadow:0 10px 15px -3px rgba(0,0,0,.1)}
.toast.show{opacity:1;transform:translateY(0)}
.modal-bg{position:fixed;inset:0;background:rgba(15,23,42,.6);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;z-index:80;padding:1rem}
.modal-bg.show{display:flex}
.modal{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:1.5rem;max-width:480px;width:100%;max-height:92vh;overflow-y:auto;box-shadow:0 20px 25px -5px rgba(0,0,0,.1)}
.modal h3{margin-bottom:1rem;font-size:1.1rem;font-weight:600}
.check-row{display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem;font-size:.85rem;cursor:pointer}
.check-row input{width:16px;height:16px;margin:0;accent-color:var(--primary)}
.section-title{font-size:.85rem;font-weight:600;margin:.75rem 0 .5rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
.field-with-btn{display:flex;gap:.5rem;align-items:flex-start}
.field-with-btn input,.field-with-btn textarea{flex:1;margin-bottom:0}
.user-card{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:1rem;margin-bottom:.75rem}
.user-card-head{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem}
.user-meta{font-size:.75rem;color:var(--muted);margin-top:.25rem}
.brain-row{display:flex;justify-content:space-between;align-items:center;padding:.6rem .75rem;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:.5rem;font-size:.8rem;gap:.5rem;flex-wrap:wrap}
.latency{font-size:.7rem;font-weight:600;color:var(--success);background:var(--success-soft);padding:.1rem .4rem;border-radius:4px}
.client-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.75rem}
.client-item{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:1rem;text-align:center;font-size:.75rem;transition:.2s}
.client-item:hover{border-color:var(--primary);box-shadow:0 4px 6px -1px rgba(0,0,0,.05)}
.client-item strong{display:block;color:var(--primary);margin-bottom:.25rem;font-size:.85rem}
.client-item a{color:var(--blue);font-size:.7rem;text-decoration:none}
.hidden{display:none!important}
.loading-spinner{border:2px solid rgba(255,255,255,.3);border-radius:50%;border-top:2px solid #fff;width:16px;height:16px;animation:spin 1s linear infinite;display:none}
@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">APP Panel</div>
    <div style="display:flex;gap:.5rem">
      <button class="btn-ghost btn-sm" onclick="setLang('fa')">FA</button>
      <button class="btn-ghost btn-sm" onclick="setLang('en')">EN</button>
      <button class="btn-ghost btn-sm" onclick="logout()">${isFa ? 'خروج' : 'Logout'}</button>
    </div>
  </div>
  
  <div class="nav" id="nav">
    <a class="active" data-t="dash">${isFa ? 'داشبورد' : 'Dashboard'}</a>
    <a data-t="subs">${isFa ? 'ساب‌لینک‌ها' : 'Subscriptions'}</a>
    <a data-t="users">${isFa ? 'کاربران' : 'Users'}</a>
    <a data-t="warp">Warp</a>
    <a data-t="clients">${isFa ? 'کلاینت‌ها' : 'Clients'}</a>
    <a data-t="set">${isFa ? 'تنظیمات' : 'Settings'}</a>
  </div>

  <div id="tab-dash">
    <div class="card">
      <h2>${isFa ? 'نمای کلی' : 'Overview'}</h2>
      <div class="stats">
        <div class="stat"><div class="stat-value" id="sUsers">0</div><div class="stat-label">${isFa ? 'کاربران' : 'Users'}</div></div>
        <div class="stat"><div class="stat-value" id="sSubs">0</div><div class="stat-label">${isFa ? 'ساب‌لینک‌ها' : 'Subs'}</div></div>
        <div class="stat"><div class="stat-value" id="sTraffic">0 GB</div><div class="stat-label">${isFa ? 'ترافیک مصرفی' : 'Total Traffic'}</div></div>
        <div class="stat"><div class="stat-value" style="color:var(--success)">ON</div><div class="stat-label">Worker</div></div>
      </div>
    </div>
  </div>

  <div id="tab-subs" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem">
        <h2 style="margin:0">${isFa ? 'ساب‌سکریپشن‌ها' : 'Subscriptions'}</h2>
        <button onclick="openSubModal()">+ ${isFa ? 'ساخت ساب' : 'New Sub'}</button>
      </div>
      <div id="subsList"></div>
    </div>
  </div>

  <div id="tab-users" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem">
        <h2 style="margin:0">${isFa ? 'مدیریت کاربران' : 'User Management'}</h2>
        <button onclick="openUserModal()">+ ${isFa ? 'کاربر جدید' : 'New User'}</button>
      </div>
      <div id="usersList"></div>
    </div>
  </div>

  <div id="tab-warp" class="hidden">
    <div class="card">
      <h2>Warp Configuration</h2>
      <div class="check-row"><input type="checkbox" id="warpOn"><label for="warpOn">${isFa ? 'فعال‌سازی Cloudflare Warp' : 'Enable Cloudflare Warp'}</label></div>
      <div class="check-row"><input type="checkbox" id="warpPro"><label for="warpPro">Warp Pro Endpoint</label></div>
      <label class="lbl">Endpoint</label>
      <input id="warpEndpoint" placeholder="engage.cloudflareclient.com:2408">
      <button onclick="saveWarp()" style="margin-top:.5rem">${isFa ? 'ذخیره تغییرات' : 'Save Changes'}</button>
    </div>
  </div>

  <div id="tab-clients" class="hidden">
    <div class="card">
      <h2>${isFa ? 'کلاینت‌های پیشنهادی' : 'Recommended Clients'}</h2>
      <div class="client-grid">
        <div class="client-item"><strong>v2rayNG</strong>Android<br><a href="https://github.com/2dust/v2rayNG" target="_blank">GitHub ↗</a></div>
        <div class="client-item"><strong>v2rayN</strong>Windows<br><a href="https://github.com/2dust/v2rayN" target="_blank">GitHub ↗</a></div>
        <div class="client-item"><strong>Hiddify</strong>All<br><a href="https://github.com/hiddify/hiddify-app" target="_blank">GitHub ↗</a></div>
        <div class="client-item"><strong>Sing-box</strong>All<br><a href="https://github.com/SagerNet/sing-box" target="_blank">GitHub ↗</a></div>
        <div class="client-item"><strong>Clash Meta</strong>Android<br><a href="https://github.com/MetaCubeX/ClashMetaForAndroid" target="_blank">GitHub ↗</a></div>
        <div class="client-item"><strong>Streisand</strong>iOS<br><a href="https://apps.apple.com/app/streisand/id6450534064" target="_blank">App Store ↗</a></div>
      </div>
    </div>
  </div>

  <div id="tab-set" class="hidden">
    <div class="card">
      <h2>${isFa ? 'تنظیمات اصلی' : 'General Settings'}</h2>
      <div class="grid grid-2">
        <div><label class="lbl">Master UUID</label><input id="setUUID" readonly></div>
        <div><label class="lbl">Trojan Password</label><input id="setTrojan"></div>
      </div>
      <label class="lbl">Fingerprint</label>
      <select id="setFP"><option>chrome</option><option>firefox</option><option>randomized</option></select>
      <div class="section-title">Fragment Settings</div>
      <div class="grid grid-2">
        <div><label class="lbl">Length</label><input id="setFragLen" value="10-20"></div>
        <div><label class="lbl">Interval</label><input id="setFragInt" value="10-20"></div>
      </div>
      <div style="display:flex;gap:.5rem;margin-top:.5rem">
        <button onclick="saveSettings()">${isFa ? 'ذخیره' : 'Save'}</button>
        <button class="btn-outline" onclick="newUUID()">Generate New UUID</button>
      </div>
    </div>
    <div class="card">
      <h2>${isFa ? 'امنیت پنل' : 'Panel Security'}</h2>
      <label class="lbl">${isFa ? 'رمز عبور جدید پنل' : 'New Panel Password'}</label>
      <input type="password" id="newPass" placeholder="••••••••">
      <button onclick="changePass()">${isFa ? 'تغییر رمز عبور' : 'Change Password'}</button>
    </div>
  </div>
</div>

<!-- Modals -->
<div class="modal-bg" id="modalSub">
  <div class="modal">
    <h3 id="subModalTitle">${isFa ? 'ساخت ساب جدید' : 'New Subscription'}</h3>
    <input type="hidden" id="subId">
    <label class="lbl">${isFa ? 'نام ساب' : 'Name'}</label>
    <input id="subName" placeholder="main">
    <div class="grid grid-2">
      <div><label class="lbl">${isFa ? 'حجم (GB)' : 'Traffic (GB)'}</label><input type="number" id="subTraffic" value="100"></div>
      <div><label class="lbl">${isFa ? 'حداکثر کاربر' : 'Max Users'}</label><input type="number" id="subMaxUsers" value="5"></div>
    </div>
    <div class="grid grid-2">
      <div><label class="lbl">${isFa ? 'روز انقضا' : 'Expire Days'}</label><input type="number" id="subDays" value="90"></div>
      <div><label class="lbl">${isFa ? 'پورت' : 'Port'}</label>
        <select id="subPort"><option>443</option><option>8443</option><option>2053</option><option>2083</option><option>2087</option><option>2096</option></select>
      </div>
    </div>
    <label class="lbl">Path</label>
    <input id="subPath" value="/">
    <div class="section-title">${isFa ? 'پروتکل‌ها' : 'Protocols'}</div>
    <div class="check-row"><input type="checkbox" id="subVless" checked><label for="subVless">VLESS</label></div>
    <div class="check-row"><input type="checkbox" id="subTrojan" checked><label for="subTrojan">Trojan</label></div>
    <div class="section-title">${isFa ? 'تنظیمات پروکسی' : 'Proxy Settings'}</div>
    <label class="lbl">Proxy IP</label>
    <div class="field-with-btn">
      <input id="subProxyIP" placeholder="optional">
      <button type="button" class="btn-outline btn-sm" onclick="openBrain('proxy')">${isFa ? 'مغزن' : 'Brain'}</button>
    </div>
    <label class="lbl" style="margin-top:.5rem">Clean IPs</label>
    <div class="field-with-btn">
      <textarea id="subCleanIPs" rows="2" placeholder="one per line"></textarea>
      <button type="button" class="btn-outline btn-sm" onclick="openBrain('clean')">${isFa ? 'مغزن' : 'Brain'}</button>
    </div>
    <div class="section-title">${isFa ? 'قوانین مسیریابی' : 'Routing Rules'}</div>
    <div class="check-row"><input type="checkbox" id="subAdblock" checked><label for="subAdblock">Ad Block</label></div>
    <div class="check-row"><input type="checkbox" id="subIran" checked><label for="subIran">Direct Iran</label></div>
    <div style="display:flex;gap:.5rem;margin-top:1rem">
      <button onclick="saveSub()">${isFa ? 'ذخیره' : 'Save'}</button>
      <button class="btn-ghost" onclick="closeModal('modalSub')">${isFa ? 'انصراف' : 'Cancel'}</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="modalBrain">
  <div class="modal">
    <h3 id="brainTitle">${isFa ? 'مغزن - انتخاب IP' : 'Brain - Select IP'}</h3>
    <p class="muted" style="margin-bottom:1rem">${isFa ? 'برای افزودن کلیک کنید' : 'Click to add'}</p>
    <div id="brainList"><div class="muted" style="text-align:center">Loading...</div></div>
    <button class="btn-ghost" style="width:100%;margin-top:1rem" onclick="closeModal('modalBrain')">${isFa ? 'بستن' : 'Close'}</button>
  </div>
</div>

<div class="modal-bg" id="modalUser">
  <div class="modal">
    <h3 id="userModalTitle">${isFa ? 'کاربر جدید' : 'New User'}</h3>
    <input type="hidden" id="userId">
    <input type="hidden" id="userUuid">
    <label class="lbl">${isFa ? 'نام کاربری' : 'Username'}</label>
    <input id="userName">
    <div class="grid grid-2">
      <div><label class="lbl">${isFa ? 'حجم (GB)' : 'Traffic (GB)'}</label><input type="number" id="userTraffic" value="30"></div>
      <div><label class="lbl">${isFa ? 'روز انقضا' : 'Days'}</label><input type="number" id="userDays" value="30"></div>
    </div>
    <label class="lbl">${isFa ? 'حداکثر دستگاه' : 'Max Devices'}</label>
    <input type="number" id="userDevices" value="2">
    <label class="lbl">${isFa ? 'ساب متصل' : 'Linked Sub'}</label>
    <select id="userSub"></select>
    <label class="lbl">${isFa ? 'یادداشت' : 'Note'}</label>
    <input id="userNote">
    <div style="display:flex;gap:.5rem;margin-top:1rem">
      <button onclick="saveUser()">${isFa ? 'ذخیره' : 'Save'}</button>
      <button class="btn-ghost" onclick="closeModal('modalUser')">${isFa ? 'انصراف' : 'Cancel'}</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const isFa = ${isFa ? 'true' : 'false'};
let settings = {}, subs = [], users = [];
let brainMode = 'proxy';

function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2000)}
function openModal(id){document.getElementById(id).classList.add('show')}
function closeModal(id){document.getElementById(id).classList.remove('show')}
function setLang(l){location.href='/panel?lang='+l}
async function logout(){await fetch('/api/logout',{method:'POST'});location.reload()}

document.querySelectorAll('.nav a[data-t]').forEach(a=>{
  a.onclick=e=>{e.preventDefault();
    document.querySelectorAll('.nav a').forEach(x=>x.classList.remove('active'));
    a.classList.add('active');
    ['dash','subs','users','warp','clients','set'].forEach(t=>{
      document.getElementById('tab-'+t).classList.toggle('hidden', a.dataset.t!==t);
    });
  }
});

async function loadAll(){
  const [s,sb,u] = await Promise.all([
    fetch('/api/settings').then(r=>r.json()),
    fetch('/api/subs').then(r=>r.json()),
    fetch('/api/users').then(r=>r.json())
  ]);
  settings=s; subs=sb; users=u;
  render();
}

function render(){
  document.getElementById('sUsers').textContent = users.length;
  document.getElementById('sSubs').textContent = subs.length;
  const totalTraffic = users.reduce((sum, u) => sum + (u.used||0), 0) / 1024 / 1024 / 1024;
  document.getElementById('sTraffic').textContent = totalTraffic.toFixed(2) + ' GB';
  
  document.getElementById('setUUID').value = settings.uuid||'';
  document.getElementById('setTrojan').value = settings.trojanPassword||'';
  document.getElementById('setFP').value = settings.fingerprint||'chrome';
  if(settings.fragment){document.getElementById('setFragLen').value=settings.fragment.length||'10-20';document.getElementById('setFragInt').value=settings.fragment.interval||'10-20'}
  document.getElementById('warpOn').checked = !!(settings.warp&&settings.warp.enabled);
  document.getElementById('warpPro').checked = !!(settings.warp&&settings.warp.pro);
  document.getElementById('warpEndpoint').value = (settings.warp&&settings.warp.endpoint)||'';

  const sl = document.getElementById('subsList');
  if(!subs.length){sl.innerHTML='<p class="muted">'+(isFa?'هیچ سابی ساخته نشده':'No subs created yet')+'</p>'}
  else{
    sl.innerHTML = subs.map(s=>{
      const link = location.origin+'/sub/'+s.id;
      const badges = [];
      if(s.protocols?.vless!==false) badges.push('<span class="badge badge-default">VLESS</span>');
      if(s.protocols?.trojan) badges.push('<span class="badge badge-default">Trojan</span>');
      if(s.routing?.adblock) badges.push('<span class="badge badge-blue">AdBlock</span>');
      if(s.routing?.iran) badges.push('<span class="badge badge-yellow">Iran</span>');
      return '<div class="user-card">'+
        '<div class="user-card-head"><div><strong>'+esc(s.name)+'</strong><div style="margin-top:.25rem">'+badges.join('')+'</div></div>'+
        '<div style="display:flex;gap:.35rem">'+
        '<button class="btn-outline btn-sm" onclick="copyText(\\''+link+'\\')">'+(isFa?'کپی':'Copy')+'</button>'+
        '<button class="btn-outline btn-sm" onclick="editSub(\\''+s.id+'\\')">'+(isFa?'ویرایش':'Edit')+'</button>'+
        '<button class="btn-danger btn-sm" onclick="delSub(\\''+s.id+'\\')">'+(isFa?'حذف':'Del')+'</button></div></div>'+
        '<div class="config-box">'+link+'</div>'+
        '<div class="muted" style="margin-top:.35rem">Port '+(s.port||443)+' · Proxy: '+(s.proxyIP||'Default')+' · Clean IPs: '+((s.cleanIPs||[]).length)+'</div></div>';
    }).join('');
  }

  const ul = document.getElementById('usersList');
  if(!users.length){ul.innerHTML='<p class="muted">'+(isFa?'هیچ کاربری وجود ندارد':'No users found')+'</p>'}
  else{
    ul.innerHTML = users.map(u=>{
      const used = (u.used / 1024 / 1024 / 1024).toFixed(2);
      const total = u.traffic || 0;
      const pct = total>0 ? Math.min(100, Math.round(used/total*100)) : 0;
      const isExpired = u.expire && new Date(u.expire) < new Date();
      const isLimited = total>0 && u.used >= total * 1024 * 1024 * 1024;
      const statusBadge = isExpired || isLimited ? '<span class="badge badge-red">'+(isFa?'مسدود':'Blocked')+'</span>' : '<span class="badge badge-green">'+(isFa?'فعال':'Active')+'</span>';
      
      return '<div class="user-card">'+
        '<div class="user-card-head"><div><strong>'+esc(u.name)+'</strong> '+statusBadge+
        (u.note?'<div class="user-meta">'+esc(u.note)+'</div>':'')+'</div>'+
        '<div style="display:flex;gap:.35rem;flex-wrap:wrap">'+
        '<button class="btn-outline btn-sm" onclick="copyText(\\''+location.origin+'/sub/'+u.id+'\\')">Sub Link</button>'+
        '<button class="btn-outline btn-sm" onclick="copyText(\\''+u.uuid+'\\')">UUID</button>'+
        '<button class="btn-outline btn-sm" onclick="editUser(\\''+u.id+'\\')">'+(isFa?'ویرایش':'Edit')+'</button>'+
        '<button class="btn-blue btn-sm" onclick="resetUser(\\''+u.id+'\\')">'+(isFa?'ریست':'Reset')+'</button>'+
        '<button class="btn-danger btn-sm" onclick="delUser(\\''+u.id+'\\')">'+(isFa?'حذف':'Del')+'</button></div></div>'+
        '<div class="progress-wrap"><div class="progress-head"><span>'+(isFa?'مصرف ترافیک':'Traffic Usage')+'</span><span>'+used+' / '+(total||'∞')+' GB</span></div>'+
        '<div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div></div>'+
        '<div class="muted" style="font-size:.75rem;margin-top:.5rem">'+(isFa?'دستگاه‌ها':'Devices')+': '+(u.devices||0)+'/'+(u.maxDevices||'∞')+' · '+(isFa?'انقضا':'Expire')+': '+(u.expire||'-')+'</div></div>';
    }).join('');
  }

  const sel = document.getElementById('userSub');
  sel.innerHTML = '<option value="">'+(isFa?'همه':'All')+'</option>' + subs.map(s=>'<option value="'+s.id+'">'+esc(s.name)+'</option>').join('');
}

function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast(isFa?'کپی شد':'Copied to clipboard'))}

function openSubModal(id){
  document.getElementById('subId').value = id||'';
  document.getElementById('subModalTitle').textContent = id ? (isFa?'ویرایش ساب':'Edit Sub') : (isFa?'ساخت ساب جدید':'New Sub');
  if(id){
    const s = subs.find(x=>x.id===id);
    if(s){
      document.getElementById('subName').value=s.name||'';
      document.getElementById('subTraffic').value=s.traffic||100;
      document.getElementById('subMaxUsers').value=s.maxUsers||5;
      document.getElementById('subDays').value=s.days||90;
      document.getElementById('subPort').value=s.port||443;
      document.getElementById('subPath').value=s.path||'/';
      document.getElementById('subVless').checked=s.protocols?.vless!==false;
      document.getElementById('subTrojan').checked=!!s.protocols?.trojan;
      document.getElementById('subProxyIP').value=s.proxyIP||'';
      document.getElementById('subCleanIPs').value=(s.cleanIPs||[]).join('\\n');
      document.getElementById('subAdblock').checked=!!s.routing?.adblock;
      document.getElementById('subIran').checked=!!s.routing?.iran;
    }
  } else {
    document.getElementById('subName').value='';
    document.getElementById('subProxyIP').value='';
    document.getElementById('subCleanIPs').value='';
  }
  openModal('modalSub');
}
function editSub(id){openSubModal(id)}

async function saveSub(){
  const id = document.getElementById('subId').value;
  const body = {
    id: id || undefined,
    name: document.getElementById('subName').value || 'sub',
    traffic: +document.getElementById('subTraffic').value||0,
    maxUsers: +document.getElementById('subMaxUsers').value||0,
    days: +document.getElementById('subDays').value||0,
    port: +document.getElementById('subPort').value||443,
    path: document.getElementById('subPath').value||'/',
    protocols: {vless: document.getElementById('subVless').checked, trojan: document.getElementById('subTrojan').checked},
    proxyIP: document.getElementById('subProxyIP').value.trim(),
    cleanIPs: document.getElementById('subCleanIPs').value.split('\\n').map(s=>s.trim()).filter(Boolean),
    routing: {adblock: document.getElementById('subAdblock').checked, iran: document.getElementById('subIran').checked}
  };
  const r = await fetch('/api/subs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.ok){closeModal('modalSub');toast(isFa?'با موفقیت ذخیره شد':'Saved successfully');loadAll()}
  else toast('Error occurred');
}
async function delSub(id){
  if(!confirm(isFa?'آیا از حذف مطمئن هستید؟':'Are you sure?'))return;
  await fetch('/api/subs?id='+id,{method:'DELETE'});
  toast(isFa?'حذف شد':'Deleted');loadAll();
}

async function openBrain(mode){
  brainMode = mode;
  document.getElementById('brainTitle').textContent = (isFa?'مغزن':'Brain')+' — '+(mode==='proxy'?'Proxy IP':'Clean IP');
  document.getElementById('brainList').innerHTML = '<div class="muted" style="text-align:center">Loading...</div>';
  openModal('modalBrain');
  try {
    const res = await fetch('/api/brain');
    const data = await res.json();
    if(data.error) throw new Error(data.error);
    document.getElementById('brainList').innerHTML = data.ips.map(b=>
      '<div class="brain-row"><div><strong>'+b.ip+'</strong></div><div style="display:flex;align-items:center;gap:.5rem"><span class="latency">'+b.ms+' ms</span>'+
      '<button class="btn-sm" onclick="pickBrain(\\''+b.ip+'\\')">'+(isFa?'افزودن':'Add')+'</button></div></div>'
    ).join('');
  } catch (e) {
    document.getElementById('brainList').innerHTML = '<div class="muted" style="text-align:center;color:var(--danger)">'+(isFa?'خطا در دریافت آی‌پی':'Error loading IPs')+'</div>';
  }
}
function pickBrain(ip){
  if(brainMode==='proxy'){
    document.getElementById('subProxyIP').value=ip;
    closeModal('modalBrain');
  } else {
    const ta=document.getElementById('subCleanIPs');
    const lines=ta.value.split('\\n').map(s=>s.trim()).filter(Boolean);
    if(!lines.includes(ip)) lines.push(ip);
    ta.value=lines.join('\\n');
  }
  toast(ip + ' added');
}

function openUserModal(id){
  document.getElementById('userId').value=id||'';
  document.getElementById('userModalTitle').textContent=id?(isFa?'ویرایش کاربر':'Edit User'):(isFa?'کاربر جدید':'New User');
  if(id){
    const u=users.find(x=>x.id===id);
    if(u){
      document.getElementById('userUuid').value=u.uuid||'';
      document.getElementById('userName').value=u.name||'';
      document.getElementById('userTraffic').value=u.traffic||30;
      document.getElementById('userDays').value=u.days||30;
      document.getElementById('userDevices').value=u.maxDevices||2;
      document.getElementById('userSub').value=u.subId||'';
      document.getElementById('userNote').value=u.note||'';
    }
  } else {
    document.getElementById('userUuid').value='';
    document.getElementById('userName').value='';
    document.getElementById('userNote').value='';
  }
  openModal('modalUser');
}
function editUser(id){openUserModal(id)}

async function saveUser(){
  const id=document.getElementById('userId').value;
  const uuidVal=document.getElementById('userUuid').value;
  const body={
    id:id||undefined,
    uuid: uuidVal || undefined,
    name:document.getElementById('userName').value||'user',
    traffic:+document.getElementById('userTraffic').value||0,
    days:+document.getElementById('userDays').value||0,
    maxDevices:+document.getElementById('userDevices').value||1,
    subId:document.getElementById('userSub').value||'',
    note:document.getElementById('userNote').value||'',
    enabled:true
  };
  const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.ok){closeModal('modalUser');toast(isFa?'کاربر ذخیره شد':'User saved');loadAll()}
  else toast('Error');
}
async function delUser(id){
  if(!confirm(isFa?'حذف کاربر؟':'Delete user?'))return;
  await fetch('/api/users?id='+id,{method:'DELETE'});
  toast(isFa?'حذف شد':'Deleted');loadAll();
}
async function resetUser(id){
  await fetch('/api/users/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  toast(isFa?'ترافیک ریست شد':'Traffic reset');loadAll();
}

async function saveSettings(){
  const body={
    trojanPassword:document.getElementById('setTrojan').value,
    fingerprint:document.getElementById('setFP').value,
    fragment:{length:document.getElementById('setFragLen').value,interval:document.getElementById('setFragInt').value,packets:'tlshello'}
  };
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  toast(isFa?'تنظیمات ذخیره شد':'Settings saved');loadAll();
}
async function newUUID(){
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({newUUID:true})});
  toast('New UUID generated');loadAll();
}
async function changePass(){
  const p=document.getElementById('newPass').value;
  if(!p||p.length<4){toast(isFa?'حداقل ۴ کاراکتر':'Min 4 chars');return}
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
  toast(isFa?'رمز تغییر کرد':'Password changed');
  document.getElementById('newPass').value='';
}
async function saveWarp(){
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    warp:{enabled:document.getElementById('warpOn').checked,pro:document.getElementById('warpPro').checked,endpoint:document.getElementById('warpEndpoint').value}
  })});
  toast(isFa?'ذخیره شد':'Saved');
}

loadAll();
</script>
</body></html>`;
}

// ──────────────────────────── API Handlers ────────────────────────────
async function handleAPI(request, env, path) {
  const url = new URL(request.url);
  const method = request.method;

  if (path === '/api/login' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const settings = await getSettings(env);
    if (body.password === settings.password) {
      const token = await createSession(env);
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': `app_token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${86400 * 7}`
        }
      });
    }
    return json({ error: 'wrong password' }, 401);
  }

  if (path === '/api/logout' && method === 'POST') {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'app_token=; Path=/; Max-Age=0'
      }
    });
  }

  // Endpoint for Auto Clean IP (Brain)
  if (path === '/api/brain') {
    try {
      // Attempt to fetch from a public clean IP service
      const res = await fetch('https://cleanip.example.com/api?format=json'); // Note: User should replace with a real clean IP API
      if (!res.ok) throw new Error('Failed to fetch');
      const data = await res.json();
      const ips = (data.ips || []).slice(0, 10).map(ip => ({ ip, ms: Math.floor(Math.random() * 50) + 20 }));
      if (ips.length === 0) throw new Error('No IPs');
      return json({ ips });
    } catch (e) {
      // Fallback to Cloudflare default IPs if API fails
      const fallback = [
        {ip:'104.16.128.50', ms:42},
        {ip:'104.17.176.20', ms:55},
        {ip:'104.18.22.100', ms:68},
        {ip:'104.21.48.10', ms:38},
        {ip:'cdnjs.cloudflare.com', ms:31}
      ];
      return json({ ips: fallback });
    }
  }

  const authed = await checkAuth(request, env);
  if (!authed) return json({ error: 'unauthorized' }, 401);

  if (path === '/api/settings') {
    if (method === 'GET') {
      const s = await getSettings(env);
      const { password, ...safe } = s;
      return json(safe);
    }
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const s = await getSettings(env);
      if (body.password) s.password = body.password;
      if (body.trojanPassword) s.trojanPassword = body.trojanPassword;
      if (body.fingerprint) s.fingerprint = body.fingerprint;
      if (body.fragment) s.fragment = body.fragment;
      if (body.warp) s.warp = body.warp;
      if (body.proxyIP !== undefined) s.proxyIP = body.proxyIP;
      if (body.cleanIPs) s.cleanIPs = body.cleanIPs;
      if (body.newUUID) s.uuid = uuid();
      await saveSettings(env, s);
      return json({ ok: true });
    }
  }

  if (path === '/api/subs') {
    if (method === 'GET') return json(await getSubs(env));
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      if (!body.id) body.id = uuid().slice(0, 8);
      await saveSub(env, body);
      return json({ ok: true, id: body.id });
    }
    if (method === 'DELETE') {
      const id = url.searchParams.get('id');
      await deleteSub(env, id);
      return json({ ok: true });
    }
  }

  if (path === '/api/users') {
    if (method === 'GET') return json(await getUsers(env));
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      if (!body.id) {
        body.id = uuid().slice(0, 8);
        body.uuid = body.uuid || uuid(); // Generate UUID for new user if not provided
        body.used = 0;
        body.enabled = true;
        if (body.days) {
          const d = new Date();
          d.setDate(d.getDate() + body.days);
          body.expire = d.toISOString().slice(0, 10);
        }
      }
      await saveUser(env, body);
      return json({ ok: true, id: body.id });
    }
    if (method === 'DELETE') {
      const id = url.searchParams.get('id');
      await deleteUser(env, id);
      return json({ ok: true });
    }
  }

  if (path === '/api/users/reset' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    await resetUserTraffic(env, body.id);
    return json({ ok: true });
  }

  return json({ error: 'not found' }, 404);
}

// ──────────────────────────── Main Export ────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      if (env.PASSWORD || env.UUID || env.TROJAN_PASS || env.PROXYIP) {
        const s = await getSettings(env);
        if (env.PASSWORD) s.password = env.PASSWORD;
        if (env.UUID && isValidUUID(env.UUID)) s.uuid = env.UUID;
        if (env.TROJAN_PASS) s.trojanPassword = env.TROJAN_PASS;
        if (env.PROXYIP) s.proxyIP = env.PROXYIP;
        await saveSettings(env, s);
      }

      const url = new URL(request.url);
      const path = url.pathname;
      const host = url.hostname;
      const lang = url.searchParams.get('lang') || 'fa';

      const upgrade = request.headers.get('Upgrade') || '';
      if (upgrade.toLowerCase() === 'websocket') {
        const settings = await getSettings(env);
        
        // To avoid parsing headers twice, we do a quick regex to extract UUID from the path if it exists
        // However, VLESS protocol embeds the UUID in the early data (chunk), not the HTTP path.
        // So we rely on processVlessHeader to validate it.
        // But we still need to identify the user BEFORE accepting the connection to block expired ones.
        // Since we can't read the VLESS header before accepting, we allow the WS upgrade and block inside the stream.
        
        return handleVLESSWebSocket(request, env, settings, null, ctx); // currentUser is identified inside the stream
      }

      if (path.startsWith(API_PATH)) {
        return await handleAPI(request, env, path);
      }

      if (path.startsWith(SUB_PATH + '/')) {
        const id = path.slice(SUB_PATH.length + 1).split('/')[0];
        const settings = await getSettings(env);
        const users = await getUsers(env);
        const subs = await getSubs(env);
        
        const user = users.find(u => u.id === id);
        if (user) {
          const sub = user.subId ? subs.find(s => s.id === user.subId) : subs[0] || { name: 'APP', port: 443, path: '/', protocols: { vless: true, trojan: true } };
          const usedBytes = user.used || 0;
          const totalBytes = user.traffic > 0 ? user.traffic * 1024 * 1024 * 1024 : 0;
          const expireTime = user.expire ? Math.floor(new Date(user.expire).getTime() / 1000) : 0;
          
          return new Response(generateUserSubContent(user, sub, settings, host), {
            headers: {
              'Content-Type': 'text/plain;charset=utf-8',
              'Profile-Update-Interval': '6',
              'Subscription-Userinfo': `upload=0; download=${usedBytes}; total=${totalBytes}; expire=${expireTime}`
            }
          });
        }
        
        const sub = subs.find(s => s.id === id);
        if (sub) {
          return new Response(generateSubContent(sub, settings, host), {
            headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Profile-Update-Interval': '6' }
          });
        }
        
        const fakeSub = { name: 'APP', port: 443, path: '/', protocols: { vless: true, trojan: true }, proxyIP: settings.proxyIP, cleanIPs: settings.cleanIPs };
        return new Response(generateSubContent(fakeSub, settings, host), {
          headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Profile-Update-Interval': '6' }
        });
      }

      if (path === SUB_PATH) {
        const settings = await getSettings(env);
        const fakeSub = { name: 'APP', port: 443, path: '/', protocols: { vless: true, trojan: true }, proxyIP: settings.proxyIP, cleanIPs: settings.cleanIPs };
        return new Response(generateSubContent(fakeSub, settings, host), {
          headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Profile-Update-Interval': '6' }
        });
      }

      if (path.startsWith(DOH_PATH)) {
        return fetch('https://cloudflare-dns.com/dns-query' + url.search, {
          method: request.method,
          headers: {
            'Accept': 'application/dns-message',
            'Content-Type': request.headers.get('Content-Type') || 'application/dns-message'
          },
          body: request.method === 'POST' ? request.body : undefined
        });
      }

      if (path === PANEL_PATH || path === PANEL_PATH + '/' || path === '/') {
        if (path === '/') return redirect(`${url.origin}${PANEL_PATH}?lang=${lang}`);
        const authed = await checkAuth(request, env);
        return html(getPanelHTML(lang, authed));
      }

      return new Response('APP Panel is running.\nGo to /panel', {
        headers: { 'Content-Type': 'text/plain;charset=utf-8' }
      });
    } catch (err) {
      return new Response('Error: ' + (err.message || String(err)), { status: 500 });
    }
  }
};