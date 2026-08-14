/**
 * ═══════════════════════════════════════════════════════════════
 *   SinaPanel / APP Panel · Advanced Proxy System v2.0
 *   پشتیبانی کامل از VLESS, Trojan, محاسبه واقعی ترافیک و ساب‌لینک
 * ═══════════════════════════════════════════════════════════════
 */

import { connect } from 'cloudflare:sockets';

const DEFAULT_PASSWORD = '123456';
const PANEL_PATH = '/panel';
const SUB_PATH = '/sub';
const DOH_PATH = '/doh';
const API_PATH = '/api';

// ──────────────────────────── Crypto & Helpers ────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

async function sha224Hex(str) {
  const buf = await crypto.subtle.digest('SHA-224', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
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

// ──────────────────────────── KV Operations ────────────────────────────
function defaultSettings() {
  return {
    password: DEFAULT_PASSWORD,
    uuid: uuid(),
    trojanPassword: 'tr-' + Math.random().toString(36).slice(2, 10),
    proxyIP: '',
    cleanIPs: []
  };
}

async function getSettings(env) {
  if (!env.APP_KV) return defaultSettings();
  const raw = await env.APP_KV.get('settings', 'json');
  return raw ? { ...defaultSettings(), ...raw } : defaultSettings();
}

async function saveSettings(env, data) {
  if (!env.APP_KV) return;
  await env.APP_KV.put('settings', JSON.stringify(data));
}

async function getSubs(env) {
  if (!env.APP_KV) return [];
  const raw = await env.APP_KV.get('subs', 'json');
  return raw || [];
}

async function saveSubs(env, data) {
  if (!env.APP_KV) return;
  await env.APP_KV.put('subs', JSON.stringify(data));
}

async function getUsers(env) {
  if (!env.APP_KV) return [];
  const raw = await env.APP_KV.get('users', 'json');
  return raw || [];
}

async function saveUsers(env, data) {
  if (!env.APP_KV) return;
  await env.APP_KV.put('users', JSON.stringify(data));
}

async function addTrafficToUser(env, userId, bytes) {
  if (!env.APP_KV || !userId || bytes <= 0) return;
  const gbUsed = bytes / (1024 * 1024 * 1024);
  const users = await getUsers(env);
  const idx = users.findIndex(u => u.id === userId || u.uuid === userId);
  if (idx >= 0) {
    users[idx].used = Number(((users[idx].used || 0) + gbUsed).toFixed(4));
    await saveUsers(env, users);
  }
}

// ──────────────────────────── Session Auth ────────────────────────────
async function checkAuth(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/app_token=([^;]+)/);
  if (!match) return false;
  const token = match[1];
  if (!env.APP_KV) return token.length > 8;
  const session = await env.APP_KV.get('session:' + token);
  return !!session;
}

async function createSession(env) {
  const token = crypto.randomUUID().replace(/-/g, '');
  if (env.APP_KV) {
    await env.APP_KV.put('session:' + token, '1', { expirationTtl: 86400 * 7 });
  }
  return token;
}

// ──────────────────────────── Config Generators ────────────────────────────
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
  return `vless://${userUuid}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark)}`;
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
  return `trojan://${password}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark)}`;
}

function generateUserSubContent(user, settings, subs, host) {
  const links = [];
  const userUuid = user.uuid || settings.uuid;
  const trojanPass = user.trojanPassword || settings.trojanPassword;

  if (!subs || subs.length === 0) {
    subs = [{
      name: 'Standard',
      port: 443,
      path: '/',
      protocols: { vless: true, trojan: true },
      proxyIP: settings.proxyIP,
      cleanIPs: settings.cleanIPs
    }];
  }

  for (const sub of subs) {
    const port = sub.port || 443;
    const path = sub.path || '/';
    const baseRemark = `${user.name}-${sub.name || 'CF'}`;
    const proxyIP = sub.proxyIP || settings.proxyIP || '';
    const cleanIPs = (sub.cleanIPs || settings.cleanIPs || []).filter(Boolean);

    if (sub.protocols?.vless !== false) {
      links.push(generateVlessLink(host, userUuid, port, path, baseRemark, proxyIP));
      for (let i = 0; i < cleanIPs.length; i++) {
        links.push(generateVlessLink(host, userUuid, port, path, `${baseRemark}-Clean${i + 1}`, cleanIPs[i]));
      }
    }
    if (sub.protocols?.trojan) {
      links.push(generateTrojanLink(host, trojanPass, port, path, `${baseRemark}-Trojan`, proxyIP));
    }
  }

  return btoa(links.join('\n'));
}

// ──────────────────────────── Header Decoders ────────────────────────────
function processVlessHeader(buffer) {
  if (buffer.byteLength < 24) return { hasError: true };
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1))[0];
  const uuidBytes = new Uint8Array(buffer.slice(1, 17));
  const userUuid = [...uuidBytes].map(b => b.toString(16).padStart(2, '0')).join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');

  const optLen = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLen, 19 + optLen))[0];
  if (cmd !== 1 && cmd !== 2) return { hasError: true };

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
      return { hasError: true };
  }

  const rawDataIndex = addressIndex + addressLength;
  return {
    hasError: false,
    userUuid,
    addressRemote,
    portRemote,
    rawDataIndex,
    versionByte: new Uint8Array([version]),
    isUDP: cmd === 2
  };
}

async function processTrojanHeader(buffer) {
  if (buffer.byteLength < 58) return { hasError: true };
  const hexBytes = new Uint8Array(buffer.slice(0, 56));
  const recvHash = new TextDecoder().decode(hexBytes);
  
  const view = new DataView(buffer);
  const cmd = view.getUint8(58);
  const addressType = view.getUint8(59);
  
  let addressIndex = 60;
  let addressRemote = '';
  let addressLength = 0;

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressRemote = new Uint8Array(buffer.slice(addressIndex, addressIndex + addressLength)).join('.');
      break;
    case 3:
      addressLength = view.getUint8(addressIndex);
      addressIndex += 1;
      addressRemote = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(addressIndex + i * 2).toString(16));
      addressRemote = ipv6.join(':');
      break;
    default:
      return { hasError: true };
  }

  const portIndex = addressIndex + addressLength;
  const portRemote = view.getUint16(portIndex);
  const rawDataIndex = portIndex + 4;

  return {
    hasError: false,
    recvHash,
    addressRemote,
    portRemote,
    rawDataIndex,
    isUDP: cmd === 3
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

// ──────────────────────────── Core Proxy Handler ────────────────────────────
async function handleProxyWebSocket(request, env, settings) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let remoteSocket = { value: null };
  let trackedUserId = null;
  let totalBytesTransferred = 0;

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const { data: earlyData } = base64ToArrayBuffer(earlyDataHeader);
  const readable = makeReadableWebSocketStream(webSocket, earlyData);

  const users = await getUsers(env);

  readable.pipeTo(new WritableStream({
    async write(chunk) {
      totalBytesTransferred += chunk.byteLength;

      if (remoteSocket.value) {
        const writer = remoteSocket.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      // 1. Try VLESS
      const parsedVless = processVlessHeader(chunk);
      if (!parsedVless.hasError) {
        const matchedUser = users.find(u => u.uuid === parsedVless.userUuid) ||
                            (parsedVless.userUuid.toLowerCase() === settings.uuid.toLowerCase() ? { id: 'admin', enabled: true } : null);

        if (!matchedUser || matchedUser.enabled === false) {
          webSocket.close(1000, 'Unauthorized');
          return;
        }

        if (matchedUser.id !== 'admin') {
          if (matchedUser.traffic > 0 && matchedUser.used >= matchedUser.traffic) {
            webSocket.close(1000, 'Traffic Limit Exceeded');
            return;
          }
          if (matchedUser.expire && new Date(matchedUser.expire) < new Date()) {
            webSocket.close(1000, 'Expired');
            return;
          }
          trackedUserId = matchedUser.id;
        }

        const target = settings.proxyIP || parsedVless.addressRemote;
        try {
          const sock = connect({ hostname: target, port: parsedVless.portRemote });
          remoteSocket.value = sock;
          const writer = sock.writable.getWriter();
          await writer.write(chunk.slice(parsedVless.rawDataIndex));
          writer.releaseLock();

          webSocket.send(new Uint8Array([parsedVless.versionByte[0], 0]));

          sock.readable.pipeTo(new WritableStream({
            write(data) {
              totalBytesTransferred += data.byteLength;
              webSocket.send(data);
            },
            close() { try { webSocket.close(); } catch (_) {} },
            abort() { try { webSocket.close(); } catch (_) {} }
          })).catch(() => {});
        } catch (e) {
          webSocket.close(1000, 'Connection Failed');
        }
        return;
      }

      // 2. Try Trojan
      const parsedTrojan = await processTrojanHeader(chunk);
      if (!parsedTrojan.hasError) {
        const adminHash = await sha224Hex(settings.trojanPassword);
        let matchedUser = parsedTrojan.recvHash === adminHash ? { id: 'admin', enabled: true } : null;

        if (!matchedUser) {
          for (const u of users) {
            const uHash = await sha224Hex(u.trojanPassword || settings.trojanPassword);
            if (uHash === parsedTrojan.recvHash) {
              matchedUser = u;
              break;
            }
          }
        }

        if (!matchedUser || matchedUser.enabled === false) {
          webSocket.close(1000, 'Trojan Unauthorized');
          return;
        }

        if (matchedUser.id !== 'admin') {
          if (matchedUser.traffic > 0 && matchedUser.used >= matchedUser.traffic) {
            webSocket.close(1000, 'Traffic Limit Exceeded');
            return;
          }
          trackedUserId = matchedUser.id;
        }

        const target = settings.proxyIP || parsedTrojan.addressRemote;
        try {
          const sock = connect({ hostname: target, port: parsedTrojan.portRemote });
          remoteSocket.value = sock;
          const writer = sock.writable.getWriter();
          await writer.write(chunk.slice(parsedTrojan.rawDataIndex));
          writer.releaseLock();

          sock.readable.pipeTo(new WritableStream({
            write(data) {
              totalBytesTransferred += data.byteLength;
              webSocket.send(data);
            },
            close() { try { webSocket.close(); } catch (_) {} },
            abort() { try { webSocket.close(); } catch (_) {} }
          })).catch(() => {});
        } catch (e) {
          webSocket.close(1000, 'Trojan Connect Failed');
        }
        return;
      }

      webSocket.close(1000, 'Invalid Protocol');
    }
  })).then(async () => {
    if (trackedUserId && totalBytesTransferred > 0) {
      await addTrafficToUser(env, trackedUserId, totalBytesTransferred);
    }
  }).catch(() => {});

  return new Response(null, { status: 101, webSocket: client });
}

// ──────────────────────────── Dashboard UI ────────────────────────────
function getPanelHTML(lang, authenticated) {
  const isFa = lang !== 'en';
  if (!authenticated) {
    return `<!DOCTYPE html>
<html lang="${isFa ? 'fa' : 'en'}" dir="${isFa ? 'rtl' : 'ltr'}">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SinaPanel Login</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
:root{--bg:#030303;--green:#00ff88;--glow:rgba(0,255,136,.35);--text:#e8ffe8;--muted:#6b8f6b;--border:rgba(0,255,136,.15)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#0a0f0a;border:1px solid var(--border);border-radius:14px;padding:2rem;width:100%;max-width:360px;text-align:center}
h1{color:var(--green);font-size:1.4rem;margin-bottom:.3rem;text-shadow:0 0 14px var(--glow)}
p{color:var(--muted);font-size:.85rem;margin-bottom:1.2rem}
input{width:100%;padding:.7rem;background:rgba(0,0,0,.45);border:1px solid var(--border);border-radius:9px;color:var(--text);font-size:.95rem;margin-bottom:.8rem}
button{width:100%;padding:.7rem;background:var(--green);color:#000;border:none;border-radius:9px;font-weight:700;cursor:pointer}
.err{color:#ff4d6a;font-size:.8rem;margin-top:.5rem;display:none}
</style>
</head>
<body>
<div class="box">
  <h1>SinaPanel v2.0</h1>
  <p>${isFa ? 'رمز عبور مدیریت را وارد کنید' : 'Enter Admin Password'}</p>
  <form id="f">
    <input type="password" id="pass" placeholder="${isFa ? 'رمز عبور' : 'Password'}" autofocus>
    <button type="submit">${isFa ? 'ورود' : 'Login'}</button>
    <div class="err" id="err">${isFa ? 'رمز عبور اشتباه است' : 'Invalid Password'}</div>
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
<title>SinaPanel Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root{--bg:#030303;--card:#0a0f0a;--green:#00ff88;--g2:#00cc6a;--glow:rgba(0,255,136,.35);--soft:rgba(0,255,136,.1);--text:#e8ffe8;--muted:#6b8f6b;--border:rgba(0,255,136,.15);--border2:rgba(0,255,136,.3);--red:#ff4d6a}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
.container{max-width:1080px;margin:0 auto;padding:1rem .9rem 3rem}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;padding-bottom:.7rem;border-bottom:1px solid var(--border)}
.logo{font-weight:800;font-size:1.15rem;color:var(--green);text-shadow:0 0 12px var(--glow)}
.nav{display:flex;gap:.3rem;margin-bottom:1rem}
.nav a{padding:.4rem .8rem;border-radius:8px;color:var(--muted);font-size:.8rem;font-weight:600;cursor:pointer;text-decoration:none}
.nav a.active,.nav a:hover{color:#000;background:var(--green);box-shadow:0 0 10px var(--glow)}
.card{background:var(--card);border:1px solid var(--border);border-radius:11px;padding:1rem;margin-bottom:.8rem}
h2{font-size:.9rem;font-weight:700;color:var(--green);margin-bottom:.6rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.5rem;margin-bottom:.8rem}
.stat{background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:9px;padding:.6rem;text-align:center}
.stat-value{font-size:1.2rem;font-weight:800;color:var(--green)}
.stat-label{font-size:.65rem;color:var(--muted)}
.progress-wrap{margin:.4rem 0}.progress-head{display:flex;justify-content:space-between;font-size:.7rem;margin-bottom:.15rem}
.progress-bar{height:6px;background:rgba(0,255,136,.1);border-radius:99px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--g2),var(--green))}
.config-box{background:rgba(0,0,0,.5);border:1px solid var(--border);border-radius:8px;padding:.5rem;font-family:monospace;font-size:.7rem;word-break:break-all;color:#b8ffd0;margin:.4rem 0}
button,.btn{display:inline-flex;align-items:center;gap:.3rem;padding:.45rem .8rem;background:var(--green);color:#000;border:none;border-radius:8px;font-size:.78rem;font-weight:700;cursor:pointer}
.btn-sm{padding:.25rem .5rem;font-size:.7rem}
.btn-outline{background:transparent;border:1px solid var(--border2);color:var(--green)}
.btn-danger{background:transparent;border:1px solid rgba(255,77,106,.4);color:var(--red)}
.badge{padding:.1rem .4rem;border-radius:999px;font-size:.62rem;font-weight:600;background:var(--soft);color:var(--green);border:1px solid var(--border)}
.badge-red{background:rgba(255,77,106,.1);color:var(--red);border-color:rgba(255,77,106,.3)}
input,select{width:100%;padding:.5rem;background:rgba(0,0,0,.45);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:.8rem;margin-bottom:.4rem}
.toast{position:fixed;bottom:1rem;left:1rem;background:var(--green);color:#000;padding:.5rem 1rem;border-radius:8px;font-weight:700;font-size:.8rem;opacity:0;transition:.25s;z-index:90}
.toast.show{opacity:1}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.8);display:none;align-items:center;justify-content:center;z-index:80;padding:.8rem}
.modal-bg.show{display:flex}
.modal{background:var(--card);border:1px solid var(--border2);border-radius:12px;padding:1.2rem;max-width:450px;width:100%}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">SinaPanel v2.0</div>
    <div><button class="btn-outline btn-sm" onclick="logout()">${isFa ? 'خروج' : 'Logout'}</button></div>
  </div>
  <div class="nav">
    <a class="active" onclick="tab('dash')">${isFa ? 'داشبورد' : 'Dashboard'}</a>
    <a onclick="tab('users')">${isFa ? 'مدیریت کاربران' : 'Users'}</a>
    <a onclick="tab('subs')">${isFa ? 'قالب ساب‌لینک' : 'Templates'}</a>
    <a onclick="tab('set')">${isFa ? 'تنظیمات' : 'Settings'}</a>
  </div>

  <div id="tab-dash">
    <div class="card">
      <h2>${isFa ? 'خلاصه وضعیت سیستم' : 'System Overview'}</h2>
      <div class="stats">
        <div class="stat"><div class="stat-value" id="sUsers">0</div><div class="stat-label">${isFa ? 'کل کاربران' : 'Total Users'}</div></div>
        <div class="stat"><div class="stat-value" id="sActiveUsers">0</div><div class="stat-label">${isFa ? 'کاربران فعال' : 'Active Users'}</div></div>
        <div class="stat"><div class="stat-value" id="sTotalTraffic">0 GB</div><div class="stat-label">${isFa ? 'کل مصرف ترافیک' : 'Total Traffic'}</div></div>
      </div>
    </div>
  </div>

  <div id="tab-users" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem">
        <h2 style="margin:0">${isFa ? 'مدیریت کاربران' : 'User Management'}</h2>
        <button onclick="openUserModal()">${isFa ? '+ کاربر جدید' : '+ New User'}</button>
      </div>
      <div id="usersList"></div>
    </div>
  </div>

  <div id="tab-subs" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.8rem">
        <h2 style="margin:0">${isFa ? 'قالب‌های ساب‌لینک' : 'Subscription Templates'}</h2>
        <button onclick="openSubModal()">${isFa ? '+ ساخت قالب' : '+ New Template'}</button>
      </div>
      <div id="subsList"></div>
    </div>
  </div>

  <div id="tab-set" class="hidden">
    <div class="card">
      <h2>${isFa ? 'تنظیمات عمومی پروکسی' : 'Global Settings'}</h2>
      <label>${isFa ? 'پروکسی آی‌پی (Proxy IP)' : 'Proxy IP'}</label>
      <input id="setProxyIP" placeholder="104.16.128.50">
      <label>${isFa ? 'رمز پیش‌فرض ترجان' : 'Default Trojan Password'}</label>
      <input id="setTrojan">
      <button onclick="saveSettings()">${isFa ? 'ذخیره تنظیمات' : 'Save Settings'}</button>
    </div>
  </div>
</div>

<!-- Modal User -->
<div class="modal-bg" id="modalUser">
  <div class="modal">
    <h3>${isFa ? 'افزودن کاربر جدید' : 'New User'}</h3>
    <input type="hidden" id="userId">
    <label>${isFa ? 'نام کاربر' : 'Username'}</label>
    <input id="userName" placeholder="e.g. Ali">
    <label>${isFa ? 'حجم به گیگابایت (0 = نامحدود)' : 'Traffic GB'}</label>
    <input type="number" id="userTraffic" value="50">
    <label>${isFa ? 'مدت اعتبار (روز)' : 'Expire Days'}</label>
    <input type="number" id="userDays" value="30">
    <div style="display:flex;gap:.4rem;margin-top:.8rem">
      <button onclick="saveUser()">${isFa ? 'ذخیره' : 'Save'}</button>
      <button class="btn-outline" onclick="closeModal('modalUser')">${isFa ? 'انصراف' : 'Cancel'}</button>
    </div>
  </div>
</div>

<!-- Modal Sub -->
<div class="modal-bg" id="modalSub">
  <div class="modal">
    <h3>${isFa ? 'قالب ساب‌لینک' : 'Sub Template'}</h3>
    <input type="hidden" id="subId">
    <label>${isFa ? 'نام قالب' : 'Template Name'}</label>
    <input id="subName" placeholder="CF-Direct">
    <label>${isFa ? 'پورت' : 'Port'}</label>
    <input type="number" id="subPort" value="443">
    <label>${isFa ? 'Clean IPs (هر آی‌پی در یک خط)' : 'Clean IPs'}</label>
    <textarea id="subCleanIPs" style="width:100%;height:60px;background:rgba(0,0,0,.45);border:1px solid var(--border);color:var(--text);border-radius:7px;padding:.5rem;margin-bottom:.4rem" placeholder="104.21.48.10"></textarea>
    <div style="display:flex;gap:.4rem;margin-top:.8rem">
      <button onclick="saveSub()">${isFa ? 'ذخیره' : 'Save'}</button>
      <button class="btn-outline" onclick="closeModal('modalSub')">${isFa ? 'انصراف' : 'Cancel'}</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const isFa = ${isFa ? 'true' : 'false'};
let users = [], subs = [], settings = {};

function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200)}
function tab(t){
  document.querySelectorAll('.nav a').forEach(x=>x.classList.remove('active'));
  event.target.classList.add('active');
  ['dash','users','subs','set'].forEach(x=>document.getElementById('tab-'+x).classList.toggle('hidden', x!==t));
}
function openModal(id){document.getElementById(id).classList.add('show')}
function closeModal(id){document.getElementById(id).classList.remove('show')}
async function logout(){await fetch('/api/logout',{method:'POST'});location.reload()}

async function loadAll(){
  const [s, u, sb] = await Promise.all([
    fetch('/api/settings').then(r=>r.json()),
    fetch('/api/users').then(r=>r.json()),
    fetch('/api/subs').then(r=>r.json())
  ]);
  settings=s; users=u; subs=sb;
  render();
}

function render(){
  document.getElementById('sUsers').textContent = users.length;
  document.getElementById('sActiveUsers').textContent = users.filter(x=>x.enabled!==false).length;
  const totUsed = users.reduce((acc, u) => acc + (u.used || 0), 0);
  document.getElementById('sTotalTraffic').textContent = totUsed.toFixed(2) + ' GB';
  document.getElementById('setProxyIP').value = settings.proxyIP || '';
  document.getElementById('setTrojan').value = settings.trojanPassword || '';

  const ul = document.getElementById('usersList');
  if(!users.length) { ul.innerHTML = '<p style="color:var(--muted)">' + (isFa?'هیچ کاربر متصلی پیدا نشد':'No users created yet') + '</p>'; }
  else {
    ul.innerHTML = users.map(u => {
      const subUrl = location.origin + '/sub/' + (u.uuid || u.id);
      const used = (u.used || 0).toFixed(2);
      const total = u.traffic || '∞';
      const pct = u.traffic > 0 ? Math.min(100, Math.round((u.used / u.traffic) * 100)) : 0;
      const isExpired = u.expire && new Date(u.expire) < new Date();
      const isActive = u.enabled !== false && !isExpired && (u.traffic === 0 || u.used < u.traffic);

      return '<div class="card" style="background:rgba(0,0,0,.3)">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.4rem">' +
        '<div><strong>' + u.name + '</strong> ' + (isActive ? '<span class="badge">' + (isFa?'فعال':'Active') + '</span>' : '<span class="badge badge-red">' + (isFa?'غیرفعال':'Disabled') + '</span>') + '</div>' +
        '<div style="display:flex;gap:.3rem">' +
        '<button class="btn-outline btn-sm" onclick="copyText(\\'' + subUrl + '\\')">' + (isFa?'کپی ساب':'Copy Sub') + '</button>' +
        '<button class="btn-outline btn-sm" onclick="toggleUser(\\'' + u.id + '\\')">' + (u.enabled!==false?(isFa?'غیرفعال':'Disable'):(isFa?'فعال':'Enable')) + '</button>' +
        '<button class="btn-outline btn-sm" onclick="resetUser(\\'' + u.id + '\\')">' + (isFa?'صفر کردن حجم':'Reset') + '</button>' +
        '<button class="btn-danger btn-sm" onclick="delUser(\\'' + u.id + '\\')">' + (isFa?'حذف':'Delete') + '</button>' +
        '</div></div>' +
        '<div class="progress-wrap"><div class="progress-head"><span>' + (isFa?'مصرف ترافیک':'Traffic') + '</span><span>' + used + ' / ' + total + ' GB</span></div>' +
        '<div class="progress-bar"><div class="progress-fill" style="width:' + pct + '%"></div></div></div>' +
        '<div class="config-box">' + subUrl + '</div>' +
        '<div style="font-size:.7rem;color:var(--muted)">UUID: ' + u.uuid + ' | ' + (isFa?'تاریخ انقضا':'Expire') + ': ' + (u.expire || 'Permanent') + '</div>' +
        '</div>';
    }).join('');
  }

  const sl = document.getElementById('subsList');
  if(!subs.length) { sl.innerHTML = '<p style="color:var(--muted)">' + (isFa?'قالبی وجود ندارد':'No templates') + '</p>'; }
  else {
    sl.innerHTML = subs.map(s => {
      return '<div class="card" style="background:rgba(0,0,0,.3)">' +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<div><strong>' + s.name + '</strong> (Port ' + s.port + ')</div>' +
        '<button class="btn-danger btn-sm" onclick="delSub(\\'' + s.id + '\\')">' + (isFa?'حذف':'Delete') + '</button>' +
        '</div></div>';
    }).join('');
  }
}

function copyText(t){navigator.clipboard.writeText(t).then(()=>toast(isFa?'لینک ساب‌لینک کپی شد':'Copied'))}

function openUserModal(){
  document.getElementById('userId').value='';
  document.getElementById('userName').value='';
  openModal('modalUser');
}

async function saveUser(){
  const id = document.getElementById('userId').value;
  const name = document.getElementById('userName').value || 'User';
  const traffic = +document.getElementById('userTraffic').value || 0;
  const days = +document.getElementById('userDays').value || 0;

  await fetch('/api/users', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ id, name, traffic, days })
  });
  closeModal('modalUser');
  toast(isFa?'ذخیره شد':'Saved');
  loadAll();
}

async function toggleUser(id){
  const u = users.find(x=>x.id===id);
  if(!u) return;
  await fetch('/api/users', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ id: u.id, enabled: u.enabled === false ? true : false })
  });
  toast(isFa?'وضعیت تغییر کرد':'Status updated');
  loadAll();
}

async function resetUser(id){
  await fetch('/api/users/reset', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ id })
  });
  toast(isFa?'حجم مصرفی صفر شد':'Traffic reset');
  loadAll();
}

async function delUser(id){
  if(!confirm(isFa?'آیا از حذف این کاربر اطمینان دارید؟':'Delete?')) return;
  await fetch('/api/users?id='+id, {method: 'DELETE'});
  toast(isFa?'حذف شد':'Deleted');
  loadAll();
}

function openSubModal(){ openModal('modalSub'); }

async function saveSub(){
  const name = document.getElementById('subName').value || 'CF';
  const port = +document.getElementById('subPort').value || 443;
  const cleanIPs = document.getElementById('subCleanIPs').value.split('\n').map(x=>x.trim()).filter(Boolean);

  await fetch('/api/subs', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ name, port, cleanIPs, protocols: {vless: true, trojan: true} })
  });
  closeModal('modalSub');
  toast(isFa?'ذخیره شد':'Saved');
  loadAll();
}

async function delSub(id){
  await fetch('/api/subs?id='+id, {method: 'DELETE'});
  loadAll();
}

async function saveSettings(){
  const proxyIP = document.getElementById('setProxyIP').value.trim();
  const trojanPassword = document.getElementById('setTrojan').value.trim();
  await fetch('/api/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ proxyIP, trojanPassword })
  });
  toast(isFa?'تنظیمات ذخیره شد':'Saved');
  loadAll();
}

loadAll();
</script>
</body></html>`;
}

// ──────────────────────────── API Router ────────────────────────────
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
      if (body.proxyIP !== undefined) s.proxyIP = body.proxyIP;
      if (body.trojanPassword) s.trojanPassword = body.trojanPassword;
      await saveSettings(env, s);
      return json({ ok: true });
    }
  }

  if (path === '/api/users') {
    if (method === 'GET') return json(await getUsers(env));
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      let list = await getUsers(env);
      if (body.id) {
        const idx = list.findIndex(x => x.id === body.id);
        if (idx >= 0) list[idx] = { ...list[idx], ...body };
      } else {
        const newUser = {
          id: uuid().slice(0, 8),
          uuid: uuid(),
          name: body.name || 'User',
          traffic: body.traffic || 0,
          used: 0,
          enabled: true,
          trojanPassword: 'tr-' + Math.random().toString(36).slice(2, 8)
        };
        if (body.days > 0) {
          const d = new Date();
          d.setDate(d.getDate() + body.days);
          newUser.expire = d.toISOString().slice(0, 10);
        }
        list.push(newUser);
      }
      await saveUsers(env, list);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      const id = url.searchParams.get('id');
      let list = await getUsers(env);
      list = list.filter(x => x.id !== id);
      await saveUsers(env, list);
      return json({ ok: true });
    }
  }

  if (path === '/api/users/reset' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    let list = await getUsers(env);
    const idx = list.findIndex(x => x.id === body.id);
    if (idx >= 0) {
      list[idx].used = 0;
      await saveUsers(env, list);
    }
    return json({ ok: true });
  }

  if (path === '/api/subs') {
    if (method === 'GET') return json(await getSubs(env));
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      let list = await getSubs(env);
      body.id = uuid().slice(0, 8);
      list.push(body);
      await saveSubs(env, list);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      const id = url.searchParams.get('id');
      let list = await getSubs(env);
      list = list.filter(x => x.id !== id);
      await saveSubs(env, list);
      return json({ ok: true });
    }
  }

  return json({ error: 'not found' }, 404);
}

// ──────────────────────────── Main Entry Point ────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const host = url.hostname;
      const lang = url.searchParams.get('lang') || 'fa';

      // 1. WebSocket Upgrade Handler
      const upgrade = request.headers.get('Upgrade') || '';
      if (upgrade.toLowerCase() === 'websocket') {
        const settings = await getSettings(env);
        return await handleProxyWebSocket(request, env, settings);
      }

      // 2. API Endpoints
      if (path.startsWith(API_PATH)) {
        return await handleAPI(request, env, path);
      }

      // 3. User Subscription Link (/sub/:user_id)
      if (path.startsWith(SUB_PATH + '/')) {
        const token = path.slice(SUB_PATH.length + 1).split('/')[0];
        const settings = await getSettings(env);
        const users = await getUsers(env);
        const subs = await getSubs(env);

        const user = users.find(u => u.uuid === token || u.id === token);

        if (!user) {
          return new Response('User Not Found', { status: 404 });
        }

        if (user.enabled === false) {
          return new Response('User Disabled', { status: 403 });
        }

        const usedBytes = Math.floor((user.used || 0) * 1024 * 1024 * 1024);
        const totalBytes = Math.floor((user.traffic || 0) * 1024 * 1024 * 1024);
        const expireTs = user.expire ? Math.floor(new Date(user.expire).getTime() / 1000) : 0;

        const subContent = generateUserSubContent(user, settings, subs, host);

        return new Response(subContent, {
          headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Subscription-Userinfo': `upload=0; download=${usedBytes}; total=${totalBytes}; expire=${expireTs}`,
            'Profile-Update-Interval': '6'
          }
        });
      }

      // 4. DoH Resolver
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

      // 5. Panel Routing
      if (path === PANEL_PATH || path === PANEL_PATH + '/' || path === '/') {
        if (path === '/') return redirect(`${url.origin}${PANEL_PATH}?lang=${lang}`);
        const authed = await checkAuth(request, env);
        return html(getPanelHTML(lang, authed));
      }

      return new Response('SinaPanel v2.0 is Active.\nGo to /panel', { status: 200 });
    } catch (err) {
      return new Response('Error: ' + (err.message || String(err)), { status: 500 });
    }
  }
};