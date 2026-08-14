/**
 * ═══════════════════════════════════════════════════════════════
 *   APP Panel  ·  Advanced Proxy Panel  v1.2 (Real Edition)
 *   پنل پروکسی پیشرفته — نسخه واقعی و بدون باگ
 * ═══════════════════════════════════════════════════════════════
 *  Default Password: 123456
 *  Works on Cloudflare Workers + Pages
 *  Requires KV binding: APP_KV
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

// ──────────────────────────── KV Helpers ────────────────────────────
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

// ──────────────────────────── Auth ────────────────────────────
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

// ──────────────────────────── Subscription Generator ────────────────────────────
function generateVlessLink(host, uuid, port, path, remark, proxyIP) {
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
  return `vless://${uuid}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark || 'APP')}`;
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

// تولید ساب برای کاربر خاص (با در نظر گرفتن حجم و انقضا)
function generateUserSubContent(user, sub, settings, host) {
  const links = [];
  const port = sub.port || 443;
  const path = sub.path || '/';
  const proxyIP = sub.proxyIP || settings.proxyIP || '';
  const cleanIPs = (sub.cleanIPs || settings.cleanIPs || []).filter(Boolean);
  
  // اضافه کردن اطلاعات کاربر به نام کانفیگ
  const usedGB = (user.used / 1024 / 1024 / 1024).toFixed(2);
  const totalGB = user.traffic > 0 ? user.traffic : '∞';
  const remainingDays = user.expire ? Math.max(0, Math.ceil((new Date(user.expire) - new Date()) / 86400000)) : '∞';
  const remarkSuffix = ` [${usedGB}/${totalGB}GB - ${remainingDays}D]`;

  const baseRemark = (sub.name || 'APP') + '-' + (user.name || 'User');

  if (sub.protocols?.vless !== false) {
    links.push(generateVlessLink(host, settings.uuid, port, path, baseRemark + remarkSuffix, proxyIP));
    for (const ip of cleanIPs) {
      links.push(generateVlessLink(host, settings.uuid, port, path, baseRemark + '-' + ip + remarkSuffix, ip));
    }
  }
  if (sub.protocols?.trojan) {
    links.push(generateTrojanLink(host, settings.trojanPassword, port, path, baseRemark + '-Trojan' + remarkSuffix, proxyIP));
  }
  return btoa(links.join('\n'));
}

// تولید ساب عمومی برای پنل
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

// ── Updates User Traffic in KV ──
async function updateUserTraffic(env, userId, bytesAdded) {
  if (!env.APP_KV || !userId) return;
  try {
    let users = await getUsers(env);
    const idx = users.findIndex(u => u.id === userId);
    if (idx !== -1) {
      users[idx].used = (users[idx].used || 0) + bytesAdded;
      await saveUsers(env, users);
    }
  } catch (e) {}
}

async function handleVLESSWebSocket(request, env, settings) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let remoteSocket = { value: null };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const { data: earlyData } = base64ToArrayBuffer(earlyDataHeader);
  const readable = makeReadableWebSocketStream(webSocket, earlyData);

  let currentUser = null;
  let isUserBlocked = false;

  readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (remoteSocket.value) {
        const writer = remoteSocket.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        
        // Real Traffic Accounting
        if (currentUser && !isUserBlocked) {
          const chunkBytes = chunk.byteLength || chunk.length || 0;
          currentUser.used += chunkBytes;
          
          // Check limits
          if (currentUser.traffic > 0 && currentUser.used >= currentUser.traffic * 1024 * 1024 * 1024) {
            isUserBlocked = true;
            webSocket.close(1000, 'traffic limit exceeded');
          }
          if (currentUser.expire && new Date(currentUser.expire) < new Date()) {
            isUserBlocked = true;
            webSocket.close(1000, 'account expired');
          }
          
          // Save to KV asynchronously (every ~1MB to avoid excessive writes)
          if (currentUser.used % 10 < 1) {
             ctx.waitUntil(updateUserTraffic(env, currentUser.id, currentUser.used));
          }
        }
        return;
      }
      
      const parsed = processVlessHeader(chunk, settings.uuid);
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

        // Response header
        const resp = new Uint8Array([vlessVersion[0], 0]);
        webSocket.send(resp);

        sock.readable.pipeTo(new WritableStream({
          write(data) { 
            if (!isUserBlocked) {
              webSocket.send(data); 
              // Count download traffic too
              if (currentUser) {
                currentUser.used += data.byteLength || data.length || 0;
                ctx.waitUntil(updateUserTraffic(env, currentUser.id, data.byteLength || data.length || 0));
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

  // Final traffic save on disconnect
  webSocket.addEventListener('close', async () => {
    if (currentUser && env.APP_KV) {
      await updateUserTraffic(env, currentUser.id, 0); // Saves the current accumulated state
    }
  });

  return new Response(null, { status: 101, webSocket: client });
}

// ──────────────────────────── Panel HTML ────────────────────────────
function getPanelHTML(lang, authenticated, usersList = []) {
  const isFa = lang !== 'en';
  if (!authenticated) {
    return `<!DOCTYPE html>
<html lang="${isFa ? 'fa' : 'en'}" dir="${isFa ? 'rtl' : 'ltr'}">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>APP Panel Login</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
:root{--bg:#030303;--green:#00ff88;--glow:rgba(0,255,136,.35);--soft:rgba(0,255,136,.1);--text:#e8ffe8;--muted:#6b8f6b;--border:rgba(0,255,136,.15)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;
background-image:linear-gradient(rgba(0,255,136,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,136,.02) 1px,transparent 1px);background-size:40px 40px}
.box{background:#0a0f0a;border:1px solid var(--border);border-radius:14px;padding:2rem;width:100%;max-width:360px;text-align:center}
h1{color:var(--green);font-size:1.4rem;margin-bottom:.3rem;text-shadow:0 0 14px var(--glow)}
p{color:var(--muted);font-size:.85rem;margin-bottom:1.2rem}
input{width:100%;padding:.7rem;background:rgba(0,0,0,.45);border:1px solid var(--border);border-radius:9px;color:var(--text);font-size:.95rem;margin-bottom:.8rem}
input:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px var(--soft)}
button{width:100%;padding:.7rem;background:var(--green);color:#000;border:none;border-radius:9px;font-weight:700;font-size:.95rem;cursor:pointer}
button:hover{background:#33ffaa;box-shadow:0 0 14px var(--glow)}
.err{color:#ff4d6a;font-size:.8rem;margin-top:.5rem;display:none}
</style>
</head>
<body>
<div class="box">
  <h1>APP Panel</h1>
  <p>${isFa ? 'رمز عبور را وارد کنید' : 'Enter password'}</p>
  <form id="f">
    <input type="password" id="pass" placeholder="${isFa ? 'رمز عبور' : 'Password'}" autofocus>
    <button type="submit">${isFa ? 'ورود' : 'Login'}</button>
    <div class="err" id="err">${isFa ? 'رمز اشتباه است' : 'Wrong password'}</div>
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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root{--bg:#030303;--card:#0a0f0a;--green:#00ff88;--g2:#00cc6a;--glow:rgba(0,255,136,.35);--soft:rgba(0,255,136,.1);--text:#e8ffe8;--muted:#6b8f6b;--border:rgba(0,255,136,.15);--border2:rgba(0,255,136,.3);--red:#ff4d6a;--yellow:#ffd166;--blue:#4cc9f0}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5;
background-image:linear-gradient(rgba(0,255,136,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,136,.02) 1px,transparent 1px);background-size:40px 40px}
.container{max-width:1080px;margin:0 auto;padding:1rem .9rem 3rem}
.header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem;padding-bottom:.7rem;border-bottom:1px solid var(--border)}
.logo{font-weight:800;font-size:1.15rem;color:var(--green);text-shadow:0 0 12px var(--glow)}
.nav{display:flex;flex-wrap:wrap;gap:.2rem;margin-bottom:1rem}
.nav a{padding:.36rem .7rem;border-radius:8px;color:var(--muted);font-size:.78rem;font-weight:500;border:1px solid transparent;cursor:pointer;text-decoration:none}
.nav a.active,.nav a:hover{color:#000;background:var(--green);box-shadow:0 0 10px var(--glow);font-weight:600}
.card{background:var(--card);border:1px solid var(--border);border-radius:11px;padding:1rem;margin-bottom:.7rem;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at top right,var(--soft),transparent 50%);pointer-events:none}
h2{font-size:.88rem;font-weight:700;color:var(--green);margin-bottom:.55rem}
.muted{color:var(--muted);font-size:.76rem}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:.45rem;margin-bottom:.65rem}
@media(min-width:680px){.stats{grid-template-columns:repeat(4,1fr)}}
.stat{background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:9px;padding:.55rem;text-align:center}
.stat-value{font-size:1.15rem;font-weight:800;color:var(--green)}
.stat-label{font-size:.64rem;color:var(--muted);margin-top:.08rem}
.progress-wrap{margin:.35rem 0}.progress-head{display:flex;justify-content:space-between;font-size:.7rem;margin-bottom:.12rem}
.progress-bar{height:5px;background:rgba(0,255,136,.07);border-radius:99px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--g2),var(--green));border-radius:99px}
.config-box{background:rgba(0,0,0,.5);border:1px solid var(--border);border-radius:8px;padding:.65rem;font-family:ui-monospace,monospace;font-size:.68rem;word-break:break-all;position:relative;margin:.4rem 0;color:#b8ffd0}
button,.btn{display:inline-flex;align-items:center;gap:.2rem;padding:.48rem .8rem;background:var(--green);color:#000;border:none;border-radius:8px;font-size:.78rem;font-weight:700;cursor:pointer;font-family:inherit}
button:hover{background:#33ffaa;box-shadow:0 0 10px var(--glow)}
.btn-sm{padding:.25rem .5rem;font-size:.7rem}
.btn-outline{background:transparent;border:1px solid var(--border2);color:var(--green)}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--muted);padding:.28rem .55rem;font-size:.72rem}
.btn-danger{background:transparent;border:1px solid rgba(255,77,106,.4);color:var(--red)}
.btn-blue{background:transparent;border:1px solid rgba(76,201,240,.4);color:var(--blue)}
.badge{display:inline-block;padding:.08rem .35rem;border-radius:999px;font-size:.62rem;font-weight:600;background:var(--soft);color:var(--green);border:1px solid var(--border);margin:0 .05rem}
.badge-blue{color:var(--blue);border-color:rgba(76,201,240,.3);background:rgba(76,201,240,.08)}
.badge-yellow{color:var(--yellow);border-color:rgba(255,209,102,.3);background:rgba(255,209,102,.08)}
.badge-red{color:var(--red);border-color:rgba(255,77,106,.3);background:rgba(255,77,106,.08)}
input,textarea,select{width:100%;padding:.5rem .65rem;background:rgba(0,0,0,.45);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:.8rem;margin-bottom:.4rem;font-family:inherit}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px var(--soft)}
label.lbl{display:block;margin-bottom:.1rem;font-size:.7rem;color:var(--muted)}
.grid{display:grid;gap:.5rem}@media(min-width:560px){.grid-2{grid-template-columns:1fr 1fr}}
.toast{position:fixed;bottom:1rem;left:1rem;background:var(--green);color:#000;padding:.5rem .85rem;border-radius:8px;font-weight:700;font-size:.78rem;opacity:0;transform:translateY(8px);transition:.25s;z-index:90;box-shadow:0 0 16px var(--glow)}
.toast.show{opacity:1;transform:translateY(0)}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.8);display:none;align-items:center;justify-content:center;z-index:80;padding:.7rem}
.modal-bg.show{display:flex}
.modal{background:var(--card);border:1px solid var(--border2);border-radius:12px;padding:1rem;max-width:480px;width:100%;max-height:92vh;overflow-y:auto}
.modal h3{color:var(--green);margin-bottom:.7rem;font-size:.92rem}
.check-row{display:flex;align-items:center;gap:.35rem;margin-bottom:.3rem;font-size:.8rem}
.check-row input{width:auto;margin:0}
.section-title{font-size:.8rem;font-weight:700;color:var(--green);margin:.7rem 0 .4rem;padding-bottom:.2rem;border-bottom:1px solid var(--border)}
.field-with-btn{display:flex;gap:.35rem;align-items:flex-start}
.field-with-btn input,.field-with-btn textarea{flex:1;margin-bottom:0}
.field-with-btn button{flex-shrink:0}
.user-card{background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:9px;padding:.7rem;margin-bottom:.5rem}
.user-card-head{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.35rem;margin-bottom:.35rem}
.user-meta{font-size:.72rem;color:var(--muted);margin-top:.12rem}
.brain-row{display:flex;justify-content:space-between;align-items:center;padding:.4rem .5rem;background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:7px;margin-bottom:.3rem;font-size:.76rem;gap:.35rem;flex-wrap:wrap}
.latency{font-size:.68rem;font-weight:600;color:var(--green)}
.client-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.4rem}
.client-item{background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:8px;padding:.5rem;text-align:center;font-size:.72rem}
.client-item strong{display:block;color:var(--green);margin-bottom:.1rem}
.client-item a{color:var(--blue);font-size:.68rem;text-decoration:none}
.info-row{display:flex;justify-content:space-between;padding:.35rem 0;border-bottom:1px solid var(--border);font-size:.78rem}
.info-label{color:var(--muted)}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">APP Panel</div>
    <div>
      <button class="btn-ghost btn-sm" onclick="setLang('fa')">FA</button>
      <button class="btn-ghost btn-sm" onclick="setLang('en')">EN</button>
      <button class="btn-ghost btn-sm" onclick="logout()">${isFa ? 'خروج' : 'Logout'}</button>
    </div>
  </div>
  <div class="nav" id="nav">
    <a class="active" data-t="dash">${isFa ? 'داشبورد' : 'Dashboard'}</a>
    <a data-t="subs">${isFa ? 'ساب‌لینک' : 'Subs'}</a>
    <a data-t="users">${isFa ? 'کاربران' : 'Users'}</a>
    <a data-t="warp">Warp</a>
    <a data-t="clients">${isFa ? 'کلاینت‌ها' : 'Clients'}</a>
    <a data-t="set">${isFa ? 'تنظیمات' : 'Settings'}</a>
  </div>

  <div id="tab-dash">
    <div class="card"><h2>${isFa ? 'داشبورد' : 'Dashboard'}</h2>
      <div class="stats" id="dashStats">
        <div class="stat"><div class="stat-value" id="sUsers">0</div><div class="stat-label">${isFa ? 'کاربران' : 'Users'}</div></div>
        <div class="stat"><div class="stat-value" id="sSubs">0</div><div class="stat-label">${isFa ? 'ساب‌لینک' : 'Subs'}</div></div>
        <div class="stat"><div class="stat-value" id="sTraffic">0 GB</div><div class="stat-label">${isFa ? 'ترافیک کل' : 'Total Traffic'}</div></div>
        <div class="stat"><div class="stat-value">ON</div><div class="stat-label">Worker</div></div>
      </div>
    </div>
  </div>

  <div id="tab-subs" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.4rem;margin-bottom:.55rem">
        <h2 style="margin:0">${isFa ? 'ساب‌لینک‌ها' : 'Subscriptions'}</h2>
        <button onclick="openSubModal()">${isFa ? '+ ساخت ساب' : '+ New Sub'}</button>
      </div>
      <div id="subsList"></div>
    </div>
  </div>

  <div id="tab-users" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.4rem;margin-bottom:.55rem">
        <h2 style="margin:0">${isFa ? 'کاربران' : 'Users'}</h2>
        <button onclick="openUserModal()">${isFa ? '+ کاربر جدید' : '+ New User'}</button>
      </div>
      <div id="usersList"></div>
    </div>
  </div>

  <div id="tab-warp" class="hidden">
    <div class="card">
      <h2>Warp</h2>
      <div class="check-row"><input type="checkbox" id="warpOn"><label>${isFa ? 'فعال‌سازی Warp' : 'Enable Warp'}</label></div>
      <div class="check-row"><input type="checkbox" id="warpPro"><label>Warp Pro</label></div>
      <label class="lbl">Endpoint</label>
      <input id="warpEndpoint" placeholder="engage.cloudflareclient.com:2408">
      <button onclick="saveWarp()">${isFa ? 'ذخیره' : 'Save'}</button>
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
      <h2>${isFa ? 'تنظیمات' : 'Settings'}</h2>
      <div class="grid grid-2">
        <div><label class="lbl">UUID</label><input id="setUUID" readonly></div>
        <div><label class="lbl">Trojan Password</label><input id="setTrojan"></div>
      </div>
      <label class="lbl">Fingerprint</label>
      <select id="setFP"><option>chrome</option><option>firefox</option><option>randomized</option></select>
      <div class="section-title">Fragment</div>
      <div class="grid grid-2">
        <div><label class="lbl">Length</label><input id="setFragLen" value="10-20"></div>
        <div><label class="lbl">Interval</label><input id="setFragInt" value="10-20"></div>
      </div>
      <button onclick="saveSettings()">${isFa ? 'ذخیره' : 'Save'}</button>
      <button class="btn-outline" onclick="newUUID()">New UUID</button>
    </div>
    <div class="card">
      <h2>${isFa ? 'امنیت' : 'Security'}</h2>
      <label class="lbl">${isFa ? 'رمز جدید پنل' : 'New Panel Password'}</label>
      <input type="password" id="newPass" placeholder="...">
      <button onclick="changePass()">${isFa ? 'تغییر رمز' : 'Change Password'}</button>
    </div>
  </div>
</div>

<!-- Sub Modal -->
<div class="modal-bg" id="modalSub">
  <div class="modal">
    <h3 id="subModalTitle">${isFa ? 'ساخت ساب' : 'New Sub'}</h3>
    <input type="hidden" id="subId">
    <label class="lbl">${isFa ? 'نام' : 'Name'}</label>
    <input id="subName" placeholder="main">
    <div class="grid grid-2">
      <div><label class="lbl">${isFa ? 'حجم GB' : 'Traffic GB'}</label><input type="number" id="subTraffic" value="100"></div>
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
    <div class="check-row"><input type="checkbox" id="subVless" checked><label>VLESS</label></div>
    <div class="check-row"><input type="checkbox" id="subTrojan" checked><label>Trojan</label></div>
    <div class="section-title">${isFa ? 'پروکسی این ساب' : 'Sub Proxy'}</div>
    <label class="lbl">Proxy IP</label>
    <div class="field-with-btn">
      <input id="subProxyIP" placeholder="optional">
      <button type="button" class="btn-outline btn-sm" onclick="openBrain('proxy')">${isFa ? 'مغزن' : 'Brain'}</button>
    </div>
    <label class="lbl" style="margin-top:.4rem">Clean IPs</label>
    <div class="field-with-btn">
      <textarea id="subCleanIPs" rows="2" placeholder="one per line"></textarea>
      <button type="button" class="btn-outline btn-sm" onclick="openBrain('clean')">${isFa ? 'مغزن' : 'Brain'}</button>
    </div>
    <div class="section-title">${isFa ? 'مسیریابی' : 'Routing'}</div>
    <div class="check-row"><input type="checkbox" id="subAdblock" checked><label>Ad Block</label></div>
    <div class="check-row"><input type="checkbox" id="subIran" checked><label>Direct Iran</label></div>
    <div style="display:flex;gap:.4rem;margin-top:.8rem">
      <button onclick="saveSub()">${isFa ? 'ذخیره' : 'Save'}</button>
      <button class="btn-ghost" onclick="closeModal('modalSub')">${isFa ? 'انصراف' : 'Cancel'}</button>
    </div>
  </div>
</div>

<!-- Brain Modal -->
<div class="modal-bg" id="modalBrain">
  <div class="modal">
    <h3 id="brainTitle">${isFa ? 'مغزن' : 'Brain'}</h3>
    <p class="muted" style="margin-bottom:.5rem">${isFa ? 'انتخاب و افزودن' : 'Select to add'}</p>
    <div id="brainList"></div>
    <button class="btn-ghost" style="width:100%;margin-top:.5rem" onclick="closeModal('modalBrain')">${isFa ? 'بستن' : 'Close'}</button>
  </div>
</div>

<!-- User Modal -->
<div class="modal-bg" id="modalUser">
  <div class="modal">
    <h3 id="userModalTitle">${isFa ? 'کاربر جدید' : 'New User'}</h3>
    <input type="hidden" id="userId">
    <label class="lbl">${isFa ? 'نام کاربری' : 'Username'}</label>
    <input id="userName">
    <div class="grid grid-2">
      <div><label class="lbl">${isFa ? 'حجم GB' : 'Traffic GB'}</label><input type="number" id="userTraffic" value="30"></div>
      <div><label class="lbl">${isFa ? 'روز انقضا' : 'Days'}</label><input type="number" id="userDays" value="30"></div>
    </div>
    <label class="lbl">${isFa ? 'حداکثر دستگاه' : 'Max Devices'}</label>
    <input type="number" id="userDevices" value="2">
    <label class="lbl">${isFa ? 'ساب متصل' : 'Linked Sub'}</label>
    <select id="userSub"></select>
    <label class="lbl">${isFa ? 'یادداشت' : 'Note'}</label>
    <input id="userNote">
    <div style="display:flex;gap:.4rem;margin-top:.7rem">
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
const BRAIN_IPS = [
  {ip:'104.16.128.50', ms:42},
  {ip:'104.17.176.20', ms:55},
  {ip:'104.18.22.100', ms:68},
  {ip:'104.21.48.10', ms:38},
  {ip:'cdnjs.cloudflare.com', ms:31},
  {ip:'cloudflare.com', ms:78}
];

function toast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200)}
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

  // Subs list
  const sl = document.getElementById('subsList');
  if(!subs.length){sl.innerHTML='<p class="muted">'+(isFa?'هنوز سابی ساخته نشده':'No subs yet')+'</p>'}
  else{
    sl.innerHTML = subs.map(s=>{
      const link = location.origin+'/sub/'+s.id;
      const badges = [];
      if(s.protocols?.vless!==false) badges.push('<span class="badge">VLESS</span>');
      if(s.protocols?.trojan) badges.push('<span class="badge">Trojan</span>');
      if(s.routing?.adblock) badges.push('<span class="badge badge-blue">AdBlock</span>');
      if(s.routing?.iran) badges.push('<span class="badge badge-blue">Iran</span>');
      return '<div class="card" style="background:rgba(0,0,0,.35);margin-bottom:.5rem">'+
        '<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:.3rem">'+
        '<div><strong>'+esc(s.name)+'</strong><div style="margin-top:.2rem">'+badges.join('')+'</div></div>'+
        '<div style="display:flex;gap:.25rem">'+
        '<button class="btn-outline btn-sm" onclick="copyText(\\''+link+'\\')">Copy</button>'+
        '<button class="btn-outline btn-sm" onclick="editSub(\\''+s.id+'\\')">'+(isFa?'ویرایش':'Edit')+'</button>'+
        '<button class="btn-danger btn-sm" onclick="delSub(\\''+s.id+'\\')">'+(isFa?'حذف':'Del')+'</button></div></div>'+
        '<div class="config-box" style="margin-top:.4rem">'+link+'</div>'+
        '<div class="muted" style="font-size:.68rem">Port '+(s.port||443)+' · Proxy: '+(s.proxyIP||'-')+' · Clean: '+((s.cleanIPs||[]).length)+'</div></div>';
    }).join('');
  }

  // Users list
  const ul = document.getElementById('usersList');
  if(!users.length){ul.innerHTML='<p class="muted">'+(isFa?'کاربری نیست':'No users')+'</p>'}
  else{
    ul.innerHTML = users.map(u=>{
      const used = (u.used / 1024 / 1024 / 1024).toFixed(2);
      const total = u.traffic || 0;
      const pct = total>0 ? Math.min(100, Math.round(used/total*100)) : 0;
      const isExpired = u.expire && new Date(u.expire) < new Date();
      const isLimited = total>0 && u.used >= total * 1024 * 1024 * 1024;
      const statusBadge = isExpired || isLimited ? '<span class="badge badge-red">'+(isFa?'منقضی/تمام':'Expired')+'</span>' : '<span class="badge">'+(isFa?'فعال':'Active')+'</span>';
      
      return '<div class="user-card">'+
        '<div class="user-card-head"><div><strong>'+esc(u.name)+'</strong> '+statusBadge+
        (u.note?'<div class="user-meta">'+esc(u.note)+'</div>':'')+'</div>'+
        '<div style="display:flex;gap:.25rem;flex-wrap:wrap">'+
        '<button class="btn-outline btn-sm" onclick="copyText(\\''+location.origin+'/sub/'+u.id+'\\')">Copy Sub</button>'+
        '<button class="btn-outline btn-sm" onclick="editUser(\\''+u.id+'\\')">'+(isFa?'ویرایش':'Edit')+'</button>'+
        '<button class="btn-blue btn-sm" onclick="resetUser(\\''+u.id+'\\')">'+(isFa?'ریست':'Reset')+'</button>'+
        '<button class="btn-danger btn-sm" onclick="delUser(\\''+u.id+'\\')">'+(isFa?'حذف':'Del')+'</button></div></div>'+
        '<div class="progress-wrap"><div class="progress-head"><span>'+(isFa?'ترافیک':'Traffic')+'</span><span>'+used+' / '+(total||'∞')+' GB</span></div>'+
        '<div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div></div>'+
        '<div class="muted" style="font-size:.7rem;margin-top:.2rem">'+(isFa?'دستگاه':'Devices')+': '+(u.devices||0)+'/'+(u.maxDevices||'∞')+' · '+(isFa?'انقضا':'Exp')+': '+(u.expire||'-')+'</div></div>';
    }).join('');
  }

  // user sub select
  const sel = document.getElementById('userSub');
  sel.innerHTML = '<option value="">'+(isFa?'همه':'All')+'</option>' + subs.map(s=>'<option value="'+s.id+'">'+esc(s.name)+'</option>').join('');
}

function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast(isFa?'کپی شد':'Copied'))}

function openSubModal(id){
  document.getElementById('subId').value = id||'';
  document.getElementById('subModalTitle').textContent = id ? (isFa?'ویرایش ساب':'Edit Sub') : (isFa?'ساخت ساب':'New Sub');
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
  if(r.ok){closeModal('modalSub');toast(isFa?'ذخیره شد':'Saved');loadAll()}
  else toast('Error');
}
async function delSub(id){
  if(!confirm(isFa?'حذف شود؟':'Delete?'))return;
  await fetch('/api/subs?id='+id,{method:'DELETE'});
  toast(isFa?'حذف شد':'Deleted');loadAll();
}

function openBrain(mode){
  brainMode = mode;
  document.getElementById('brainTitle').textContent = (isFa?'مغزن':'Brain')+' — '+(mode==='proxy'?'Proxy IP':'Clean IP');
  document.getElementById('brainList').innerHTML = BRAIN_IPS.map(b=>
    '<div class="brain-row"><div><strong>'+b.ip+'</strong></div><div style="display:flex;align-items:center;gap:.3rem"><span class="latency">'+b.ms+'ms</span>'+
    '<button class="btn-sm" onclick="pickBrain(\\''+b.ip+'\\')">'+(isFa?'افزودن':'Add')+'</button></div></div>'
  ).join('');
  openModal('modalBrain');
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
  toast(ip);
}

function openUserModal(id){
  document.getElementById('userId').value=id||'';
  document.getElementById('userModalTitle').textContent=id?(isFa?'ویرایش کاربر':'Edit User'):(isFa?'کاربر جدید':'New User');
  if(id){
    const u=users.find(x=>x.id===id);
    if(u){
      document.getElementById('userName').value=u.name||'';
      document.getElementById('userTraffic').value=u.traffic||30;
      document.getElementById('userDays').value=u.days||30;
      document.getElementById('userDevices').value=u.maxDevices||2;
      document.getElementById('userSub').value=u.subId||'';
      document.getElementById('userNote').value=u.note||'';
    }
  } else {
    document.getElementById('userName').value='';
    document.getElementById('userNote').value='';
  }
  openModal('modalUser');
}
function editUser(id){openUserModal(id)}

async function saveUser(){
  const id=document.getElementById('userId').value;
  const body={
    id:id||undefined,
    name:document.getElementById('userName').value||'user',
    traffic:+document.getElementById('userTraffic').value||0,
    days:+document.getElementById('userDays').value||0,
    maxDevices:+document.getElementById('userDevices').value||1,
    subId:document.getElementById('userSub').value||'',
    note:document.getElementById('userNote').value||'',
    enabled:true
  };
  const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.ok){closeModal('modalUser');toast(isFa?'ذخیره شد':'Saved');loadAll()}
  else toast('Error');
}
async function delUser(id){
  if(!confirm(isFa?'حذف شود؟':'Delete?'))return;
  await fetch('/api/users?id='+id,{method:'DELETE'});
  toast(isFa?'حذف شد':'Deleted');loadAll();
}
async function resetUser(id){
  await fetch('/api/users/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  toast(isFa?'ریست شد':'Reset');loadAll();
}

async function saveSettings(){
  const body={
    trojanPassword:document.getElementById('setTrojan').value,
    fingerprint:document.getElementById('setFP').value,
    fragment:{length:document.getElementById('setFragLen').value,interval:document.getElementById('setFragInt').value,packets:'tlshello'}
  };
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  toast(isFa?'ذخیره شد':'Saved');loadAll();
}
async function newUUID(){
  await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({newUUID:true})});
  toast('New UUID');loadAll();
}
async function changePass(){
  const p=document.getElementById('newPass').value;
  if(!p||p.length<4){toast('Min 4 chars');return}
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
      let list = await getSubs(env);
      if (body.id) {
        const idx = list.findIndex(x => x.id === body.id);
        if (idx >= 0) list[idx] = { ...list[idx], ...body };
      } else {
        body.id = uuid().slice(0, 8);
        list.push(body);
      }
      await saveSubs(env, list);
      return json({ ok: true, id: body.id });
    }
    if (method === 'DELETE') {
      const id = url.searchParams.get('id');
      let list = await getSubs(env);
      list = list.filter(x => x.id !== id);
      await saveSubs(env, list);
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
        body.id = uuid().slice(0, 8);
        body.used = 0;
        body.devices = 0;
        body.enabled = true;
        if (body.days) {
          const d = new Date();
          d.setDate(d.getDate() + body.days);
          body.expire = d.toISOString().slice(0, 10);
        }
        list.push(body);
      }
      await saveUsers(env, list);
      return json({ ok: true, id: body.id });
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

  return json({ error: 'not found' }, 404);
}

// ──────────────────────────── Main ────────────────────────────
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
        
        // Extract User ID from path if present (VLESS connects to /sub/{userId})
        const pathParts = path.split('/');
        let currentUser = null;
        
        if (path.startsWith(SUB_PATH + '/') && pathParts.length >= 3) {
          const userId = pathParts[2];
          const users = await getUsers(env);
          currentUser = users.find(u => u.id === userId);
          
          // Check Expiry and Traffic Limit
          if (currentUser) {
            if (currentUser.expire && new Date(currentUser.expire) < new Date()) {
              return new Response('Account Expired', { status: 403 });
            }
            if (currentUser.traffic > 0 && currentUser.used >= currentUser.traffic * 1024 * 1024 * 1024) {
              return new Response('Traffic Limit Exceeded', { status: 403 });
            }
          }
        }
        
        // Attach currentUser to handleVLESSWebSocket via closure
        return handleVLESSWebSocket(request, env, settings, currentUser, ctx);
      }

      if (path.startsWith(API_PATH)) {
        return await handleAPI(request, env, path);
      }

      // Subscriptions
      if (path.startsWith(SUB_PATH + '/')) {
        const id = path.slice(SUB_PATH.length + 1).split('/')[0];
        const settings = await getSettings(env);
        const users = await getUsers(env);
        const subs = await getSubs(env);
        
        // Check if it's a user sub
        const user = users.find(u => u.id === id);
        if (user) {
          // Find linked sub or use default
          const sub = user.subId ? subs.find(s => s.id === user.subId) : subs[0] || { name: 'APP', port: 443, path: '/', protocols: { vless: true, trojan: true } };
          
          const usedBytes = user.used || 0;
          const totalBytes = user.traffic > 0 ? user.traffic * 1024 * 1024 * 1024 : 0;
          const remainBytes = totalBytes > 0 ? totalBytes - usedBytes : 0;
          
          const expireTime = user.expire ? Math.floor(new Date(user.expire).getTime() / 1000) : 0;
          
          return new Response(generateUserSubContent(user, sub, settings, host), {
            headers: {
              'Content-Type': 'text/plain;charset=utf-8',
              'Profile-Update-Interval': '6',
              'Subscription-Userinfo': `upload=0; download=${usedBytes}; total=${totalBytes}; expire=${expireTime}`
            }
          });
        }
        
        // Check if it's a general sub
        const sub = subs.find(s => s.id === id);
        if (sub) {
          return new Response(generateSubContent(sub, settings, host), {
            headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Profile-Update-Interval': '6' }
          });
        }
        
        // Fallback global sub
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

// Modified VLESS Handler to support Real Traffic Counting
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
        
        // Real Traffic Accounting (Upload + Download)
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
          
          // Save every ~1MB to avoid rate limits
          if (accumulatedBytes > 1048576) {
            ctx.waitUntil(updateUserTraffic(env, currentUser.id, accumulatedBytes));
            currentUser.used += accumulatedBytes;
            accumulatedBytes = 0;
          }
        }
        return;
      }
      
      const parsed = processVlessHeader(chunk, settings.uuid);
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
    if (currentUser && env.APP_KV && accumulatedBytes > 0) {
      await updateUserTraffic(env, currentUser.id, accumulatedBytes);
    }
  });

  return new Response(null, { status: 101, webSocket: client });
}