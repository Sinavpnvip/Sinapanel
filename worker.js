/* SFDNS_PANEL_V2_PATCH */

/*
 * SFDNS Panel v2 compatibility / reliability patch
 *
 * Goals:
 * - Never let malformed KV JSON crash user/sub endpoints.
 * - Validate and normalize users/subscriptions.
 * - Return useful API errors instead of generic "Error".
 * - Preserve the existing protocol implementation.
 * - Keep backward compatibility with the original KV array format.
 */

const SFDNS_V2 = {
  version: 2,

  jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store"
      }
    });
  },

  asArray(value, name) {
    if (Array.isArray(value)) return value;
    if (value == null) return [];
    throw new Error(`${name} storage is not an array`);
  },

  async readArray(kv, key, name) {
    if (!kv || typeof kv.get !== "function") {
      throw new Error("APP_KV binding is missing");
    }

    const raw = await kv.get(key);
    if (!raw) return [];

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`${name} storage contains invalid JSON`);
    }

    return SFDNS_V2.asArray(parsed, name);
  },

  async writeArray(kv, key, value, name) {
    if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
    await kv.put(key, JSON.stringify(value));
  },

  id(prefix = "id") {
    return `${prefix}_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  },

  cleanString(value, max = 256) {
    if (typeof value !== "string") return "";
    return value.trim().slice(0, max);
  },

  positiveInt(value, fallback = 0, max = 2147483647) {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(0, Math.floor(n)));
  },

  normalizeUser(input) {
    const u = (input && typeof input === "object") ? input : {};
    return {
      ...u,
      id: this.cleanString(u.id, 128) || this.id("usr"),
      name: this.cleanString(u.name, 100),
      subId: this.cleanString(u.subId, 128),
      traffic: this.positiveInt(u.traffic, 0),
      days: this.positiveInt(u.days, 0, 36500),
      maxDevices: this.positiveInt(u.maxDevices, 1, 1000),
      enabled: u.enabled !== false
    };
  },

  normalizeSub(input) {
    const s = (input && typeof input === "object") ? input : {};
    return {
      ...s,
      id: this.cleanString(s.id, 128) || this.id("sub"),
      name: this.cleanString(s.name, 100),
      maxUsers: this.positiveInt(s.maxUsers, 0, 1000000),
      traffic: this.positiveInt(s.traffic, 0),
      days: this.positiveInt(s.days, 0, 36500),
      enabled: s.enabled !== false
    };
  },

  validateUser(u) {
    const errors = [];
    if (!u.name) errors.push("name is required");
    if (!u.subId) errors.push("subId is required");
    if (u.maxDevices < 1) errors.push("maxDevices must be at least 1");
    return errors;
  },

  validateSub(s) {
    const errors = [];
    if (!s.name) errors.push("name is required");
    if (s.maxUsers < 0) errors.push("maxUsers is invalid");
    return errors;
  },

  error(message, status = 400, details = null) {
    return this.jsonResponse({
      ok: false,
      error: message,
      ...(details ? { details } : {})
    }, status);
  }
};


/**
 * ═══════════════════════════════════════════════════════════════
 *   APP Panel  ·  Advanced Proxy Panel  v1.1
 *   پنل پروکسی پیشرفته — نسخه واقعی
 * ═══════════════════════════════════════════════════════════════
 *  Default Password: sfdns990 (change it after first login!)
 *  Works on Cloudflare Workers + Pages
 *  Requires KV binding: APP_KV
 */

import { connect } from 'cloudflare:sockets';

const DEFAULT_PASSWORD = 'sfdns990';
const PANEL_PATH = '/panel';
const SUB_PATH = '/sub';
const DOH_PATH = '/doh';
const API_PATH = '/api';
const SESSION_TTL = 86400 * 7; // 7 days
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_SECONDS = 300; // 5 minutes

// ──────────────────────────── Utils ────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

function isValidUUID(u) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u);
}

function randomToken(len = 16) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
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

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function base64UrlEncode(strOrBytes) {
  let bytes;
  if (typeof strOrBytes === 'string') bytes = new TextEncoder().encode(strOrBytes);
  else bytes = new Uint8Array(strOrBytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecodeToString(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return atob(b64);
}

// Constant-time string comparison (mitigates timing attacks on password checks)
function safeEqual(a, b) {
  a = String(a || '');
  b = String(b || '');
  const len = Math.max(a.length, b.length, 1);
  let diff = a.length === b.length ? 0 : 1;
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

// ──────────────────────────── SHA-224 (needed for Trojan handshake hash) ────────────────────────────
// Pure JS SHA-224 (FIPS 180-4). Web Crypto's subtle.digest does not support SHA-224.
function sha224Hex(message) {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  let h = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
  const bytes = new TextEncoder().encode(message);
  const bitLen = bytes.length * 8;
  const padLen = (((bytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(padLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padLen - 4, bitLen >>> 0, false);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let offset = 0; offset < padLen; offset += 64) {
    const w = new Array(64);
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let [a,b,c,d,e,f,g,hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (hh + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;
      hh = g; g = f; f = e; e = (d + temp1) | 0;
      d = c; c = b; b = a; a = (temp1 + temp2) | 0;
    }
    h[0]=(h[0]+a)|0; h[1]=(h[1]+b)|0; h[2]=(h[2]+c)|0; h[3]=(h[3]+d)|0;
    h[4]=(h[4]+e)|0; h[5]=(h[5]+f)|0; h[6]=(h[6]+g)|0; h[7]=(h[7]+hh)|0;
  }
  return h.slice(0,7).map(x => (x>>>0).toString(16).padStart(8,'0')).join('');
}

// ──────────────────────────── HMAC session tokens (stateless, KV-independent) ────────────────────────────
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signToken(secret, payloadObj) {
  const payload = base64UrlEncode(JSON.stringify(payloadObj));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return payload + '.' + base64UrlEncode(sig);
}

async function verifyToken(secret, token) {
  if (!token || token.indexOf('.') === -1) return null;
  const [payload, sig] = token.split('.');
  try {
    const key = await hmacKey(secret);
    const expected = base64UrlEncode(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload)));
    if (!safeEqual(expected, sig)) return null;
    const data = JSON.parse(base64UrlDecodeToString(payload));
    if (!data.exp || Date.now() / 1000 > data.exp) return null;
    return data;
  } catch (e) {
    return null;
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
    secret: randomToken(32), // used to sign session tokens (HMAC)
    uuid: uuid(),
    trojanPassword: 'trojan' + Math.random().toString(36).slice(2, 10),
    fingerprint: 'chrome',
    fragment: { length: '10-20', interval: '10-20', packets: 'tlshello' },
    warp: { enabled: false, pro: false, endpoint: '' },
    proxyIP: '',
    cleanIPs: []
  };
}

function defaultSubs() {
  return [];
}

function defaultUsers() {
  return [];
}

// ──────────────────────────── In-memory fallback (used only when APP_KV is not bound) ────────────────────────────
// Without KV, Worker state can't survive across isolates/deploys — this at least keeps
// settings/subs/users/usage stable for the lifetime of a single running isolate instead of
// regenerating (e.g. a new random UUID) on every request, which was a functional bug before.
// A KV binding is strongly recommended for real deployments — see README.
const MEM = {
  settings: null,
  subs: null,
  users: null,
  loginAttempts: new Map() // ip -> { count, until }
};

// ──────────────────────────── KV Helpers ────────────────────────────
async function getSettings(env) {
  if (!env.APP_KV) {
    if (!MEM.settings) MEM.settings = defaultSettings();
    return MEM.settings;
  }
  const raw = await env.APP_KV.get('settings', 'json');
  if (raw) return { ...defaultSettings(), ...raw, secret: raw.secret || (await ensurePersistedSecret(env, raw)) };
  const fresh = defaultSettings();
  await env.APP_KV.put('settings', JSON.stringify(fresh));
  return fresh;
}

async function ensurePersistedSecret(env, raw) {
  const secret = randomToken(32);
  await env.APP_KV.put('settings', JSON.stringify({ ...raw, secret }));
  return secret;
}

async function saveSettings(env, data) {
  if (!env.APP_KV) { MEM.settings = data; return; }
  await env.APP_KV.put('settings', JSON.stringify(data));
}

async function getSubs(env) {
  if (!env.APP_KV) return (MEM.subs = MEM.subs || defaultSubs());
  const raw = await env.APP_KV.get('subs', 'json');
  return raw || defaultSubs();
}

async function saveSubs(env, data) {
  if (!env.APP_KV) { MEM.subs = data; return; }
  await env.APP_KV.put('subs', JSON.stringify(data));
}

async function getUsers(env) {
  if (!env.APP_KV) return (MEM.users = MEM.users || defaultUsers());
  const raw = await env.APP_KV.get('users', 'json');
  return raw || defaultUsers();
}

async function saveUsers(env, data) {
  if (!env.APP_KV) { MEM.users = data; return; }
  await env.APP_KV.put('users', JSON.stringify(data));
}

// ──────────────────────────── Auth ────────────────────────────
function getCookieToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/app_token=([^;]+)/);
  return match ? match[1] : null;
}

// Real, stateless, signed-session auth — works identically with or without KV,
// and can no longer be bypassed with an arbitrary >8 char cookie value.
async function checkAuth(request, env, settingsIn) {
  const token = getCookieToken(request);
  if (!token) return false;
  const settings = settingsIn || await getSettings(env);
  const data = await verifyToken(settings.secret, token);
  return !!data;
}

async function createSession(env, settingsIn) {
  const settings = settingsIn || await getSettings(env);
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  return signToken(settings.secret, { exp });
}

// ──────────────────────────── Login rate limiting ────────────────────────────
function clientIP(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
}

async function isLoginLocked(request, env) {
  const ip = clientIP(request);
  const now = Math.floor(Date.now() / 1000);
  if (env.APP_KV) {
    const raw = await env.APP_KV.get('loginfail:' + ip, 'json');
    return !!(raw && raw.count >= LOGIN_MAX_ATTEMPTS && raw.until > now);
  }
  const rec = MEM.loginAttempts.get(ip);
  return !!(rec && rec.count >= LOGIN_MAX_ATTEMPTS && rec.until > now);
}

async function recordLoginFailure(request, env) {
  const ip = clientIP(request);
  const now = Math.floor(Date.now() / 1000);
  if (env.APP_KV) {
    const raw = (await env.APP_KV.get('loginfail:' + ip, 'json')) || { count: 0, until: 0 };
    const count = raw.until > now ? raw.count + 1 : 1;
    await env.APP_KV.put('loginfail:' + ip, JSON.stringify({ count, until: now + LOGIN_LOCK_SECONDS }), { expirationTtl: LOGIN_LOCK_SECONDS });
    return;
  }
  const rec = MEM.loginAttempts.get(ip);
  const count = rec && rec.until > now ? rec.count + 1 : 1;
  MEM.loginAttempts.set(ip, { count, until: now + LOGIN_LOCK_SECONDS });
}

async function clearLoginFailures(request, env) {
  const ip = clientIP(request);
  if (env.APP_KV) { await env.APP_KV.delete('loginfail:' + ip); return; }
  MEM.loginAttempts.delete(ip);
}

// ──────────────────────────── Subscription Generator ────────────────────────────
function generateVlessLink(host, uuid, port, path, remark, proxyIP, fp) {
  const address = proxyIP || host;
  const params = new URLSearchParams({
    encryption: 'none',
    security: 'tls',
    sni: host,
    fp: fp || 'chrome',
    type: 'ws',
    host: host,
    path: path || '/'
  });
  return `vless://${uuid}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark || 'APP')}`;
}

function generateTrojanLink(host, password, port, path, remark, proxyIP, fp) {
  const address = proxyIP || host;
  const params = new URLSearchParams({
    security: 'tls',
    sni: host,
    fp: fp || 'chrome',
    type: 'ws',
    host: host,
    path: path || '/'
  });
  return `trojan://${password}@${address}:${port}?${params.toString()}#${encodeURIComponent(remark || 'APP-Trojan')}`;
}

// credUUID/credTrojan let callers generate a link for a specific user's own credentials
// instead of always the global admin ones — this is what makes per-user access real.
function generateSubContent(sub, settings, host, credUUID, credTrojan) {
  const links = [];
  const port = sub.port || 443;
  const path = sub.path || '/';
  const remark = sub.name || 'APP';
  const proxyIP = sub.proxyIP || settings.proxyIP || '';
  const cleanIPs = (sub.cleanIPs || settings.cleanIPs || []).filter(Boolean);
  const fp = settings.fingerprint || 'chrome';
  const vlessUUID = credUUID || settings.uuid;
  const trojanPass = credTrojan || settings.trojanPassword;

  if (sub.protocols?.vless !== false) {
    links.push(generateVlessLink(host, vlessUUID, port, path, remark, proxyIP, fp));
    for (const ip of cleanIPs) {
      links.push(generateVlessLink(host, vlessUUID, port, path, remark + '-' + ip, ip, fp));
    }
  }
  if (sub.protocols?.trojan) {
    links.push(generateTrojanLink(host, trojanPass, port, path, remark + '-Trojan', proxyIP, fp));
  }
  return btoa(links.join('\n'));
}

// ──────────────────────────── VLESS Handler (core) ────────────────────────────
// No longer takes an expectedUUID — it just extracts the UUID from the header.
// The caller matches that UUID against the admin + all per-user UUIDs, so every
// user's own credentials actually work (previously only the single global UUID did).
function processVlessHeader(buffer) {
  if (buffer.byteLength < 24) return { hasError: true, message: 'invalid header' };
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1))[0];
  const uuidBytes = new Uint8Array(buffer.slice(1, 17));
  const uuidStr = [...uuidBytes].map(b => b.toString(16).padStart(2, '0')).join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
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
      // Each group must be zero-padded to 4 hex digits, or the address is malformed
      // (e.g. "1" instead of "0001") — this was a bug in the original parser.
      for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16).padStart(4, '0'));
      addressRemote = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: 'invalid address type' };
  }
  const rawDataIndex = addressIndex + addressLength;
  return {
    hasError: false,
    uuidStr,
    addressRemote,
    portRemote,
    rawDataIndex,
    vlessVersion: new Uint8Array([version]),
    isUDP
  };
}

// ──────────────────────────── Trojan Handler (core) ────────────────────────────
// Trojan-over-WebSocket header: hex(SHA224(password)) [56 chars] + CRLF + CMD(1) ATYP(1) ADDR PORT(2, BE) + CRLF + payload
// This was previously never implemented — links were generated but any real Trojan
// client would get rejected by the VLESS parser. This makes Trojan actually work.
function looksLikeTrojan(bytes) {
  if (bytes.length < 58) return false;
  for (let i = 0; i < 56; i++) {
    const c = bytes[i];
    const isHex = (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
    if (!isHex) return false;
  }
  return bytes[56] === 0x0d && bytes[57] === 0x0a; // \r\n
}

function processTrojanHeader(buffer) {
  const bytes = new Uint8Array(buffer);
  if (!looksLikeTrojan(bytes)) return { hasError: true, message: 'invalid trojan header' };
  const hashHex = new TextDecoder().decode(bytes.slice(0, 56)).toLowerCase();
  let offset = 58; // skip hash + CRLF
  const cmd = bytes[offset]; // 1 = TCP
  const addressType = bytes[offset + 1];
  offset += 2;
  let addressRemote = '';
  let addressLength = 0;
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressRemote = Array.from(bytes.slice(offset, offset + 4)).join('.');
      break;
    case 3:
      addressLength = bytes[offset];
      offset += 1;
      addressRemote = new TextDecoder().decode(bytes.slice(offset, offset + addressLength));
      break;
    case 4:
      addressLength = 16;
      { const ipv6 = []; const dv = new DataView(buffer.slice(offset, offset + 16));
        for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16).padStart(4, '0'));
        addressRemote = ipv6.join(':'); }
      break;
    default:
      return { hasError: true, message: 'invalid trojan address type' };
  }
  const portIndex = offset + addressLength;
  const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0, false);
  const rawDataIndex = portIndex + 2 + 2; // + CRLF after the request
  return { hasError: false, hashHex, addressRemote, portRemote, rawDataIndex, isUDP: cmd === 3 };
}

function makeReadableWebSocketStream(webSocket, earlyData) {
  let cancelled = false;
  return new ReadableStream({
    start(controller) {
      webSocket.addEventListener('message', e => {
        if (cancelled) return;
        // WS text frames arrive as strings; the protocol parsers need raw bytes.
        if (typeof e.data === 'string') {
          controller.enqueue(new TextEncoder().encode(e.data).buffer);
        } else {
          controller.enqueue(e.data);
        }
      });
      webSocket.addEventListener('close', () => { try { controller.close(); } catch (_) {} });
      webSocket.addEventListener('error', err => controller.error(err));
      if (earlyData) controller.enqueue(earlyData);
    },
    cancel() { cancelled = true; }
  });
}

// ──────────────────────────── Credential index & usage accounting ────────────────────────────
// Builds a lookup of every valid credential (the admin's global UUID/password, plus every
// user's own UUID/trojan password) so a connecting client identifies to a specific record.
function buildCredentialIndex(settings, users) {
  const byUUID = new Map();
  const byTrojanHash = new Map();
  byUUID.set(settings.uuid.toLowerCase(), { kind: 'admin' });
  byTrojanHash.set(sha224Hex(settings.trojanPassword), { kind: 'admin' });
  for (const u of users) {
    if (u.enabled === false) continue;
    if (u.uuid) byUUID.set(String(u.uuid).toLowerCase(), { kind: 'user', user: u });
    if (u.trojanPassword) byTrojanHash.set(sha224Hex(u.trojanPassword), { kind: 'user', user: u });
  }
  return { byUUID, byTrojanHash };
}

function isUserBlocked(user) {
  if (!user) return null;
  if (user.enabled === false) return 'disabled';
  if (user.expire) {
    const exp = new Date(user.expire + 'T23:59:59');
    if (!isNaN(exp) && Date.now() > exp.getTime()) return 'expired';
  }
  if (user.traffic > 0 && (user.used || 0) >= user.traffic) return 'traffic-limit';
  return null;
}

const GB = 1024 * 1024 * 1024;

// Persists accumulated bytes for a connection to KV once it ends (not per-chunk — that
// would be far too many writes). Best-effort / eventually-consistent, same limitation the
// README already called out for real traffic counting on Workers.
async function flushUsage(env, identity, totalBytes) {
  if (!identity || identity.kind !== 'user' || totalBytes <= 0) return;
  try {
    const users = await getUsers(env);
    const idx = users.findIndex(x => x.id === identity.user.id);
    if (idx === -1) return;
    users[idx].used = +(((users[idx].used || 0) + totalBytes / GB).toFixed(4));
    users[idx].lastSeen = new Date().toISOString();
    await saveUsers(env, users);
    if (users[idx].subId) {
      const subs = await getSubs(env);
      const sidx = subs.findIndex(x => x.id === users[idx].subId);
      if (sidx !== -1) {
        subs[sidx].used = +(((subs[sidx].used || 0) + totalBytes / GB).toFixed(4));
        await saveSubs(env, subs);
      }
    }
  } catch (e) { /* best-effort */ }
}

async function handleVLESSWebSocket(request, env, settings, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const users = await getUsers(env);
  const creds = buildCredentialIndex(settings, users);

  let remoteSocket = { value: null };
  let identity = null;
  let bytesUp = 0, bytesDown = 0;
  let flushed = false;
  const doFlush = () => {
    if (flushed) return;
    flushed = true;
    const total = bytesUp + bytesDown;
    if (total > 0) ctx.waitUntil(flushUsage(env, identity, total));
  };

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const { data: earlyData } = base64ToArrayBuffer(earlyDataHeader);
  const readable = makeReadableWebSocketStream(webSocket, earlyData);

  readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (remoteSocket.value) {
        bytesUp += chunk.byteLength || 0;
        const writer = remoteSocket.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const bytes = new Uint8Array(chunk);
      const isTrojan = looksLikeTrojan(bytes);
      const parsed = isTrojan ? processTrojanHeader(chunk) : processVlessHeader(chunk);
      if (parsed.hasError) {
        webSocket.close(1000, parsed.message);
        return;
      }

      // Identify who is connecting and enforce their limits BEFORE dialing out.
      const match = isTrojan ? creds.byTrojanHash.get(parsed.hashHex) : creds.byUUID.get((parsed.uuidStr || '').toLowerCase());
      if (!match) {
        webSocket.close(1000, isTrojan ? 'invalid trojan password' : 'invalid uuid');
        return;
      }
      const blockReason = match.kind === 'user' ? isUserBlocked(match.user) : null;
      if (blockReason) {
        webSocket.close(1000, 'blocked: ' + blockReason);
        return;
      }
      identity = match;
      // Note: real concurrent-device limiting isn't reliably enforceable on a distributed
      // edge platform like Workers (there's no single process to count live connections
      // across). "Max Devices" is kept as an informational field the admin sets manually
      // rather than a hard technical limit — this is stated plainly in the README.

      const { addressRemote, portRemote, rawDataIndex, isUDP } = parsed;
      if (isUDP) {
        webSocket.close(1000, 'UDP not fully supported in this build');
        return;
      }
      const rawClientData = chunk.slice(rawDataIndex);
      bytesUp += rawClientData.byteLength || 0;
      const target = settings.proxyIP || addressRemote;
      try {
        const sock = connect({ hostname: target, port: portRemote });
        remoteSocket.value = sock;
        const writer = sock.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();

        if (!isTrojan) {
          // VLESS response header (Trojan has no response header)
          const resp = new Uint8Array([parsed.vlessVersion[0], 0]);
          webSocket.send(resp);
        }

        sock.readable.pipeTo(new WritableStream({
          write(data) {
            bytesDown += data.byteLength || 0;
            webSocket.send(data);
          },
          close() { doFlush(); try { webSocket.close(); } catch (_) {} },
          abort() { doFlush(); try { webSocket.close(); } catch (_) {} }
        })).catch(() => { doFlush(); });
      } catch (e) {
        webSocket.close(1000, 'connect failed');
      }
    },
    close() { doFlush(); },
    abort() { doFlush(); }
  })).catch(() => { doFlush(); });

  return new Response(null, { status: 101, webSocket: client });
}

// ──────────────────────────── Panel HTML ────────────────────────────
function getPanelHTML(lang, authenticated) {
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

  // Full authenticated panel (compact but complete)
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
    <a data-t="usage">${isFa ? 'مصرف' : 'Usage'}</a>
    <a data-t="warp">Warp</a>
    <a data-t="clients">${isFa ? 'کلاینت‌ها' : 'Clients'}</a>
    <a data-t="set">${isFa ? 'تنظیمات' : 'Settings'}</a>
  </div>

  <div id="tab-dash">
    <div class="card"><h2>${isFa ? 'داشبورد' : 'Dashboard'}</h2>
      <div class="stats" id="dashStats">
        <div class="stat"><div class="stat-value" id="sUsers">0</div><div class="stat-label">${isFa ? 'کاربران' : 'Users'}</div></div>
        <div class="stat"><div class="stat-value" id="sSubs">0</div><div class="stat-label">${isFa ? 'ساب‌لینک' : 'Subs'}</div></div>
        <div class="stat"><div class="stat-value" id="sTraffic">—</div><div class="stat-label">${isFa ? 'ترافیک مصرفی' : 'Traffic Used'}</div></div>
        <div class="stat"><div class="stat-value">ON</div><div class="stat-label">Worker</div></div>
      </div>
    </div>
  </div>

  <div id="tab-usage" class="hidden">
    <div class="card">
      <h2>${isFa ? 'مصرف کاربران' : 'Usage by User'}</h2>
      <p class="muted" style="margin-bottom:.5rem">${isFa ? 'شمارش تقریبی و لحظه‌ای است (محدودیت شناخته‌شده Workers)' : 'Approximate, best-effort counting (a known Workers limitation)'}</p>
      <div id="usageUsersList"></div>
    </div>
    <div class="card">
      <h2>${isFa ? 'مصرف ساب‌لینک‌ها' : 'Usage by Sub'}</h2>
      <div id="usageSubsList"></div>
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
    ['dash','subs','users','usage','warp','clients','set'].forEach(t=>{
      document.getElementById('tab-'+t).classList.toggle('hidden', a.dataset.t!==t);
    });
  }
});

let usage = {totalUsed:0,totalCap:0,users:[],subs:[]};
async function loadAll(){
  const [s,sb,u,ug] = await Promise.all([
    fetch('/api/settings').then(r=>r.json()),
    fetch('/api/subs').then(r=>r.json()),
    fetch('/api/users').then(r=>r.json()),
    fetch('/api/usage').then(r=>r.json())
  ]);
  settings=s; subs=sb; users=u; usage=ug;
  render();
}

function fmtGB(n){ return (Math.round((n||0)*100)/100)+' GB'; }

function renderUsage(){
  document.getElementById('sTraffic').textContent = fmtGB(usage.totalUsed) + (usage.totalCap>0 ? (' / '+fmtGB(usage.totalCap)) : '');
  const ul = document.getElementById('usageUsersList');
  if(!usage.users || !usage.users.length){ ul.innerHTML='<p class="muted">'+(isFa?'داده‌ای نیست':'No data yet')+'</p>'; }
  else {
    ul.innerHTML = usage.users.slice().sort((a,b)=>(b.used||0)-(a.used||0)).map(u=>{
      const pct = u.traffic>0 ? Math.min(100, Math.round((u.used||0)/u.traffic*100)) : 0;
      return '<div class="progress-wrap"><div class="progress-head"><span>'+esc(u.name)+(u.enabled===false?' <span class="badge badge-yellow">'+(isFa?'غیرفعال':'Off')+'</span>':'')+'</span>'+
        '<span>'+fmtGB(u.used)+' / '+(u.traffic?fmtGB(u.traffic):'∞')+'</span></div>'+
        '<div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div></div>';
    }).join('');
  }
  const sl = document.getElementById('usageSubsList');
  if(!usage.subs || !usage.subs.length){ sl.innerHTML='<p class="muted">'+(isFa?'داده‌ای نیست':'No data yet')+'</p>'; }
  else {
    sl.innerHTML = usage.subs.slice().sort((a,b)=>(b.used||0)-(a.used||0)).map(s=>{
      const pct = s.traffic>0 ? Math.min(100, Math.round((s.used||0)/s.traffic*100)) : 0;
      return '<div class="progress-wrap"><div class="progress-head"><span>'+esc(s.name)+'</span>'+
        '<span>'+fmtGB(s.used)+' / '+(s.traffic?fmtGB(s.traffic):'∞')+'</span></div>'+
        '<div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div></div>';
    }).join('');
  }
}

function render(){
  document.getElementById('sUsers').textContent = users.length;
  document.getElementById('sSubs').textContent = subs.length;
  renderUsage();
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
      const used = u.used||0;
      const total = u.traffic||0;
      const pct = total>0 ? Math.min(100, Math.round(used/total*100)) : 0;
      const link = location.origin+'/sub/u/'+u.id;
      return '<div class="user-card">'+
        '<div class="user-card-head"><div><strong>'+esc(u.name)+'</strong> <span class="badge">'+(u.enabled!==false?(isFa?'فعال':'Active'):(isFa?'غیرفعال':'Off'))+'</span>'+
        (u.note?'<div class="user-meta">'+esc(u.note)+'</div>':'')+'</div>'+
        '<div style="display:flex;gap:.25rem;flex-wrap:wrap">'+
        '<button class="btn-outline btn-sm" onclick="copyText(\\''+link+'\\')">'+(isFa?'کپی لینک':'Copy Link')+'</button>'+
        '<button class="btn-outline btn-sm" onclick="editUser(\\''+u.id+'\\')">'+(isFa?'ویرایش':'Edit')+'</button>'+
        '<button class="btn-blue btn-sm" onclick="resetUser(\\''+u.id+'\\')">'+(isFa?'ریست':'Reset')+'</button>'+
        '<button class="btn-danger btn-sm" onclick="delUser(\\''+u.id+'\\')">'+(isFa?'حذف':'Del')+'</button></div></div>'+
        '<div class="config-box" style="margin:.3rem 0;font-size:.62rem">'+link+'</div>'+
        '<div class="progress-wrap"><div class="progress-head"><span>'+(isFa?'ترافیک':'Traffic')+'</span><span>'+fmtGB(used)+' / '+(total?fmtGB(total):'∞')+'</span></div>'+
        '<div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div></div>'+
        '<div class="muted" style="font-size:.7rem;margin-top:.2rem">'+(isFa?'دستگاه':'Devices')+': '+(u.devices||0)+'/'+(u.maxDevices||'∞')+' · '+(isFa?'انقضا':'Exp')+': '+(u.expire||'-')+(u.lastSeen?(' · '+(isFa?'آخرین اتصال':'Last seen')+': '+new Date(u.lastSeen).toLocaleString(isFa?'fa-IR':'en-US')):'')+'</div></div>';
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
  else {
  let msg = 'Request failed';
  try {
    const e = await r.json();
    msg = e.error || e.message || msg;
  } catch {}
  toast(msg);
};
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
  else {
  let msg = 'Request failed';
  try {
    const e = await r.json();
    msg = e.error || e.message || msg;
  } catch {}
  toast(msg);
};
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

  // Login (no auth required) — now rate-limited and constant-time compared.
  if (path === '/api/login' && method === 'POST') {
    if (await isLoginLocked(request, env)) {
      return json({ error: 'too many attempts, try again later' }, 429);
    }
    const body = await request.json().catch(() => ({}));
    const settings = await getSettings(env);
    if (safeEqual(body.password, settings.password)) {
      await clearLoginFailures(request, env);
      const token = await createSession(env, settings);
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': `app_token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`
        }
      });
    }
    await recordLoginFailure(request, env);
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

  // Auth required from here
  const settingsForAuth = await getSettings(env);
  const authed = await checkAuth(request, env, settingsForAuth);
  if (!authed) return json({ error: 'unauthorized' }, 401);

  if (path === '/api/settings') {
    if (method === 'GET') {
      // don't expose password or the session-signing secret
      const { password, secret, ...safe } = settingsForAuth;
      return json(safe);
    }
    if (method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const s = settingsForAuth;
      if (body.password) s.password = String(body.password).slice(0, 200);
      if (body.trojanPassword) s.trojanPassword = String(body.trojanPassword).slice(0, 200);
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
        if (idx >= 0) list[idx] = { ...list[idx], ...body, used: list[idx].used || 0 };
      } else {
        body.id = uuid().slice(0, 8);
        body.used = 0;
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
        if (idx >= 0) {
          // Never let a plain edit wipe out generated credentials / accumulated usage.
          const { uuid: _u, trojanPassword: _t, used: _used, devices: _d, ...rest } = body;
          list[idx] = { ...list[idx], ...rest };
        }
      } else {
        // Every real user gets their OWN VLESS UUID and Trojan password — this is what
        // makes per-user access control (and per-user traffic accounting) actually work,
        // instead of every client silently sharing the single admin UUID.
        body.id = uuid().slice(0, 8);
        body.uuid = uuid();
        body.trojanPassword = 'u' + randomToken(12);
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

  // Usage summary — total + per-user + per-sub consumption, for the dashboard/usage tab.
  if (path === '/api/usage' && method === 'GET') {
    const [users, subs] = await Promise.all([getUsers(env), getSubs(env)]);
    const totalUsed = users.reduce((sum, u) => sum + (u.used || 0), 0);
    const totalCap = users.reduce((sum, u) => sum + (u.traffic || 0), 0);
    return json({
      totalUsed: +totalUsed.toFixed(3),
      totalCap: +totalCap.toFixed(3),
      users: users.map(u => ({ id: u.id, name: u.name, used: u.used || 0, traffic: u.traffic || 0, lastSeen: u.lastSeen || null, enabled: u.enabled !== false })),
      subs: subs.map(s => ({ id: s.id, name: s.name, used: s.used || 0, traffic: s.traffic || 0 }))
    });
  }

  return json({ error: 'not found' }, 404);
}

// ──────────────────────────── Main ────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      // Override from env vars if present — only touches KV/memory when something actually changed,
      // instead of writing settings back on every single request.
      if (env.PASSWORD || env.UUID || env.TROJAN_PASS || env.PROXYIP) {
        const s = await getSettings(env);
        let changed = false;
        if (env.PASSWORD && s.password !== env.PASSWORD) { s.password = env.PASSWORD; changed = true; }
        if (env.UUID && isValidUUID(env.UUID) && s.uuid !== env.UUID) { s.uuid = env.UUID; changed = true; }
        if (env.TROJAN_PASS && s.trojanPassword !== env.TROJAN_PASS) { s.trojanPassword = env.TROJAN_PASS; changed = true; }
        if (env.PROXYIP && s.proxyIP !== env.PROXYIP) { s.proxyIP = env.PROXYIP; changed = true; }
        if (changed) await saveSettings(env, s);
      }

      const url = new URL(request.url);
      const path = url.pathname;
      const host = url.hostname;
      const lang = url.searchParams.get('lang') || 'fa';

      // WebSocket → VLESS / Trojan
      const upgrade = request.headers.get('Upgrade') || '';
      if (upgrade.toLowerCase() === 'websocket') {
        const settings = await getSettings(env);
        return await handleVLESSWebSocket(request, env, settings, ctx);
      }

      // API
      if (path.startsWith(API_PATH)) {
        return await handleAPI(request, env, path);
      }

      // Personal per-user subscription link: /sub/u/{userId} — uses that user's OWN
      // uuid/trojanPassword rather than the shared admin credentials.
      if (path.startsWith(SUB_PATH + '/u/')) {
        const userId = path.slice((SUB_PATH + '/u/').length).split('/')[0];
        const settings = await getSettings(env);
        const users = await getUsers(env);
        const user = users.find(u => u.id === userId);
        if (!user) return new Response('user not found', { status: 404 });
        const subs = await getSubs(env);
        const linkedSub = subs.find(s => s.id === user.subId) ||
          { name: user.name || 'user', port: 443, path: '/', protocols: { vless: true, trojan: true }, proxyIP: settings.proxyIP, cleanIPs: settings.cleanIPs };
        return new Response(generateSubContent(linkedSub, settings, host, user.uuid, user.trojanPassword), {
          headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Profile-Update-Interval': '6' }
        });
      }

      // Subscription (admin / shared)
      if (path.startsWith(SUB_PATH + '/')) {
        const subId = path.slice(SUB_PATH.length + 1).split('/')[0];
        const settings = await getSettings(env);
        const subs = await getSubs(env);
        const sub = subs.find(s => s.id === subId);
        if (!sub) {
          // fallback: generate with global settings
          const fakeSub = { name: 'APP', port: 443, path: '/', protocols: { vless: true, trojan: true }, proxyIP: settings.proxyIP, cleanIPs: settings.cleanIPs };
          return new Response(generateSubContent(fakeSub, settings, host), {
            headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Profile-Update-Interval': '6' }
          });
        }
        return new Response(generateSubContent(sub, settings, host), {
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

      // DoH
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

      // Panel
      if (path === PANEL_PATH || path === PANEL_PATH + '/' || path === '/') {
        if (path === '/') return redirect(`${url.origin}${PANEL_PATH}?lang=${lang}`);
        const settings = await getSettings(env);
        const authed = await checkAuth(request, env, settings);
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
