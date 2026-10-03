'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const querystring = require('querystring');

const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;
const SESSION_SECRET = String(process.env.SESSION_SECRET || '');
const COOKIE_NAME = 'ul_admin_session';
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const PBKDF2_DIGEST = 'sha256';
const MAX_BODY = 16 * 1024;

if (SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET is missing or too short. Use a random secret of at least 32 characters.');
  process.exit(1);
}

let USERS;
try {
  USERS = JSON.parse(process.env.ADMIN_USERS_JSON || '[]');
} catch {
  console.error('ADMIN_USERS_JSON is not valid JSON.');
  process.exit(1);
}
if (!Array.isArray(USERS) || USERS.length < 1) {
  console.error('ADMIN_USERS_JSON must contain at least one admin user.');
  process.exit(1);
}
USERS = USERS.map(u => ({
  username: String(u.username || '').trim().toLowerCase(),
  displayName: String(u.displayName || u.username || '').trim(),
  salt: String(u.salt || ''),
  hash: String(u.hash || ''),
  iterations: Math.max(100000, Number(u.iterations || 310000))
})).filter(u => u.username && u.salt && u.hash);

if (!USERS.length) {
  console.error('No valid admin users were found in ADMIN_USERS_JSON.');
  process.exit(1);
}

const failures = new Map();

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}
function hmac(input) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(input).digest('base64url');
}
function makeSession(user) {
  const payload = base64url(JSON.stringify({
    u: user.username,
    n: user.displayName || user.username,
    exp: Date.now() + SESSION_SECONDS * 1000
  }));
  return payload + '.' + hmac(payload);
}
function readCookies(req) {
  const raw = String(req.headers.cookie || '');
  const out = {};
  raw.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function readSession(req) {
  const token = readCookies(req)[COOKIE_NAME];
  if (!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = hmac(payload);
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.u || !data.exp || Date.now() > data.exp) return null;
    if (!USERS.some(u => u.username === data.u)) return null;
    return data;
  } catch {
    return null;
  }
}
function verifyPassword(password, user) {
  try {
    const derived = crypto.pbkdf2Sync(
      String(password),
      Buffer.from(user.salt, 'base64'),
      user.iterations,
      32,
      PBKDF2_DIGEST
    );
    const expected = Buffer.from(user.hash, 'base64');
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}
function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}
function loginBlocked(ip) {
  const rec = failures.get(ip);
  if (!rec) return false;
  if (rec.blockedUntil && rec.blockedUntil > Date.now()) return true;
  if (rec.blockedUntil && rec.blockedUntil <= Date.now()) failures.delete(ip);
  return false;
}
function recordFailure(ip) {
  const now = Date.now();
  let rec = failures.get(ip);
  if (!rec || now - rec.first > 15 * 60 * 1000) rec = { count: 0, first: now, blockedUntil: 0 };
  rec.count += 1;
  if (rec.count >= 5) rec.blockedUntil = now + 15 * 60 * 1000;
  failures.set(ip, rec);
}
function clearFailures(ip) {
  failures.delete(ip);
}
function commonHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function send(res, status, body, type = 'text/plain; charset=utf-8', extra = {}) {
  commonHeaders(res);
  res.writeHead(status, { 'Content-Type': type, ...extra });
  res.end(body);
}
function redirect(res, location) {
  commonHeaders(res);
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
  res.end();
}
function loginPage(error = '') {
  let html = fs.readFileSync(path.join(ROOT, 'login.html'), 'utf8');
  const safe = String(error).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const block = safe ? '<div class="error">'+safe+'</div>' : '';
  return html.replaceAll('{{ERROR}}', block);
}
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (Buffer.byteLength(raw) > MAX_BODY) {
        reject(new Error('Request too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(querystring.parse(raw)));
    req.on('error', reject);
  });
}
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};
const ALLOWED_FILES = new Set([
  'index.html',
  'service-worker.js',
  'manifest.webmanifest',
  'icon.svg'
]);
function serveProtectedFile(req, res, pathname) {
  let file = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  if (!ALLOWED_FILES.has(file)) return send(res, 404, 'Not found');
  const full = path.join(ROOT, file);
  fs.readFile(full, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    const ext = path.extname(full);
    const cache = file === 'service-worker.js' || file === 'index.html'
      ? 'no-cache, no-store, must-revalidate'
      : 'private, max-age=3600';
    send(res, 200, data, MIME[ext] || 'application/octet-stream', { 'Cache-Control': cache });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  if (pathname === '/health') {
    return send(res, 200, 'ok', 'text/plain; charset=utf-8', { 'Cache-Control': 'no-store' });
  }

  if (req.method === 'GET' && pathname === '/login') {
    if (readSession(req)) return redirect(res, '/');
    const error = url.searchParams.get('error') ? 'نام کاربری یا رمز عبور درست نیست.' :
      (url.searchParams.get('locked') ? 'تلاش‌های ناموفق زیاد بود. ۱۵ دقیقه دیگر دوباره امتحان کنید.' : '');
    return send(res, 200, loginPage(error), 'text/html; charset=utf-8', { 'Cache-Control': 'no-store' });
  }

  if (req.method === 'POST' && pathname === '/auth/login') {
    const ip = clientIp(req);
    if (loginBlocked(ip)) return redirect(res, '/login?locked=1');
    let body;
    try { body = await parseBody(req); }
    catch { return send(res, 400, 'Bad request'); }

    const username = String(body.username || '').trim().toLowerCase();
    const password = String(body.password || '');
    const user = USERS.find(u => u.username === username);
    if (!user || !verifyPassword(password, user)) {
      recordFailure(ip);
      return redirect(res, '/login?error=1');
    }

    clearFailures(ip);
    const cookie = `${COOKIE_NAME}=${encodeURIComponent(makeSession(user))}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
    commonHeaders(res);
    res.writeHead(302, {
      Location: '/',
      'Set-Cookie': cookie,
      'Cache-Control': 'no-store'
    });
    return res.end();
  }

  if (req.method === 'POST' && pathname === '/auth/logout') {
    commonHeaders(res);
    res.writeHead(302, {
      Location: '/login',
      'Set-Cookie': `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
      'Cache-Control': 'no-store'
    });
    return res.end();
  }

  const session = readSession(req);
  if (!session) return redirect(res, '/login');

  if (req.method === 'GET' && pathname === '/api/me') {
    return send(res, 200, JSON.stringify({ username: session.u, displayName: session.n || session.u }), 'application/json; charset=utf-8', { 'Cache-Control': 'no-store' });
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
  return serveProtectedFile(req, res, pathname);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`University Leaderboard secure server listening on port ${PORT}`);
  console.log(`Configured admin users: ${USERS.map(u => u.username).join(', ')}`);
});
