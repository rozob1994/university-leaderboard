'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const querystring = require('querystring');
const { createClient } = require('@libsql/client');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;
const SESSION_SECRET = String(process.env.SESSION_SECRET || '');
const COOKIE_NAME = 'ul_admin_session';
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const PBKDF2_DIGEST = 'sha256';
const MAX_FORM_BODY = 16 * 1024;
const MAX_JSON_BODY = 2 * 1024 * 1024;

const DATABASE_URL = String(process.env.DATABASE_URL || process.env.POSTGRES_URL || '').trim();
const TURSO_DATABASE_URL = String(process.env.TURSO_DATABASE_URL || '').trim();
const TURSO_AUTH_TOKEN = String(process.env.TURSO_AUTH_TOKEN || '').trim();
const SHARED_DB_CONFIGURED = Boolean(DATABASE_URL || (TURSO_DATABASE_URL && TURSO_AUTH_TOKEN));
let sharedDb = null;
let sharedDbKind = null;
let sharedDbError = null;

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
function sendJson(res, status, value) {
  send(res, status, JSON.stringify(value), 'application/json; charset=utf-8', { 'Cache-Control': 'no-store' });
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

function readRawBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('Request too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
async function parseFormBody(req) {
  return querystring.parse(await readRawBody(req, MAX_FORM_BODY));
}
async function parseJsonBody(req) {
  const raw = await readRawBody(req, MAX_JSON_BODY);
  return JSON.parse(raw || '{}');
}

async function initSharedDb() {
  if (!SHARED_DB_CONFIGURED) {
    console.log('Shared data: disabled until DATABASE_URL or Turso credentials are configured.');
    return;
  }
  try {
    if (DATABASE_URL) {
      const sslMode = String(process.env.PGSSL || process.env.PGSSLMODE || '').toLowerCase();
      const ssl = ['require','verify-ca','verify-full'].includes(sslMode) ? { rejectUnauthorized: false } : undefined;
      sharedDb = new Pool({ connectionString: DATABASE_URL, ssl });
      sharedDbKind = 'postgres';
      await sharedDb.query(`CREATE TABLE IF NOT EXISTS shared_project (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        data TEXT NOT NULL,
        revision BIGINT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL
      )`);
      await sharedDb.query(`CREATE TABLE IF NOT EXISTS project_revisions (
        revision BIGINT PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL
      )`);
      sharedDbError = null;
      console.log('Shared data: PostgreSQL connected.');
      return;
    }

    sharedDb = createClient({ url: TURSO_DATABASE_URL, authToken: TURSO_AUTH_TOKEN });
    sharedDbKind = 'turso';
    await sharedDb.batch([
      `CREATE TABLE IF NOT EXISTS shared_project (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        data TEXT NOT NULL,
        revision INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS project_revisions (
        revision INTEGER PRIMARY KEY,
        data TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL
      )`
    ], 'write');
    sharedDbError = null;
    console.log('Shared data: Turso connected.');
  } catch (err) {
    try { if (sharedDbKind === 'postgres' && sharedDb) await sharedDb.end(); } catch {}
    sharedDb = null;
    sharedDbKind = null;
    sharedDbError = String(err && err.message || err);
    console.error('Shared data initialization failed:', sharedDbError);
  }
}

async function readSharedProject() {
  if (!sharedDb) return null;
  let rows;
  if (sharedDbKind === 'postgres') {
    const rs = await sharedDb.query('SELECT data, revision, updated_at, updated_by FROM shared_project WHERE id = 1');
    rows = rs.rows;
  } else {
    const rs = await sharedDb.execute('SELECT data, revision, updated_at, updated_by FROM shared_project WHERE id = 1');
    rows = rs.rows;
  }
  if (!rows.length) return null;
  const row = rows[0];
  return {
    project: JSON.parse(String(row.data)),
    revision: Number(row.revision || 0),
    updatedAt: String(row.updated_at || ''),
    updatedBy: String(row.updated_by || '')
  };
}

function validProjectShape(project) {
  return project && typeof project === 'object' &&
    Array.isArray(project.students) &&
    Array.isArray(project.assignments) &&
    project.scores && typeof project.scores === 'object';
}

async function insertInitialSharedProject(data, now, username) {
  if (sharedDbKind === 'postgres') {
    const rs = await sharedDb.query(
      'INSERT INTO shared_project (id, data, revision, updated_at, updated_by) VALUES (1, $1, 1, $2, $3) ON CONFLICT (id) DO NOTHING',
      [data, now, username]
    );
    return rs.rowCount;
  }
  const rs = await sharedDb.execute({
    sql: 'INSERT OR IGNORE INTO shared_project (id, data, revision, updated_at, updated_by) VALUES (1, ?, 1, ?, ?)',
    args: [data, now, username]
  });
  return rs.rowsAffected;
}

async function saveRevision(revision, data, now, username) {
  if (sharedDbKind === 'postgres') {
    await sharedDb.query(
      `INSERT INTO project_revisions (revision, data, updated_at, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (revision) DO UPDATE SET data=EXCLUDED.data, updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by`,
      [revision, data, now, username]
    );
  } else {
    await sharedDb.execute({
      sql: 'INSERT OR REPLACE INTO project_revisions (revision, data, updated_at, updated_by) VALUES (?, ?, ?, ?)',
      args: [revision, data, now, username]
    });
  }
}

async function updateSharedProjectRow(data, next, now, username, currentRevision) {
  if (sharedDbKind === 'postgres') {
    const rs = await sharedDb.query(
      'UPDATE shared_project SET data=$1, revision=$2, updated_at=$3, updated_by=$4 WHERE id=1 AND revision=$5',
      [data, next, now, username, currentRevision]
    );
    return rs.rowCount;
  }
  const rs = await sharedDb.execute({
    sql: 'UPDATE shared_project SET data = ?, revision = ?, updated_at = ?, updated_by = ? WHERE id = 1 AND revision = ?',
    args: [data, next, now, username, currentRevision]
  });
  return rs.rowsAffected;
}

async function trimRevisions(minRevision) {
  if (sharedDbKind === 'postgres') {
    await sharedDb.query('DELETE FROM project_revisions WHERE revision < $1', [minRevision]);
  } else {
    await sharedDb.execute({ sql: 'DELETE FROM project_revisions WHERE revision < ?', args: [minRevision] });
  }
}

async function listSharedRevisions() {
  let rows;
  if (sharedDbKind === 'postgres') {
    const rs = await sharedDb.query('SELECT revision, updated_at, updated_by FROM project_revisions ORDER BY revision DESC LIMIT 20');
    rows = rs.rows;
  } else {
    const rs = await sharedDb.execute('SELECT revision, updated_at, updated_by FROM project_revisions ORDER BY revision DESC LIMIT 20');
    rows = rs.rows;
  }
  return rows.map(r => ({
    revision: Number(r.revision),
    updatedAt: String(r.updated_at || ''),
    updatedBy: String(r.updated_by || '')
  }));
}

async function saveSharedProject(project, baseRevision, username) {
  const data = JSON.stringify(project);
  if (Buffer.byteLength(data, 'utf8') > 1500000) throw new Error('Project is too large');
  const now = new Date().toISOString();
  const current = await readSharedProject();

  if (!current) {
    if (Number(baseRevision || 0) !== 0) return { conflict: true, current: null };
    const inserted = await insertInitialSharedProject(data, now, username);
    if (!inserted) return { conflict: true, current: await readSharedProject() };
    await saveRevision(1, data, now, username);
    return { conflict: false, revision: 1, updatedAt: now, updatedBy: username };
  }

  const base = Number(baseRevision || 0);
  if (base !== current.revision) return { conflict: true, current };

  const next = current.revision + 1;
  const updated = await updateSharedProjectRow(data, next, now, username, current.revision);
  if (!updated) return { conflict: true, current: await readSharedProject() };

  await saveRevision(next, data, now, username);
  await trimRevisions(Math.max(1, next - 99));
  return { conflict: false, revision: next, updatedAt: now, updatedBy: username };
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
  'app.private',
  'service-worker.js',
  'manifest.webmanifest',
  'icon.svg'
]);
function serveProtectedFile(req, res, pathname) {
  let file = pathname === '/' ? 'app.private' : pathname.replace(/^\/+/, '');
  if (!ALLOWED_FILES.has(file)) return send(res, 404, 'Not found');
  const full = path.join(ROOT, file);
  fs.readFile(full, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    const ext = path.extname(full);
    const cache = file === 'service-worker.js' || file === 'index.html'
      ? 'no-cache, no-store, must-revalidate'
      : 'private, max-age=3600';
    const type = file === 'app.private' ? 'text/html; charset=utf-8' : (MIME[ext] || 'application/octet-stream');
    send(res, 200, data, type, { 'Cache-Control': cache });
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;

    if (pathname === '/health') {
      return sendJson(res, 200, {
        ok: true,
        sharedDataConfigured: SHARED_DB_CONFIGURED,
        sharedDataConnected: Boolean(sharedDb),
        sharedDataKind: sharedDbKind,
        sharedDataError: sharedDbError
      });
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
      try { body = await parseFormBody(req); }
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
    if (!session) {
      if (pathname.startsWith('/api/')) return sendJson(res, 401, { error: 'unauthorized' });
      return redirect(res, '/login');
    }

    if (req.method === 'GET' && pathname === '/api/me') {
      return sendJson(res, 200, { username: session.u, displayName: session.n || session.u });
    }

    if (pathname === '/api/project') {
      if (!SHARED_DB_CONFIGURED) {
        return sendJson(res, 503, { configured: false, error: 'shared_database_not_configured' });
      }
      if (!sharedDb) {
        return sendJson(res, 503, { configured: true, error: 'shared_database_unavailable', detail: sharedDbError });
      }

      if (req.method === 'GET') {
        const current = await readSharedProject();
        if (!current) return sendJson(res, 200, { configured: true, project: null, revision: 0 });
        return sendJson(res, 200, { configured: true, ...current });
      }

      if (req.method === 'PUT') {
        let body;
        try { body = await parseJsonBody(req); }
        catch (err) { return sendJson(res, 400, { error: 'invalid_json', detail: String(err.message || err) }); }
        if (!validProjectShape(body.project)) return sendJson(res, 400, { error: 'invalid_project' });

        const result = await saveSharedProject(body.project, body.baseRevision, session.u);
        if (result.conflict) {
          return sendJson(res, 409, {
            error: 'revision_conflict',
            current: result.current
          });
        }
        return sendJson(res, 200, {
          ok: true,
          revision: result.revision,
          updatedAt: result.updatedAt,
          updatedBy: result.updatedBy
        });
      }
    }

    if (req.method === 'GET' && pathname === '/api/project/revisions') {
      if (!sharedDb) return sendJson(res, 503, { error: 'shared_database_unavailable' });
      return sendJson(res, 200, { revisions: await listSharedRevisions() });
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    return serveProtectedFile(req, res, pathname);
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: 'server_error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`University Leaderboard secure server listening on port ${PORT}`);
  console.log(`Configured admin users: ${USERS.map(u => u.username).join(', ')}`);
  initSharedDb().catch(err => {
    sharedDbError = String(err && err.message || err);
    console.error('Shared data initialization failed after server start:', sharedDbError);
  });
});
