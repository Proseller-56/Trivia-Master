'use strict';
// Trivia Master server. No npm packages needed: just `node server.js`.
// Admin secret: set ADMIN_PASSWORD in the environment, or one is generated on first start
// and printed ONCE in this console (only a salted hash is stored in data.json).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '127.0.0.1';
const DATA = path.join(__dirname, 'data.json'), PAGE = path.join(__dirname, 'trivia-master.html');
const SESSION_MS = 7 * 864e5, ADMIN_MS = 30 * 6e4;

// ---------- storage ----------
let db = { users: {}, runs: [], admin: null, sessions: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DATA, 'utf8'))); } catch (e) {}
db.users = Object.assign(Object.create(null), db.users);
const save = () => { const t = DATA + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, DATA); };
const scrypt = (p, s) => new Promise((ok, no) => crypto.scrypt(p, s, 64, (e, k) => e ? no(e) : ok(k)));
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
async function makeHash(pw) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: (await scrypt(pw, salt)).toString('hex') }; }
async function checkHash(pw, rec) { return safeEq(await scrypt(pw, rec.salt), Buffer.from(rec.hash, 'hex')); }
const DUMMY = { salt: 'x'.repeat(32), hash: '0'.repeat(128) };

async function checkAdmin(pw) {
  if (process.env.ADMIN_PASSWORD) return safeEq(sha(pw), sha(process.env.ADMIN_PASSWORD));
  return db.admin ? checkHash(pw, db.admin) : false;
}
async function initAdmin() {
  if (process.env.ADMIN_PASSWORD || db.admin) return;
  const pw = crypto.randomBytes(9).toString('base64url');
  db.admin = await makeHash(pw); save();
  console.log('\n  Admin password (shown once, store it safely): ' + pw + '\n  Set ADMIN_PASSWORD to choose your own.\n');
}

// ---------- sessions & limits ----------
const sessions = new Map(), fails = new Map();
const th = t => sha(t).toString('hex');
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]).map(p => [p[0], p[1]]));
function getSession(req) {
  const t = cookies(req).tm_sid; if (!t) return null;
  let s = sessions.get(t);
  if (!s) {
    const r = db.sessions[th(t)];
    if (r && Date.now() < r.exp) { s = { user: r.user, admin: false, adminUntil: 0, exp: r.exp, tok: t }; sessions.set(t, s); }
  }
  if (!s) return null;
  if (Date.now() > s.exp) { sessions.delete(t); return null; }
  return s;
}
function newSession(req, res, keep) {
  const old = cookies(req).tm_sid; if (old) { sessions.delete(old); delete db.sessions[th(old)]; }
  const tok = crypto.randomBytes(32).toString('hex');
  const s = { user: null, admin: false, adminUntil: 0, exp: Date.now() + SESSION_MS, tok };
  if (keep) { s.admin = keep.admin; s.adminUntil = keep.adminUntil; }
  sessions.set(tok, s);
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `tm_sid=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}${secure}`);
  return s;
}
const isAdmin = s => !!(s && s.admin && Date.now() < s.adminUntil);
const ip = req => req.socket.remoteAddress || '?';
function limited(req) { const f = fails.get(ip(req)); return f && f.n >= 8 && Date.now() < f.until; }
function fail(req) { const f = fails.get(ip(req)) || { n: 0, until: 0 }; f.n++; f.until = Date.now() + 15 * 6e4; fails.set(ip(req), f); }
const clear = req => fails.delete(ip(req));
setInterval(() => { const n = Date.now(); for (const [k, s] of sessions) if (n > s.exp) sessions.delete(k); for (const k in db.sessions) if (n > db.sessions[k].exp) delete db.sessions[k]; for (const [k, f] of fails) if (n > f.until) fails.delete(k); }, 6e4).unref();

// ---------- validation ----------
const SUBS = {
  Capital: ['10 Questions', '20 Questions', '30 Questions', '50 Questions', '100 Questions', 'All Questions'],
  Flags: ['10 Questions', '20 Questions', '30 Questions', '50 Questions', '100 Questions', 'All Questions'],
  Words: ['1 Minute', '2 Minutes', '3 Minutes', '4 Minutes', '5 Minutes', '10 Minutes']
};
const cleanName = v => typeof v === 'string' ? v.replace(/\s+/g, ' ').trim() : '';
const nameOk = n => /^[^\p{C}<>]{1,16}$/u.test(n);
const pwOk = p => typeof p === 'string' && p.length >= 6 && p.length <= 128;
function validRun(b) {
  const { g, sub, c, t, tm } = b || {};
  if (!SUBS[g] || !SUBS[g].includes(sub)) return 'Invalid game.';
  if (![c, t, tm].every(Number.isInteger) || c < 0 || t < 0 || tm < 0 || c > t || tm > 3600) return 'Invalid score.';
  const n = parseInt(sub, 10);
  if (g === 'Words') { if (tm !== n * 60 || c > n * 180) return 'Invalid score.'; }
  else if (sub === 'All Questions' ? (t < 100 || t > 300) : t !== n) return 'Invalid score.';
  return '';
}

// ---------- http helpers ----------
const ADS_ON = process.env.ADSENSE === '1'; // set ADSENSE=1 once you use real AdSense ad units
const G = 'https://*.googlesyndication.com https://*.google.com https://*.doubleclick.net https://*.googleadservices.com https://*.adtrafficquality.google';
const CSP = ADS_ON
  ? `default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval' ${G}; style-src 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' ${G}; frame-src ${G}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  : "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' https://flagcdn.com data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const SEC = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store',
  'Content-Security-Policy': CSP
};
const send = (res, code, obj) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json' }, SEC)); res.end(JSON.stringify(obj)); };
const err = (res, code, error, extra) => send(res, code, Object.assign({ error }, extra));
function body(req) {
  return new Promise(ok => {
    let d = '', big = false;
    req.on('data', c => { d += c; if (d.length > 10240) { big = true; req.destroy(); } });
    req.on('end', () => { if (big) return ok(null); try { ok(JSON.parse(d || '{}')); } catch (e) { ok(null); } });
    req.on('error', () => ok(null));
  });
}

// ---------- routes ----------
async function api(req, res, url) {
  const m = req.method, p = url.pathname;
  if (m !== 'GET') {
    if (req.headers['x-requested-with'] !== 'tm') return err(res, 403, 'Forbidden.');
    const o = req.headers.origin;
    if (o) { let h; try { h = new URL(o).host; } catch (e) {} if (h !== req.headers.host) return err(res, 403, 'Forbidden.'); }
  }
  const b = m === 'GET' ? {} : await body(req);
  if (b === null || typeof b !== 'object') return err(res, 400, 'Bad request.');
  let s = getSession(req);

  if (m === 'GET' && p === '/api/me') return send(res, 200, { user: s && s.user, admin: isAdmin(s) });

  if (m === 'GET' && p === '/api/runs')
    return send(res, 200, { runs: db.runs.slice(-5000).map(r => ({ u: r.u, g: r.g, sub: r.sub, c: r.c, t: r.t, tm: r.tm, d: r.d })) });

  if (m === 'POST' && (p === '/api/register' || p === '/api/login')) {
    if (limited(req)) return err(res, 429, 'Too many attempts. Try again in 15 minutes.');
    const name = cleanName(b.username), pw = b.password, key = name.toLowerCase();
    if (p === '/api/register') {
      if (!nameOk(name)) return err(res, 400, 'Username must be 1-16 characters.');
      if (!pwOk(pw)) return err(res, 400, 'Password must be 6-128 characters.');
      if (db.users[key]) return err(res, 409, 'That username is taken.', { code: 'taken' });
      db.users[key] = Object.assign({ name, created: Date.now() }, await makeHash(pw)); save();
    } else {
      const u = typeof pw === 'string' && db.users[key];
      const ok = await checkHash(typeof pw === 'string' ? pw : '', u || DUMMY);
      if (!u || !ok) { fail(req); return err(res, 401, 'Username or password is incorrect.'); }
      clear(req);
    }
    s = newSession(req, res, s); s.user = db.users[key].name;
    db.sessions[th(s.tok)] = { user: s.user, exp: s.exp }; save();
    return send(res, 200, { user: s.user, admin: isAdmin(s) });
  }
  if (m === 'POST' && p === '/api/logout') {
    const t = cookies(req).tm_sid; if (t) { sessions.delete(t); delete db.sessions[th(t)]; save(); }
    res.setHeader('Set-Cookie', 'tm_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    return send(res, 200, {});
  }
  if (m === 'POST' && p === '/api/runs') {
    if (!s || !s.user) return err(res, 401, 'Log in to submit scores.', { code: 'auth_required' });
    const e = validRun(b); if (e) return err(res, 400, e);
    db.runs.push({ id: crypto.randomBytes(8).toString('hex'), u: s.user, g: b.g, sub: b.sub, c: b.c, t: b.t, tm: b.tm, d: Date.now() });
    save(); return send(res, 200, {});
  }
  if (m === 'POST' && p === '/api/me/delete-times') {
    if (!s || !s.user) return err(res, 401, 'Log in first.', { code: 'auth_required' });
    if (limited(req)) return err(res, 429, 'Too many attempts. Try again later.');
    const rec = db.users[s.user.toLowerCase()];
    if (!rec || typeof b.password !== 'string' || !(await checkHash(b.password, rec))) { fail(req); return err(res, 401, 'Incorrect password.'); }
    clear(req);
    const before = db.runs.length; db.runs = db.runs.filter(r => r.u.toLowerCase() !== s.user.toLowerCase()); save();
    return send(res, 200, { deleted: before - db.runs.length });
  }

  // ----- admin: every check is made here on the server -----
  if (m === 'POST' && p === '/api/admin/login') {
    if (limited(req)) return err(res, 429, 'Too many attempts. Try again in 15 minutes.');
    if (typeof b.password !== 'string' || !(await checkAdmin(b.password))) { fail(req); return err(res, 401, 'Incorrect admin password.'); }
    clear(req);
    if (!s) s = newSession(req, res, null);
    s.admin = true; s.adminUntil = Date.now() + ADMIN_MS;
    return send(res, 200, { admin: true });
  }
  if (p.startsWith('/api/admin/')) {
    if (m === 'POST' && p === '/api/admin/logout') { if (s) s.admin = false; return send(res, 200, {}); }
    if (!isAdmin(s)) return err(res, 403, 'Admin access required.', { code: 'admin_required' });
    if (m === 'GET' && p === '/api/admin/runs') return send(res, 200, { runs: db.runs.slice().reverse().slice(0, 2000) });
    if (m === 'POST' && p === '/api/admin/delete') {
      const before = db.runs.length;
      if (b.all === true) db.runs = [];
      else if (Array.isArray(b.ids)) { const ids = new Set(b.ids.filter(x => typeof x === 'string')); db.runs = db.runs.filter(r => !ids.has(r.id)); }
      else return err(res, 400, 'Bad request.');
      save(); return send(res, 200, { deleted: before - db.runs.length });
    }
  }
  return err(res, 404, 'Not found.');
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, SEC));
      return res.end(fs.readFileSync(PAGE));
    }
    if (req.method === 'GET' && url.pathname === '/ads.txt') { // AdSense requires this file next to server.js
      try { const t = fs.readFileSync(path.join(__dirname, 'ads.txt')); res.writeHead(200, Object.assign({ 'Content-Type': 'text/plain' }, SEC)); return res.end(t); } catch (e) {}
    }
    err(res, 404, 'Not found.');
  } catch (e) { console.error(e); if (!res.headersSent) err(res, 500, 'Server error.'); else res.end(); }
}).listen(PORT, HOST, async () => { await initAdmin(); console.log(`Trivia Master running at http://${HOST}:${PORT}`); });
