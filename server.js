// Emploi du temps : Node.js + PostgreSQL (Neon, Supabase, Render…) – une seule dépendance : pg
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { Pool } = require('pg');
const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL manquante (adresse de ta base PostgreSQL).'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
const bad = () => Object.assign(new Error('bad'), { bad: true });

let SECRET = process.env.SECRET;
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL DEFAULT '', salt TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS cells(user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, day INT NOT NULL, hour INT NOT NULL, title TEXT NOT NULL, color INT NOT NULL, dur INT NOT NULL, PRIMARY KEY(user_id, day, hour));
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);`);
  if (!SECRET) {
    await pool.query('INSERT INTO meta VALUES($1,$2) ON CONFLICT DO NOTHING', ['secret', crypto.randomBytes(32).toString('hex')]);
    SECRET = (await pool.query("SELECT v FROM meta WHERE k='secret'")).rows[0].v;
  }
}
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const makeToken = uid => { const p = uid + '.' + (Date.now() + 30 * 864e5); return p + '.' + sign(p); };
function readToken(t) {
  const p = (t || '').split('.'); if (p.length !== 3) return null;
  const a = Buffer.from(sign(p[0] + '.' + p[1])), b = Buffer.from(p[2]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b) || Date.now() > +p[1]) return null;
  return +p[0];
}
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const cookie = (v, age) => `sid=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${PROD ? '; Secure' : ''}`;
const send = (res, code, obj, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...h }); res.end(JSON.stringify(obj)); };
const body = req => new Promise((ok, ko) => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e4) { req.destroy(); ko(bad()); } }); req.on('end', () => { try { ok(JSON.parse(d || '{}')); } catch { ko(bad()); } }); });
const tries = new Map();
function limited(ip) { const t = tries.get(ip) || { n: 0, t: Date.now() }; if (Date.now() - t.t > 9e5) { t.n = 0; t.t = Date.now(); } tries.set(ip, t); return t.n >= 10; }
const int = (v, a, b) => Number.isInteger(v) && v >= a && v <= b;
const q = (text, params) => pool.query(text, params).then(r => r.rows);

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  res.setHeader('X-Content-Type-Options', 'nosniff');
  try {
    if (url.pathname === '/healthz') return send(res, 200, { ok: true });
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
    }
    if (!url.pathname.startsWith('/api/')) return send(res, 404, { error: 'Introuvable' });
    const route = req.method + ' ' + url.pathname;

    if (route === 'POST /api/register' || route === 'POST /api/login') {
      if (limited(ip)) return send(res, 429, { error: 'Trop de tentatives, réessaie dans 15 minutes.' });
      const b = await body(req), email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
      if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 120) return send(res, 400, { error: 'Adresse e-mail invalide.' });
      let uid;
      if (route.endsWith('register')) {
        if (pw.length < 8 || pw.length > 100) return send(res, 400, { error: 'Mot de passe : 8 caractères minimum.' });
        const salt = crypto.randomBytes(16).toString('hex');
        try {
          uid = (await q('INSERT INTO users(email,name,salt,hash) VALUES($1,$2,$3,$4) RETURNING id', [email, String(b.name || '').slice(0, 40), salt, hashPw(pw, salt)]))[0].id;
        } catch (e) { if (e.code === '23505') return send(res, 409, { error: 'Un compte existe déjà avec cet e-mail.' }); throw e; }
      } else {
        const u = (await q('SELECT id,salt,hash FROM users WHERE email=$1', [email]))[0];
        const ok = u && crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt)), Buffer.from(u.hash));
        if (!ok) { tries.get(ip).n++; return send(res, 401, { error: 'E-mail ou mot de passe incorrect.' }); }
        uid = u.id;
      }
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookie(makeToken(uid), 2592000) });
    }
    if (route === 'POST /api/logout') return send(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) });

    const uid = readToken((req.headers.cookie || '').match(/(?:^|; )sid=([^;]*)/)?.[1]);
    const user = uid && (await q('SELECT id,email,name FROM users WHERE id=$1', [uid]))[0];
    if (!user) return send(res, 401, { error: 'Session expirée, reconnecte-toi.' });

    if (route === 'GET /api/plan') {
      const cells = await q('SELECT day,hour,title,color,dur FROM cells WHERE user_id=$1', [user.id]);
      return send(res, 200, { name: user.name, email: user.email, cells });
    }
    if (route === 'PUT /api/name') {
      const b = await body(req); await q('UPDATE users SET name=$1 WHERE id=$2', [String(b.name || '').slice(0, 40), user.id]);
      return send(res, 200, { ok: true });
    }
    if (route === 'PUT /api/cell') {
      const b = await body(req), t = String(b.title || '').trim();
      if (!int(b.day, 0, 6) || !int(b.hour, 8, 23) || !int(b.color, 1, 8) || !int(b.dur, 1, 4) || b.hour + b.dur > 24 || !t || t.length > 60)
        return send(res, 400, { error: 'Données invalides.' });
      if ((await q('SELECT 1 FROM cells WHERE user_id=$1 AND day=$2 AND hour<$3 AND hour+dur>$3', [user.id, b.day, b.hour])).length)
        return send(res, 409, { error: 'Ce créneau est déjà occupé par une activité plus longue.' });
      const c = await pool.connect();
      try {
        await c.query('BEGIN');
        await c.query('DELETE FROM cells WHERE user_id=$1 AND day=$2 AND hour>=$3 AND hour<$4', [user.id, b.day, b.hour, b.hour + b.dur]);
        await c.query('INSERT INTO cells VALUES($1,$2,$3,$4,$5,$6)', [user.id, b.day, b.hour, t, b.color, b.dur]);
        await c.query('COMMIT');
      } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
      return send(res, 200, { ok: true });
    }
    if (route === 'DELETE /api/cell') {
      await q('DELETE FROM cells WHERE user_id=$1 AND day=$2 AND hour=$3', [user.id, +url.searchParams.get('day'), +url.searchParams.get('hour')]);
      return send(res, 200, { ok: true });
    }
    if (route === 'DELETE /api/plan') { await q('DELETE FROM cells WHERE user_id=$1', [user.id]); return send(res, 200, { ok: true }); }
    send(res, 404, { error: 'Introuvable' });
  } catch (e) {
    if (!e.bad) console.error(e);
    send(res, e.bad ? 400 : 500, { error: e.bad ? 'Requête invalide.' : 'Erreur serveur, réessaie dans un instant.' });
  }
}).listen(PORT, () => {
  console.log('Emploi du temps : http://localhost:' + PORT);
  init().then(() => console.log('Base de données prête.')).catch(e => { console.error('Connexion base impossible :', e.message); process.exit(1); });
});
