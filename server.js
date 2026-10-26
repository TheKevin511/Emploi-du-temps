/**
 * Emploi du temps — serveur HTTP.
 * Node.js (ES modules) + PostgreSQL + génération de PDF.
 * Dépendances : pg, pdf-lib.
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import pg from 'pg';
import { buildPlanPdf } from './pdf.js';

/* ==========================================================================
   Configuration
   ========================================================================== */
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const { DATABASE_URL } = process.env;

const SESSION_COOKIE = 'sid';
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 10_000;

const LOGIN_MAX_FAILURES = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

const EMAIL_PATTERN = /^\S+@\S+\.\S+$/;
const PG_UNIQUE_VIOLATION = '23505';

const LIMITS = {
  name: 40,
  email: 120,
  passwordMin: 8,
  passwordMax: 100,
  title: 60,
  firstHour: 8,
  lastHour: 23,
};

const INDEX_PATH = join(import.meta.dirname, 'public', 'index.html');
const scryptAsync = promisify(scrypt);

if (!DATABASE_URL) {
  console.error('DATABASE_URL manquante (adresse de ta base PostgreSQL).');
  process.exit(1);
}

/* ==========================================================================
   Erreurs HTTP
   ========================================================================== */
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/* ==========================================================================
   Base de données
   ========================================================================== */
const pool = new pg.Pool({ connectionString: DATABASE_URL, max: 5 });

const query = async (text, params) => (await pool.query(text, params)).rows;

const withTransaction = async (callback) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
};

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id    SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name  TEXT NOT NULL DEFAULT '',
    salt  TEXT NOT NULL,
    hash  TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS cells (
    user_id INT  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day     INT  NOT NULL,
    hour    INT  NOT NULL,
    title   TEXT NOT NULL,
    color   INT  NOT NULL,
    dur     INT  NOT NULL,
    PRIMARY KEY (user_id, day, hour)
  );

  CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
  );
`;

// Clé de signature des sessions : variable SECRET, sinon générée une fois et stockée en base.
const loadSessionSecret = async () => {
  if (process.env.SECRET) return process.env.SECRET;

  await query('INSERT INTO meta (k, v) VALUES ($1, $2) ON CONFLICT DO NOTHING', [
    'secret',
    randomBytes(32).toString('hex'),
  ]);
  const [row] = await query("SELECT v FROM meta WHERE k = 'secret'");
  return row.v;
};

let sessionSecret;
try {
  await pool.query(SCHEMA_SQL);
  sessionSecret = await loadSessionSecret();
  console.log('Base de données prête.');
} catch (error) {
  console.error('Connexion à la base impossible :', error.message);
  process.exit(1);
}

const indexHtml = await readFile(INDEX_PATH);

/* ==========================================================================
   Sécurité : mots de passe, sessions, limitation des tentatives
   ========================================================================== */
const safeEqual = (a, b) => {
  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);
  return bufferA.length === bufferB.length && timingSafeEqual(bufferA, bufferB);
};

const hashPassword = async (password, salt) => (await scryptAsync(password, salt, 64)).toString('hex');

const sign = (payload) => createHmac('sha256', sessionSecret).update(payload).digest('hex');

// Format du jeton : "<idUtilisateur>.<expiration>.<signature>"
const createSessionToken = (userId) => {
  const payload = `${userId}.${Date.now() + SESSION_DURATION_MS}`;
  return `${payload}.${sign(payload)}`;
};

const readSessionToken = (token = '') => {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [userId, expiresAt, signature] = parts;
  const isValid = safeEqual(sign(`${userId}.${expiresAt}`), signature) && Date.now() <= Number(expiresAt);
  return isValid ? Number(userId) : null;
};

const getCookie = (req, name) => req.headers.cookie?.match(new RegExp(`(?:^|; )${name}=([^;]*)`))?.[1];

const buildSessionCookie = (value, maxAgeSeconds) =>
  [
    `${SESSION_COOKIE}=${value}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${maxAgeSeconds}`,
    ...(IS_PRODUCTION ? ['Secure'] : []),
  ].join('; ');

const failedLogins = new Map(); // ip -> { count, since }

const getLoginAttempts = (ip) => {
  const now = Date.now();
  const entry = failedLogins.get(ip);

  if (entry && now - entry.since <= LOGIN_WINDOW_MS) return entry;

  const fresh = { count: 0, since: now };
  failedLogins.set(ip, fresh);
  return fresh;
};

const assertNotRateLimited = (ip) => {
  if (getLoginAttempts(ip).count >= LOGIN_MAX_FAILURES) {
    throw new HttpError(429, 'Trop de tentatives, réessaie dans 15 minutes.');
  }
};

const recordFailedLogin = (ip) => {
  getLoginAttempts(ip).count += 1;
};

const authenticate = async (req) => {
  const userId = readSessionToken(getCookie(req, SESSION_COOKIE));
  const [user] = userId ? await query('SELECT id, email, name FROM users WHERE id = $1', [userId]) : [];

  if (!user) throw new HttpError(401, 'Session expirée, reconnecte-toi.');
  return user;
};

/* ==========================================================================
   Utilitaires HTTP et validation
   ========================================================================== */
const sendJson = (res, status, payload, headers = {}) => {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(JSON.stringify(payload));
};

const readJsonBody = async (req) => {
  req.setEncoding('utf8');
  let raw = '';

  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > MAX_BODY_BYTES) throw new HttpError(413, 'Requête trop volumineuse.');
  }

  try {
    return JSON.parse(raw || '{}');
  } catch {
    throw new HttpError(400, 'Requête invalide.');
  }
};

const getClientIp = (req) => req.headers['x-forwarded-for']?.split(',')[0].trim() ?? req.socket.remoteAddress;

const isInt = (value, min, max) => Number.isInteger(value) && value >= min && value <= max;

const parseName = (value) => String(value ?? '').trim().slice(0, LIMITS.name);

const parseEmail = (value) => {
  const email = String(value ?? '').trim().toLowerCase();
  if (!EMAIL_PATTERN.test(email) || email.length > LIMITS.email) {
    throw new HttpError(400, 'Adresse e-mail invalide.');
  }
  return email;
};

const parseCell = (body) => {
  const { day, hour, color, dur } = body;
  const title = String(body.title ?? '').trim();

  const isValid =
    isInt(day, 0, 6) &&
    isInt(hour, LIMITS.firstHour, LIMITS.lastHour) &&
    isInt(color, 1, 8) &&
    isInt(dur, 1, 4) &&
    hour + dur <= LIMITS.lastHour + 1 &&
    title.length > 0 &&
    title.length <= LIMITS.title;

  if (!isValid) throw new HttpError(400, 'Données invalides.');
  return { day, hour, title, color, dur };
};

const startSession = (res, userId) =>
  sendJson(res, 200, { ok: true }, {
    'Set-Cookie': buildSessionCookie(createSessionToken(userId), SESSION_DURATION_MS / 1000),
  });

/* ==========================================================================
   Routes publiques (sans session)
   ========================================================================== */
const register = async ({ req, res, ip }) => {
  assertNotRateLimited(ip);

  const body = await readJsonBody(req);
  const email = parseEmail(body.email);
  const password = String(body.password ?? '');

  if (password.length < LIMITS.passwordMin || password.length > LIMITS.passwordMax) {
    throw new HttpError(400, `Mot de passe : ${LIMITS.passwordMin} caractères minimum.`);
  }

  const salt = randomBytes(16).toString('hex');
  const hash = await hashPassword(password, salt);

  try {
    const [{ id }] = await query(
      'INSERT INTO users (email, name, salt, hash) VALUES ($1, $2, $3, $4) RETURNING id',
      [email, parseName(body.name), salt, hash],
    );
    startSession(res, id);
  } catch (error) {
    if (error.code === PG_UNIQUE_VIOLATION) {
      throw new HttpError(409, 'Un compte existe déjà avec cet e-mail.');
    }
    throw error;
  }
};

const login = async ({ req, res, ip }) => {
  assertNotRateLimited(ip);

  const body = await readJsonBody(req);
  const email = parseEmail(body.email);
  const password = String(body.password ?? '');

  const [user] = await query('SELECT id, salt, hash FROM users WHERE email = $1', [email]);
  const isValid = user && safeEqual(await hashPassword(password, user.salt), user.hash);

  if (!isValid) {
    recordFailedLogin(ip);
    throw new HttpError(401, 'E-mail ou mot de passe incorrect.');
  }
  startSession(res, user.id);
};

const logout = async ({ res }) =>
  sendJson(res, 200, { ok: true }, { 'Set-Cookie': buildSessionCookie('', 0) });

const PUBLIC_ROUTES = {
  'POST /api/register': register,
  'POST /api/login': login,
  'POST /api/logout': logout,
};

/* ==========================================================================
   Routes privées (session obligatoire)
   ========================================================================== */
const getPlan = async ({ res, user }) => {
  const cells = await query('SELECT day, hour, title, color, dur FROM cells WHERE user_id = $1', [user.id]);
  sendJson(res, 200, { name: user.name, email: user.email, cells });
};

const updateName = async ({ req, res, user }) => {
  const { name } = await readJsonBody(req);
  await query('UPDATE users SET name = $1 WHERE id = $2', [parseName(name), user.id]);
  sendJson(res, 200, { ok: true });
};

const saveCell = async ({ req, res, user }) => {
  const { day, hour, title, color, dur } = parseCell(await readJsonBody(req));

  // Refuse si une activité plus longue, commencée avant, couvre déjà ce créneau.
  const [overlap] = await query(
    'SELECT 1 FROM cells WHERE user_id = $1 AND day = $2 AND hour < $3 AND hour + dur > $3',
    [user.id, day, hour],
  );
  if (overlap) throw new HttpError(409, 'Ce créneau est déjà occupé par une activité plus longue.');

  await withTransaction(async (client) => {
    await client.query(
      'DELETE FROM cells WHERE user_id = $1 AND day = $2 AND hour >= $3 AND hour < $4',
      [user.id, day, hour, hour + dur],
    );
    await client.query(
      'INSERT INTO cells (user_id, day, hour, title, color, dur) VALUES ($1, $2, $3, $4, $5, $6)',
      [user.id, day, hour, title, color, dur],
    );
  });
  sendJson(res, 200, { ok: true });
};

const deleteCell = async ({ res, url, user }) => {
  const day = Number(url.searchParams.get('day'));
  const hour = Number(url.searchParams.get('hour'));

  await query('DELETE FROM cells WHERE user_id = $1 AND day = $2 AND hour = $3', [user.id, day, hour]);
  sendJson(res, 200, { ok: true });
};

const deletePlan = async ({ res, user }) => {
  await query('DELETE FROM cells WHERE user_id = $1', [user.id]);
  sendJson(res, 200, { ok: true });
};

const downloadPdf = async ({ res, url, user }) => {
  const cells = await query('SELECT day, hour, title, color, dur FROM cells WHERE user_id = $1', [user.id]);
  const pdf = await buildPlanPdf({ name: user.name, cells, themeId: url.searchParams.get('theme') });

  res.writeHead(200, {
    'Content-Type': 'application/pdf',
    'Content-Disposition': 'attachment; filename="emploi-du-temps.pdf"',
    'Cache-Control': 'no-store',
  });
  res.end(Buffer.from(pdf));
};

const PRIVATE_ROUTES = {
  'GET /api/plan': getPlan,
  'GET /api/pdf': downloadPdf,
  'PUT /api/name': updateName,
  'PUT /api/cell': saveCell,
  'DELETE /api/cell': deleteCell,
  'DELETE /api/plan': deletePlan,
};

/* ==========================================================================
   Serveur
   ========================================================================== */
const serveIndex = (res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
  res.end(indexHtml);
};

const handleRequest = async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const route = `${req.method} ${url.pathname}`;
  const context = { req, res, url, ip: getClientIp(req) };

  if (route === 'GET /healthz') return sendJson(res, 200, { ok: true });
  if (route === 'GET /' || route === 'GET /index.html') return serveIndex(res);

  const publicHandler = PUBLIC_ROUTES[route];
  if (publicHandler) return publicHandler(context);

  const privateHandler = PRIVATE_ROUTES[route];
  if (!privateHandler) throw new HttpError(404, 'Introuvable');

  context.user = await authenticate(req);
  return privateHandler(context);
};

const server = createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');

  try {
    await handleRequest(req, res);
  } catch (error) {
    if (error instanceof HttpError) {
      sendJson(res, error.status, { error: error.message });
      return;
    }
    console.error(error);
    sendJson(res, 500, { error: 'Erreur serveur, réessaie dans un instant.' });
  }
});

const shutdown = () => {
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen(PORT, () => console.log(`Emploi du temps : http://localhost:${PORT}`));
