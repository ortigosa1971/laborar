// server.js — TODO EN UNO: sesión única + claim atómico + /health + raíz + CSP opcional + compat form
// Funciona en Railway. Reemplaza tu 'server.js' por este.
// Env opcionales: SESSION_SECRET, ENABLE_TRANSLATE=true, COOKIE_SECURE=true, SAMESITE=none, DEBUG_SINGLE_SESSION=1

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

// ========= CONFIG =========
const ENABLE_TRANSLATE = process.env.ENABLE_TRANSLATE === 'true';

// ========= CORS =========
app.use(cors({ origin: true, credentials: true }));

// ========= Carpetas =========
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');

// ========= CSP con helmet =========
const baseDirectives = {
  defaultSrc: ["'self'"],
  styleSrc: ["'self'", "'unsafe-inline'"],
  styleSrcElem: ["'self'", "'unsafe-inline'"],
  scriptSrc: ["'self'", "'unsafe-inline'"],
  scriptSrcElem: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", "data:", "https:"],
  fontSrc: ["'self'", "data:"],
  connectSrc: ["'self'"],
  frameSrc: ["'self'"],
};

if (ENABLE_TRANSLATE) {
  baseDirectives.styleSrc.push("https://fonts.googleapis.com", "https://www.gstatic.com");
  baseDirectives.styleSrcElem.push("https://fonts.googleapis.com", "https://www.gstatic.com");
  baseDirectives.scriptSrcElem.push("https://translate.google.com", "https://translate.googleapis.com", "https://www.gstatic.com");
  baseDirectives.fontSrc.push("https://fonts.gstatic.com");
  baseDirectives.frameSrc.push("https://translate.google.com");
}

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: baseDirectives
  }
}));

// ========= Sesiones (SQLite store) =========
const store = new SQLiteStore({
  db: 'sessions.sqlite',
  dir: DB_DIR
});

app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'cambia-esta-clave',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.SAMESITE || 'lax', // 'none' si front/back en dominios distintos (+ secure:true)
    secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Promesas para store.get/destroy
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

// Body y estáticos
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ========= DB usuarios =========
const db = new Database(path.join(DB_DIR, 'usuarios.db'));
db.pragma('journal_mode = wal');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

const DEBUG = process.env.DEBUG_SINGLE_SESSION === '1';
const log = (...a) => DEBUG && console.log('[single-session]', ...a);

// ========= Healthcheck (PUBLICO) =========
app.get('/health', (req, res) => res.status(200).send('OK'));

// ========= Raíz (PUBLICO) =========
app.get('/', (req, res) => {
  const loginFile = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(loginFile)) return res.sendFile(loginFile);
  // fallback mínimo
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head>
  <body><h1>Login</h1>
  <form method="POST" action="/login">
    <input name="usuario" placeholder="usuario" required>
    <input name="password" type="password" placeholder="password">
    <button>Entrar</button>
  </form>
  </body></html>`);
});

// ========= Helper: autenticar (ajusta a tu lógica) =========
function autenticar(username, password) {
  const row = db.prepare('SELECT username, password, session_id FROM users WHERE username = ?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row;
}

// ========= Login: bloqueo 2º + CLAIM ATOMICO =========
app.post('/login', async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = usuario || username;
    if (!userField) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(userField, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    // Si hay session_id en DB, comprobar si sigue viva
    if (user.session_id) {
      const sess = await storeGet(user.session_id);
      if (sess) {
        log('rechazo segundo login: sesión activa para', user.username);
        return res.redirect('/login.html?error=sesion_activa');
      }
      // limpiar huérfana
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    // Reclamación ATOMICA: solo si session_id está NULL justo ahora
    const claim = db.prepare(
      'UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL'
    ).run(req.sessionID, user.username);

    if (claim.changes === 0) {
      log('claim fallido (alguien la tomó) para', user.username);
      return res.redirect('/login.html?error=sesion_activa');
    }

    // Éxito: crear sesión app
    req.session.usuario = user.username;
    log('login OK (claim) para', user.username, 'sid:', req.sessionID);
    return res.redirect('/inicio.html');
  } catch (e) {
    console.error(e);
    return res.redirect('/login.html?error=interno');
  }
});

// ========= Middleware: sesión única =========
async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');

    const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!row) return res.redirect('/login.html');

    if (!row.session_id) {
      req.session.destroy(() => res.redirect('/login.html?error=sesion_invalida'));
      return;
    }

    if (row.session_id !== req.sessionID) {
      req.session.destroy(() => res.redirect('/login.html?error=conectado_en_otra_maquina'));
      return;
    }

    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(req.session.usuario);
      req.session.destroy(() => res.redirect('/login.html?error=sesion_expirada'));
      return;
    }

    next();
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
}

// ========= Rutas protegidas =========
app.get('/inicio', requiereSesionUnica, (req, res) => {
  const inicioFile = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(inicioFile)) return res.sendFile(inicioFile);
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Inicio</title></head>
  <body><h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>
  <form method="POST" action="/logout"><button>Salir</button></form>
  </body></html>`);
});

app.get('/api/datos', requiereSesionUnica, (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario, sid: req.sessionID });
});

// Pública: útil para frontends
app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session?.usuario });
});

// ========= Logout =========
app.post('/logout', (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;

  req.session.destroy(async () => {
    if (usuario) {
      const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(usuario);
      if (row?.session_id === sid) {
        db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(usuario);
      }
    }
    res.redirect('/login.html?msg=logout');
  });
});

// ========= Admin: forzar logout (opcional) =========
app.post('/admin/forzar-logout', async (req, res) => {
  const { username } = req.body;
  const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(username);
  if (row?.session_id) {
    await storeDestroy(row.session_id).catch(() => {});
    db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(username);
  }
  res.json({ ok: true });
});

// ========= Arranque =========
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 http://0.0.0.0:${PORT} — sesión única con claim atómico${ENABLE_TRANSLATE ? ' + CSP Translate' : ''}`));





