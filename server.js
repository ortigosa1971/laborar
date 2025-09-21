
// server.js (solo una sesión activa por usuario)
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

// CORS
app.use(cors({ origin: true, credentials: true }));

// ====== Carpetas ======
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');

// ====== Sesiones (SQLite store) ======
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
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Promesas para store.get/destroy
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ====== DB usuarios ======
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

// ====== Auth ======
function autenticar(username, password) {
  const row = db.prepare('SELECT username, password, session_id FROM users WHERE username = ?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row;
}

// ====== Login ======
app.post('/login', async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = usuario || username;
    if (!userField) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(userField, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    if (user.session_id) {
      const sess = await storeGet(user.session_id);
      if (sess) {
        log('rechazo segundo login para', user.username);
        return res.redirect('/login.html?error=sesion_activa');
      }
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    req.session.usuario = user.username;
    db.prepare('UPDATE users SET session_id = ? WHERE username = ?').run(req.sessionID, user.username);

    res.redirect('/inicio.html');
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
});

// ====== Middleware: una sola sesión válida ======
async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');

    const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!row?.session_id) {
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

const rutasPublicas = new Set(['/login', '/verificar-sesion', '/logout', '/', '/login.html', '/favicon.ico']);
app.use((req, res, next) => {
  if (req.method === 'GET' && req.path.startsWith('/public')) return next();
  if (rutasPublicas.has(req.path)) return next();
  return requiereSesionUnica(req, res, next);
});

// ====== Rutas protegidas ======
app.get('/inicio', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'inicio.html'));
});

app.get('/api/datos', (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario, sid: req.sessionID });
});

app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session?.usuario });
});

// ====== Logout ======
app.post('/logout', (req, res) => {
  const usuario = req.session?.usuario;
  const sid = req.sessionID;
  req.session.destroy(() => {
    if (usuario) {
      const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(usuario);
      if (row?.session_id === sid) {
        db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(usuario);
      }
    }
    res.redirect('/login.html?msg=logout');
  });
});

// ====== Admin ======
app.post('/admin/forzar-logout', async (req, res) => {
  const { username } = req.body;
  const row = db.prepare('SELECT session_id FROM users WHERE username = ?').get(username);
  if (row?.session_id) {
    await storeDestroy(row.session_id).catch(() => {});
    db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(username);
  }
  res.json({ ok: true });
});

// ====== Arranque ======
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 http://localhost:${PORT} (una sola sesión por usuario)`));

