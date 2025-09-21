// server.js (una sola sesión por usuario + claim atómico + /health + '/')
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');

const app = express();
app.set('trust proxy', 1);

// ====== Carpetas ======
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');

// ====== Sesiones (SQLite) ======
const store = new SQLiteStore({
  db: 'sessions.sqlite',
  dir: DB_DIR
});

app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'clave-secreta-cambiala',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.SAMESITE || 'lax', // usar 'none' + secure:true si front/back en dominios distintos
    secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8 // 8 horas
  }
}));

// Promesas para store.get/destroy
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ====== DB (usuarios) ======
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

// ====== Healthcheck (PUBLICO) ======
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// ====== Raíz (PUBLICO) ======
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

// ====== Helper: autenticar (ajusta a tu lógica real) ======
function autenticar(username, password) {
  const row = db.prepare('SELECT username, password, session_id FROM users WHERE username = ?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row; // { username, password, session_id }
}

// ====== Login: bloqueo segundo inicio + CLAIM ATOMICO ======
app.post('/login', async (req, res) => {
  try {
    const { usuario, username, password } = req.body;
    const userField = usuario || username;
    if (!userField) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(userField, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    // 1) Si hay session_id en DB, verificar si sigue viva
    if (user.session_id) {
      const sess = await storeGet(user.session_id);
      if (sess) {
        log('rechazo segundo login: sesion activa para', user.username);
        return res.redirect('/login.html?error=sesion_activa');
      }
      // limpiar huérfana
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    // 2) Intento ATOMICO de reclamar la sesión: solo si session_id sigue NULL
    const claim = db.prepare(
      'UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL'
    ).run(req.sessionID, user.username);

    if (claim.changes === 0) {
      // Alguien más la reclamó en microsegundos -> bloquear
      log('claim fallido (otro proceso la tomó) para', user.username);
      return res.redirect('/login.html?error=sesion_activa');
    }

    // 3) Crear la sesión actual
    req.session.usuario = user.username;

    log('login OK (claim atómico) para', user.username, 'sid:', req.sessionID);
    return res.redirect('/inicio.html');
  } catch (e) {
    console.error(e);
    return res.redirect('/login.html?error=interno');
  }
});

// ====== Middleware: exigir sesión y única por usuario ======
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

// ====== Endpoints protegidos ======
app.get('/inicio', requiereSesionUnica, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'inicio.html'));
});

app.get('/api/datos', requiereSesionUnica, (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario, sid: req.sessionID });
});

app.get('/verificar-sesion', (req, res) => {
  res.json({ activo: !!req.session?.usuario });
});

// ====== Logout ======
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

// ====== Admin: forzar logout ======
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
app.listen(PORT, () => console.log(`🚀 Servidor en http://0.0.0.0:${PORT} (claim atómico activo)`));




