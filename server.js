
// server.js
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const Database = require('better-sqlite3');
const util = require('util');

const app = express();
app.set('trust proxy', 1);

// ====== Sesiones (SQLite) ======
const store = new SQLiteStore({
  db: 'sessions.sqlite',
  dir: path.join(__dirname, 'db')
});

app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'clave-secreta-cámbiame',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8 // 8 horas
  }
}));

// Promesas para usar store.get/destroy cómodamente
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ====== DB (usuarios) ======
const db = new Database(path.join(__dirname, 'db', 'usuarios.db'));
db.pragma('journal_mode = wal');

// Asegura la tabla (si no existe)
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

// ====== Helper: autenticar (ajusta a tu lógica real) ======
function autenticar(username, password) {
  const row = db.prepare('SELECT username, password, session_id FROM users WHERE username = ?').get(username);
  if (!row) return null;
  if (row.password && password && row.password !== password) return null;
  return row; // { username, password, session_id }
}

// ====== Login: bloquear segundos inicios de sesión ======
app.post('/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    if (!usuario) return res.redirect('/login.html?error=credenciales');

    const user = autenticar(usuario, password);
    if (!user) return res.redirect('/login.html?error=credenciales');

    // ¿Tiene sesión registrada?
    if (user.session_id) {
      // ¿Sigue viva en el store?
      const sess = await storeGet(user.session_id);
      if (sess) {
        // Sesión ACTIVA: rechazamos este nuevo login
        return res.redirect('/login.html?error=sesion_activa');
      }
      // Si no existe en store (expirada/limpiada): liberamos el campo
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user.username);
    }

    // Crea sesión para este dispositivo
    req.session.usuario = user.username;

    // Guarda el session_id vivo en la tabla users
    db.prepare('UPDATE users SET session_id = ? WHERE username = ?').run(req.sessionID, user.username);

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

    const user = db.prepare('SELECT session_id FROM users WHERE username = ?').get(req.session.usuario);
    if (!user) return res.redirect('/login.html');

    if (!user.session_id) {
      req.session.destroy(() => res.redirect('/login.html?error=sesion_invalida'));
      return;
    }

    if (user.session_id !== req.sessionID) {
      req.session.destroy(() => res.redirect('/login.html?error=conectado_en_otra_maquina'));
      return;
    }

    const sess = await storeGet(user.session_id);
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
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

app.get('/api/datos', requiereSesionUnica, (req, res) => {
  res.json({ ok: true, usuario: req.session.usuario });
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
app.listen(PORT, () => console.log(`🚀 Servidor en http://localhost:${PORT}`));


