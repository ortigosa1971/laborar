// server.js — Express + sesiones, login y /inicio protegido (listo para Railway)
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import compression from 'compression';
import helmet from 'helmet';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ---------- Seguridad / básicos ----------
app.set('trust proxy', 1); // necesario en Railway para cookies 'secure'
app.use(helmet({
  contentSecurityPolicy: false, // desactiva CSP por simplicidad; ajústalo si lo necesitas
}));
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------- Sesión ----------
const SESSION_SECRET = process.env.SESSION_SECRET || 'cambia-esto-por-un-secreto-fuerte';
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // en Railway es true
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8, // 8h
  },
}));

// ---------- Archivos estáticos públicos ----------
// ¡NO pongas views/inicio.html aquí! Evita servir un index por defecto.
app.get('/inicio.html', (req, res) => res.redirect('/inicio'));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ---------- Guardia global para rutas protegidas ----------
function hasSession(req) {
  return !!(req.session && req.session.user);
}
app.use((req, res, next) => {
  const protegido = /^\/inicio(\/|$)/i.test(req.path) || (/^\/api\//i.test(req.path) && !/^\/api\/(login|salud)/i.test(req.path));
  if (protegido && !hasSession(req)) {
    // Si es API, responde 401; si no, redirige a /login
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthorized' });
    return res.redirect('/login');
  }
  next();
});

// ---------- Login / Logout ----------
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Usuario demo (sobrescribible por variables de entorno)
const DEMO_USER = process.env.DEMO_USER || 'prueba';
const DEMO_PASS = process.env.DEMO_PASS || '1234';

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === DEMO_USER && password === DEMO_PASS) {
    req.session.user = { username };
    return res.status(200).json({ ok: true, redirect: '/inicio' });
  }
  return res.status(401).json({ ok: false, error: 'Usuario o contraseña incorrectos' });
});
  return res.status(401).send('Usuario o contraseña incorrectos');
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// ---------- Rutas protegidas ----------
app.get('/inicio', (req, res) => {
  // Cabeceras anti-caché
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user });
});

// (Ejemplo) API de datos protegida
app.get('/api/datos', (req, res) => {
  res.json({ ok: true, msg: 'Solo con sesión', ts: Date.now() });
});

// ---------- Healthcheck Railway ----------
app.get('/salud', (req, res) => res.status(200).send('ok'));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`✅ Servidor escuchando en http://${HOST}:${PORT}`);
  console.log(`   DEMO_USER=${DEMO_USER} DEMO_PASS=${DEMO_PASS}`);
});



















