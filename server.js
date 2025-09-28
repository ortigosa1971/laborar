// server.js — versión final para Railway
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

// Helmet SIN CSP (para no bloquear recursos externos)
app.use(helmet({ contentSecurityPolicy: false }));

// Middlewares básicos
app.use(compression());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true })); // formularios
app.use(express.json()); // APIs JSON

// Sesión en memoria (Railway muestra un warning, es normal; si quieres luego usamos SQLiteStore)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax' }
}));

// Archivos estáticos desde /public
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ✅ Healthcheck para Railway
app.get('/salud', (req, res) => res.status(200).send('ok'));

// Raíz -> login
app.get('/', (req, res) => res.redirect('/login'));

// Usuario demo
const DEMO_USER = process.env.DEMO_USER || 'prueba';
const DEMO_PASS = process.env.DEMO_PASS || '1234';

// Página de login
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login clásico: POST /login -> redirect /inicio
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === DEMO_USER && password === DEMO_PASS) {
    req.session.user = { username };
    return res.redirect('/inicio');
  }
  return res.status(401).send(`
    <meta charset="utf-8">
    <p>Credenciales inválidas. <a href="/login">Volver</a></p>
  `);
});

// Página de inicio (protegida)
app.get('/inicio', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

// API ejemplo
app.get('/api/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'unauthorized' });
  res.json({ user: req.session.user });
});

// 404 simple
app.use((req, res) => res.status(404).send('Página no encontrada'));

// ✅ Arranque correcto en Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Servidor escuchando en http://localhost:${PORT}`);
});
