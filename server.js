// server.js — flujo clásico: POST /login -> redirect /inicio
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

// Helmet SIN CSP para no bloquear recursos externos (gstatic, translate, etc.)
app.use(helmet({ contentSecurityPolicy: false }));

app.use(compression());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true })); // <-- formulario clásico
app.use(express.json());

// Sesión en memoria (simple)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax' }
}));

// Estáticos
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Healthcheck
app.get('/salud', (_req, res) => res.status(200).send('ok'));

// Raíz -> login
app.get('/', (_req, res) => res.redirect('/login'));

// Usuario demo
const DEMO_USER = process.env.DEMO_USER || 'prueba';
const DEMO_PASS = process.env.DEMO_PASS || '1234';

// Páginas
app.get('/login', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === DEMO_USER && password === DEMO_PASS) {
    req.session.user = { username };
    return res.redirect('/inicio');     // ← redirección clásica
  }
  // Volver a login con mensaje simple
  return res.status(401).send(`
    <meta charset="utf-8">
    <p>Credenciales inválidas. <a href="/login">Volver</a></p>
  `);
});

app.get('/inicio', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

// (Opcional) API JSON para saber quién soy, por si lo necesitas
app.get('/api/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'unauthorized' });
  res.json({ user: req.session.user });
});

// 404 sencillo
app.use((_req, res) => res.status(404).send('Página no encontrada'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Servidor escuchando en http://localhost:${PORT}`);
});
