// server.js — servidor mínimo con redirección raíz y sin CSP para evitar bloqueos
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

// Helmet SIN contentSecurityPolicy (para evitar errores CSP)
app.use(helmet({ contentSecurityPolicy: false }));

// Otros middlewares
app.use(compression());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sesiones en memoria
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax' }
}));

// Archivos estáticos
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Healthcheck para Railway
app.get('/salud', (req, res) => res.status(200).send('ok'));

// 👇 NUEVO: redirigir raíz al login
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Usuario demo
const DEMO_USER = process.env.DEMO_USER || 'prueba';
const DEMO_PASS = process.env.DEMO_PASS || '1234';

// API login → SIEMPRE responde JSON
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === DEMO_USER && password === DEMO_PASS) {
    req.session.user = { username };
    return res.json({ ok: true, redirect: '/inicio' });
  }
  return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });
});

// API usuario actual
app.get('/api/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'unauthorized' });
  res.json({ user: req.session.user });
});

// Página de login
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Página de inicio (protegida)
app.get('/inicio', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

// 404 amigable (opcional)
app.use((req, res) => {
  res.status(404).send('Página no encontrada');
});

// Arrancar
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Servidor escuchando en http://localhost:${PORT}`);
});
