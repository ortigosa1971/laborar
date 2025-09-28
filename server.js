// server.js — servidor mínimo, JSON seguro y healthcheck
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

// Middlewares básicos
app.use(helmet());
app.use(compression());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sesiones en memoria (simple para empezar)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { sameSite: 'lax' }
}));

// Estáticos
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Healthcheck para Railway
app.get('/salud', (req, res) => res.status(200).send('ok'));

// Demo de usuario
const DEMO_USER = process.env.DEMO_USER || 'prueba';
const DEMO_PASS = process.env.DEMO_PASS || '1234';

// API: login JSON
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === DEMO_USER && password === DEMO_PASS) {
    req.session.user = { username };
    return res.status(200).json({ ok: true, redirect: '/inicio' });
  }
  return res.status(401).json({ ok: false, error: 'Credenciales inválidas' });
});

app.get('/api/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'unauthorized' });
  res.json({ user: req.session.user });
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/inicio', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'inicio.html'));
});

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`✅ Servidor escuchando en http://${HOST}:${PORT}`);
});
