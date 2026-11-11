/*
 * SERVICIO DE USUARIOS — vulnerable A PROPÓSITO (tesis DevSecOps, FIUSAC).
 * Las etiquetas [Vxx] corresponden a la Tabla 9 y a docs/CONJUNTO_REFERENCIA.md.
 */
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { perfilPublico, validarRegistro } = require('./util');

// [V01] Secreto de firma JWT y credenciales de la base de datos escritos en el código.
const JWT_SECRET = 'jwt_s3cr3t0_t3s1s_fiusac_2026';
const MONGO_URI =
  process.env.MONGO_URI || 'mongodb://admin:Usuarios2026!@mongo-usuarios:27017/usuarios?authSource=admin';

const app = express();
app.use(express.json());

const Usuario = mongoose.model(
  'Usuario',
  new mongoose.Schema({ nombre: String, email: String, password: String, rol: String })
);

app.get('/health', (req, res) => {
  const ok = mongoose.connection.readyState === 1;
  res.status(ok ? 200 : 503).json({ servicio: 'usuarios', db: ok });
});

app.post('/registro', async (req, res, next) => {
  try {
    const error = validarRegistro(req.body);
    if (error) return res.status(400).json({ error });
    const u = await Usuario.create({ ...req.body, rol: 'cliente' });
    res.status(201).json(perfilPublico(u));
  } catch (err) {
    next(err);
  }
});

// [V02] Inyección NoSQL: el cuerpo se pasa sin validar a la consulta.
// Ataque: {"email":"admin@testbed.local","password":{"$ne":null}}
app.post('/login', async (req, res, next) => {
  try {
    const u = await Usuario.findOne({ email: req.body.email, password: req.body.password });
    if (!u) return res.status(401).json({ error: 'Credenciales inválidas' });
    const token = jwt.sign({ id: u._id, rol: u.rol }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    next(err);
  }
});

function autenticar(req, res, next) {
  const h = req.headers.authorization || '';
  try {
    req.usuario = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// [V09] Control de acceso roto (IDOR): se verifica que el usuario esté autenticado,
// pero no que el perfil solicitado sea el suyo.
app.get('/perfil/:id', autenticar, async (req, res, next) => {
  try {
    const u = await Usuario.findById(req.params.id);
    if (!u) return res.status(404).json({ error: 'No encontrado' });
    res.json(perfilPublico(u));
  } catch (err) {
    next(err);
  }
});

// [V08] Manejador de errores que expone la traza de pila al cliente.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

async function sembrar() {
  if ((await Usuario.countDocuments()) > 0) return;
  await Usuario.create([
    { nombre: 'Administrador', email: 'admin@testbed.local', password: 'Admin2026', rol: 'admin' },
    { nombre: 'Ana López', email: 'ana@testbed.local', password: 'Ana2026', rol: 'cliente' },
    { nombre: 'Carlos Pérez', email: 'carlos@testbed.local', password: 'Carlos2026', rol: 'cliente' },
  ]);
  console.log('Datos sintéticos de usuarios cargados');
}

mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(sembrar)
  .catch((e) => console.error('Error de conexión a MongoDB:', e.message));

app.listen(process.env.PORT || 3001, () => console.log('servicio-usuarios escuchando'));
