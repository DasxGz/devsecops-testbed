/*
 * SERVICIO DE PRODUCTOS — vulnerable A PROPÓSITO (tesis DevSecOps, FIUSAC).
 * Las etiquetas [Vxx] corresponden a la Tabla 9 y a docs/CONJUNTO_REFERENCIA.md.
 */
const express = require('express');
const mongoose = require('mongoose');
const { exec } = require('child_process');
const { formatearPrecio, filaHtml } = require('./util');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://mongo-productos:27017/productos';

const app = express();
app.use(express.json());

const Producto = mongoose.model(
  'Producto',
  new mongoose.Schema({ nombre: String, categoria: String, precio: Number, stock: Number })
);

app.get('/health', (req, res) => {
  const ok = mongoose.connection.readyState === 1;
  res.status(ok ? 200 : 503).json({ servicio: 'productos', db: ok });
});

app.get('/', async (req, res, next) => {
  try {
    res.json(await Producto.find().lean());
  } catch (err) {
    next(err);
  }
});

// [V04] XSS reflejado: el término de búsqueda se devuelve en HTML sin escapar.
app.get('/buscar', async (req, res, next) => {
  try {
    const q = req.query.q || '';
    const lista = await Producto.find({ nombre: { $regex: String(q).replace(/[^\w\s]/g, ''), $options: 'i' } }).lean();
    res.send(
      '<html><body><h2>Resultados para: ' + q + '</h2><table>' + lista.map(filaHtml).join('') + '</table></body></html>'
    );
  } catch (err) {
    next(err);
  }
});

// [V03] Inyección de comandos: el parámetro "formato" se concatena en child_process.exec.
// Ataque: /exportar?formato=csv;id
app.get('/exportar', (req, res) => {
  const formato = req.query.formato || 'csv';
  exec('echo "Exportando catálogo en formato ' + formato + '" && date', (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: err.message, stack: err.stack, stderr }); // [V08]
    res.type('text/plain').send(stdout);
  });
});

app.get('/:id', async (req, res, next) => {
  try {
    const p = await Producto.findById(req.params.id).lean();
    if (!p) return res.status(404).json({ error: 'No encontrado' });
    res.json({ ...p, precioTexto: formatearPrecio(p.precio) });
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
  if ((await Producto.countDocuments()) > 0) return;
  await Producto.create([
    { nombre: 'Laptop 14 pulgadas', categoria: 'computo', precio: 6500, stock: 12 },
    { nombre: 'Monitor 24 pulgadas', categoria: 'computo', precio: 1450, stock: 30 },
    { nombre: 'Teclado mecánico', categoria: 'accesorios', precio: 525.5, stock: 50 },
    { nombre: 'Mouse inalámbrico', categoria: 'accesorios', precio: 180, stock: 80 },
  ]);
  console.log('Datos sintéticos de productos cargados');
}

mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(sembrar)
  .catch((e) => console.error('Error de conexión a MongoDB:', e.message));

app.listen(process.env.PORT || 3002, () => console.log('servicio-productos escuchando'));
