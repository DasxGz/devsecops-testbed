/*
 * API GATEWAY — Banco de pruebas vulnerable A PROPÓSITO (tesis DevSecOps, FIUSAC).
 * NO desplegar en producción. Las etiquetas [Vxx] corresponden a la Tabla 9
 * (conjunto de referencia) y a docs/CONJUNTO_REFERENCIA.md.
 */
const express = require('express');
const cors = require('cors');
const proxy = require('http-proxy-middleware');
const path = require('path');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 8080;
const USUARIOS_URL = process.env.USUARIOS_URL || 'http://servicio-usuarios:3001';
const PRODUCTOS_URL = process.env.PRODUCTOS_URL || 'http://servicio-productos:3002';

// [V06] No se configuran cabeceras de seguridad HTTP (sin helmet): faltan
// Content-Security-Policy, X-Frame-Options y X-Content-Type-Options, y Express
// deja visible la cabecera X-Powered-By.

// [V07] Política CORS permisiva: refleja cualquier origen y permite credenciales.
app.use(cors({ origin: true, credentials: true }));

// Verificación de salud: el gateway responde 200 solo si ambos servicios responden.
function ping(url) {
  return new Promise((resolve) => {
    http.get(url + '/health', (r) => resolve(r.statusCode === 200)).on('error', () => resolve(false));
  });
}
app.get('/health', async (req, res) => {
  const [u, p] = await Promise.all([ping(USUARIOS_URL), ping(PRODUCTOS_URL)]);
  res.status(u && p ? 200 : 503).json({ gateway: 'ok', usuarios: u, productos: p });
});

// [V05] Ruta de depuración sin autenticación que expone las variables de entorno.
app.get('/debug', (req, res) => {
  res.json({ env: process.env, versiones: process.versions, uptime: process.uptime() });
});

// Especificación OpenAPI de todas las rutas (la usa OWASP ZAP en el escenario C).
app.get('/openapi.json', (req, res) => res.sendFile(path.join(__dirname, 'openapi.json')));

// Enrutamiento hacia los servicios de negocio.
app.use('/api/usuarios', proxy({ target: USUARIOS_URL, changeOrigin: true, pathRewrite: { '^/api/usuarios': '' } }));
app.use('/api/productos', proxy({ target: PRODUCTOS_URL, changeOrigin: true, pathRewrite: { '^/api/productos': '' } }));

app.listen(PORT, () => console.log(`api-gateway escuchando en el puerto ${PORT}`));
