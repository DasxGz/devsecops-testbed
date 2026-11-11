// Funciones puras del servicio de usuarios (cubiertas por las pruebas unitarias).

function perfilPublico(u) {
  return { id: String(u._id), nombre: u.nombre, email: u.email, rol: u.rol };
}

function validarRegistro(body) {
  if (!body || typeof body !== 'object') return 'Cuerpo inválido';
  if (!body.nombre || String(body.nombre).trim().length < 2) return 'Nombre requerido';
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(body.email || ''))) return 'Email inválido';
  if (String(body.password || '').length < 6) return 'La contraseña debe tener al menos 6 caracteres';
  return null;
}

module.exports = { perfilPublico, validarRegistro };
