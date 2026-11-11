// Pruebas unitarias del servicio de usuarios (sin dependencias externas).
const assert = require('assert');
const { perfilPublico, validarRegistro } = require('../src/util');

let ok = 0;
function prueba(nombre, fn) {
  fn();
  ok += 1;
  console.log('  ✓ ' + nombre);
}

prueba('perfilPublico no expone la contraseña', () => {
  const p = perfilPublico({ _id: 'abc', nombre: 'Ana', email: 'a@b.c', password: 'x', rol: 'cliente' });
  assert.deepStrictEqual(p, { id: 'abc', nombre: 'Ana', email: 'a@b.c', rol: 'cliente' });
});
prueba('validarRegistro acepta datos correctos', () => {
  assert.strictEqual(validarRegistro({ nombre: 'Ana', email: 'ana@x.com', password: '123456' }), null);
});
prueba('validarRegistro rechaza email inválido', () => {
  assert.strictEqual(validarRegistro({ nombre: 'Ana', email: 'ana', password: '123456' }), 'Email inválido');
});
prueba('validarRegistro rechaza contraseña corta', () => {
  assert.ok(validarRegistro({ nombre: 'Ana', email: 'ana@x.com', password: '1' }));
});

console.log(`servicio-usuarios: ${ok} pruebas aprobadas`);
