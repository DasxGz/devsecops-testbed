// Pruebas unitarias del servicio de productos (sin dependencias externas).
const assert = require('assert');
const { formatearPrecio, filaHtml } = require('../src/util');

let ok = 0;
function prueba(nombre, fn) {
  fn();
  ok += 1;
  console.log('  ✓ ' + nombre);
}

prueba('formatearPrecio usa quetzales, dos decimales y separador de miles', () => {
  assert.strictEqual(formatearPrecio(6500), 'Q 6,500.00');
  assert.strictEqual(formatearPrecio(525.5), 'Q 525.50');
});
prueba('formatearPrecio maneja valores inválidos', () => {
  assert.strictEqual(formatearPrecio('abc'), 'Q 0.00');
  assert.strictEqual(formatearPrecio(-5), 'Q 0.00');
});
prueba('filaHtml genera una fila de tabla', () => {
  assert.strictEqual(filaHtml({ nombre: 'Mouse', precio: 180 }), '<tr><td>Mouse</td><td>Q 180.00</td></tr>');
});

console.log(`servicio-productos: ${ok} pruebas aprobadas`);
