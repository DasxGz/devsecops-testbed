// Funciones puras del servicio de productos (cubiertas por las pruebas unitarias).

function formatearPrecio(valor) {
  const n = Number(valor);
  if (!Number.isFinite(n) || n < 0) return 'Q 0.00';
  return 'Q ' + n.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function filaHtml(p) {
  return '<tr><td>' + p.nombre + '</td><td>' + formatearPrecio(p.precio) + '</td></tr>';
}

module.exports = { formatearPrecio, filaHtml };
