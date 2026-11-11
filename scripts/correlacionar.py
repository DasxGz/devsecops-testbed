#!/usr/bin/env python3
"""Correlación de hallazgos (escenario C, sección 2.6.3).

Consolida los reportes de las tres herramientas en una estructura común y agrupa
los hallazgos según la vulnerabilidad del conjunto de referencia a la que
probablemente corresponden. Genera:
  reports/hallazgos_normalizados.json  -> todos los hallazgos homologados
  reports/correlacion.json             -> por cada Vxx, qué herramientas la señalaron

Uso: python3 scripts/correlacionar.py reports
"""
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from hallazgos import cargar  # noqa: E402

carpeta = sys.argv[1] if len(sys.argv) > 1 else "reports"
hall = cargar(carpeta)
with open(os.path.join(carpeta, "hallazgos_normalizados.json"), "w", encoding="utf-8") as f:
    json.dump(hall, f, ensure_ascii=False, indent=1)

corr = defaultdict(lambda: defaultdict(int))
sin_asignar = defaultdict(int)
for h in hall:
    if h["sugerencia"]:
        corr[h["sugerencia"]][h["herramienta"]] += 1
    else:
        sin_asignar[h["herramienta"]] += 1

resultado = {
    "por_vulnerabilidad": {v: dict(corr[v]) for v in sorted(corr)},
    "confirmadas_por_varias_herramientas": sorted(v for v in corr if len(corr[v]) > 1),
    "sin_asignar_por_herramienta": dict(sin_asignar),
    "nota": "Asignación automática sugerida; la clasificación VP/FP definitiva se hace en el triaje manual.",
}
with open(os.path.join(carpeta, "correlacion.json"), "w", encoding="utf-8") as f:
    json.dump(resultado, f, ensure_ascii=False, indent=2)

print(f"{len(hall)} hallazgos normalizados.")
for v, herr in resultado["por_vulnerabilidad"].items():
    print(f"  {v}: " + ", ".join(f"{k} ({n})" for k, n in herr.items()))
print("Confirmadas por más de una herramienta:", ", ".join(resultado["confirmadas_por_varias_herramientas"]) or "ninguna")
