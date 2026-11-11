#!/usr/bin/env python3
"""Compuerta de seguridad (sección 2.6.4).

Homologa la severidad de los tres reportes y termina con código 1 si existe al
menos un hallazgo de severidad Alta o Crítica (equivalente a CVSS >= 7.0).
Escribe la tabla de conteos en el resumen de la ejecución de GitHub Actions.

Uso: python3 scripts/compuerta.py reports
"""
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from hallazgos import NIVELES, cargar  # noqa: E402

carpeta = sys.argv[1] if len(sys.argv) > 1 else "reports"
hall = cargar(carpeta)

por_herr = defaultdict(Counter)
for h in hall:
    por_herr[h["herramienta"]][h["severidad"]] += 1
total = Counter(h["severidad"] for h in hall)

filas = ["| Herramienta | " + " | ".join(NIVELES) + " |", "|---|" + "---:|" * len(NIVELES)]
for herr in ("Semgrep", "Trivy", "OWASP ZAP"):
    if herr in por_herr:
        filas.append(f"| {herr} | " + " | ".join(str(por_herr[herr][n]) for n in NIVELES) + " |")
filas.append("| **Total** | " + " | ".join(f"**{total[n]}**" for n in NIVELES) + " |")
tabla = "\n".join(filas)
print(tabla)

bloq = total["Crítica"] + total["Alta"]
veredicto = (f"❌ COMPUERTA FALLIDA: {bloq} hallazgos de severidad Alta o Crítica."
             if bloq else "✅ Compuerta aprobada: sin hallazgos de severidad Alta o Crítica.")
print("\n" + veredicto)

if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
        f.write("## Compuerta de seguridad\n\n" + tabla + "\n\n" + veredicto + "\n")

sys.exit(1 if bloq else 0)
