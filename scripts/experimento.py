#!/usr/bin/env python3
"""Ejecución del experimento en bloques aleatorizados (sección 2.7).

Cada bloque contiene una ejecución de cada escenario (A, B y C) en orden
aleatorio. El orden se genera con una semilla fija y se guarda en
data/plan.csv para que sea reproducible. Las ejecuciones son secuenciales: se
lanza una y se espera a que termine antes de lanzar la siguiente.

Una ejecución es VÁLIDA si terminó con éxito o si el único paso que falló fue
la compuerta de seguridad, que en B y C es el resultado esperado. Cualquier otra
falla se registra como "falla_infraestructura" en la bitácora y la ejecución se
repite, hasta 2 veces.

Requisitos: GitHub CLI (gh) autenticado y estar dentro del repositorio.
Uso:
  python3 scripts/experimento.py --piloto              # 3 bloques de prueba (P1-P3)
  python3 scripts/experimento.py                       # 30 bloques oficiales
  python3 scripts/experimento.py --ref v1.0 --semilla 2026 --bloques 30
Si se interrumpe, se vuelve a ejecutar el mismo comando y continúa donde quedó.
"""
import argparse
import csv
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timedelta

WF = "pipeline.yml"
ESCENARIOS = ["A", "B", "C"]
PASO_COMPUERTA = "12 Compuerta de seguridad"


def gh(*args):
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def generar_plan(semilla, n, piloto):
    rnd = random.Random(semilla)
    plan = []
    for b in range(1, n + 1):
        orden = ESCENARIOS[:]
        rnd.shuffle(orden)
        for k, esc in enumerate(orden, 1):
            plan.append({"bloque": f"P{b}" if piloto else str(b), "orden": str(k), "escenario": esc})
    return plan


def leer_bitacora(ruta):
    if not os.path.exists(ruta):
        return []
    with open(ruta, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def anotar(ruta, fila):
    nuevo = not os.path.exists(ruta)
    with open(ruta, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(fila.keys()))
        if nuevo:
            w.writeheader()
        w.writerow(fila)


def lanzar_y_esperar(ref, p):
    titulo = f"Bloque {p['bloque']} · orden {p['orden']} · escenario {p['escenario']}"
    inicio = (datetime.utcnow() - timedelta(seconds=60)).isoformat(timespec="seconds") + "Z"
    gh("workflow", "run", WF, "--ref", ref,
       "-f", f"escenario={p['escenario']}", "-f", f"bloque={p['bloque']}", "-f", f"orden={p['orden']}")
    run_id = None
    for _ in range(40):
        time.sleep(5)
        runs = json.loads(gh("run", "list", "--workflow", WF, "--limit", "10",
                             "--json", "databaseId,displayTitle,createdAt"))
        cand = [r for r in runs if r["displayTitle"] == titulo and r["createdAt"] >= inicio]
        if cand:
            run_id = str(cand[0]["databaseId"])
            break
    if not run_id:
        raise RuntimeError(f"No se encontró la ejecución «{titulo}»")
    subprocess.run(["gh", "run", "watch", run_id, "--interval", "15"], capture_output=True)
    info = json.loads(gh("run", "view", run_id, "--json", "conclusion,jobs"))
    fallidos = [s["name"] for j in info["jobs"] for s in j.get("steps", []) if s.get("conclusion") == "failure"]
    if info["conclusion"] == "success":
        estado = "valida"
    elif fallidos == [PASO_COMPUERTA]:
        estado = "valida"  # la compuerta bloqueó: resultado esperado en B y C
    else:
        estado = "falla_infraestructura"
    return run_id, info["conclusion"], estado, ";".join(fallidos)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--piloto", action="store_true")
    ap.add_argument("--semilla", type=int, default=None, help="Por defecto 2026 (oficial) y 1 (piloto)")
    ap.add_argument("--bloques", type=int, default=None)
    ap.add_argument("--ref", default="v1.0", help="Etiqueta de Git congelada del banco de pruebas")
    a = ap.parse_args()

    n = a.bloques or (3 if a.piloto else 30)
    if a.semilla is None:
        a.semilla = 1 if a.piloto else 2026
    os.makedirs("data", exist_ok=True)
    sufijo = "_piloto" if a.piloto else ""
    ruta_plan, ruta_bit = f"data/plan{sufijo}.csv", f"data/bitacora{sufijo}.csv"

    plan = generar_plan(a.semilla, n, a.piloto)
    with open(ruta_plan, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["bloque", "orden", "escenario"])
        w.writeheader()
        w.writerows(plan)
    print(f"Plan: {len(plan)} ejecuciones, semilla {a.semilla}, ref {a.ref} -> {ruta_plan}")

    hechas = {(r["bloque"], r["escenario"]) for r in leer_bitacora(ruta_bit) if r["estado"] == "valida"}
    for i, p in enumerate(plan, 1):
        if (p["bloque"], p["escenario"]) in hechas:
            continue
        for intento in range(1, 4):
            hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{i}/{len(plan)}] bloque {p['bloque']} orden {p['orden']} escenario {p['escenario']} "
                  f"(intento {intento}) {hora}", flush=True)
            try:
                run_id, concl, estado, fallidos = lanzar_y_esperar(a.ref, p)
            except Exception as e:  # noqa: BLE001
                run_id, concl, estado, fallidos = "", "error", "falla_infraestructura", str(e)[:200]
            anotar(ruta_bit, {**p, "intento": intento, "run_id": run_id, "conclusion": concl,
                              "estado": estado, "pasos_fallidos": fallidos, "hora_local": hora,
                              "semilla": a.semilla, "ref": a.ref})
            print(f"    -> run {run_id}: {concl} ({estado})", flush=True)
            if estado == "valida":
                break
            time.sleep(30)
        else:
            print("Tres fallas de infraestructura seguidas; se detiene el experimento.", file=sys.stderr)
            sys.exit(1)
        time.sleep(10)
    print(f"Experimento completo. Bitácora: {ruta_bit}. Siguiente paso: python3 scripts/recolectar.py"
          + (" --piloto" if a.piloto else ""))


if __name__ == "__main__":
    main()
