#!/usr/bin/env python3
"""Recolección de tiempos y artefactos (sección 2.8).

Para cada ejecución válida de la bitácora consulta la API REST de GitHub
Actions (endpoints de ejecuciones y de trabajos) y genera:
  data/tiempos.csv          -> una fila por ejecución y una columna por etapa (segundos)
  data/artefactos/<esc>-b<bloque>/  -> reportes JSON/HTML y metadatos de la ejecución

Uso: python3 scripts/recolectar.py [--piloto]
"""
import csv
import json
import os
import subprocess
import sys
from datetime import datetime


def gh_api(path):
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def seg(a, b):
    a, b = ts(a), ts(b)
    return round((b - a).total_seconds()) if a and b else ""


def main():
    piloto = "--piloto" in sys.argv
    suf = "_piloto" if piloto else ""
    with open(f"data/bitacora{suf}.csv", encoding="utf-8") as f:
        validas = [r for r in csv.DictReader(f) if r["estado"] == "valida"]
    repo = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
                          check=True, capture_output=True, text=True).stdout.strip()

    filas, etapas = [], []
    for r in validas:
        run = gh_api(f"repos/{repo}/actions/runs/{r['run_id']}")
        jobs = gh_api(f"repos/{repo}/actions/runs/{r['run_id']}/jobs")["jobs"]
        inicio = min(j["started_at"] for j in jobs)
        fin = max(j["completed_at"] for j in jobs)
        fila = {
            "escenario": r["escenario"], "bloque": r["bloque"], "orden": r["orden"], "run_id": r["run_id"],
            "conclusion": run["conclusion"],
            "tiempo_total_s": seg(inicio, fin),          # variable dependiente
            "tiempo_cola_s": seg(run["created_at"], inicio),  # variable de control
            "inicio_utc": inicio,
        }
        for j in jobs:
            for s in j.get("steps", []):
                if s["name"][:2].isdigit():
                    d = seg(s.get("started_at"), s.get("completed_at")) if s.get("conclusion") != "skipped" else 0
                    fila[s["name"]] = d
                    if s["name"] not in etapas:
                        etapas.append(s["name"])
        destino = f"data/artefactos{suf}/{r['escenario']}-b{r['bloque']}"
        if not os.path.isdir(destino):
            subprocess.run(["gh", "run", "download", r["run_id"], "-D", destino], capture_output=True)
        meta = next((os.path.join(dp, "metadatos.json") for dp, _, fs in os.walk(destino) if "metadatos.json" in fs), None)
        if meta:
            m = json.load(open(meta, encoding="utf-8"))
            fila["runner_image_version"] = m.get("runner_image_version", "")
        filas.append(fila)
        print(f"  {r['escenario']} bloque {r['bloque']}: {fila['tiempo_total_s']} s")

    etapas.sort()
    campos = ["escenario", "bloque", "orden", "run_id", "conclusion", "tiempo_total_s", "tiempo_cola_s",
              "inicio_utc", "runner_image_version"] + etapas
    with open(f"data/tiempos{suf}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos, extrasaction="ignore")
        w.writeheader()
        w.writerows(filas)
    print(f"\n{len(filas)} ejecuciones -> data/tiempos{suf}.csv")
    for e in "ABC":
        v = [x["tiempo_total_s"] for x in filas if x["escenario"] == e and x["tiempo_total_s"] != ""]
        if v:
            print(f"  Escenario {e}: n={len(v)}, media={sum(v)/len(v):.1f} s, min={min(v)}, max={max(v)}")


if __name__ == "__main__":
    main()
