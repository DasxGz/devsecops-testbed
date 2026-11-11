# Banco de pruebas DevSecOps (SAST / SCA / DAST) — Tesis FIUSAC

Este es el laboratorio del trabajo de graduación *"Evaluación del impacto en la latencia de despliegue y
la eficacia en la detección temprana de vulnerabilidades mediante la integración de herramientas
DevSecOps (SAST/DAST) en canalizaciones CI/CD para arquitecturas de microservicios"*.

> **Vulnerable a propósito.** No lo despliegues en un servidor público.

La implementación corresponde al capítulo 2 de la tesis (secciones 2.5 a 2.10).

| Carpeta | Contenido |
|---|---|
| `api-gateway/` | Gateway Express, puerto 8080 (V05, V06, V07) y especificación OpenAPI |
| `servicio-usuarios/` | Registro, login con JWT y perfiles (V01, V02, V08, V09) + pruebas unitarias |
| `servicio-productos/` | Catálogo, búsqueda y exportación (V03, V04, V08) + pruebas unitarias |
| `docker-compose.yml` | 5 contenedores; solo el gateway se expone |
| `.github/workflows/pipeline.yml` | Workflow único con el parámetro `escenario` (A, B o C) |
| `.github/workflows/preparar-instantanea.yml` | Congela las reglas de Semgrep y la base de Trivy (se ejecuta una vez) |
| `scripts/experimento.py` | Bloques aleatorizados (semilla 2026), bitácora y repetición de fallas de infraestructura |
| `scripts/recolectar.py` | Tiempos por etapa desde la API de GitHub y descarga de artefactos |
| `scripts/compuerta.py`, `correlacionar.py`, `hallazgos.py` | Homologación de severidad, compuerta y correlación |
| `docs/CONJUNTO_REFERENCIA.md` | Tabla 9 (V01–V12) y línea base de dependencias |

Versiones fijas: Semgrep 1.170.0, Trivy 0.69.3 y ZAP 2.17.0. Trivy queda en 0.69.3 porque las versiones
0.69.4 a 0.69.6 fueron publicadas maliciosamente en marzo de 2026 (GHSA-69fq-xp46-6x23).

## Paso a paso

Requisitos: Git, Python 3 y GitHub CLI (`gh auth login`). En Windows, usa Git Bash. **No necesitas Docker
en tu computadora**, porque todo corre en GitHub Actions.

```bash
# 1. Crear el repositorio (público: minutos de Actions ilimitados)
git init -b main && git add . && git commit -m "Banco de pruebas v1.0"
gh repo create devsecops-testbed --public --source . --push

# 2. Congelar las reglas de Semgrep y la base de Trivy (una sola vez, ~5 min)
gh workflow run preparar-instantanea.yml
gh run watch $(gh run list --workflow preparar-instantanea.yml --limit 1 --json databaseId -q '.[0].databaseId')
git pull

# 3. Congelar la versión del código en una etiqueta
git tag v1.0 && git push origin v1.0

# 4. Piloto: 3 bloques (9 ejecuciones)
python3 scripts/experimento.py --piloto
python3 scripts/recolectar.py --piloto

# 5. Experimento oficial: 30 bloques (90 ejecuciones). Puede quedar corriendo de noche.
python3 scripts/experimento.py
python3 scripts/recolectar.py
```

Si el script se interrumpe, se vuelve a ejecutar el mismo comando y continúa donde quedó. Si hay que
corregir algo después del piloto, se hace el commit, se mueve la etiqueta
(`git tag -f v1.0 && git push -f origin v1.0`) y se repite el piloto **antes** del experimento oficial.

## Problemas comunes

- **GitHub bloquea el push por "secret detected"**: los secretos son ficticios y están puestos a propósito.
  Usa el enlace del mensaje para permitirlo ("It's used in tests").
- **Falla la descarga de una imagen** (`manifest unknown`): avísame qué etiqueta falló y la cambiamos en los
  dos YAML **antes** de etiquetar v1.0.
