"""Normalización de los reportes de Semgrep, Trivy y OWASP ZAP.

Lo usan compuerta.py, correlacionar.py y los scripts de análisis.
- Homologa la severidad de cada herramienta a una escala común (Tabla 11).
- Asigna la categoría del OWASP Top 10:2025.
- Elimina duplicados con los criterios de la sección 2.8.2.
- Propone el identificador del conjunto de referencia (V01-V12) que probablemente
  corresponde a cada hallazgo. Es solo una SUGERENCIA para el triaje: la
  clasificación definitiva (VP/FP) se hace manualmente.
"""
import glob
import json
import os
from urllib.parse import urlsplit

NIVELES = ["Crítica", "Alta", "Media", "Baja", "Informativa"]

SEV_SEMGREP = {"ERROR": "Alta", "WARNING": "Media", "INFO": "Baja"}
SEV_TRIVY = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja", "UNKNOWN": "Informativa"}
SEV_ZAP = {"3": "Alta", "2": "Media", "1": "Baja", "0": "Informativa"}

ZAP_V = {
    # V06 cabeceras de seguridad ausentes / X-Powered-By
    "10038": "V06", "10020": "V06", "10021": "V06", "10037": "V06", "10035": "V06", "10063": "V06",
    # V04 XSS
    "40012": "V04", "40014": "V04", "40026": "V04",
    # V03 inyección de comandos
    "90020": "V03",
    # V02 inyección NoSQL / SQL
    "40033": "V02", "40018": "V02", "40019": "V02", "40020": "V02", "40021": "V02", "40022": "V02",
    # V08 divulgación de errores
    "90022": "V08", "10023": "V08",
    # V07 CORS
    "40040": "V07", "10098": "V07",
}


# Categoría OWASP Top 10:2025 de cada vulnerabilidad del conjunto de referencia (Tabla 9)
OWASP_V = {"V01": "A04", "V02": "A05", "V03": "A05", "V04": "A05", "V05": "A02", "V06": "A02",
           "V07": "A02", "V08": "A10", "V09": "A01", "V10": "A03", "V11": "A03", "V12": "A02"}
# Categoría por tipo de análisis cuando el hallazgo no corresponde a ninguna Vxx
OWASP_TIPO = {"SCA": "A03", "Configuración": "A02", "Secretos": "A04"}


def categoria_owasp(h):
    if h.get("sugerencia"):
        return OWASP_V[h["sugerencia"]]
    return OWASP_TIPO.get(h["tipo"], "Por clasificar en el triaje")


def _leer(ruta):
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)


def _sugerir_semgrep(regla, ruta):
    r, p = regla.lower(), ruta.lower()
    if "dockerfile" in p or "dockerfile" in r:
        return "V12" if ("user" in r or "root" in r) else None
    if "cors" in r:
        return "V07"
    if "nosql" in r or ("mongo" in r and "inject" in r):
        return "V02"
    if "child_process" in r or "child-process" in r or "exec" in r or "command" in r or "shell" in r:
        return "V03"
    if "xss" in r or "html" in r or "response-write" in r or "res-send" in r or "raw" in r:
        return "V04"
    if any(k in r for k in ("secret", "hardcoded", "hard-coded", "credential", "password", "jwt", "mongo", "token")):
        return "V01"
    if "debug" in r or "env" in r:
        return "V05"
    if "stack" in r or "error" in r:
        return "V08"
    return None


def semgrep(ruta):
    for r in _leer(ruta).get("results", []):
        regla, archivo = r.get("check_id", ""), r.get("path", "")
        yield {
            "herramienta": "Semgrep", "tipo": "SAST", "regla": regla,
            "severidad_original": r.get("extra", {}).get("severity", "INFO"),
            "severidad": SEV_SEMGREP.get(r.get("extra", {}).get("severity"), "Baja"),
            "ubicacion": f"{archivo}:{r.get('start', {}).get('line')}",
            "descripcion": (r.get("extra", {}).get("message") or "")[:250],
            "sugerencia": _sugerir_semgrep(regla, archivo),
        }


def trivy(ruta):
    data = _leer(ruta)
    reporte = os.path.basename(ruta).replace("trivy-", "").replace(".json", "")  # imagen-<servicio>, config, secretos
    for res in data.get("Results", []) or []:
        clase, objetivo = res.get("Class", ""), res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            yield {
                "herramienta": "Trivy", "tipo": "SCA", "regla": v.get("VulnerabilityID"),
                "severidad_original": v.get("Severity"), "severidad": SEV_TRIVY.get(v.get("Severity"), "Informativa"),
                "ubicacion": f"{reporte} | {objetivo} | {v.get('PkgName')}@{v.get('InstalledVersion')}",
                "descripcion": (v.get("Title") or "")[:250],
                "sugerencia": "V11" if clase == "os-pkgs" else "V10",
            }
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            yield {
                "herramienta": "Trivy", "tipo": "Configuración", "regla": m.get("ID"),
                "severidad_original": m.get("Severity"), "severidad": SEV_TRIVY.get(m.get("Severity"), "Informativa"),
                "ubicacion": objetivo, "descripcion": (m.get("Title") or "")[:250],
                "sugerencia": "V12" if m.get("ID") in ("DS002", "DS-0002") else None,
            }
        for s in res.get("Secrets", []) or []:
            yield {
                "herramienta": "Trivy", "tipo": "Secretos", "regla": s.get("RuleID"),
                "severidad_original": s.get("Severity"), "severidad": SEV_TRIVY.get(s.get("Severity"), "Informativa"),
                "ubicacion": f"{objetivo}:{s.get('StartLine')}", "descripcion": (s.get("Title") or "")[:250],
                "sugerencia": "V01",
            }


def zap(ruta):
    for site in _leer(ruta).get("site", []) or []:
        for a in site.get("alerts", []) or []:
            pid = str(a.get("pluginid"))
            rutas = sorted({urlsplit(i.get("uri", "")).path or "/" for i in a.get("instances", [])}) or ["/"]
            for r in rutas:
                sug = "V05" if r.startswith("/debug") and pid not in ZAP_V else ZAP_V.get(pid)
                yield {
                    "herramienta": "OWASP ZAP", "tipo": "DAST", "regla": f"{pid} {a.get('alert', '')}",
                    "severidad_original": a.get("riskdesc", ""),
                    "severidad": SEV_ZAP.get(str(a.get("riskcode")), "Informativa"),
                    "ubicacion": r, "descripcion": a.get("alert", ""),
                    "sugerencia": sug,
                }


def clave(h):
    """Criterio de duplicado (sección 2.8.2):
    Semgrep: misma regla, archivo y línea. Trivy: mismo CVE (o regla) y paquete en la
    misma imagen u objetivo. OWASP ZAP: misma alerta y ruta."""
    return (h["herramienta"], h["regla"], h["ubicacion"])


def deduplicar(hallazgos):
    vistos, out = set(), []
    for h in hallazgos:
        k = clave(h)
        if k not in vistos:
            vistos.add(k)
            out.append(h)
    return out


def cargar(carpeta, dedup=True):
    """Devuelve los hallazgos normalizados (y sin duplicados) de una carpeta de reportes."""
    out = []
    ruta = os.path.join(carpeta, "semgrep.json")
    if os.path.exists(ruta):
        out += list(semgrep(ruta))
    for ruta in sorted(glob.glob(os.path.join(carpeta, "trivy-*.json"))):
        out += list(trivy(ruta))
    ruta = os.path.join(carpeta, "zap.json")
    if os.path.exists(ruta):
        out += list(zap(ruta))
    for h in out:
        h["owasp"] = categoria_owasp(h)
    return deduplicar(out) if dedup else out
