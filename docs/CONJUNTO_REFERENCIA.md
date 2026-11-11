# Conjunto de referencia (*ground truth*) — Tabla 9 del capítulo 2

Las etiquetas `[Vxx]` del código fuente corresponden a esta tabla. Este conjunto se definió
**antes** de ejecutar cualquier escaneo (sección 2.5.2).

## Nivel de aplicación (cada vulnerabilidad cuenta como una unidad)

| ID | Vulnerabilidad sembrada | Ubicación exacta | OWASP 2025 | Detección esperada |
|---|---|---|---|---|
| V01 | Secreto JWT y credenciales de MongoDB en el código | `servicio-usuarios/src/server.js` (constantes `JWT_SECRET`, `MONGO_URI`) | A04 | Semgrep, Trivy (secretos) |
| V02 | Inyección NoSQL en el inicio de sesión | `POST /api/usuarios/login` | A05 | Semgrep, OWASP ZAP |
| V03 | Inyección de comandos con `child_process.exec` | `GET /api/productos/exportar?formato=` | A05 | Semgrep, OWASP ZAP |
| V04 | XSS reflejado en la búsqueda | `GET /api/productos/buscar?q=` | A05 | Semgrep, OWASP ZAP |
| V05 | Ruta `/debug` sin autenticación que expone variables de entorno | `api-gateway`, `GET /debug` | A02 | OWASP ZAP (parcial) |
| V06 | Ausencia de cabeceras de seguridad HTTP (y `X-Powered-By` visible) | `api-gateway` (sin helmet) | A02 | OWASP ZAP |
| V07 | CORS permisivo: refleja cualquier origen con credenciales | `api-gateway`, `cors({ origin: true, credentials: true })` | A02 | OWASP ZAP, Semgrep |
| V08 | Errores que exponen la traza de pila | Manejadores de error de ambos servicios | A10 | OWASP ZAP |
| V09 | IDOR: cualquier usuario autenticado consulta el perfil de otro | `GET /api/usuarios/perfil/:id` | A01 | Ninguna (revisión manual) |
| V12 | Contenedores ejecutados como root | Los tres `Dockerfile` (sin `USER`) | A02 | Trivy (configuración) |

## Puntuación CVSS v3.1 (Apéndice 1 de la tesis)

Se asignó antes de cualquier escaneo. Verificar con https://www.first.org/cvss/calculator/3.1

| ID | Vector | Puntaje | Severidad |
|---|---|---|---|
| V01 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | Crítica |
| V02 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N | 8.2 | Alta |
| V03 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Crítica |
| V04 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | Media |
| V05 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | Alta |
| V06 | CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N | 3.1 | Baja |
| V07 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N | 6.5 | Media |
| V08 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | Media |
| V09 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 | Media |
| V12 | CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.0 | Alta |

V10 y V11: cada par paquete–CVE conserva la puntuación publicada en la NVD.

## Nivel de componentes (la unidad es el par paquete–CVE)

- **V10, dependencias npm antiguas.** express 4.16.0, cors 2.8.4, http-proxy-middleware 0.19.1,
  minimist 1.2.0, mongoose 5.7.0, jsonwebtoken 8.5.1, lodash 4.17.4 y moment 2.19.3.
  Línea base de `npm audit` (GitHub Advisory Database) del 03/11/2026: **87 avisos** en los tres servicios.
  El detalle está en `docs/npm-audit-*.json`. Esta línea base se debe **actualizar en la fecha de la instantánea**
  de la base de Trivy (sección 2.10) y contrastarse con la NVD.
- **V11, imagen base desactualizada.** `node:14.17.0-buster-slim` (Node.js 14 sin soporte desde abril de
  2023, Debian 10). La lista de CVE del sistema operativo se obtiene en la fecha de la instantánea.

| Servicio | Paquete | Tipo | Aviso | Severidad |
|---|---|---|---|---|
| api-gateway | body-parser | Transitiva | GHSA-qwcr-r2fm-qrc7 | high |
| api-gateway | body-parser | Transitiva | GHSA-v422-hmwv-36x6 | low |
| api-gateway | body-parser | Transitiva | GHSA-27r3-jxmh-p828 | high |
| api-gateway | braces | Transitiva | GHSA-grv7-fg5c-xmjg | high |
| api-gateway | cookie | Transitiva | GHSA-pxg6-pf52-xh8x | low |
| api-gateway | decode-uri-component | Transitiva | GHSA-vcc3-ghjq-m6fr | moderate |
| api-gateway | decode-uri-component | Transitiva | GHSA-qr28-fpjm-wq7f | high |
| api-gateway | express | Directa | GHSA-qw6h-vgh9-j6wx | low |
| api-gateway | express | Directa | GHSA-rv95-896h-c2vc | moderate |
| api-gateway | http-proxy-middleware | Directa | GHSA-c7qv-q95q-8v27 | high |
| api-gateway | http-proxy-middleware | Directa | GHSA-64mm-vxmg-q3vj | moderate |
| api-gateway | micromatch | Transitiva | GHSA-952p-6rrq-rcjv | moderate |
| api-gateway | minimist | Directa | GHSA-vh95-rmgr-6w4m | moderate |
| api-gateway | minimist | Directa | GHSA-xvch-5gv4-984h | critical |
| api-gateway | path-to-regexp | Transitiva | GHSA-9wv6-86v2-598j | high |
| api-gateway | path-to-regexp | Transitiva | GHSA-rhx6-c78j-4q9w | high |
| api-gateway | path-to-regexp | Transitiva | GHSA-37ch-88jc-xwx2 | high |
| api-gateway | qs | Transitiva | GHSA-hrpp-h998-j3pp | high |
| api-gateway | qs | Transitiva | GHSA-6rw7-vpxm-498p | moderate |
| api-gateway | qs | Transitiva | GHSA-4mjr-xmp4-gh2g | moderate |
| api-gateway | send | Transitiva | GHSA-m6fv-jmcg-4jfg | low |
| api-gateway | serve-static | Transitiva | GHSA-cm22-4g7w-348p | low |
| servicio-usuarios | async | Transitiva | GHSA-fwr7-v2mv-hh25 | high |
| servicio-usuarios | body-parser | Transitiva | GHSA-qwcr-r2fm-qrc7 | high |
| servicio-usuarios | body-parser | Transitiva | GHSA-v422-hmwv-36x6 | low |
| servicio-usuarios | body-parser | Transitiva | GHSA-27r3-jxmh-p828 | high |
| servicio-usuarios | cookie | Transitiva | GHSA-pxg6-pf52-xh8x | low |
| servicio-usuarios | express | Directa | GHSA-qw6h-vgh9-j6wx | low |
| servicio-usuarios | express | Directa | GHSA-rv95-896h-c2vc | moderate |
| servicio-usuarios | jsonwebtoken | Directa | GHSA-8cf7-32gw-wr33 | high |
| servicio-usuarios | jsonwebtoken | Directa | GHSA-hjrf-2m68-5959 | moderate |
| servicio-usuarios | jsonwebtoken | Directa | GHSA-qwph-4952-7xr6 | moderate |
| servicio-usuarios | lodash | Directa | GHSA-fvqr-27wr-82fm | moderate |
| servicio-usuarios | lodash | Directa | GHSA-35jh-r3h4-6jhm | high |
| servicio-usuarios | lodash | Directa | GHSA-4xc9-xhrj-v574 | high |
| servicio-usuarios | lodash | Directa | GHSA-jf85-cpcp-j695 | critical |
| servicio-usuarios | lodash | Directa | GHSA-p6mc-m468-83gw | high |
| servicio-usuarios | lodash | Directa | GHSA-29mw-wpgm-hmr9 | moderate |
| servicio-usuarios | lodash | Directa | GHSA-x5rq-j2xg-h7qm | moderate |
| servicio-usuarios | lodash | Directa | GHSA-r5fr-rjxr-66jc | high |
| servicio-usuarios | lodash | Directa | GHSA-f23m-r3pf-42rh | moderate |
| servicio-usuarios | lodash | Directa | GHSA-xxjr-mmjv-4gpg | moderate |
| servicio-usuarios | mongoose | Directa | GHSA-8687-vv9j-hgph | critical |
| servicio-usuarios | mongoose | Directa | GHSA-f825-f98c-gj3g | high |
| servicio-usuarios | mongoose | Directa | GHSA-9m93-w8w6-76hh | critical |
| servicio-usuarios | mongoose | Directa | GHSA-h8hf-x3f4-xwgp | critical |
| servicio-usuarios | mongoose | Directa | GHSA-m7xq-9374-9rvx | high |
| servicio-usuarios | mongoose | Directa | GHSA-vg7j-7cwx-8wgw | critical |
| servicio-usuarios | mongoose | Directa | GHSA-wpg9-53fq-2r8h | high |
| servicio-usuarios | mongoose | Directa | GHSA-664h-wqgq-64gw | moderate |
| servicio-usuarios | mpath | Transitiva | GHSA-p92x-r36w-9395 | moderate |
| servicio-usuarios | mquery | Transitiva | GHSA-45q2-34rf-mr94 | moderate |
| servicio-usuarios | path-to-regexp | Transitiva | GHSA-9wv6-86v2-598j | high |
| servicio-usuarios | path-to-regexp | Transitiva | GHSA-rhx6-c78j-4q9w | high |
| servicio-usuarios | path-to-regexp | Transitiva | GHSA-37ch-88jc-xwx2 | high |
| servicio-usuarios | qs | Transitiva | GHSA-hrpp-h998-j3pp | high |
| servicio-usuarios | qs | Transitiva | GHSA-6rw7-vpxm-498p | moderate |
| servicio-usuarios | qs | Transitiva | GHSA-4mjr-xmp4-gh2g | moderate |
| servicio-usuarios | send | Transitiva | GHSA-m6fv-jmcg-4jfg | low |
| servicio-usuarios | serve-static | Transitiva | GHSA-cm22-4g7w-348p | low |
| servicio-productos | async | Transitiva | GHSA-fwr7-v2mv-hh25 | high |
| servicio-productos | body-parser | Transitiva | GHSA-qwcr-r2fm-qrc7 | high |
| servicio-productos | body-parser | Transitiva | GHSA-v422-hmwv-36x6 | low |
| servicio-productos | body-parser | Transitiva | GHSA-27r3-jxmh-p828 | high |
| servicio-productos | cookie | Transitiva | GHSA-pxg6-pf52-xh8x | low |
| servicio-productos | express | Directa | GHSA-qw6h-vgh9-j6wx | low |
| servicio-productos | express | Directa | GHSA-rv95-896h-c2vc | moderate |
| servicio-productos | moment | Directa | GHSA-8hfj-j24r-96c4 | high |
| servicio-productos | moment | Directa | GHSA-wc69-rhjr-hc9g | high |
| servicio-productos | mongoose | Directa | GHSA-8687-vv9j-hgph | critical |
| servicio-productos | mongoose | Directa | GHSA-f825-f98c-gj3g | high |
| servicio-productos | mongoose | Directa | GHSA-9m93-w8w6-76hh | critical |
| servicio-productos | mongoose | Directa | GHSA-h8hf-x3f4-xwgp | critical |
| servicio-productos | mongoose | Directa | GHSA-m7xq-9374-9rvx | high |
| servicio-productos | mongoose | Directa | GHSA-vg7j-7cwx-8wgw | critical |
| servicio-productos | mongoose | Directa | GHSA-wpg9-53fq-2r8h | high |
| servicio-productos | mongoose | Directa | GHSA-664h-wqgq-64gw | moderate |
| servicio-productos | mpath | Transitiva | GHSA-p92x-r36w-9395 | moderate |
| servicio-productos | mquery | Transitiva | GHSA-45q2-34rf-mr94 | moderate |
| servicio-productos | path-to-regexp | Transitiva | GHSA-9wv6-86v2-598j | high |
| servicio-productos | path-to-regexp | Transitiva | GHSA-rhx6-c78j-4q9w | high |
| servicio-productos | path-to-regexp | Transitiva | GHSA-37ch-88jc-xwx2 | high |
| servicio-productos | qs | Transitiva | GHSA-hrpp-h998-j3pp | high |
| servicio-productos | qs | Transitiva | GHSA-6rw7-vpxm-498p | moderate |
| servicio-productos | qs | Transitiva | GHSA-4mjr-xmp4-gh2g | moderate |
| servicio-productos | send | Transitiva | GHSA-m6fv-jmcg-4jfg | low |
| servicio-productos | serve-static | Transitiva | GHSA-cm22-4g7w-348p | low |
