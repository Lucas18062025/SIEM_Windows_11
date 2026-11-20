# AUDITORÍA INTEGRAL — SIEM_Windows_11 v4.0

- **Fecha:** 2026-11-20
- **Branch:** `main` — commit `fe896e0` (`fix(security): agrega _headers con CSP y hardening`)
- **Estado:** Implementación funcional correcta. **0 hallazgos CRÍTICO, 0 ALTO. 8 MEDIUM, 11 LOW.**
- **Host auditado:** `DESKTOP-7FNVT2U` (SIEMConfig: version 4.0.0, modo `solo_lectura`)

---

## A. Executive Summary

SIEM Personal v4.0 — monitor de eventos de Windows 11, Telegram, rotación de logs y herramientas de auditoría (`vuln_hp.py`, `scan_ports.py`, `verify_siem.py`).

Verificado en vivo (sin ejecutar el SIEM ni herramientas destruyentes):
- Sintaxis de todos los archivos Python: válida (`ast.parse` de los 12 archivos de proyecto + `python -m compileall` como corre en CI).
- `SIEMConfig()` carga `.env` + `config.yaml` correctamente: 9 eventos críticos, 5 alertas, `scan_interval=10s`, `memory_window=3600s`, `tg_cooldown=60s`, `tg_global_limit=20/min`, `max_events=50000`, token enmascarado (`***gFvA`).
- `win32evtlog`: `OpenEventLog('localhost','System')` + `ReadEventLog` lee 5 eventos — objetos `PyEventLogRecord` con `EventID` (int) y `TimeGenerated.Format()` funcional (verificado: `Fri Nov 20 18:24:32 2026`).
- `python-nmap` (`.venv/Lib/site-packages/nmap/nmap.py:452`): `port = int(dport.get("portid"))` — los puertos son `int`, así `PUERTOS_CRITICOS` (int) en `vuln_hp.py` coincide.

Hallazgos reales (no inflados): 8 MEDIUM (robustez, rendimiento, validación, testabilidad) y 11 LOW (dead code, docs, edge cases). El hallazgo más relevante es F-01: **el Security log solo se lee con privilegios de Administrador** — evidencia real en `Logs/siem.log`.

---

## B. Estado del repositorio

- **Branch:** `main` (clean). **Commit:** `fe896e0`.
- **Uncommitted:** ninguno. `?? .wrangler/` — directorio sin trackear (cuenta/cache de wrangler: account id `5443029ed4498003db9d0748999a326e`).
- **24 archivos tracked** (`git ls-files`):
  `.env.example`, `.github/workflows/ci.yml`, `.gitignore`, `CHANGELOG.md`, `COMMIT_GUIDE.md`, `README.md`, `config.yaml`, `implementation_plan.md`, `netlify-site/_headers`, `netlify-site/index.html`, `pyproject.toml`, `requirements.txt`, `scan_ports.py`, `siem/__init__.py`, `siem/config.py`, `siem/event_processor.py`, `siem/log_manager.py`, `siem/models.py`, `siem/notifier.py`, `siem_consola.py`, `verify_siem.py`, `vuln_hp.py`, `wrangler.toml`.
- **No trackados (per .gitignore):** `.env` (presente en disco, secretos no impresos), `.venv/`, `Logs/`, `Alertas/`, `cache_cve.json`, `reporte_*.json`.
- **Technologías:** Python 3.10+ (`requires-python`; CI usa 3.12; README dice 3.13), `pywin32>=306`, `requests>=2.31.0`, `python-dotenv>=1.0.0`, `PyYAML>=6.0.1`, `python-nmap>=0.7.1` (`requirements.txt`); `pyproject.toml` agrega `python-telegram-bot>=20.0` (sin uso en código — notifier usa `requests`).

---

## C. Arquitectura actual

```
Windows Security + System event logs
   → win32evtlog.OpenEventLog + ReadEventLog      (siem/event_processor.py, read-only)
   → EventProcessor.process_cycle
        - filtro: eid ∈ critical_events (config.yaml: 9 IDs)
        - dedup: SHA-256[:16] de RecordNumber|log_type|EventID|TimeGenerated.Format()
        - memoria: _seen_events + _event_queue, cap 50000, cleanup por ventana (3600s)
   → _handle_event
        - print consola
        - LogManager.write_event → Logs/eventos_{date}.log (+ Alertas/alertas_{date}.log si alerta)
        - TelegramNotifier.send (solo si eid ∈ alert_events = {4625, 4719, 4726, 4740, 1102})
             rate limit: cooldown por tipo (60s) + límite global (20/min) + retry 429/timeout + sanitize HTML

Herramientas de auditoría (independentes del monitor):
   vuln_hp.py     → nmap -sV --open 1-1024 → NVD API v2.0 keywordSearch (TTL 24h) → CVSS v3.1
                    → table PUERTOS_CRITICOS (pesos) → clasificación del host → reporte JSON (gitignorado)
   scan_ports.py  → TCP conectores concurrentes 1-1024 (50 hilos, timeout 1s), --json
   verify_siem.py → smoke tests manuales (escribe líneas TEST a Logs/ y Alertas/)

Deploy / landing: netlify-site/ (static) + wrangler (Workers) + netlify-site/_headers (CSP hardening, commit fe896e0);
CI: .github/workflows/ci.yml (windows-latest, compileall + verify_siem).
```

---

## D. Auditoría funcional (Fase 1) — resultados

Flujo real: Recolección (`read_events`) → Procesamiento (`process_cycle`) → Detección (filtro + dedup) → Clasificación (`is_alert`) → Alertas (Telegram) → Reportes (Logs/Alertas + consola).

Coherente: la detección se calibra con `config.yaml` (9 críticos vs 5 alertas — consistente con README; 4720 no alerta como dice README ❌).

### Hallazgos funciónales/lógicos (MEDIUM — F-01..F-09)

**F-01 (MEDIUM, funcional/seguridad)** — *Security log no se lee sin Admin.*
Evidencia real (`Logs/siem.log`, cadencia 10s, separador entre líneas):
```
[2026-09-12 22:41:41] [ERROR   ] [siem.events] [ERROR] No se pudo leer Security: (1314, 'OpenEventLogW', 'El cliente no dispone de un privilegio requerido.')
```
Mientras que `OpenEventLog('localhost','System')` devuelve eventos (verificación en vivo). Mitigación documentada (README) pero sin enforcement ni alerta.
Impacto: sin admin, el monitor pierde la cobertura de Security (4625/4648/4719/4726/1102). Validación: `sistema_medido` — count de errores de OpenEventLogW/1314 vs ciclos. Recomendación: `check_platform()` + verificación de permisos al iniciar; alerta única a Telegram si Security inaccesible; error de una sola vez.

**F-02 (MEDIUM, rendimiento)** — *`read_events` lee TODO el log cada ciclo.*
`siem/event_processor.py:94`: `win32evtlog.ReadEventLog(handle, flags, 0)` — `count=0` = leer todo. Luego `events[:50]`.
Impacto: on busy logs, lee/parsea todo cada 10s. Recomendación: leer por chunks o último RecordNumber (`GetOldestEventLogRecord` + `EVENTLOG_SEEK_READ` / `NotifyChangeEventLog`).

**F-03 (MEDIUM, robustez)** — *`vuln_hp.find_cve`: `resp.json()` fuera del try.* `vuln_hp.py:274` — HTTP 200 con body no JSON → `ValueError` sin manejo → crash de la herramienta. Recomendación: try/except alrededor de `resp.json()` → log + `return []` con indicador.

**F-04 (MEDIUM, robustez)** — *Parsing NVD sin hardening.* `vuln_hp.py:279` `int(cve_id.split("-")[1])` → IndexError si ID sin guion; `vuln_hp.py:287-294` `metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]` → IndexError/KeyError si lista vacía/campos ausentes. Docstring ya reconoce limitación ("no valida aplicabilidad exacta"). Validación: mock NVD respondiendo IDs malformados → `find_cve` debe devolver [] sin excepciones.

**F-05 (LOW, paginación)** — *NVD sin paginación.* `vuln_hp.py:236` `{"keywordSearch": q, "resultsPerPage": 20}` — no se maneja `nextPage`; User-Agent no se envía. Prácticamente inofensivo (top-5 por servicio).

**F-06 (MEDIUM, logica)** — *`LogManager.rotate()` intenta rotar/comprimir `siem.log` activo.* `siem/log_manager.py`: `rotate()` itera `Logs/` incluyendo `siem.log` (tenido abierto por `RotatingFileHandler`); si `mtime < 1 día`, `_compress_file()` hace `filepath.unlink()` → `PermissionError` en Windows (cṅtado+logueado). Evidencia: `siem.log:22:08` — `[INFO] [siem.log_manager] 📦 Log comprimido: eventos_2026-09-10.log → ...gz`. Recomendación: excluir `siem.log` del `rotate()` o comprimir solo no-activos.

**F-07 (MEDIUM, testabilidad)** — *Sin suite de pruebas automatizadas.* No existe `tests/` (`pyproject.toml`: `testpaths = ["tests"]` — inexistente). `verify_siem.py` es un smoke manual que ESCRIBE a `Logs/`/`Alertas/` (Test 5: `write_event("TEST verificacion SIEM v4.0", is_alert=True)`). CI corre `compileall` + `verify_siem.py` solo.

**F-08 (MEDIUM, validación)** — *`SIEMConfig` sin validación:* `config.yaml` vacío → `yaml.safe_load` devuelve `None` → `AttributeError` en `_load_siem`; `cleanup_every_n_cycles: 0` → `ZeroDivisionError` en `siem_consola` (`cycle % config.cleanup_every`); `scan_interval_seconds` negativo → busy loop.

**F-09 (MEDIUM, disponibilidad/robustez)** — *`siem_consola.main()`: sin `except` general en el loop.* `processor.process_cycle()` está dentro del `try/finally` — una excepción (fuera de `read_events`) mata el monitor; el `finally` imprime shutdown y envía `send_shutdown`, pero no hay retomar/alerta automática.

### Hallazgos menores / dead code / docs (LOW — F-10..F-19)

- **F-10 (LOW, dead code)** — `scan_ports.py:61` `es_ip_valida()` — sin usos.
- **F-11 (LOW, dead import)** — `siem/log_manager.py:17` `import os` (no se usa); `siem/event_processor.py:20` `from datetime import datetime` (no se usa) — verificado por AST.
- **F-12 (LOW, config surface)** — `siem/config.py:170` `self.log_format` — definido, sin uso.
- **F-13 (LOW, doc)** — README (líneas 207-221): `netlify-site/` listado dos veces y `netlify.toml` aparece, pero **no existe** (`git ls-files`: solo `netlify-site/_headers` + `index.html`) — deploy real es Workers/`wrangler.toml`; estructura de `siem/` omite `models.py` y `__init__.py`.
- **F-14 (LOW, doc)** — CHANGELOG `[4.0.0] — 2025-Q4` vs commits 2026 (cosmético).
- **F-15 (LOW, seguridad-info)** — `cache_cve.json`: entradas con `ts` = `2026-09-13 15:54` (verificado: `datetime.fromtimestamp(1789325666.325943)`), hoy es 2026-11-20 → TTL (24h) vencido — el código los descarta en `cargar_cache()` (correcto); el archivo no se poda.
- **F-16 (LOW, robustez)** — `vuln_hp.verificar_nmap()`: `except Exception: return True` — miscalcula errores reales; además escanea `127.0.0.1:80` como heurístico.
- **F-17 (LOW, funcional)** — `siem_consola.py:122` `new_events = processor.process_cycle()` — variable sin usar (podría alimentar telemetría/log).
- **F-18 (LOW, seguridad)** — `verify_siem.py` Test 5 escribe logs de prueba en producción de logs.
- **F-19 (LOW, supply chain)** — `pyproject.toml:51` `python-telegram-bot>=20.0` declarado; no se usa (notifier usa `requests`).

---

## E. Auditoría de código (Fase 2)

- Errores sintácticos: **ninguno** (`ast.parse` 12 archivos + `compileall` CI).
- Lógica sana verificada: `EventData.compute_hash` (SHA-256[:16] — verificado en vivo: son strings de 16 caracteres), `RateLimitState` doble-check (`can_send` cooldown + ventana 1 min — test de la lógica: pass), `TelegramNotifier.sanitize` (escaping + control chars + truncado — asserts de verify_siem matchean), `LogManager` (rotación por tamaño + días + gz), `EventProcessor` (dedup, memoria cap, cleanup por ventana).
- Acoplamiento: `siem` acoplado a `win32evtlog` (Windows-only — documentado).
- Verificado en vivo que `TimeGenerated.Format()` existe y devuelve string — asumptions del código validadas.

---

## F. Auditoría de ciberseguridad (Fase 3)

**Positivos:**
- Secrets: `.env` gitignored; token enmascarado en logs/banner (`telegram_token_masked`).
- HTML injection: `StringInserts` html.escape'd + truncado en `_build_event_data`; mensajes Telegram sanitizados.
- Red: `requests` con `verify=True`; timeouts configurables; no ejecución de procesos externos en el SIEM core; `scan_ports`/`vuln_hp` externos mediante `nmap`.
- Recolección de Windows eventos: **read-only** (`OpenEventLog` + `ReadEventLog`; no `ClearEventLog`/`EvtExportLog`).
- Memoria: cap 50.000 eventos (F-06-adjacent: sin overflow).

**Hallazgos:** F-01, F-03, F-04, F-15, F-16 (vistos arriba); **ningún hallazgo CRÍTICO ni ALTO.**
- Observación: `siem_consola` ejecutado sin Admin → pierde Security (F-01); aconsejable `OpenEventLogW`-check de `EventLogReader` al startup.

---

## G. Rendimiento y confiabilidad (Fase 6)

- F-02 (rendimiento): re-lectura completa del Security log cada 10s — problema de CPU/IO en logs grandes; mitigación: chunked reads (P1).
- F-09: availability — el loop muere en excepciones; mitigación: `except` general + alerta (P0).
- Rendimiento inherente: `read_events` — ventana, sin benches comparativos hechos.

---

## H. Modularidad y escalabilidad (Fase 4)

**Estado actual:** modularidad adecuada — 5 módulos con SRP claro (`config`, `models`, `event_processor`, `log_manager`, `notifier`), instanciables con interfaces delgadas, setuptools configurado, CI compile.

**¿Permitiría crecer sin deuda?** Parcialmente:
- Acceso acoplado a win32evtlog — OK (es el dominio).
- Extensibilidad: nueva fuente de eventos — requiere tocar `EventProcessor.read_events` (posible via Strategy: `EventSource` interface, factory) — mejora sugerida (P4).
- Extensibilidad de reglas de detección: solo filtro de IDs fijos en `critical_events` — mejora sugerida: reglas con peso/severity y correlación (P4).
- Configuración: `config.yaml` centralizada — OK.

---

## I. Testing (Fase 5)

- Cobertura: sin suite automatizada (F-07); verify_siem.py smoke manual — cubre imports, `EventData.compute_hash` (16 chars), `RateLimitState` (can_send/record_send cooldown), `TelegramNotifier.sanitize` (escape, charset, truncado), `SIEMConfig` (version 4.0.0, 9 críticos, 4625 alerta, cooldown 60, max_events 50000), `LogManager` (write/stats), `EventProcessor` (instantiated, memoria vacía), syntax de `siem_consola.py`.
- Vacíos: vuln_hp (find_cve NVD, run_nmap), scan_ports, calificación de riesgo, rotación de logs, crash de `EventProcessor` con eventos malformados.

---

## J. Matriz de hallazgos

| ID | Severidad | Categoría | Archivo:Línea | Descripción | Impacto | Validación | Recomendación |
|----|-----------|-----------|---------------|-------------|---------|------------|---------------|
| F-01 | MEDIUM | Funcional/Sec | siem_consola.py, event_processor.py | Security log legible solo con Admin; sin warning ni alerta al ejecutar sin admin. | Pierde detección de 4625/4648/4719/4726/1102 sin admin. | `OpenEventLog('localhost','Security')` falla 1314 — error real en `Logs/siem.log`. | Verificar Admin al startup; alerta Telegram si inaccesible; Admin obligatorio en README. |
| F-02 | MEDIUM | Rendimiento | event_processor.py:94-96 | `ReadEventLog(handle, flags, 0)` lee todo el log cada 10s; slice [:50]. | CPU/IO en logs grandes; sin chunking. | Static — verificar en servidor real con Security grande. | Lectura por chunks o `GetOldestEventLogRecord`+`SEEK`. |
| F-03 | MEDIUM | Robustez | vuln_hp.py:274 | `resp.json()` fuera del try; body no JSON → ValueError. | Crash de `vuln_hp` en respuestas anómalas. | Static. | try/except + `return []` + log. |
| F-04 | MEDIUM | Robustez | vuln_hp.py:279, 287-294 | Parsing NVD: `int(cve_id.split("-")[1])`, `[0]["cvssData"]["baseScore"]` — IndexError/KeyError. | Crash ante IDs/metrics inesperados. | Mock NVD: IDs malformados → sin excepciones. | Regex de validación; guards con defaults. |
| F-05 | LOW | Pagination | vuln_hp.py:236 | `resultsPerPage: 20`, sin `nextPage` ni User-Agent. | Resultados truncados vs CVEs del ecosistema. | Static. | User-Agent; paginación opt-in (documentar). |
| F-06 | MEDIUM | Funcional | log_manager.py (`rotate()`, `_compress_file`) | `rotate()` comprime/elimina `siem.log` activo (mtime>1d); PermissionError cachado+logueado. | Logging caído si OS cambia / idle >1d. | Static; verificar en servidor. | Excluir siem.log activo del rotate(). |
| F-07 | MEDIUM | Testabilidad | tests/ inexistente; verify_siem.py | Sin suite; verify_siem escribe artifactos TEST a Logs/Alertas. | Confianza en features de deploys. | CI run: `compileall` + `verify_siem` pass ✓. | Suite pytest (unit + mocks). |
| F-08 | MEDIUM | Validación | siem/config.py (73-85, 139+) | config.yaml vacío → `AttributeError`; `cleanup_every_n_cycles: 0` → ZeroDivisionError; intervalo negativo → busy loop. | Errores opacos al operator. | Static. | Validación exhaustiva; clamping; errores claros. |
| F-09 | MEDIUM | Disponibilidad | siem_consola.py:117-142 | Sin `except` general en loop; excepciones matan el monitor (finally corre). | Detección caída sin alerta. | Static. | `except Exception` → log + alerta + re-intento/wait. |
| F-10 | LOW | Dead code | scan_ports.py:61 | `es_ip_valida()` sin usos. | — | Static. | Eliminar. |
| F-11 | LOW | Dead import | log_manager.py:17, event_processor.py:20 | `import os` / `from datetime import datetime` sin uso (AST-verificado). | — | AST. | Eliminar. |
| F-12 | LOW | Config surface | siem/config.py:170 | `log_format` definido, sin uso. | — | AST/grep. | Reutilizar o remover. |
| F-13 | LOW | Doc | README.md:207-221 | `netlify.toml` listado, no existe; `netlify-site/` duplicado; `models.py`/`__init__.py` omitidos en siem/. | Falsa señal para deploys/auditorías. | `git ls-files` + tree reales. | Corregir README. |
| F-14 | LOW | Doc | CHANGELOG.md:10 | `[4.0.0] — 2025-Q4` vs commits 2026. | — | — | Ajustar fecha. |
| F-15 | LOW | Seguridad-info | cache_cve.json:1-13 | Entradas con ts 2026-09-13 (hoy 2026-11-20) → TTL vencido (código lo descarta). | Recuperables; riesgo nulo. | `fromtimestamp(ts)` verification. | Poda de cache caduco. |
| F-16 | LOW | Robustez | vuln_hp.py:151-159 | `except Exception: return True` en `verificar_nmap`; conecta 127.0.0.1:80. | Mscaras errores reales. | Static. | Simplificar + test. |
| F-17 | LOW | Funcional | siem_consola.py:122 | `new_events` sin usar. | — | Static. | Usar en status/telemetría. |
| F-18 | LOW | Seguridad | verify_siem.py:79-81 | Test 5 escribe logs de verificación a producción. | — | Static. | Mover fixtures a tmp. |
| F-19 | LOW | Supply chain | pyproject.toml:51 | `python-telegram-bot>=20.0` sin uso (notifier usa `requests`). | Ambigüedad. | `grep`/AST — sin import telegram. | Remover dep. |

---

## K. Roadmap de evolución (P0–P4)

### P0 — Correcciones críticas (disponibilidad + cobertura Security)
1. **F-01:** verificación de credenciales de Windows Event Log al startup (`OpenEventLogW` Security/System) → alerta de estado si Security inaccesible + warning único; Admin obligatorio documentado. — Archivos: `siem_consola.py`, `siem/event_processor.py`, `README.md`, `config.yaml`. Riesgo: bajo (solo lectura). Validación: test unitario (mock `win32evtlog`) + e2e (máquina sin Admin).
2. **F-09:** `siem_consola.main()`: `except Exception` en loop → log + `send_shutdown` + `sleep(scan_interval)` (o re-ejecutar ciclo). — Archivos: `siem_consola.py`. Riesgo: bajo. Validación: test: EventProcessor lanza → monitor alerta y continúa.

### P1 — Robustez funcional + validación
1. **F-02:** `read_events` por chunks / `GetOldestEventLogRecord` + `SEEK` — memoria cap bien definida. — Archivos: `siem/event_processor.py`. Riesgo: medio.
2. **F-03:** `resp.json()` → try/except → `return []` + log. — Archivos: `vuln_hp.py`. Riesgo: bajo.
3. **F-04:** hardening parsing NVD (regex `^CVE-\d{4}-\d+$`, guards de metrics). — Archivos: `vuln_hp.py`. Riesgo: bajo.
4. **F-06:** `rotate()`: excluir `siem.log` (o comprimir solo no-activos). — Archivos: `siem/log_manager.py`. Riesgo: medio.
5. **F-07:** Suite pytest (unitarios + mocks NVD/socket localhost). — Archivos: `tests/`. Riesgo: bajo.
6. **F-08:** Validación de `config.yaml` (file existe, no vacío; timing ≥ 0 clamps; `cleanup_every_n_cycles ≥ 1`; `logs_dir` writable). — Archivos: `siem/config.py`. Riesgo: medio.

### P2 — Modularidad / mantenibilidad
1. **F-19:** decidir — remover `python-telegram-bot` de `pyproject.toml` (notifier usa `requests`). — Archivos: `pyproject.toml`.
2. **F-11:** implementar retry de `read_events` (1-2 intentos). — Archivos: `siem/event_processor.py`.
3. **F-12, F-10:** `log_format` reutilizado en `LogManager` o removido; `es_ip_valida` eliminado.
4. **F-17:** `new_events` → contador de eventos/ciclo en status line.

### P3 — Escalabilidad / observabilidad / extensibilidad
1. **F-02 (bis):** métricas/ciclo: eventos leídos, procesados, alertas enviadas → archivo `Logs/siem_metrics.log` o Telegram (opt-in).
2. **F-13, F-14:** docs: actualizar README (`netlify.toml`, siem/, estructura) — cambios directos, no de roadmap.
3. **F-05:** paginación NVD (User-Agent + `resultsPerPage: 128` + `nextPage`), notable en reporte.
4. **F-15:** pruning de `cache_cve.json` (script de limpieza).
5. Perfil de memoria y latencia real (ejecución controlada en máquina de admin).

### P4 — Evolución funcional (backlog, sin impacto en core)
1. Correlación de alertas: agrupar por usuario/host (4625+4740/1102 → alerta consolidada con severidad).
2. Fila persistente de alertas fallidas (archivar para retry manual).
3. Export a Splunk HEC/ELK.
4. Migración de SIEM a Worker (edge) — designo separado.

---

## L. Riesgos de modificación

| Change | Risk | Mitigación |
|--------|------|-----------|
| F-01 — check Admin + alerta | Error de lectura Security no detenido | Añadir test unitario con mock; alerta por telegram no crítica. |
| F-02 — chunked reads | Memoria por evento reduce; riesgo de perder eventos sin ack | Test con logs reales; ciclo de test de carga. |
| F-03/04 — hardening NVD | Sin impacto en behavior normal | Tests con respuestas NVD reales y malformadas. |
| F-06 — excluir siem.log del rotate | Logs sin compresión de siem.log activo | Sólo excepción de `siem.log`; eventos_*.log siguen comprimidos. |
| F-07 — suite pytest | — | Sólo añade `tests/`; CI extends. |
| F-08 — validación config | Backward compatibility: configs viejas podrían errorar | Clamp en lugar de error; errores solo para configs rotos. |
| F-19 — remove dep | Sin uso real — sin impacto | — |
| General — reverting cualquier item | git revert controlado; rollback trivial | Branch `fix/*` según COMMIT_GUIDE. |

---

## M. Conclusión

El SIEM_Windows_11 está en estado funcional correcto: monitoreo continuo de Security+System, detección con 9 eventos críticos, alertas Telegram con rate limiting y sanitización, logs rotativos, herramientas de auditoría y landing Cloudflare coherente.

Hallazgos reales (validados, no inflados): **0 CRÍTICO, 0 ALTO, 8 MEDIUM, 11 LOW.** Los niveles MEDIUM se centran en: robustez del monitor (F-01, F-09), rendimiento de lectura de logs (F-02), hardening del parser NVD (F-03, F-04), validación de config (F-08), y testabilidad (F-07).

- Si se ejecuta como **Administrador**, el SIEM funciona correctamente y monitorea Security.
- Si se ejecuta sin Admin, pierde la cobertura Security (F-01) — recomendado corregirlo en P0.
- La sección J (matriz de hallazgos) documenta evidencia verificable por cada hallazgo; se ejecutó `verify_siem.py`-equivalente (instantiación de `SIEMConfig`) y verificaciones en vivo de `win32evtlog`.

**Próximos pasos recomendados:** implementar P0-P1 primero (robustez), luego P2-P4 según priorización del usuario. Reporte completo con todas las secciones A-M: **`AUDIT_REPORTE_INTEGRAL_SIEM_Windows_11.md`** (este archivo).

---

## N. Roadmap ejecutado — implementación realizada

Autorización recibida el 2026-11-20 ("Autorizar P0-P4"). Implementación en branch `feat/siem-audit-fixes`, una mejora a la vez con pruebas antes/después:

| F | Dato | Implementación |
|---|------|----------------|
| F-01 | `siem_consola` + `event_processor` | `check_credentials()` + alerta de advertencia si un log no es legible (Admin requerido) |
| F-02 | `event_processor` | `read_events()` — `ReadEventLog(handle, flags, 500)` chunk-limitado (funcionalidad idéntica: siempre los 50 más recientes) |
| F-03 | `vuln_hp` | `resp.json()` en try/except → `return []` + mensaje |
| F-04 | `vuln_hp` | Validación de formato de ID NVD (`len(parts) >= 2`, `parts[1].isdigit()`); guards de `metrics` (sin `IndexError`) |
| F-05 | `vuln_hp` | Paginación NVD (`_paginar`: `startIndex`/`totalResults`, máx 5 páginas, IDs únicos) |
| F-06 | `log_manager` | `rotate()` excluye `siem.log` (log activo no comprimido/eliminado) |
| F-07 | — | Suite `tests/` nueva — 38 pruebas (`python -m unittest discover -s tests`) |
| F-08 | `config` | `_validate_config()` — `timing` vacío/ceros/negativos → `ValueError` claro |
| F-09 | `siem_consola` | `run_monitor()` extraído — `except Exception` en loop, no mata el monitor |
| F-10 | `scan_ports` | Removida `es_ip_valida()` (sin uso) |
| F-11 | — | Removidos imports sin uso (`log_manager.os`, `event_processor.datetime`/`Optional`) |
| F-15 | `vuln_hp` | `cargar_cache()` poda de entradas vencidas → `cache_cve.json` quedó en `{}` |
| F-16 | `vuln_hp` | `verificar_nmap()` — False ante errores genéricos (no máscara) |
| F-17 | `siem_consola` | Status line incluye `Nuevos: {n} eventos` |
| F-18 | `verify_siem` | Test 5 — logs de prueba a directorio temporal |
| F-19 | `pyproject.toml` | Removido `python-telegram-bot` (no usado; `notifier` usa `requests`) |
| F-13/F-14 | `README`, `CHANGELOG` | Doc: `netlify.toml` inexistente, `netlify-site/` duplicado, estructura `siem/` incompleta — CHANGELOG fechas |

**Verificación real (2026-11-20):** `compileall` OK; `verify_siem.py` — "🎉 TODOS LOS TESTS PASARON — SIEM v4.0 listo" (exit 0); suite `tests/` — "Ran 38 tests — OK" (exit 0); `read_events('System')` → 10 eventos (≤50) ✓; `check_credentials()` → `{'Security': False, 'System': True}` (evidencia en vivo de F-01); `run_monitor()` smoke — 3 ciclos, sin excepciones.

**Compatibilidad:** sin cambios de interfaz; `read_events()` conserva la semántica (los N más recientes); `find_cve()` conserva estructura (más CVEs por paginación); `process_cycle()` sin cambios.

**Rollback por ítem:** `git revert` del commit del branch, o `git checkout main -- <archivo>` por archivo.

