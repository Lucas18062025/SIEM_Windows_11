# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.0.0/)
y el versionado sigue [Semantic Versioning](https://semver.org/lang/es/).

---

## [4.0.0] — 2025-Q4

### Agregado
- Arquitectura modular completa: `siem/config.py`, `siem/event_processor.py`, `siem/log_manager.py`, `siem/notifier.py`
- Sistema de shutdown limpio con `threading.Event` y handlers para `SIGINT`, `SIGTERM`, `SIGBREAK` (Windows)
- Rate limiting global en notificaciones Telegram (`global_rate_limit_per_minute`)
- Cooldown por tipo de evento (evita spam por evento individual)
- Rotación de logs con compresión `.gz` y retención por días + tamaño máximo
- Ventana de memoria configurable con cap máximo de eventos en RAM
- `config.yaml` como fuente única de configuración operacional
- Script `verify_siem.py` para validación de instalación
- Soporte para `uv` como gestor de entorno virtual (alternativa a pip)

### Cambiado
- Entry point refactorizado a `siem_consola.py` limpio con función `main()`
- Banner de inicio con información completa del host y configuración activa
- Notificaciones de startup y shutdown con estadísticas del ciclo

### Corregido
- Sleep bloqueante reemplazado por `shutdown_event.wait(timeout=)` — responde a señales inmediatamente
- Imports reorganizados según PEP 8 (stdlib → third-party → local)

---

## [3.2.0] — 2025-Q3

### Agregado
- `vuln_hp.py`: clasificación ejecutiva del host (`clasificar_host`) con niveles `CRÍTICO / ALTO / MEDIO / BAJO`
- `vuln_hp.py`: scoring de riesgo basado en CVSS real del peor caso (reemplaza conteo de CVEs)
- `vuln_hp.py`: caché persistente en disco (`cache_cve.json`) — persiste entre ejecuciones
- `vuln_hp.py`: retry con backoff exponencial ante HTTP 429 (NVD rate limiting)
- `vuln_hp.py`: filtro de CVEs anteriores a 2015 (reduce ruido masivamente)
- Exportación de reporte en formato JSON con metadata del operador

### Cambiado
- NVD API actualizada a v2.0 (`/rest/json/cves/2.0`)
- Scoring CVSS actualizado a v3.1 como prioridad (fallback a v3.0 y v2)
- Top 5 CVEs por servicio (ordenadas por score descendente)

---

## [2.1.0] — 2025-Q2

### Agregado
- `scan_ports.py`: escáner concurrente con `ThreadPoolExecutor`
- Detección de eventos críticos adicionales: `4648`, `4719`, `4740`, `7031`, `7036`
- Integración con `.env` para credenciales via `python-dotenv`
- `.env.example` con template completo de variables

### Cambiado
- Información del operador migrada de hardcode a variables de entorno (`CONTACT_*`)
- Banners de todas las herramientas unificados con el mismo formato visual

---

## [1.0.0] — 2025-Q1

### Agregado
- `siem_consola.py`: primer monitor funcional de Windows Event Logs
- Detección de login fallidos (Event ID `4625`) y borrado de logs (`1102`)
- Alertas por Telegram con bot dedicado (`SiemRayzen5Bot`)
- Escritura de logs locales en carpeta `Logs/`
- Detección de creación de usuarios (Event ID `4720`)
- `vuln_hp.py` v1: integración básica con NVD API y python-nmap
- `requirements.txt` inicial
