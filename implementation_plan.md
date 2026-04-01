# SIEM Personal v3.2 → v4.0 — Plan Final

## Estructura Final del Proyecto

```
SIEM_WINDOWS_11/
├── siem_consola.py           ← Entry point (ejecutás SOLO este)
├── config.yaml               ← Configuración completa (eventos, contacto, timings)
├── .env                      ← Secrets (tokens) — NO se sube a GitHub
├── .env.example              ← Template de .env — SÍ se sube
├── .gitignore                ← Lista de archivos que Git ignora
├── requirements.txt          ← Dependencias del proyecto
│
├── siem/                     ← Paquete con módulos
│   ├── __init__.py           ← Inicializador del paquete
│   ├── config.py             ← SIEMConfig — carga .env + config.yaml + validaciones
│   ├── notifier.py           ← TelegramNotifier — rate limiting, sanitización HTML
│   ├── log_manager.py        ← LogManager — rotación por tamaño/días, integridad
│   ├── event_processor.py    ← EventProcessor — lectura y procesamiento de eventos Windows
│   └── models.py             ← Dataclasses tipadas (EventData, AlertConfig, etc.)
│
├── Logs/                     ← Generado automáticamente — NO se sube a GitHub
├── Alertas/                  ← Generado automáticamente — NO se sube a GitHub
└── cache_cve.json            ← Caché de CVEs — NO se sube a GitHub
```

---

## Riesgos Actuales → Solución Aplicada

| # | Riesgo | Sev. | Solución |
|---|--------|------|----------|
| 1 | Secrets en .env sin protección | 🔴 | `.gitignore` + validación de formato + masking en logs |
| 2 | PII hardcodeada en código | 🔴 | Toda la PII movida a `config.yaml` |
| 3 | Token Telegram en URL visible | 🟠 | Masking en logs, token nunca se imprime |
| 4 | Hostname hardcodeado | 🟠 | `socket.gethostname()` dinámico |
| 5 | Sin rate-limit global Telegram | 🟠 | Token bucket: máx 20 msgs/min global |
| 6 | Sin sanitización de StringInserts | 🟠 | `html.escape()` + truncate 200 chars |
| 7 | Logs sin protección | 🟡 | Permisos restrictivos al crear archivos |
| 8 | Sin límite de tamaño en logs | 🟡 | `RotatingFileHandler` 50MB + por días |
| 9 | Memoria unbounded | 🟡 | Cap de 50,000 eventos + limpieza forzada |
| 10 | Sin signal handling | 🟡 | `signal.SIGBREAK` (Windows) + cleanup |
| 11 | Estado global mutable | 🟡 | Encapsulado en clases con estado privado |
| 12 | Rotación bloquea main loop | 🟢 | Rotación en thread separado |
| 13 | RecordNumber puede repetirse | 🟢 | Hash compuesto: RecordNumber + TimeGenerated + EventID |
| 14 | Sin cert pinning | 🟢 | `verify=True` explícito (default de requests) |
| 15 | Sin file locking | 🟢 | `msvcrt.locking()` para Windows |

---

## Archivos a Crear/Modificar

### [NEW] siem/__init__.py
- Exporta las clases principales
- Versión del paquete: `__version__ = "4.0.0"`

### [NEW] siem/config.py — `SIEMConfig`
- Carga `config.yaml` con `pyyaml`
- Carga `.env` con `python-dotenv`
- Valida formato de tokens con regex
- Valida que directorios existan y sean escribibles
- Propiedades tipadas para acceder a configuración
- Masking de secrets: `token[-4:]` visible, resto `***`

### [NEW] siem/models.py — Dataclasses
```python
@dataclass
class EventData:
    event_id: int
    description: str
    timestamp: str
    log_type: str
    details: str
    is_alert: bool
    record_hash: str  # Hash único del evento

@dataclass
class RateLimitState:
    last_sent: Dict[int, float]
    global_count: int
    window_start: float
```

### [NEW] siem/notifier.py — `TelegramNotifier`
- Rate limiting doble: por tipo de evento + global (token bucket)
- Sanitización HTML con `html.escape()`
- Truncate de campos largos (200 chars)
- Retry con backoff exponencial
- Timeout configurable
- Token nunca aparece en logs/prints

### [NEW] siem/log_manager.py — `LogManager`
- `logging.handlers.RotatingFileHandler` (por tamaño, 50MB default)
- `logging.handlers.TimedRotatingFileHandler` (por día)
- Formato estructurado: `[TIMESTAMP] [LEVEL] [MODULE] message`
- Compresión `.gz` de logs antiguos
- Creación automática de directorios
- Console handler con emojis (mantiene el look actual)

### [NEW] siem/event_processor.py — `EventProcessor`
- Lee eventos de Windows con `win32evtlog`
- Guarda último `RecordNumber` procesado por log type
- Hash de deduplicación robusto
- Memoria con cap (50,000 eventos)
- Limpieza automática por ventana de tiempo

### [MODIFY] siem_consola.py — Entry point
- Solo import + `main()` + banner
- ~50 líneas en lugar de 281
- Manejo de señales para shutdown limpio

### [NEW] config.yaml
- Toda la configuración externalizada (ver ejemplo en sección anterior)

### [NEW] .gitignore
```gitignore
# Secrets
.env

# Python
__pycache__/
*.pyc
*.pyo

# Datos generados
Logs/
Alertas/
cache_cve.json
reporte_*.json

# IDE
.vscode/
*.swp
```

### [NEW] .env.example
```env
# Copiá este archivo como .env y completá con tus datos reales
TELEGRAM_TOKEN=tu_token_de_botfather_aqui
TELEGRAM_CHAT_ID=tu_chat_id_aqui
NVD_API_KEY=tu_api_key_de_nvd_aqui
```

### [NEW] requirements.txt
```
pywin32>=306
requests>=2.31.0
python-dotenv>=1.0.0
PyYAML>=6.0.1
```

---

## Cómo Ejecutar (paso a paso)

```powershell
# 1. Instalás la nueva dependencia (una sola vez)
pip install pyyaml

# 2. Ejecutás IGUAL QUE SIEMPRE
cd "C:\Users\HP Ryzen 5\.vscode\Host_Ryzen_5\SIEM_WINDOWS_11"
python siem_consola.py

# 3. Para subir a GitHub (primera vez)
git init
git add .
git commit -m "SIEM v4.0 — refactorización completa"
git remote add origin https://github.com/TU_USUARIO/SIEM_WINDOWS_11.git
git push -u origin main
```

---

## Verification Plan

### Pre-ejecución
```powershell
# Verificar que pyyaml está instalado
python -c "import yaml; print('PyYAML OK')"

# Verificar sintaxis de todos los archivos
python -m py_compile siem_consola.py
python -m py_compile siem/config.py
python -m py_compile siem/notifier.py
python -m py_compile siem/log_manager.py
python -m py_compile siem/event_processor.py
python -m py_compile siem/models.py
```

### Ejecución
- Ejecutar como admin y verificar banner
- Verificar que Telegram recibe alertas
- Verificar que logs se crean en `Logs/` y `Alertas/`
- Verificar que `.env` NO aparece en `git status`
- Verificar que secrets no aparecen en ningún output

---
