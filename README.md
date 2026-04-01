# 🛡️ SIEM Personal v4.0 — Windows Security Monitor

[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-22c55e?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-22c55e?style=flat-square)]()
[![CVSS](https://img.shields.io/badge/scoring-CVSS%20v3.1-dc2626?style=flat-square)]()
[![NVD](https://img.shields.io/badge/database-NVD%20%2F%20NIST-1d4ed8?style=flat-square)](https://nvd.nist.gov/)

> **SIEM ligero para Windows 11** con detección de eventos en tiempo real, alertas Telegram, clasificación de riesgo CVSS y consulta automática de CVEs contra la NVD. Diseñado para entornos de auditoría, homelab y Blue Team operations.

---

## 📐 Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                        SIEM Personal v4.0                       │
│                                                                 │
│   Windows Event Logs          siem_consola.py (Entry Point)     │
│   ┌──────────────┐            ┌────────────────────────────┐    │
│   │  Security    │──────────▶ │       SIEMConfig           │    │
│   │  System      │            │   (config.yaml + .env)     │    │
│   └──────────────┘            └───────────┬────────────────┘    │
│                                           │                     │
│                              ┌────────────▼────────────────┐    │
│                              │      EventProcessor         │    │
│                              │  ┌──────────────────────┐   │    │
│                              │  │ IDs: 4625, 4740,     │   │    │
│                              │  │ 1102, 4719, 4720...  │   │    │
│                              │  └──────────┬───────────┘   │    │
│                              └─────────────┼───────────────┘    │
│                         ┌──────────────────┤                    │
│                         │                  │                    │
│              ┌──────────▼──────┐  ┌────────▼────────┐          │
│              │ TelegramNotifier│  │   LogManager    │          │
│              │  rate limiting  │  │  rotation + gz  │          │
│              │  cooldown/type  │  │  Logs/ Alertas/ │          │
│              └─────────────────┘  └─────────────────┘          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Herramientas de Auditoría                   │
│                                                                 │
│   vuln_hp.py                    scan_ports.py                   │
│   ┌─────────────────────┐       ┌────────────────────────┐     │
│   │ nmap -sV (1-1024)   │       │ ThreadPoolExecutor     │     │
│   │        │            │       │ puertos 1-1024         │     │
│   │ NVD API v2.0        │       │ concurrente            │     │
│   │ CVSS v3.1 scoring   │       └────────────────────────┘     │
│   │ caché disco TTL     │                                       │
│   │ reporte JSON        │                                       │
│   └─────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Componentes

### `siem_consola.py` — Monitor de Eventos en Tiempo Real
- Lectura de Windows Event Logs via `win32evtlog` (modo **solo lectura**, riesgo host: 0/10)
- Detección de eventos críticos de seguridad (ver tabla completa abajo)
- Alertas inmediatas por Telegram con rate limiting y cooldown por tipo de evento
- Rotación automática de logs (días + tamaño máximo + compresión `.gz`)
- Memoria de eventos con ventana temporal configurable (previene spam)
- Shutdown limpio via `SIGINT` / `SIGTERM` / `SIGBREAK` (Windows)

### `vuln_hp.py` — Clasificador de Riesgo y CVEs
- Escaneo de servicios con `nmap -sV` (puertos 1-1024)
- Consulta automática a la [NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities)
- Scoring basado en **CVSS v3.1 real** (peor caso, no conteo de CVEs)
- Clasificación ejecutiva del host: `CRÍTICO / ALTO / MEDIO / BAJO`
- Caché persistente en disco con TTL configurable (evita rate limit de NVD)
- Retry con backoff exponencial ante errores HTTP 429
- Exportación de reporte en formato **JSON** con metadata del operador

### `scan_ports.py` — Escáner Rápido de Red
- Escaneo concurrente de puertos 1-1024 con `ThreadPoolExecutor`
- Optimizado para bajo impacto en redes locales

---

## 🔍 Eventos Monitoreados

| Event ID | Descripción | Severidad | Alerta Telegram |
|----------|-------------|-----------|-----------------|
| `4625` | Login fallido | 🔴 Alto | ✅ Sí |
| `4648` | Login con credenciales explícitas | 🟠 Medio | ❌ No |
| `4719` | Política de auditoría modificada | 🔴 Alto | ✅ Sí |
| `4720` | Cuenta de usuario creada | 🟠 Medio | ❌ No |
| `4726` | Cuenta de usuario eliminada | 🔴 Alto | ✅ Sí |
| `4740` | Cuenta bloqueada | 🔴 Alto | ✅ Sí |
| `7031` | Servicio detenido inesperadamente | 🟡 Medio | ❌ No |
| `7036` | Cambio de estado en servicio | 🟡 Bajo | ❌ No |
| `1102` | **Log de auditoría BORRADO** | 🔴 Crítico | ✅ Sí |

---

## 🛠️ Requisitos

| Requisito | Versión | Notas |
|-----------|---------|-------|
| Windows | 10 / 11 | Requerido para `win32evtlog` |
| Python | 3.10+ | Testado en 3.13 |
| nmap | Cualquiera | Solo para `vuln_hp.py` — debe estar en `PATH` |
| NVD API Key | — | Opcional pero recomendada — [obtener aquí](https://nvd.nist.gov/developers/request-an-api-key) |

---

## 📦 Instalación

```powershell
# 1. Clonar el repositorio
git clone https://github.com/Lucas18062025/SIEM_Windows_11.git
cd SIEM_Windows_11

# 2. Crear entorno virtual e instalar dependencias (uv recomendado)
uv venv
uv pip install -r requirements.txt

# Si no usás uv:
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 3. Configurar variables de entorno
copy .env.example .env
# Editar .env con tu token de Telegram, chat ID y API key de NVD
```

---

## 💻 Uso

> ⚠️ Ejecutar **PowerShell como Administrador** — requerido para acceder a Event Logs de seguridad.

```powershell
# Activar entorno virtual
.venv\Scripts\activate

# ── SIEM Principal (monitoreo continuo)
python siem_consola.py

# ── Escanear puertos de un host
python scan_ports.py 192.168.1.1

# ── Análisis de vulnerabilidades + CVEs
python vuln_hp.py 192.168.1.1

# ── Verificar instalación
python verify_siem.py
```

**Para detener el SIEM:** `Ctrl+C` — shutdown limpio, el host no sufre cambios.

---

## ⚙️ Configuración

Toda la configuración se centraliza en `config.yaml` y `.env`:

```yaml
# config.yaml — parámetros operacionales
timing:
  scan_interval_seconds: 10
  memory_window_seconds: 3600

telegram:
  cooldown_per_type_seconds: 60
  global_rate_limit_per_minute: 20
```

```env
# .env — credenciales (nunca commitear)
TELEGRAM_TOKEN=tu_token_aqui
TELEGRAM_CHAT_ID=tu_chat_id
NVD_API_KEY=tu_api_key_nvd
CONTACT_NOMBRE=Tu Nombre
CONTACT_PORTFOLIO=https://tu-portfolio.com
CONTACT_LINKEDIN=https://linkedin.com/in/tu-perfil
```

---

## 📁 Estructura del Proyecto

```
SIEM_Windows_11/
├── siem/                    # Módulos del SIEM
│   ├── config.py            # Gestión de configuración
│   ├── event_processor.py   # Procesamiento de eventos Windows
│   ├── log_manager.py       # Rotación y escritura de logs
│   └── notifier.py          # Integración Telegram
├── siem_consola.py          # Entry point del SIEM
├── vuln_hp.py               # Escáner de vulnerabilidades + CVEs
├── scan_ports.py            # Escáner rápido de puertos
├── verify_siem.py           # Verificación de instalación
├── config.yaml              # Configuración operacional
├── requirements.txt         # Dependencias Python
├── .env.example             # Template de variables de entorno
├── .gitignore
├── CHANGELOG.md
└── LICENSE
```

---

## ⚠️ Aviso Legal

Este software es de uso **exclusivamente defensivo y educativo**. Las herramientas de escaneo (`scan_ports.py`, `vuln_hp.py`) deben ejecutarse **únicamente** en redes o hosts con autorización explícita del propietario.

El desarrollador no se responsabiliza por el uso indebido de este software.

---

## 👤 Operador

**Lucas Villagra** — Cybersecurity Student · Red Team / Blue Team · NOA, Argentina

[![Portfolio](https://img.shields.io/badge/Portfolio-lucas18062025.github.io-0f172a?style=flat-square&logo=github)](https://lucas18062025.github.io/Portafolio/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-lucas--villagra-0a66c2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/lucas-villagra-9b5097147/)
[![Google Cybersecurity](https://img.shields.io/badge/Google-Cybersecurity%20Certificate-4285f4?style=flat-square&logo=google)](https://www.coursera.org/professional-certificates/google-cybersecurity)
