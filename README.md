# 🛡️ SIEM Personal v4.0

Un sistema de Gestión de Eventos e Información de Seguridad (SIEM) ligero, diseñado específicamente para entornos Windows. Permite monitorizar logs del sistema en tiempo real, detectar actividad sospechosa, notificar por Telegram y realizar auditorías de seguridad en la red local.

---

## 🚀 Herramientas Incluidas

El repositorio incluye tres componentes principales:

1. **`siem_consola.py` (SIEM Principal)**
   - Monitoreo en tiempo real de Windows Event Logs.
   - Detección de múltiples intentos de login fallidos (ID 4625), borrado de logs, creación de usuarios, etc.
   - Alertas inmediatas enviadas a través de un bot de Telegram.
   - Sistema de rotación de logs (retención y tamaño máximo configurables).
   - Rate limiting global y memoria temporal para prevenir spam de notificaciones.

2. **`scan_ports.py` (Escáner de Red Rápido)**
   - Escaneo concurrente de puertos (1-1024) utilizando hilos.
   - Optimizado para escaneos rápidos y de bajo impacto en redes locales.

3. **`vuln_hp.py` (Clasificador de Riesgo y Vulnerabilidades)**
   - Integra `nmap` para descubrimiento de servicios y versiones reales.
   - Consulta automáticamente la API de NVD (National Vulnerability Database) buscando CVEs críticos (CVSS v3).
   - Evalúa el nivel de riesgo de un host según los servicios expuestos y vulnerabilidades asociadas.
   - Genera reportes detallados en formato JSON.

---

## 🛠️ Requisitos Previos

- **Sistema Operativo**: Windows 10/11 (requerido para `win32evtlog`).
- **Python**: 3.10+
- **Nmap**: Necesario para `vuln_hp.py`. [Descargar Nmap para Windows aquí](https://nmap.org/download) y asegurarse de agregarlo al PATH durante la instalación.

---

## 📦 Instalación

**1. Clonar el repositorio y acceder a la carpeta:**
```powershell
git clone <tu-url-del-repositorio>
cd SIEM_WINDOWS_11
```

**2. Crear un entorno virtual e instalar dependencias usando `uv` (Recomendado):**
```powershell
uv venv
uv pip install -r requirements.txt
```
*(Si no usas `uv`, usa los comandos estándar `python -m venv .venv` y `pip install -r requirements.txt`)*

**3. Configurar variables de entorno:**
```powershell
# Haz una copia del archivo de ejemplo
copy .env.example .env
```
Luego edita `.env` con un editor de texto e ingresa tu token de Telegram, ID de Chat, API Key de NVD (opcional pero recomendada), y tus datos de contacto.

---

## 💻 Uso

Para ejecutar las herramientas, **abre PowerShell como Administrador** (requerido para acceder a todos los Event Logs) y activa el entorno:

```powershell
.venv\Scripts\activate
```

### Ejecutar el SIEM Principal
```powershell
python siem_consola.py
```
> El SIEM operará en modo solo lectura ("Host SIN CAMBIOS") escuchando eventos y reportando según las reglas de configuración. Para detener, usa `Ctrl+C`.

### Escanear Puertos
```powershell
python scan_ports.py 192.168.100.12
```

### Análisis de Vulnerabilidades
```powershell
python vuln_hp.py 192.168.100.12
```

---

## ⚠️ Aviso Legal
Este software es una herramienta de uso **exclusivamente defensivo y educativo**. El uso de `nmap`, escaneo de puertos o evaluación de vulnerabilidades (`scan_ports.py` o `vuln_hp.py`) debe realizarse **ÚNICAMENTE** en redes o hosts en los que poseas autorización explícita. El desarrollador no se hace responsable del mal uso de este software.

---

### Perfil del Operador
> Configura tus datos de contacto (Portfolio, LinkedIn) directamente en el archivo `.env` para que aparezcan en los banners automáticos y reportes JSON.
