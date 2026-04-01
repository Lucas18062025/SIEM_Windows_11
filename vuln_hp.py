#!/usr/bin/env python3
"""
vuln_hp.py — Escáner de servicios + búsqueda de CVEs
=====================================================
Desarrollado por: Lucas Villagra
Portfolio: https://lucas18062025.github.io/Portafolio/

Requisitos:
  - nmap instalado y en el PATH
  - pip install python-nmap requests python-dotenv

Uso:
  python vuln_hp.py 127.0.0.1
"""

from __future__ import annotations

import os
import sys
import time
import json
from datetime import datetime
from typing import List, Dict

import nmap
import requests
from dotenv import load_dotenv

# ── Configuraciones ──────────────────────────────────────────
VERSION = "2.3"

# ── Cargar .env ──────────────────────────────────────────────
load_dotenv()

# ── Contacto (desde .env) ────────────────────────────────
CONTACTO = {
    "nombre"    : os.getenv("CONTACT_NOMBRE", "Lucas Villagra"),
    "portfolio" : os.getenv("CONTACT_PORTFOLIO", "https://lucas18062025.github.io/Portafolio/"),
    "linkedin"  : os.getenv("CONTACT_LINKEDIN", "https://www.linkedin.com/in/lucas-villagra-9b5097147/"),
}

# ── API NVD desde .env ───────────────────────────────────────
API_KEY = os.getenv("NVD_API_KEY")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Puertos críticos conocidos ───────────────────────────────
PUERTOS_CRITICOS = {
    445 : {"peso": 3, "razon": "SMB — EternalBlue, ransomware"},
    135 : {"peso": 2, "razon": "RPC — vector de movimiento lateral"},
    139 : {"peso": 2, "razon": "NetBIOS — enumeración de red"},
    22  : {"peso": 1, "razon": "SSH — fuerza bruta"},
    23  : {"peso": 3, "razon": "Telnet — credenciales en texto plano"},
    21  : {"peso": 2, "razon": "FTP — credenciales en texto plano"},
    3389: {"peso": 3, "razon": "RDP — BlueKeep, fuerza bruta"},
    80  : {"peso": 1, "razon": "HTTP — sin cifrado"},
    8080: {"peso": 1, "razon": "HTTP alternativo"},
    443 : {"peso": 0, "razon": "HTTPS — cifrado OK"},
}

# ── Caché en disco ───────────────────────────────────────────
# ✅ MEJORA 3 — persiste entre ejecuciones
# Ruta del archivo de caché junto al script
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(BASE_DIR, "cache_cve.json")

def cargar_cache() -> Dict:
    """Carga el caché desde disco al iniciar."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"[*] Caché cargado: {len(data)} queries previas ✅")
                return data
        except Exception:
            print("[*] Caché corrupto — iniciando vacío")
            return {}
    return {}

def guardar_cache(cache: Dict):
    """Guarda el caché en disco después de cada consulta."""
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] No se pudo guardar el caché: {e}")

# Cargar caché al inicio del script
_cache_cve: Dict = cargar_cache()

# ── Validación de nmap ───────────────────────────────────────
def verificar_nmap() -> bool:
    try:
        nm = nmap.PortScanner()
        nm.scan('127.0.0.1', '80', arguments='-sV', sudo=False)
        return True
    except nmap.PortScannerError:
        return False
    except Exception:
        return True

# ── Escaneo nmap ─────────────────────────────────────────────
def run_nmap(ip: str) -> List[Dict]:
    """
    Escanea la IP con nmap -sV y devuelve servicios detectados.
    ⚠️  Solo usá contra IPs de tu red local o con autorización.
    """
    try:
        nm = nmap.PortScanner()
        print(f"\n[*] Escaneando {ip} con nmap...")
        print(f"[*] Esto puede tardar 1-3 minutos...")
        nm.scan(ip, '1-1024', arguments='-sV --open')

    except nmap.PortScannerError:
        print("\n❌ nmap no encontrado.")
        print("   https://nmap.org/download — marcá 'Add to PATH'")
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ ERROR en nmap: {e}")
        print("   Corré como Administrador")
        sys.exit(1)

    results = []
    hosts   = nm.all_hosts()

    if not hosts:
        print(f"\n⚠️  Host {ip} no encontrado.")
        return results

    host = hosts[0]
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            entry = nm[host][proto][port]
            results.append({
                'port'     : port,
                'proto'    : proto,
                'service'  : entry.get('name', ''),
                'product'  : entry.get('product', ''),
                'version'  : entry.get('version', ''),
                'extrainfo': entry.get('extrainfo', ''),
                'state'    : entry.get('state', ''),
            })
    return results

# ── Búsqueda de CVEs ─────────────────────────────────────────
def find_cve(product: str, version: str) -> List[Dict]:
    """
    Consulta NVD API con caché en disco, retry y scoring CVSS.

    ✅ Filtra CVEs anteriores a 2015
    ✅ Scoring CVSS v3
    ✅ Query limpio
    ✅ Retry backoff exponencial
    ✅ Top 5 por servicio
    ✅ Caché en disco — persiste entre ejecuciones

    ⚠️  LIMITACIONES:
    - keywordSearch, no CPE → posibles falsos positivos
    - No valida si aplica exactamente a esta versión
    """
    if not product:
        return []

    q = " ".join(filter(None, [product, version]))

    # ✅ CACHÉ EN DISCO — si ya consultamos esto, devolvemos directo
    if q in _cache_cve:
        print(f"    [>] '{q}' (desde caché en disco ⚡)")
        return _cache_cve[q]

    params  = {'keywordSearch': q, 'resultsPerPage': 20}
    headers = {'apiKey': API_KEY}

    print(f"    [>] Buscando CVEs para: {q}")

    for intento in range(3):
        try:
            resp = requests.get(
                NVD_API,
                params=params,
                headers=headers,
                timeout=20
            )

            if resp.status_code == 200:
                break

            if resp.status_code == 403:
                print("    ❌ ERROR 403: API key inválida.")
                return []

            if resp.status_code == 429:
                espera = 2 ** intento * 10
                print(f"    ⚠️  Rate limit. Reintentando en {espera}s "
                      f"(intento {intento + 1}/3)...")
                time.sleep(espera)
                continue

            print(f"    ❌ ERROR HTTP {resp.status_code}")
            return []

        except requests.exceptions.Timeout:
            espera = 2 ** intento
            print(f"    ⚠️  Timeout. Reintentando en {espera}s...")
            time.sleep(espera)
            continue

        except requests.exceptions.ConnectionError:
            print("    ❌ Error de red.")
            return []

        except Exception as e:
            print(f"    ❌ Error: {e}")
            return []
    else:
        print("    ❌ Falló después de 3 intentos.")
        return []

    data    = resp.json()
    results = []

    for v in data.get('vulnerabilities', []):
        cve_id = v['cve']['id']

        if int(cve_id.split('-')[1]) < 2015:
            continue

        score    = None
        severity = None
        metrics  = v['cve'].get('metrics', {})

        if 'cvssMetricV31' in metrics:
            score    = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
        elif 'cvssMetricV30' in metrics:
            score    = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
        elif 'cvssMetricV2' in metrics:
            score    = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
            severity = metrics['cvssMetricV2'][0]['baseSeverity']

        if score is None:
            emoji = "⚪"
            label = "SIN SCORE"
        elif score >= 7.0:
            emoji = "🔴"
            label = "CRÍTICO/ALTO"
        elif score >= 4.0:
            emoji = "🟡"
            label = "MEDIO"
        else:
            emoji = "🟢"
            label = "BAJO"

        results.append({
            'id'      : cve_id,
            'score'   : score,
            'severity': label,
            'emoji'   : emoji,
        })

    results.sort(key=lambda x: x['score'] or 0, reverse=True)
    results = results[:5]

    # Guardar en caché en disco
    _cache_cve[q] = results
    guardar_cache(_cache_cve)

    time.sleep(0.6)
    return results

# ── Calcular riesgo por puerto ───────────────────────────────
def calcular_riesgo(port: int, cves: List[Dict]) -> Dict:
    """
    ✅ MEJORA 1 — Score basado en CVSS real del peor caso
    En vez de contar CVEs, usamos el score más alto real.
    Una sola CVE de 9.8 es más grave que 10 CVEs de 7.0.
    """
    score_base   = PUERTOS_CRITICOS.get(port, {}).get('peso', 0)
    razon_puerto = PUERTOS_CRITICOS.get(port, {}).get('razon', '')

    # ✅ MEJORA 1 — máximo CVSS real en lugar de contar CVEs
    # default=0 evita error si la lista está vacía
    score_cves = max(
        [c['score'] for c in cves if c['score']],
        default=0
    )

    # Normalizar score_cves a escala 0-3 para sumarlo al base
    # CVSS 10.0 → peso 3, CVSS 7.0 → peso 2, CVSS 4.0 → peso 1
    if score_cves >= 9.0:
        peso_cve = 3
    elif score_cves >= 7.0:
        peso_cve = 2
    elif score_cves >= 4.0:
        peso_cve = 1
    else:
        peso_cve = 0

    score_total = min(score_base + peso_cve, 10)

    alertas = []

    if port == 445 and score_cves >= 7.0:
        alertas.append("⚠️  SMB expuesto + CVEs críticas → riesgo alto de ransomware")
    if port == 3389 and score_cves >= 7.0:
        alertas.append("⚠️  RDP expuesto + CVEs críticas → riesgo de acceso remoto")
    if port == 23:
        alertas.append("⚠️  Telnet activo → deshabilitar inmediatamente")
    if port == 21:
        alertas.append("⚠️  FTP activo → reemplazar por SFTP")
    if score_total >= 7:
        alertas.append("🔴 ACCIÓN URGENTE: atención inmediata requerida")
    elif score_total >= 4:
        alertas.append("🟡 ACCIÓN RECOMENDADA: revisar en los próximos días")

    return {
        'score'       : score_total,
        'score_cvss'  : score_cves,
        'razon_puerto': razon_puerto,
        'alertas'     : alertas,
    }

# ── Clasificación del host completo ─────────────────────────
def clasificar_host(resultados: List[Dict]) -> Dict:
    """
    ✅ MEJORA 2 — Clasificación global del host.
    Suma los scores de todos los puertos para dar
    un veredicto ejecutivo del host completo.

    Esto es lo que aparece en un dashboard real:
    no 'puerto X tiene riesgo Y'
    sino 'este host es CRÍTICO'
    """
    riesgo_total = sum(r['riesgo']['score'] for r in resultados)
    cvss_max     = max(
        (r['riesgo']['score_cvss'] for r in resultados),
        default=0
    )

    if riesgo_total >= 15 or cvss_max >= 9.0:
        nivel = "🔴 CRÍTICO"
        accion = "Acción inmediata requerida. Aislar o parchear urgente."
    elif riesgo_total >= 8 or cvss_max >= 7.0:
        nivel = "🟠 ALTO"
        accion = "Revisar y parchear en las próximas 24-48 horas."
    elif riesgo_total >= 4:
        nivel = "🟡 MEDIO"
        accion = "Planificar parches en los próximos días."
    else:
        nivel = "🟢 BAJO"
        accion = "Mantener monitoreo regular."

    return {
        'nivel'        : nivel,
        'riesgo_total' : riesgo_total,
        'cvss_max'     : cvss_max,
        'accion'       : accion,
    }

# ── Exportar reporte ─────────────────────────────────────────
def exportar_reporte(ip: str, services: List,
                     resultados: List, host_info: Dict) -> str:
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    nombre    = f"reporte_{ip.replace('.', '_')}_{timestamp}.json"

    reporte = {
        "metadata": {
            "herramienta"  : f"vuln_hp.py v{VERSION}",
            "desarrollador": CONTACTO['nombre'],
            "portfolio"    : CONTACTO['portfolio'],
            "fecha"        : datetime.now().isoformat(),
            "ip_objetivo"  : ip,
        },
        "clasificacion_host"  : host_info,
        "servicios_detectados": len(services),
        "resultados"          : resultados,
    }

    ruta = os.path.join(BASE_DIR, nombre)
    with open(ruta, 'w', encoding='utf-8') as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    return nombre

# ── Banner ───────────────────────────────────────────────────
def mostrar_banner(ip: str) -> None:
    """Muestra el banner interactivo.
    
    Args:
        ip: Dirección IP objetivo del escaneo.
    """
    print("=" * 60)
    print(f"  🔍 vuln_hp.py — Escáner de servicios + CVEs v{VERSION}")
    print("=" * 60)
    print(f"  👤 Desarrollado por : {CONTACTO['nombre']}")
    print(f"  🌐 Portafolio       : {CONTACTO['portfolio']}")
    print(f"  💼 LinkedIn         : {CONTACTO['linkedin']}")
    print("=" * 60)
    print(f"  🎯 IP objetivo      : {ip}")
    print(f"  📡 Puertos          : 1-1024")
    print(f"  🔑 NVD API          : .env ✅")
    print(f"  📅 Filtro CVEs      : 2015+")
    print(f"  📊 Scoring          : CVSS real (peor caso)")
    print(f"  🔁 Retry            : backoff exponencial")
    print(f"  💾 Caché            : disco (cache_cve.json)")
    print(f"  📋 Límite CVEs      : top 5 por servicio")
    print(f"  🏠 Clasificación    : nivel de riesgo del host")
    print(f"  📄 Export           : JSON automático")
    print("=" * 60)
    print("  ⚠️  USO AUTORIZADO ÚNICAMENTE en redes propias")
    print("  ⚠️  o con permiso explícito del propietario")
    print("=" * 60)

# ── Main ─────────────────────────────────────────────────────
def main() -> None:
    """Punto de entrada principal para la detección y reporte.
    
    Raises:
        SystemExit: Ante configuraciones inválidas o sin conexión.
    """
    if not API_KEY:
        print("❌ ERROR: Falta NVD_API_KEY en el archivo .env")
        print("   NVD_API_KEY=tu_clave_aqui")
        print("   https://nvd.nist.gov/developers/request-an-api-key")
        sys.exit(1)

    if len(sys.argv) != 2:
        print(f"\nUso: python {sys.argv[0]} <IP>")
        print(f"Ejemplo: python {sys.argv[0]} 127.0.0.1")
        sys.exit(1)

    ip = sys.argv[1].strip()
    if not ip:
        print("❌ IP inválida.")
        sys.exit(1)

    mostrar_banner(ip)

    print("[*] Verificando dependencias...")
    if not verificar_nmap():
        print("❌ nmap no disponible.")
        sys.exit(1)
    print("[*] nmap ✅")

    # ── 1. Escaneo ───────────────────────────────────────────
    services = run_nmap(ip)

    if not services:
        print("\n[!] Sin servicios abiertos en 1-1024.")
        sys.exit(0)

    print(f"\n[+] Servicios en {ip}:")
    print(f"{'PROTO':<6} {'PUERTO':<8} {'ESTADO':<12} {'SERVICIO':<12} {'PRODUCTO + VERSIÓN'}")
    print("-" * 60)
    for s in services:
        pv = f"{s['product']} {s['version']} {s['extrainfo']}".strip()
        print(f"{s['proto']:<6} {s['port']:<8} {s['state']:<12} {s['service']:<12} {pv}")

    # ── 2. CVEs + Riesgo ─────────────────────────────────────
    print(f"\n[*] Consultando CVEs (2015+, CVSS real, caché disco)...")
    print("-" * 60)

    encontrados = 0
    con_cves    = []
    sin_cves    = []
    resultados  = []

    for s in services:
        cves   = find_cve(s['product'] or s['service'], s['version'])
        label  = f"{s['service']} | {s['product']} {s['version']}".strip(" |")
        riesgo = calcular_riesgo(s['port'], cves)

        entrada = {
            'puerto'  : s['port'],
            'servicio': label,
            'cves'    : cves,
            'riesgo'  : riesgo,
        }
        resultados.append(entrada)

        if cves:
            encontrados += len(cves)
            con_cves.append((label, cves, s['port'], riesgo))
        else:
            sin_cves.append((label, s['port'], riesgo))

    # Mostrar — mayor riesgo primero
    for label, cves, port, riesgo in sorted(
        con_cves, key=lambda x: x[3]['score'], reverse=True
    ):
        print(f"\n  🚨 PUERTO {port} — {label}")
        if riesgo['razon_puerto']:
            print(f"     ℹ️  {riesgo['razon_puerto']}")
        for cve in cves:
            print(f"     {cve['emoji']} {cve['id']} "
                  f"| CVSS: {cve['score'] or 'N/A'} "
                  f"| {cve['severity']}")
            print(f"       https://nvd.nist.gov/vuln/detail/{cve['id']}")
        for alerta in riesgo['alertas']:
            print(f"     {alerta}")

    for label, port, riesgo in sin_cves:
        print(f"  ✅ Puerto {port} — {label} → sin CVEs (2015+)")

    # ── 3. Clasificación del host ────────────────────────────
    host_info = clasificar_host(resultados)

    # ── 4. Resumen ───────────────────────────────────────────
    criticos = sum(
        1 for _, cves, _, _ in con_cves
        for cve in cves
        if cve['score'] and cve['score'] >= 7.0
    )

    print("\n" + "=" * 60)
    print(f"  📊 RESUMEN")
    print("=" * 60)
    print(f"  🎯 IP              : {ip}")
    print(f"  🔌 Servicios       : {len(services)}")
    print(f"  🚨 Con CVEs        : {len(con_cves)}")
    print(f"  ✅ Limpios         : {len(sin_cves)}")
    print(f"  📋 CVEs (2015+)    : {encontrados}")
    print(f"  🔴 CVEs críticas   : {criticos}")
    print(f"  📈 CVSS máximo     : {host_info['cvss_max']}")
    print("=" * 60)

    # ✅ MEJORA 2 — clasificación ejecutiva del host
    print(f"\n  🏠 NIVEL DE RIESGO DEL HOST: {host_info['nivel']}")
    print(f"  📌 Riesgo total    : {host_info['riesgo_total']}/30")
    print(f"  💡 Acción          : {host_info['accion']}")
    print("=" * 60)
    print(f"  👤 {CONTACTO['nombre']}")
    print(f"  🌐 {CONTACTO['portfolio']}")
    print("=" * 60)

    # ── 5. Exportar JSON ─────────────────────────────────────
    archivo = exportar_reporte(ip, services, resultados, host_info)
    print(f"\n  📄 Reporte: {archivo}")
    print(f"  💾 Caché  : cache_cve.json actualizado")

if __name__ == '__main__':
    main()
