# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Escáner de Puertos Concurrentes
# ═══════════════════════════════════════════════════════════

from __future__ import annotations

import socket
import sys
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# ── Configuración Inicial ────────────────────────────────────
load_dotenv()

CONTACT_NOMBRE = os.getenv("CONTACT_NOMBRE", "Lucas Villagra")
CONTACT_PORTFOLIO = os.getenv("CONTACT_PORTFOLIO", "https://lucas18062025.github.io/Portafolio/")
CONTACT_LINKEDIN = os.getenv("CONTACT_LINKEDIN", "https://www.linkedin.com/in/lucas-villagra-9b5097147/")

def banner(ip: str) -> None:
    """Muestra el banner de inicio.
    
    Args:
        ip: Dirección IP objetivo del escaneo.
    """
    print("=" * 60)
    print("  🔍 scan_ports.py — Escáner de Puertos Rápido v4.0")
    print("=" * 60)
    print(f"  👤 Desarrollado por : {CONTACT_NOMBRE}")
    print(f"  🌐 Portafolio       : {CONTACT_PORTFOLIO}")
    print(f"  💼 LinkedIn         : {CONTACT_LINKEDIN}")
    print("=" * 60)
    print(f"  🎯 IP Meta          : {ip}")
    print("=" * 60)

def es_ip_valida(ip: str) -> bool:
    """Verifica si una cadena es una dirección IPv4 válida.
    
    Args:
        ip: La dirección IP en formato string.
        
    Returns:
        True si es válida, False en caso contrario.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Intenta conectar a un puerto específico en una IP.
    
    Args:
        ip: Dirección IP objetivo.
        port: Puerto TCP a escanear.
        timeout: Segundos antes de abortar la conexión.
        
    Returns:
        True si el puerto está abierto, False en caso de error o cerrado.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

def scan_range(ip: str, start: int = 1, end: int = 1024, workers: int = 200) -> list[int]:
    """Escanea un rango de puertos utilizando múltiples hilos.
    
    Args:
        ip: Dirección IP objetivo.
        start: Puerto de inicio.
        end: Puerto de fin (inclusive).
        workers: Cantidad de hilos paralelos.
        
    Returns:
        Una lista de puertos abiertos ordenados.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in range(start, end + 1)}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return sorted(open_ports)

def main() -> None:
    """Punto de entrada principal para scan_ports.py."""
    
    # ⚠️ Mantenemos temporalmente tu IP para pruebas locales.
    # Antes de subir a GitHub, cambia esto a "127.0.0.1".
    default_ip = "127.0.0.1"

    if len(sys.argv) == 1:
        ip = default_ip
        print(f"[*] No se pasó IP como argumento. Usando IP por defecto: {ip}")
    elif len(sys.argv) == 2:
        ip = sys.argv[1]
    else:
        print(f"Uso: python {sys.argv[0]} [<IP>]")
        sys.exit(1)

    if not es_ip_valida(ip):
        print(f"❌ Error: La dirección IP proporcionada ('{ip}') no es válida.")
        sys.exit(1)

    banner(ip)
    
    print(f"\n[*] Escaneando puertos 1-1024...")
    abiertos = scan_range(ip)

    if abiertos:
        print("\n[+] Puertos abiertos:")
        for p in abiertos:
            print(f"  - {p}")
        print()
    else:
        print("\n[-] No se encontraron puertos abiertos en el rango 1-1024.\n")

if __name__ == "__main__":
    main()