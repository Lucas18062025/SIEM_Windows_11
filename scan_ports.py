# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Escáner de Puertos Concurrentes
# ═══════════════════════════════════════════════════════════

from __future__ import annotations

import socket
import sys
import os
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# ── Configuración Inicial ────────────────────────────────────
load_dotenv()

CONTACT_NOMBRE = os.getenv("CONTACT_NOMBRE", "Lucas Villagra")
CONTACT_EMAIL = os.getenv("CONTACT_EMAIL", "lucaslean1806@gmail.com")
CONTACT_PORTFOLIO = os.getenv("CONTACT_PORTFOLIO", "https://portafolio.lucaslean1806.workers.dev/")
CONTACT_LINKEDIN = os.getenv("CONTACT_LINKEDIN", "https://www.linkedin.com/in/lucas-villagra-cybersecurity/")

def banner(ip: str) -> None:
    """Muestra el banner de inicio.
    
    Args:
        ip: Dirección IP objetivo del escaneo.
    """
    print("=" * 60)
    print("  🔍 scan_ports.py — Escáner de Puertos Rápido v4.0")
    print("=" * 60)
    print(f"  👤 Desarrollado por : {CONTACT_NOMBRE}")
    print(f"  📧 Email            : {CONTACT_EMAIL}")
    print(f"  🌐 Portafolio       : {CONTACT_PORTFOLIO}")
    print(f"  💼 LinkedIn         : {CONTACT_LINKEDIN}")
    print("=" * 60)
    print(f"  🎯 IP Meta          : {ip}")
    print("=" * 60)

def resolver_objetivo(objetivo: str) -> str:
    """Resuelve un objetivo a IPv4: acepta IP literal o hostname.

    Args:
        objetivo: Dirección IP o hostname a resolver.

    Returns:
        La IPv4 como string.

    Raises:
        ValueError: Si no es IP válida ni hostname resoluble.
    """
    try:
        return str(ipaddress.ip_address(objetivo))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(objetivo)
    except socket.gaierror:
        raise ValueError(f"No se pudo resolver '{objetivo}' como IP ni hostname.")

def es_ip_valida(ip: str) -> bool:
    """Verifica si una cadena es IPv4 válida o hostname resoluble.

    Args:
        ip: La dirección IP u hostname en formato string.

    Returns:
        True si es válida o resoluble, False en caso contrario.
    """
    try:
        resolver_objetivo(ip)
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

def scan_range(ip: str, start: int = 1, end: int = 1024, workers: int = 50, timeout: float = 1.0) -> list[int]:
    """Escanea un rango de puertos utilizando múltiples hilos.

    Args:
        ip: Dirección IP objetivo.
        start: Puerto de inicio.
        end: Puerto de fin (inclusive).
        workers: Cantidad de hilos paralelos (defecto 50, bajo impacto LAN).
        timeout: Timeout por conexión en segundos.

    Returns:
        Una lista de puertos abiertos ordenados.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout): p for p in range(start, end + 1)}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return sorted(open_ports)

def main() -> None:
    """Punto de entrada principal para scan_ports.py."""
    
    default_ip = "127.0.0.1"
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    salida_json = "--json" in sys.argv[1:]

    if len(args) == 0:
        ip = default_ip
        if not salida_json:
            print(f"[*] No se pasó IP como argumento. Usando IP por defecto: {ip}")
    elif len(args) == 1:
        ip = args[0]
    else:
        print(f"Uso: python {sys.argv[0]} [<IP|hostname>] [--json]")
        sys.exit(1)

    try:
        objetivo = resolver_objetivo(ip)
    except ValueError:
        print(f"❌ Error: El objetivo ('{ip}') no es IP válida ni hostname resoluble.")
        sys.exit(1)

    if not salida_json:
        banner(f"{ip}" + (f" → {objetivo}" if objetivo != ip else ""))
        print(f"\n[*] Escaneando puertos 1-1024 (50 hilos, timeout 1s)...")
    abiertos = scan_range(objetivo)

    if salida_json:
        print(json.dumps({"target": ip, "ip": objetivo, "open_ports": abiertos}))
        return

    if abiertos:
        print("\n[+] Puertos abiertos:")
        for p in abiertos:
            print(f"  - {p}")
        print()
    else:
        print("\n[-] No se encontraron puertos abiertos en el rango 1-1024.\n")

if __name__ == "__main__":
    main()