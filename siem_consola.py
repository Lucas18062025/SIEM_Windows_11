# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Entry Point
# Monitor + Telegram + Logs + Memoria + Rate Limiting
# ═══════════════════════════════════════════════════════════
# Modo     : Solo lectura. Riesgo para host: 0/10
# Ejecutar : PowerShell como Administrador
#            python siem_consola.py
# ═══════════════════════════════════════════════════════════

from __future__ import annotations

import platform
import signal
import sys
import threading
from datetime import datetime

from siem.config import SIEMConfig
from siem.event_processor import EventProcessor
from siem.log_manager import LogManager, setup_logging
from siem.notifier import TelegramNotifier


# ── Verificación de plataforma ────────────────────────────
def check_platform() -> None:
    """Verifica que el SIEM se ejecuta en Windows.

    Raises:
        SystemExit: Si no se está en Windows.
    """
    if platform.system() != "Windows":
        print("❌ Este SIEM requiere Windows (usa win32evtlog).")
        print(f"   Sistema detectado: {platform.system()}")
        sys.exit(1)


# ── Banner ────────────────────────────────────────────────
def show_banner(config: SIEMConfig) -> None:
    """Muestra el banner de inicio del SIEM.

    Args:
        config: Configuración del SIEM.
    """
    print("=" * 60)
    print(f"  🛡️  SIEM Personal v{config.version} — Monitor + Telegram + Logs")
    print("=" * 60)
    print(f"  👤 Desarrollado por : {config.contact_nombre}")
    print(f"  🌐 Portafolio       : {config.contact_portfolio}")
    print(f"  💼 LinkedIn         : {config.contact_linkedin}")
    print("=" * 60)
    print(f"  🖥️  Host             : {config.hostname}")
    print(f"  ⏰ Iniciado         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  📡 Monitoreando     : {', '.join(config.event_logs)}")
    print(f"  🔒 Modo             : {config.mode} — Host SIN CAMBIOS")
    print(f"  📁 Logs             : {config.logs_dir}")
    print(f"  🚨 Alertas          : {config.alerts_dir}")
    print(f"  🧹 Memoria          : ventana {config.memory_window // 3600}h — cap {config.max_events:,}")
    print(f"  📵 Cooldown Telegram: {config.tg_cooldown}s por tipo + {config.tg_global_limit} msgs/min global")
    print(f"  🗑️  Rotación logs    : {config.rotation_days} días — máx {config.max_file_size_mb} MB/archivo")
    print(f"  🔑 Token Telegram   : {config.telegram_token_masked}")
    print("=" * 60)


# ── Main ──────────────────────────────────────────────────
def main() -> None:
    """Punto de entrada principal del SIEM.

    Inicializa todos los componentes, ejecuta el loop de
    monitoreo y maneja shutdown limpio via Ctrl+C o signal.
    """
    # 1. Verificar plataforma
    check_platform()

    # 2. Cargar configuración
    config = SIEMConfig()

    # 3. Configurar logging
    setup_logging(config)

    # 4. Inicializar componentes
    notifier = TelegramNotifier(config)
    log_manager = LogManager(config)
    processor = EventProcessor(config, notifier, log_manager)

    # 5. Evento de shutdown (para sleep interruptible)
    shutdown_event = threading.Event()

    def signal_handler(signum: int, frame: object) -> None:
        """Maneja señales de shutdown."""
        shutdown_event.set()

    # Registrar handlers de señales (Windows compatible)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # SIGBREAK es específico de Windows (Ctrl+Break)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal_handler)

    # 6. Mostrar banner
    show_banner(config)

    # 7. Enviar notificación de inicio
    notifier.send_startup(
        hostname=config.hostname,
        version=config.version,
        contact_name=config.contact_nombre,
        rotation_days=config.rotation_days,
        memory_window=config.memory_window,
        cooldown=config.tg_cooldown,
    )

    print("\n[*] Escaneando eventos... (Ctrl+C para detener)\n")

    # 8. Loop principal
    cycle = 0

    try:
        while not shutdown_event.is_set():
            cycle += 1

            # Procesar eventos
            new_events = processor.process_cycle()

            # Limpieza periódica
            if cycle % config.cleanup_every == 0:
                processor.cleanup_memory()
                log_manager.rotate()

            # Status line
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Ciclo {cycle} | "
                f"Memoria: {processor.events_in_memory:,} eventos | "
                f"Próximo en {config.scan_interval}s...",
                end="\r",
            )

            # Sleep interruptible (responde a señales inmediatamente)
            shutdown_event.wait(timeout=config.scan_interval)

    except KeyboardInterrupt:
        pass  # Manejado por signal_handler
    finally:
        # ── Shutdown limpio ───────────────────────────────
        print(f"\n\n[*] SIEM detenido. Host intacto. ✅")
        print(f"[*] Ciclos ejecutados  : {cycle}")
        print(f"[*] Eventos en memoria : {processor.events_in_memory:,}")

        log_stats = log_manager.get_stats()
        print(
            f"[*] Archivos de log    : {log_stats['total_files']} "
            f"({log_stats['total_size_mb']} MB)"
        )

        log_manager.write_event("SIEM detenido manualmente.")

        notifier.send_shutdown(
            contact_name=config.contact_nombre,
            cycle_count=cycle,
            events_in_memory=processor.events_in_memory,
        )


if __name__ == "__main__":
    main()
