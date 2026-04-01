# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Paquete principal
# ═══════════════════════════════════════════════════════════

"""
Paquete siem — Monitor de eventos de seguridad para Windows 11.

Módulos:
    config          — Carga y validación de configuración
    models          — Dataclasses tipadas para eventos y alertas
    notifier        — Notificaciones Telegram con rate limiting
    log_manager     — Gestión de logs con rotación inteligente
    event_processor — Lectura y procesamiento de eventos Windows
"""

__version__ = "4.0.0"
__author__ = "Lucas Villagra"

from siem.config import SIEMConfig
from siem.models import EventData, RateLimitState
from siem.notifier import TelegramNotifier
from siem.log_manager import LogManager
from siem.event_processor import EventProcessor

__all__ = [
    "SIEMConfig",
    "EventData",
    "RateLimitState",
    "TelegramNotifier",
    "LogManager",
    "EventProcessor",
]
