# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Modelos de datos
# ═══════════════════════════════════════════════════════════

"""
Dataclasses tipadas para el SIEM.
Define las estructuras de datos que se pasan entre módulos.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class EventData:
    """Representa un evento de seguridad de Windows procesado.

    Attributes:
        event_id: ID del evento de Windows (ej: 4625).
        description: Descripción legible del evento.
        timestamp: Timestamp formateado del evento.
        log_type: Tipo de log de origen ('Security', 'System').
        details: Detalles del evento (StringInserts sanitizados).
        is_alert: Si el evento dispara una alerta a Telegram.
        record_number: Número de registro original de Windows.
        record_hash: Hash único para deduplicación.
    """

    event_id: int
    description: str
    timestamp: str
    log_type: str
    details: str
    is_alert: bool
    record_number: int
    record_hash: str

    @staticmethod
    def compute_hash(
        record_number: int,
        log_type: str,
        event_id: int,
        timestamp: str,
    ) -> str:
        """Genera un hash único para deduplicación robusto.

        Combina RecordNumber + LogType + EventID + Timestamp
        para evitar colisiones incluso después de reboots de Windows
        (donde RecordNumber puede reiniciarse).

        Args:
            record_number: Número de registro del evento.
            log_type: Tipo de log ('Security', 'System').
            event_id: ID del evento.
            timestamp: Timestamp del evento como string.

        Returns:
            Hash SHA-256 truncado a 16 caracteres hexadecimales.
        """
        raw = f"{record_number}|{log_type}|{event_id}|{timestamp}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class RateLimitState:
    """Estado del rate limiter para Telegram.

    Implementa un sistema doble:
    - Por tipo de evento: cooldown individual.
    - Global: token bucket con ventana de 1 minuto.

    Attributes:
        last_sent_by_type: Último timestamp de envío por EventID.
        global_timestamps: Lista de timestamps de envíos recientes.
    """

    last_sent_by_type: Dict[int, float] = field(default_factory=dict)
    global_timestamps: List[float] = field(default_factory=list)

    def can_send(
        self,
        event_id: int,
        now: float,
        cooldown_seconds: float,
        global_limit_per_minute: int,
    ) -> bool:
        """Verifica si se puede enviar un mensaje para este evento.

        Args:
            event_id: ID del evento a notificar.
            now: Timestamp actual (time.time()).
            cooldown_seconds: Cooldown por tipo de evento en segundos.
            global_limit_per_minute: Máximo de mensajes globales por minuto.

        Returns:
            True si se puede enviar, False si hay rate limit activo.
        """
        # Check cooldown por tipo
        if event_id in self.last_sent_by_type:
            if now - self.last_sent_by_type[event_id] < cooldown_seconds:
                return False

        # Check rate limit global (ventana de 1 minuto)
        self._cleanup_global(now)
        if len(self.global_timestamps) >= global_limit_per_minute:
            return False

        return True

    def record_send(self, event_id: int, now: float) -> None:
        """Registra que se envió un mensaje.

        Args:
            event_id: ID del evento notificado.
            now: Timestamp actual.
        """
        self.last_sent_by_type[event_id] = now
        self.global_timestamps.append(now)

    def _cleanup_global(self, now: float) -> None:
        """Limpia timestamps de más de 60 segundos."""
        cutoff = now - 60.0
        self.global_timestamps = [
            ts for ts in self.global_timestamps if ts > cutoff
        ]

    def get_cooldown_remaining(
        self, event_id: int, now: float, cooldown_seconds: float
    ) -> Optional[float]:
        """Retorna segundos restantes de cooldown, o None si no hay.

        Args:
            event_id: ID del evento.
            now: Timestamp actual.
            cooldown_seconds: Cooldown configurado.

        Returns:
            Segundos restantes o None si no hay cooldown activo.
        """
        if event_id in self.last_sent_by_type:
            elapsed = now - self.last_sent_by_type[event_id]
            if elapsed < cooldown_seconds:
                return cooldown_seconds - elapsed
        return None
