# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Notificador Telegram
# ═══════════════════════════════════════════════════════════

"""
Módulo de notificaciones Telegram.

Envía alertas con rate limiting doble (por tipo + global),
sanitización HTML, y retry con backoff exponencial.
"""

from __future__ import annotations

import html
import logging
import time
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from siem.config import SIEMConfig

from siem.models import RateLimitState

logger = logging.getLogger("siem.notifier")


class TelegramNotifier:
    """Notificador Telegram con protecciones de seguridad.

    Features:
        - Rate limiting por tipo de evento (cooldown individual).
        - Rate limiting global (máx N mensajes/minuto).
        - Sanitización HTML de campos de texto.
        - Truncamiento de campos largos.
        - Retry con backoff exponencial.
        - Token nunca se expone en logs.

    Args:
        config: Instancia de SIEMConfig con las credenciales y settings.
    """

    # Límite de caracteres por campo de detalle
    MAX_DETAIL_LENGTH: int = 200

    def __init__(self, config: SIEMConfig) -> None:
        self._token: str = config.telegram_token
        self._chat_id: str = config.telegram_chat_id
        self._timeout: int = config.tg_timeout
        self._max_retries: int = config.tg_max_retries
        self._cooldown: int = config.tg_cooldown
        self._global_limit: int = config.tg_global_limit
        self._rate_state: RateLimitState = RateLimitState()
        self._api_url: str = (
            f"https://api.telegram.org/bot{self._token}/sendMessage"
        )

    # ── Sanitización ──────────────────────────────────────
    @staticmethod
    def sanitize(text: str, max_length: int = 200) -> str:
        """Sanitiza texto para envío seguro en HTML de Telegram.

        Escapa caracteres HTML peligrosos y trunca campos largos
        para prevenir inyección de HTML en mensajes de Telegram.

        Args:
            text: Texto a sanitizar.
            max_length: Largo máximo permitido.

        Returns:
            Texto sanitizado y truncado.
        """
        # Escapar HTML para prevenir inyección
        safe = html.escape(str(text), quote=True)
        # Eliminar caracteres de control (excepto newline)
        safe = "".join(
            c for c in safe
            if c == "\n" or (ord(c) >= 32 and ord(c) != 127)
        )
        # Truncar si es necesario
        if len(safe) > max_length:
            safe = safe[:max_length - 3] + "..."
        return safe

    # ── Rate Limiting ─────────────────────────────────────
    def can_send(self, event_id: int) -> bool:
        """Verifica si se puede enviar un mensaje para este evento.

        Aplica doble rate limiting:
        1. Cooldown por tipo de evento (ej: no repetir 4625 en 60s).
        2. Límite global por minuto (ej: máx 20 msgs/min).

        Args:
            event_id: ID del evento.

        Returns:
            True si se puede enviar, False si hay rate limit.
        """
        return self._rate_state.can_send(
            event_id=event_id,
            now=time.time(),
            cooldown_seconds=self._cooldown,
            global_limit_per_minute=self._global_limit,
        )

    def get_rate_limit_reason(self, event_id: int) -> str:
        """Retorna la razón del rate limit activo.

        Args:
            event_id: ID del evento.

        Returns:
            Descripción del rate limit activo, o cadena vacía.
        """
        now = time.time()
        remaining = self._rate_state.get_cooldown_remaining(
            event_id, now, self._cooldown
        )
        if remaining is not None:
            return f"cooldown activo ({remaining:.0f}s restantes) para evento {event_id}"

        self._rate_state._cleanup_global(now)
        if len(self._rate_state.global_timestamps) >= self._global_limit:
            return f"límite global alcanzado ({self._global_limit} msgs/min)"

        return ""

    # ── Envío ─────────────────────────────────────────────
    def send(self, message: str, event_id: int) -> bool:
        """Envía un mensaje a Telegram con rate limiting y retry.

        Args:
            message: Mensaje en formato HTML de Telegram.
            event_id: ID del evento (para rate limiting).

        Returns:
            True si se envió exitosamente, False en caso contrario.
        """
        # Verificar rate limit
        if not self.can_send(event_id):
            reason = self.get_rate_limit_reason(event_id)
            logger.info("📱 Telegram: %s", reason)
            return False

        # Intentar envío con retry
        for attempt in range(self._max_retries):
            try:
                response = requests.post(
                    self._api_url,
                    json={
                        "chat_id": self._chat_id,
                        "text": message,
                        "parse_mode": "HTML",
                    },
                    timeout=self._timeout,
                    verify=True,  # Verificar certificados SSL
                )

                if response.status_code == 200:
                    self._rate_state.record_send(event_id, time.time())
                    logger.info("📱 Telegram: alerta enviada ✅")
                    return True

                if response.status_code == 429:
                    # Rate limit de la API de Telegram
                    wait = 2 ** attempt * 5
                    logger.warning(
                        "📱 Telegram: rate limit API (429). "
                        "Reintentando en %ds (intento %d/%d)...",
                        wait, attempt + 1, self._max_retries,
                    )
                    time.sleep(wait)
                    continue

                logger.error(
                    "📱 Telegram ERROR %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                return False

            except requests.exceptions.Timeout:
                wait = 2 ** attempt
                logger.warning(
                    "📱 Telegram: timeout. Reintentando en %ds "
                    "(intento %d/%d)...",
                    wait, attempt + 1, self._max_retries,
                )
                time.sleep(wait)
                continue

            except requests.exceptions.ConnectionError:
                logger.error("📱 Telegram: error de red — sin conexión")
                return False

            except requests.exceptions.RequestException as exc:
                logger.error("📱 Telegram: error inesperado — %s", exc)
                return False

        logger.error(
            "📱 Telegram: falló después de %d intentos",
            self._max_retries,
        )
        return False

    # ── Mensajes Predefinidos ─────────────────────────────
    def send_startup(
        self,
        hostname: str,
        version: str,
        contact_name: str,
        rotation_days: int,
        memory_window: int,
        cooldown: int,
    ) -> bool:
        """Envía notificación de inicio del SIEM.

        Args:
            hostname: Nombre del host.
            version: Versión del SIEM.
            contact_name: Nombre del operador.
            rotation_days: Días de rotación de logs.
            memory_window: Ventana de memoria en segundos.
            cooldown: Cooldown por tipo de evento.

        Returns:
            True si se envió.
        """
        from datetime import datetime

        msg = (
            f"🛡️ <b>SIEM v{self.sanitize(version)} iniciado</b>\n"
            f"Monitor activo en <b>{self.sanitize(hostname)}</b>\n"
            f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"👤 {self.sanitize(contact_name)}\n"
            f"📁 Logs + rotación {rotation_days} días\n"
            f"🧹 Memoria: ventana {memory_window // 3600}h\n"
            f"📵 Rate limit: {cooldown}s por evento + "
            f"{self._global_limit} msgs/min global"
        )
        return self.send(msg, event_id=0)

    def send_shutdown(
        self,
        contact_name: str,
        cycle_count: int,
        events_in_memory: int,
    ) -> bool:
        """Envía notificación de detención del SIEM.

        Args:
            contact_name: Nombre del operador.
            cycle_count: Ciclos ejecutados.
            events_in_memory: Eventos en memoria.

        Returns:
            True si se envió.
        """
        from datetime import datetime

        msg = (
            f"⚪ <b>SIEM detenido</b>\n"
            f"👤 {self.sanitize(contact_name)}\n"
            f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"📊 Ciclos: {cycle_count} | "
            f"Memoria: {events_in_memory}"
        )
        return self.send(msg, event_id=0)
