# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Procesador de Eventos
# ═══════════════════════════════════════════════════════════

"""
Módulo de lectura y procesamiento de eventos de Windows.

Lee eventos del Event Log de Windows, los deduplica con hash
robusto, administra memoria con cap máximo, y coordina con
el notificador y el log manager.
"""

from __future__ import annotations

import calendar
import html
import logging
import time
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, Deque, Dict, List, Optional, Tuple

import win32evtlog

if TYPE_CHECKING:
    from siem.config import SIEMConfig
    from siem.log_manager import LogManager
    from siem.notifier import TelegramNotifier

from siem.models import EventData

logger = logging.getLogger("siem.events")


class EventProcessor:
    """Procesador de eventos de seguridad de Windows.

    Lee eventos del Windows Event Log, los filtra por Event IDs
    configurados, los deduplica con hash robusto, y coordina
    el flujo de alertas y logging.

    Features:
        - Deduplicación con hash SHA-256 (RecordNumber + LogType + EventID + Timestamp).
        - Memoria con cap máximo configurable (previene OOM).
        - Limpieza automática por ventana de tiempo.
        - Sanitización de StringInserts antes de procesamiento.
        - Tracking del último RecordNumber por log type.

    Args:
        config: Instancia de SIEMConfig.
        notifier: Instancia de TelegramNotifier.
        log_manager: Instancia de LogManager.
    """

    def __init__(
        self,
        config: SIEMConfig,
        notifier: TelegramNotifier,
        log_manager: LogManager,
    ) -> None:
        self._config: SIEMConfig = config
        self._notifier: TelegramNotifier = notifier
        self._log_manager: LogManager = log_manager

        # Memoria de eventos procesados
        self._seen_events: Dict[str, float] = {}
        self._event_queue: Deque[Tuple[str, float]] = deque()

        # Último RecordNumber procesado por tipo de log
        self._last_record: Dict[str, int] = {}

    # ── Propiedades ───────────────────────────────────────
    @property
    def events_in_memory(self) -> int:
        """Número de eventos actualmente en memoria."""
        return len(self._seen_events)

    # ── Lectura de Eventos Windows ────────────────────────
    def read_events(self, log_type: str) -> List:
        """Lee los últimos eventos de un log de Windows.

        Args:
            log_type: Tipo de log ('Security', 'System').

        Returns:
            Lista de eventos leídos (objetos win32evtlog).
        """
        try:
            handle = win32evtlog.OpenEventLog("localhost", log_type)
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            win32evtlog.CloseEventLog(handle)
            return events[: self._config.events_per_read]

        except Exception as exc:
            logger.error("[ERROR] No se pudo leer %s: %s", log_type, exc)
            return []

    # ── Procesamiento ─────────────────────────────────────
    def process_cycle(self) -> int:
        """Ejecuta un ciclo completo de lectura y procesamiento.

        Lee eventos de todos los logs configurados, los filtra,
        deduplica y procesa los nuevos.

        Returns:
            Número de eventos nuevos procesados en este ciclo.
        """
        new_events = 0

        for log_type in self._config.event_logs:
            events = self.read_events(log_type)

            for event in events:
                eid = event.EventID & 0xFFFF

                # Solo procesar eventos que nos interesan
                if eid not in self._config.critical_events:
                    continue

                # Generar hash de deduplicación
                ts_str = event.TimeGenerated.Format()
                record_hash = EventData.compute_hash(
                    record_number=event.RecordNumber,
                    log_type=log_type,
                    event_id=eid,
                    timestamp=ts_str,
                )

                # Verificar si ya lo procesamos
                if record_hash in self._seen_events:
                    continue

                # Registrar en memoria
                ts_real = float(
                    calendar.timegm(event.TimeGenerated.timetuple())
                )
                self._register_event(record_hash, ts_real)

                # Crear EventData tipado
                event_data = self._build_event_data(
                    event, eid, ts_str, log_type, record_hash
                )

                # Procesar el evento
                self._handle_event(event_data)
                new_events += 1

        return new_events

    def _build_event_data(
        self,
        raw_event: object,
        eid: int,
        timestamp: str,
        log_type: str,
        record_hash: str,
    ) -> EventData:
        """Construye un EventData tipado desde un evento crudo de Windows.

        Sanitiza los StringInserts para prevenir inyección HTML.

        Args:
            raw_event: Evento crudo de win32evtlog.
            eid: Event ID (masked con 0xFFFF).
            timestamp: Timestamp formateado.
            log_type: Tipo de log de origen.
            record_hash: Hash de deduplicación.

        Returns:
            EventData inmutable con datos sanitizados.
        """
        inserts = raw_event.StringInserts or []

        # Sanitizar cada insert: escapar HTML + truncar
        safe_inserts = []
        for insert in inserts[:4]:
            safe = html.escape(str(insert), quote=True)
            if len(safe) > 200:
                safe = safe[:197] + "..."
            safe_inserts.append(safe)

        details = " | ".join(safe_inserts)

        return EventData(
            event_id=eid,
            description=self._config.critical_events[eid],
            timestamp=timestamp,
            log_type=log_type,
            details=details,
            is_alert=eid in self._config.alert_events,
            record_number=raw_event.RecordNumber,
            record_hash=record_hash,
        )

    def _handle_event(self, event: EventData) -> None:
        """Procesa un evento: lo muestra, lo guarda y lo notifica.

        Args:
            event: EventData a procesar.
        """
        emoji = "🚨" if event.is_alert else "⚪"
        contact = self._config.contact_nombre

        # ── Mostrar en consola ────────────────────────────
        print(f"\n{'─' * 60}")
        print(f"  {emoji} {event.description}")
        print(f"  📅 Timestamp : {event.timestamp}")
        print(f"  📋 Log       : {event.log_type}")
        print(f"  🔢 Event ID  : {event.event_id}")
        if event.details:
            print(f"  📝 Detalles  : {event.details}")
        print(f"  👤 Monitor   : {contact}")
        print(f"{'─' * 60}")

        # ── Guardar en archivo ────────────────────────────
        line = (
            f"EventID={event.event_id} | "
            f"{event.description} | "
            f"Log={event.log_type} | "
            f"{event.details}"
        )
        self._log_manager.write_event(line, event.is_alert)

        dest = "Alertas/" if event.is_alert else "Logs/"
        print(f"  💾 Guardado en {dest}")

        # ── Notificar a Telegram (solo alertas) ───────────
        if event.is_alert:
            msg = (
                f"<b>🛡️ SIEM — {self._notifier.sanitize(contact)}</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"<b>Evento:</b> {emoji} {self._notifier.sanitize(event.description)}\n"
                f"<b>ID:</b> {event.event_id} | <b>Log:</b> {event.log_type}\n"
                f"<b>Hora:</b> {event.timestamp}\n"
                f"<b>Info:</b> {event.details if event.details else 'N/A'}\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"📧 {self._notifier.sanitize(self._config.contact_email)}\n"
                f"🌐 {self._notifier.sanitize(self._config.contact_portfolio)}\n"
                f"💼 {self._notifier.sanitize(self._config.contact_linkedin)}"
            )
            self._notifier.send(msg, event.event_id)

    # ── Memoria ───────────────────────────────────────────
    def _register_event(self, event_hash: str, timestamp: float) -> None:
        """Registra un evento en la memoria de deduplicación.

        Si la memoria excede el cap máximo, fuerza una limpieza.

        Args:
            event_hash: Hash único del evento.
            timestamp: Timestamp real del evento.
        """
        self._seen_events[event_hash] = timestamp
        self._event_queue.append((event_hash, timestamp))

        # Forzar limpieza si excedemos el cap
        if len(self._seen_events) > self._config.max_events:
            logger.warning(
                "⚠️  Memoria al límite (%d eventos). Limpieza forzada...",
                len(self._seen_events),
            )
            self.cleanup_memory(force=True)

    def cleanup_memory(self, force: bool = False) -> int:
        """Limpia eventos expirados de la memoria.

        Elimina eventos más antiguos que la ventana de memoria.
        Si `force` es True, también elimina el 25% más antiguo
        para liberar espacio.

        Args:
            force: Si True, limpieza agresiva (25% más antiguo).

        Returns:
            Número de eventos eliminados.
        """
        before = len(self._seen_events)
        now = time.time()
        window = self._config.memory_window

        # Limpiar por ventana de tiempo
        while self._event_queue:
            event_hash, ts = self._event_queue[0]
            if now - ts > window:
                self._event_queue.popleft()
                self._seen_events.pop(event_hash, None)
            else:
                break

        # Limpieza agresiva: eliminar 25% más antiguo
        if force and self._event_queue:
            to_remove = len(self._event_queue) // 4
            for _ in range(to_remove):
                if self._event_queue:
                    event_hash, _ = self._event_queue.popleft()
                    self._seen_events.pop(event_hash, None)

        after = len(self._seen_events)
        removed = before - after

        if removed > 0:
            logger.info(
                "🧹 Memoria: %d eventos expirados eliminados "
                "(quedan %d)",
                removed, after,
            )

        return removed
