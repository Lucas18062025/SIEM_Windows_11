# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Configuración
# ═══════════════════════════════════════════════════════════

"""
Módulo de configuración del SIEM.

Carga config.yaml + .env, valida formatos y proporciona
acceso tipado a toda la configuración del sistema.
"""

from __future__ import annotations

import os
import re
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

import yaml
from dotenv import load_dotenv


class SIEMConfig:
    """Configuración centralizada del SIEM.

    Carga configuración desde config.yaml y secrets desde .env,
    validando formatos y proporcionando acceso seguro.

    Attributes:
        base_dir: Directorio raíz del proyecto.
        version: Versión del SIEM.
        hostname: Nombre del host (detectado automáticamente).
    """

    # Regex para validar formato del token de Telegram
    _TOKEN_REGEX = re.compile(r"^\d{8,15}:[\w-]{30,50}$")
    # Regex para validar Chat ID (numérico, puede ser negativo para grupos)
    _CHAT_ID_REGEX = re.compile(r"^-?\d{5,15}$")

    def __init__(self, config_path: str | None = None) -> None:
        """Inicializa la configuración del SIEM.

        Args:
            config_path: Ruta al archivo config.yaml.
                Si es None, busca en el directorio del script.

        Raises:
            FileNotFoundError: Si config.yaml no existe.
            ValueError: Si los secrets o la config son inválidos.
        """
        self.base_dir: Path = Path(__file__).resolve().parent.parent
        self.hostname: str = socket.gethostname()

        # Cargar .env
        env_path = self.base_dir / ".env"
        if env_path.exists():
            load_dotenv(env_path)
        else:
            print(f"⚠️  Archivo .env no encontrado en: {env_path}")
            print(f"   Copiá .env.example como .env y completá tus datos.")
            sys.exit(1)

        # Cargar config.yaml
        if config_path is None:
            config_path = str(self.base_dir / "config.yaml")

        if not Path(config_path).exists():
            print(f"❌ Archivo config.yaml no encontrado: {config_path}")
            sys.exit(1)

        with open(config_path, "r", encoding="utf-8") as f:
            self._raw: Dict[str, Any] = yaml.safe_load(f)

        # Validar y cargar secrets
        self._load_secrets()

        # Cargar secciones de configuración
        self._load_siem()
        self._load_timing()
        self._load_telegram_config()
        self._load_logs()
        self._load_monitoring()
        self._load_contact()

        # Crear directorios necesarios
        self._ensure_directories()

    # ── Secrets ───────────────────────────────────────────
    def _load_secrets(self) -> None:
        """Carga y valida secrets desde variables de entorno."""
        token = os.getenv("TELEGRAM_TOKEN", "")
        chat_id = os.getenv("TELEGRAM_CHAT_ID", "")

        if not token or not chat_id:
            print("❌ Faltan variables de entorno en .env:")
            print("   TELEGRAM_TOKEN=tu_token")
            print("   TELEGRAM_CHAT_ID=tu_chat_id")
            sys.exit(1)

        if not self._TOKEN_REGEX.match(token):
            print("❌ TELEGRAM_TOKEN tiene formato inválido.")
            print("   Formato esperado: 1234567890:ABCdefGHI...")
            sys.exit(1)

        if not self._CHAT_ID_REGEX.match(chat_id):
            print("❌ TELEGRAM_CHAT_ID debe ser numérico.")
            sys.exit(1)

        self._telegram_token: str = token
        self._telegram_chat_id: str = chat_id

    @property
    def telegram_token(self) -> str:
        """Token de Telegram (acceso controlado)."""
        return self._telegram_token

    @property
    def telegram_chat_id(self) -> str:
        """Chat ID de Telegram."""
        return self._telegram_chat_id

    @property
    def telegram_token_masked(self) -> str:
        """Token de Telegram enmascarado para logs.

        Returns:
            Token con solo los últimos 4 caracteres visibles.
            Ejemplo: '***FvA'
        """
        if len(self._telegram_token) > 4:
            return f"***{self._telegram_token[-4:]}"
        return "***"

    # ── SIEM ──────────────────────────────────────────────
    def _load_siem(self) -> None:
        """Carga sección 'siem' de la config."""
        siem = self._raw.get("siem", {})
        self.version: str = siem.get("version", "4.0.0")
        self.mode: str = siem.get("mode", "solo_lectura")

    # ── Timing ────────────────────────────────────────────
    def _load_timing(self) -> None:
        """Carga sección 'timing' de la config."""
        timing = self._raw.get("timing", {})
        self.scan_interval: int = int(timing.get("scan_interval_seconds", 10))
        self.memory_window: int = int(timing.get("memory_window_seconds", 3600))
        self.cleanup_every: int = int(timing.get("cleanup_every_n_cycles", 10))
        self.max_events: int = int(timing.get("max_events_in_memory", 50000))

    # ── Telegram Config ───────────────────────────────────
    def _load_telegram_config(self) -> None:
        """Carga sección 'telegram' de la config."""
        tg = self._raw.get("telegram", {})
        self.tg_cooldown: int = int(tg.get("cooldown_per_type_seconds", 60))
        self.tg_global_limit: int = int(tg.get("global_rate_limit_per_minute", 20))
        self.tg_timeout: int = int(tg.get("request_timeout_seconds", 5))
        self.tg_max_retries: int = int(tg.get("max_retries", 3))

    # ── Logs ──────────────────────────────────────────────
    def _load_logs(self) -> None:
        """Carga sección 'logs' de la config."""
        logs = self._raw.get("logs", {})
        self.logs_dir: Path = self.base_dir / logs.get("directory", "Logs")
        self.alerts_dir: Path = self.base_dir / logs.get("alerts_directory", "Alertas")
        self.rotation_days: int = int(logs.get("rotation_days", 30))
        self.max_file_size_mb: int = int(logs.get("max_file_size_mb", 50))
        self.compress_old: bool = bool(logs.get("compress_old", True))
        self.log_format: str = logs.get("format", "text")

    # ── Monitoring ────────────────────────────────────────
    def _load_monitoring(self) -> None:
        """Carga sección 'monitoring' de la config."""
        monitoring = self._raw.get("monitoring", {})
        self.event_logs: List[str] = monitoring.get("event_logs", ["Security", "System"])
        self.events_per_read: int = int(monitoring.get("events_per_read", 50))

        # Eventos críticos: {EventID: "Descripción"}
        raw_critical = monitoring.get("critical_events", {})
        self.critical_events: Dict[int, str] = {
            int(k): str(v) for k, v in raw_critical.items()
        }

        # Eventos de alerta: set de EventIDs
        raw_alerts = monitoring.get("alert_events", [])
        self.alert_events: Set[int] = {int(e) for e in raw_alerts}

    # ── Contact ───────────────────────────────────────────
    def _load_contact(self) -> None:
        """Carga sección 'contact' de la config."""
        contact = self._raw.get("contact", {})
        self.contact_nombre: str = contact.get("nombre", "Operador SIEM")
        self.contact_cel: str = contact.get("cel", "")
        self.contact_email: str = contact.get("email", "")
        self.contact_portfolio: str = contact.get("portfolio", "")
        self.contact_linkedin: str = contact.get("linkedin", "")

    # ── Directorios ───────────────────────────────────────
    def _ensure_directories(self) -> None:
        """Crea los directorios de logs y alertas si no existen."""
        for directory in [self.logs_dir, self.alerts_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    # ── Representación ────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"SIEMConfig(version={self.version!r}, "
            f"hostname={self.hostname!r}, "
            f"token={self.telegram_token_masked!r})"
        )
