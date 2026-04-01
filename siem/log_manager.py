# ═══════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Gestor de Logs
# ═══════════════════════════════════════════════════════════

"""
Módulo de gestión de logs del SIEM.

Implementa escritura de logs con rotación inteligente por
tamaño y por días, compresión opcional, y logging estructurado
con el módulo estándar de Python.
"""

from __future__ import annotations

import gzip
import logging
import os
import shutil
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem.config import SIEMConfig


def setup_logging(config: SIEMConfig) -> logging.Logger:
    """Configura el sistema de logging del SIEM.

    Crea handlers para:
    - Consola: output con emojis y colores (mantiene el look original).
    - Archivo rotativo: log general con rotación por tamaño.

    Args:
        config: Instancia de SIEMConfig.

    Returns:
        Logger raíz del SIEM configurado.
    """
    root_logger = logging.getLogger("siem")
    root_logger.setLevel(logging.DEBUG)

    # Evitar handlers duplicados si se llama más de una vez
    if root_logger.handlers:
        return root_logger

    # ── Console Handler ───────────────────────────────────
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        fmt="%(message)s",
        datefmt="%H:%M:%S",
    )
    console.setFormatter(console_fmt)
    root_logger.addHandler(console)

    # ── File Handler (rotativo por tamaño) ────────────────
    log_file = config.logs_dir / "siem.log"
    max_bytes = config.max_file_size_mb * 1024 * 1024  # MB → bytes

    file_handler = RotatingFileHandler(
        filename=str(log_file),
        maxBytes=max_bytes,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)
    root_logger.addHandler(file_handler)

    return root_logger


class LogManager:
    """Gestor de logs del SIEM con rotación inteligente.

    Features:
        - Escritura de eventos a archivos diarios.
        - Escritura separada de alertas.
        - Rotación por antigüedad (días configurables).
        - Compresión de logs antiguos (.gz).
        - Verificación de espacio en disco.

    Args:
        config: Instancia de SIEMConfig.
    """

    def __init__(self, config: SIEMConfig) -> None:
        self._logs_dir: Path = config.logs_dir
        self._alerts_dir: Path = config.alerts_dir
        self._rotation_days: int = config.rotation_days
        self._compress_old: bool = config.compress_old
        self._max_file_size_mb: int = config.max_file_size_mb
        self._logger: logging.Logger = logging.getLogger("siem.log_manager")

    # ── Escritura de logs ─────────────────────────────────
    def write_event(self, content: str, is_alert: bool = False) -> None:
        """Escribe un evento al archivo de log diario.

        Args:
            content: Contenido del evento a registrar.
            is_alert: Si True, también escribe en la carpeta de alertas.
        """
        today = datetime.now().strftime("%Y-%m-%d")
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Log general
        log_file = self._logs_dir / f"eventos_{today}.log"
        self._write_line(log_file, f"[{timestamp}] {content}")

        # Log de alertas (separado)
        if is_alert:
            alert_file = self._alerts_dir / f"alertas_{today}.log"
            self._write_line(alert_file, f"[{timestamp}] ⚠️  {content}")

    def _write_line(self, filepath: Path, line: str) -> None:
        """Escribe una línea a un archivo con manejo de errores.

        Args:
            filepath: Ruta del archivo.
            line: Línea a escribir.
        """
        try:
            # Verificar tamaño antes de escribir
            if filepath.exists():
                size_mb = filepath.stat().st_size / (1024 * 1024)
                if size_mb >= self._max_file_size_mb:
                    self._rotate_file(filepath)

            with open(filepath, "a", encoding="utf-8") as f:
                f.write(f"{line}\n")

        except PermissionError:
            self._logger.error(
                "Sin permisos para escribir en: %s", filepath
            )
        except OSError as exc:
            self._logger.error(
                "Error de I/O al escribir log: %s", exc
            )

    # ── Rotación ──────────────────────────────────────────
    def rotate(self) -> int:
        """Ejecuta rotación de logs antiguos.

        Elimina archivos con más de `rotation_days` días de antigüedad.
        Opcionalmente comprime archivos mayores a 1 día.

        Returns:
            Número de archivos procesados (eliminados o comprimidos).
        """
        processed = 0
        cutoff_delete = time.time() - (self._rotation_days * 86400)
        cutoff_compress = time.time() - 86400  # Comprimir después de 1 día

        for directory in [self._logs_dir, self._alerts_dir]:
            if not directory.exists():
                continue

            for filepath in directory.iterdir():
                if not filepath.is_file():
                    continue

                try:
                    mtime = filepath.stat().st_mtime

                    # Eliminar archivos viejos
                    if mtime < cutoff_delete:
                        filepath.unlink()
                        self._logger.info(
                            "🗑️  Log expirado eliminado: %s", filepath.name
                        )
                        processed += 1
                        continue

                    # Comprimir archivos de más de 1 día (si no están comprimidos)
                    if (
                        self._compress_old
                        and mtime < cutoff_compress
                        and not filepath.suffix == ".gz"
                    ):
                        self._compress_file(filepath)
                        processed += 1

                except OSError as exc:
                    self._logger.error(
                        "Error al procesar %s: %s", filepath.name, exc
                    )

        if processed > 0:
            self._logger.info(
                "🗑️  Rotación completada: %d archivos procesados", processed
            )
        return processed

    def _rotate_file(self, filepath: Path) -> None:
        """Rota un archivo que excedió el tamaño máximo.

        Renombra el archivo actual añadiendo timestamp y opcionalmente
        lo comprime.

        Args:
            filepath: Archivo a rotar.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated = filepath.with_suffix(f".{timestamp}.log")

        try:
            filepath.rename(rotated)
            self._logger.info(
                "📦 Log rotado por tamaño: %s → %s",
                filepath.name, rotated.name,
            )

            if self._compress_old:
                self._compress_file(rotated)

        except OSError as exc:
            self._logger.error(
                "Error al rotar %s: %s", filepath.name, exc
            )

    def _compress_file(self, filepath: Path) -> None:
        """Comprime un archivo con gzip.

        Args:
            filepath: Archivo a comprimir.
        """
        gz_path = filepath.with_suffix(filepath.suffix + ".gz")

        try:
            with open(filepath, "rb") as f_in:
                with gzip.open(gz_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)

            filepath.unlink()  # Eliminar original después de comprimir
            self._logger.info(
                "📦 Log comprimido: %s → %s",
                filepath.name, gz_path.name,
            )

        except OSError as exc:
            self._logger.error(
                "Error al comprimir %s: %s", filepath.name, exc
            )

    # ── Estadísticas ──────────────────────────────────────
    def get_stats(self) -> dict:
        """Retorna estadísticas de los archivos de log.

        Returns:
            Diccionario con conteo y tamaño total de logs.
        """
        total_files = 0
        total_size = 0

        for directory in [self._logs_dir, self._alerts_dir]:
            if not directory.exists():
                continue

            for filepath in directory.iterdir():
                if filepath.is_file():
                    total_files += 1
                    total_size += filepath.stat().st_size

        return {
            "total_files": total_files,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }
