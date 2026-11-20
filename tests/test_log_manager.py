"""Tests para siem/log_manager.py — LogManager y rotate() (F-06)."""

import os
import tempfile
import time
import unittest
from pathlib import Path

from siem.config import SIEMConfig
from siem.log_manager import LogManager


def make_config(tmp: Path) -> SIEMConfig:
    cfg = SIEMConfig()
    cfg.logs_dir = tmp / "Logs"
    cfg.alerts_dir = tmp / "Alertas"
    cfg.logs_dir.mkdir(parents=True)
    cfg.alerts_dir.mkdir(parents=True)
    return cfg


class TestLogManager(unittest.TestCase):
    def test_write_event_creates_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(Path(tmp))
            lm = LogManager(cfg)
            lm.write_event("Evento de prueba")
            lm.write_event("Evento de alerta", is_alert=True)
            stats = lm.get_stats()
            self.assertGreaterEqual(stats["total_files"], 2)

    def test_rotate_excluye_siem_log_activo(self):  # F-06
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            cfg = make_config(tmp)
            active = cfg.logs_dir / "siem.log"
            active.write_text("activo", encoding="utf-8")
            old = cfg.logs_dir / "eventos_2000-01-01.log"
            old.write_text("viejo", encoding="utf-8")
            old_mtime = time.time() - 40 * 86400
            os.utime(old, (old_mtime, old_mtime))
            lm = LogManager(cfg)
            lm.rotate()
            self.assertTrue(active.exists())
            self.assertFalse((cfg.logs_dir / "siem.log.gz").exists())
            self.assertFalse(old.exists())


if __name__ == "__main__":
    unittest.main()
