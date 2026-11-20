"""Tests para siem/config.py — validación (F-08) y carga real."""

import unittest

from siem.config import SIEMConfig


class TestValidateConfig(unittest.TestCase):
    def test_empty_config_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config({})

    def test_none_config_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config(None)

    def test_cleanup_every_zero_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config({"timing": {"cleanup_every_n_cycles": 0}})

    def test_cleanup_every_negative_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config({"timing": {"cleanup_every_n_cycles": -3}})

    def test_negative_scan_interval_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config({"timing": {"scan_interval_seconds": -5}})

    def test_zero_memory_window_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config({"timing": {"memory_window_seconds": 0}})

    def test_zero_max_events_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config({"timing": {"max_events_in_memory": 0}})

    def test_non_numeric_timing_raises(self):
        with self.assertRaises(ValueError):
            SIEMConfig._validate_config({"timing": {"scan_interval_seconds": "abc"}})

    def test_valid_defaults_pass(self):
        SIEMConfig._validate_config({"timing": {}})
        SIEMConfig._validate_config({"siem": {"version": "4.0.0"}})

    def test_real_config_loads(self):
        cfg = SIEMConfig()
        self.assertEqual(cfg.version, "4.0.0")
        self.assertEqual(len(cfg.critical_events), 9)
        self.assertIn(4625, cfg.alert_events)
        self.assertEqual(cfg.tg_cooldown, 60)
        self.assertEqual(cfg.max_events, 50000)


if __name__ == "__main__":
    unittest.main()
