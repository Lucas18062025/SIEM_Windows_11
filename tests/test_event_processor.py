"""Tests para siem/event_processor.py — F-01 (credenciales), F-02 (reads),
dedup y sanitización de eventos."""

import sys
import unittest
from datetime import datetime

# Entorno de consola UTF-8 (README: PYTHONUTF8=1 en Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from siem.config import SIEMConfig
from siem.event_processor import EventProcessor


class FakeNotifier:
    def __init__(self):
        self.sent = []

    @staticmethod
    def sanitize(text, max_length=200):
        return str(text)[:max_length]

    def send(self, message, event_id):
        self.sent.append((message, event_id))
        return True


class FakeLogManager:
    def __init__(self):
        self.lines = []

    def write_event(self, line, is_alert=False):
        self.lines.append((line, is_alert))


class FakeTime:
    def Format(self):
        return "Fri Nov 20 18:24:32 2026"

    def timetuple(self):
        return datetime(2026, 11, 20, 18, 24, 32).timetuple()


class FakeEvent:
    def __init__(self, event_id, record_number, inserts=None):
        self.EventID = event_id
        self.RecordNumber = record_number
        self.StringInserts = inserts if inserts is not None else ["user", "host"]
        self.TimeGenerated = FakeTime()


class TestCheckCredentials(unittest.TestCase):
    def test_credentials_access_map(self):
        cfg = SIEMConfig()
        p = EventProcessor(cfg, FakeNotifier(), FakeLogManager())
        cred = p.check_credentials()
        self.assertIsInstance(cred, dict)
        self.assertIn("Security", cred)
        self.assertIn("System", cred)
        # System es legible en cualquier sesión interactiva
        self.assertIs(cred["System"], True)


class TestReadEvents(unittest.TestCase):
    def test_read_events_system_bounded(self):  # F-02
        cfg = SIEMConfig()
        p = EventProcessor(cfg, FakeNotifier(), FakeLogManager())
        events = p.read_events("System")
        self.assertLessEqual(len(events), cfg.events_per_read)
        for e in events:
            self.assertTrue(hasattr(e, "EventID"))


class TestProcessCycle(unittest.TestCase):
    def test_dedup_and_critical_filter(self):
        cfg = SIEMConfig()
        notifier = FakeNotifier()
        lm = FakeLogManager()

        # 4625 ∈ critical_events y ∈ alert_events
        p = EventProcessor(cfg, notifier, lm)
        event = FakeEvent(4625, 42, ["Admin", "CORP-HOST"])
        p.read_events = (
            lambda log_type: [event] if log_type == "Security" else []
        )
        self.assertEqual(p.process_cycle(), 1)
        self.assertEqual(p.process_cycle(), 0)  # dedup por hash
        self.assertEqual(notifier.sent[0][1], 4625)  # alert enviada

        # Evento no crítico (9999 ∉ critical_events)
        p2 = EventProcessor(cfg, FakeNotifier(), FakeLogManager())
        p2.read_events = lambda log_type: (
            [FakeEvent(9999, 43)] if log_type == "System" else []
        )
        self.assertEqual(p2.process_cycle(), 0)

    def test_build_event_data_sanitizes_inserts(self):
        cfg = SIEMConfig()
        p = EventProcessor(cfg, FakeNotifier(), FakeLogManager())
        raw = FakeEvent(4625, 44, ["<script>alert(1)</script>", "host"])
        ed = p._build_event_data(raw, 4625, "ts", "Security", "hash123")
        self.assertTrue(ed.details.startswith("&lt;script&gt;"))
        self.assertTrue(ed.is_alert)
        self.assertEqual(ed.description, "LOGIN FALLIDO")


if __name__ == "__main__":
    unittest.main()
