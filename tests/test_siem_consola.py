"""Tests para siem_consola.py — run_monitor() F-09 (crash-proof loop) y F-17 (status)."""

import threading
import unittest

from siem.config import SIEMConfig
from siem_consola import run_monitor


class FakeProcessor:
    def __init__(self, calls_before_shutdown=3, raise_first=0):
        self.calls = 0
        self.shutdown = None
        self._calls_before_shutdown = calls_before_shutdown
        self._raise_first = raise_first
        self.raised = 0

    def process_cycle(self):
        self.calls += 1
        if self.raised < self._raise_first:
            self.raised += 1
            raise RuntimeError("simulado")
        if self.calls >= self._calls_before_shutdown:
            self.shutdown.set()
        return self.calls

    @property
    def events_in_memory(self):
        return self.calls

    def cleanup_memory(self):
        return 0


class FakeLogManager:
    def rotate(self):
        return 0


class TestRunMonitor(unittest.TestCase):
    def _run(self, fp, ev):
        cfg = SIEMConfig()
        cfg.scan_interval = 0  # sin sleeps en los tests
        return run_monitor(fp, FakeLogManager(), cfg, ev)

    def test_normal_cycles_and_shutdown(self):
        ev = threading.Event()
        fp = FakeProcessor(calls_before_shutdown=3)
        fp.shutdown = ev
        cycles = self._run(fp, ev)
        self.assertEqual(cycles, 3)
        self.assertEqual(fp.calls, 3)

    def test_exception_does_not_kill_monitor(self):  # F-09
        ev = threading.Event()
        fp = FakeProcessor(calls_before_shutdown=3, raise_first=1)
        fp.shutdown = ev
        cycles = self._run(fp, ev)
        self.assertGreaterEqual(fp.calls, 2)


if __name__ == "__main__":
    unittest.main()
