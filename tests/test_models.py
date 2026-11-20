"""Tests para siem/models.py — EventData y RateLimitState."""

import unittest

from siem.models import EventData, RateLimitState


class TestEventData(unittest.TestCase):
    def test_compute_hash_len_16(self):
        h = EventData.compute_hash(999, "Security", 4625, "2026-03-31")
        self.assertEqual(len(h), 16)

    def test_compute_hash_deterministic_and_unique(self):
        a = EventData.compute_hash(1, "Security", 4625, "ts")
        b = EventData.compute_hash(1, "Security", 4625, "ts")
        c = EventData.compute_hash(2, "Security", 4625, "ts")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class TestRateLimitState(unittest.TestCase):
    def test_can_send_no_state(self):
        rl = RateLimitState()
        self.assertTrue(rl.can_send(4625, 1000.0, 60, 20))

    def test_cooldown_active_after_record_send(self):
        rl = RateLimitState()
        rl.record_send(4625, 1000.0)
        self.assertFalse(rl.can_send(4625, 1000.5, 60, 20))
        self.assertAlmostEqual(rl.get_cooldown_remaining(4625, 1000.5, 60), 59.5)

    def test_cooldown_expired_at_61s(self):
        rl = RateLimitState()
        rl.record_send(4625, 1000.0)
        self.assertTrue(rl.can_send(4625, 1061.0, 60, 20))

    def test_global_limit_20_per_minute(self):
        rl = RateLimitState()
        for i in range(20):
            rl.record_send(1000 + i, 1000.0)
        self.assertFalse(rl.can_send(4625, 1000.0, 60, 20))


if __name__ == "__main__":
    unittest.main()
