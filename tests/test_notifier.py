"""Tests para siem/notifier.py — sanitización de mensajes Telegram."""

import unittest

from siem.notifier import TelegramNotifier


class TestSanitize(unittest.TestCase):
    def test_escape_html(self):
        self.assertEqual(
            TelegramNotifier.sanitize("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        )

    def test_escape_amp(self):
        self.assertEqual(TelegramNotifier.sanitize("AT&T"), "AT&amp;T")

    def test_strips_control_chars(self):
        self.assertNotIn(chr(0), TelegramNotifier.sanitize("texto" + chr(0) + "fin"))

    def test_truncates_to_200(self):
        self.assertEqual(len(TelegramNotifier.sanitize("A" * 300)), 200)

    def test_newline_kept(self):
        self.assertEqual(TelegramNotifier.sanitize("a\nb"), "a\nb")


if __name__ == "__main__":
    unittest.main()
