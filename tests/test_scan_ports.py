"""Tests para scan_ports.py."""

import unittest

import scan_ports


class TestResolverObjeto(unittest.TestCase):
    def test_resolver_ip_literal(self):
        self.assertEqual(scan_ports.resolver_objetivo("127.0.0.1"), "127.0.0.1")

    def test_resolver_localhost(self):
        self.assertEqual(scan_ports.resolver_objetivo("localhost"), "127.0.0.1")

    def test_resolver_invalido(self):
        with self.assertRaises(ValueError):
            scan_ports.resolver_objetivo("999.999.999.999")


if __name__ == "__main__":
    unittest.main()
