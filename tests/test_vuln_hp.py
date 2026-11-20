"""Tests para vuln_hp.py — F-03 (resp. JSON), F-04 (IDs/metrics), F-05 (paginación)."""

import sys
import types
import unittest
from unittest import mock

# Entorno de consola UTF-8 (README: PYTHONUTF8=1 en Windows)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import vuln_hp


def clear_cache():
    vuln_hp._cache_cve.clear()


class TestFindCveF03(unittest.TestCase):
    def setUp(self):
        vuln_hp.guardar_cache = lambda cache: None
        vuln_hp.time.sleep = lambda s: None
        clear_cache()

    def test_malformed_json_returns_empty(self):
        class R:
            status_code = 200
            text = "<<not json>>"

            def json(self):
                raise ValueError("Expecting value")

        with mock.patch.object(vuln_hp.requests, "get", return_value=R()):
            self.assertEqual(vuln_hp.find_cve("Microsoft Windows RPC", ""), [])

    def test_malformed_ids_return_empty(self):
        class R:
            status_code = 200
            text = ""

            def json(self):
                return {
                    "vulnerabilities": [
                        {"cve": {"id": "CVE"}},
                        {"cve": {"id": "CVE-XYZ-1"}},
                    ]
                }

        with mock.patch.object(vuln_hp.requests, "get", return_value=R()):
            self.assertEqual(vuln_hp.find_cve("Microsoft Windows RPC", ""), [])


class TestFindCveF05(unittest.TestCase):
    def setUp(self):
        vuln_hp.guardar_cache = lambda cache: None
        vuln_hp.time.sleep = lambda s: None
        clear_cache()

    def test_pagination_fetches_all_pages(self):
        pages = [
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2030-0001"}},
                    {"cve": {"id": "CVE-2030-0002"}},
                ],
                "totalResults": 3,
                "startIndex": 0,
            },
            {
                "vulnerabilities": [{"cve": {"id": "CVE-2030-0003"}}],
                "totalResults": 3,
                "startIndex": 2,
            },
        ]
        calls = []

        class R:
            def __init__(self, data):
                self.status_code = 200
                self._d = data
                self.text = ""

            def json(self):
                return self._d

        def fake_get(url, params=None, headers=None, timeout=None):
            idx = min(len(calls), len(pages) - 1)
            calls.append(params)
            return R(pages[idx])

        with mock.patch.object(vuln_hp.requests, "get", side_effect=fake_get):
            result = vuln_hp.find_cve("Microsoft Windows RPC", "")
        self.assertEqual(
            sorted(r["id"] for r in result),
            ["CVE-2030-0001", "CVE-2030-0002", "CVE-2030-0003"],
        )
        self.assertEqual(len(calls), 2)


class TestVulnHpHelpers(unittest.TestCase):
    def test_calcular_riesgo_pesos_puertos(self):
        riesgo = vuln_hp.calcular_riesgo(445, [{"score": 9.8}])
        self.assertEqual(riesgo["score"], 6)  # 445→3 + CVSS 9.8≥7→3
        self.assertEqual(riesgo["razon_puerto"], "SMB — EternalBlue, ransomware")

    def test_clasificar_host_niveles(self):
        lvl = vuln_hp.clasificar_host([{"riesgo": {"score": 0, "score_cvss": 0}}])["nivel"]
        self.assertEqual(lvl, "🟢 BAJO")


class TestVerificarNmapF16(unittest.TestCase):
    def test_error_returns_false(self):  # F-16: antes devolvía True (máscara errores)
        fake = types.SimpleNamespace(
            PortScanner=lambda: (_ for _ in ()).throw(ValueError("boom")),
            PortScannerError=ValueError,
        )
        with mock.patch.object(vuln_hp, "nmap", fake):
            self.assertFalse(vuln_hp.verificar_nmap())


if __name__ == "__main__":
    unittest.main()
