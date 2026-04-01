"""Test de verificación del SIEM v4.0 — ejecutar antes de desplegar."""

import sys

print("=" * 55)
print("  🧪 SIEM v4.0 — Verificación de componentes")
print("=" * 55)

errors = []

# ── 1. PyYAML ────────────────────────────────────────────
try:
    import yaml
    print("✅ PyYAML importado")
except ImportError as e:
    print(f"❌ PyYAML: {e}")
    errors.append("pyyaml")

# ── 2. Modelos ───────────────────────────────────────────
try:
    from siem.models import EventData, RateLimitState

    h = EventData.compute_hash(999, "Security", 4625, "2026-03-31")
    assert len(h) == 16, "Hash debe tener 16 chars"

    rl = RateLimitState()
    assert rl.can_send(4625, 1000.0, 60, 20) is True
    rl.record_send(4625, 1000.0)
    assert rl.can_send(4625, 1000.5, 60, 20) is False   # Cooldown activo
    assert rl.can_send(4625, 1061.0, 60, 20) is True    # Cooldown expirado

    print("✅ Models + RateLimitState OK")
except Exception as e:
    print(f"❌ Models: {e}")
    errors.append("models")

# ── 3. Sanitizador ───────────────────────────────────────
try:
    from siem.notifier import TelegramNotifier

    s = TelegramNotifier.sanitize
    assert s("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert s("AT&T") == "AT&amp;T"
    assert len(s("A" * 300)) == 200
    assert chr(0) not in s("texto" + chr(0) + "fin")
    print("✅ Sanitizador HTML OK")
except Exception as e:
    print(f"❌ Sanitizador: {e}")
    errors.append("sanitizer")

# ── 4. Config ────────────────────────────────────────────
try:
    from siem.config import SIEMConfig
    cfg = SIEMConfig()

    assert cfg.version == "4.0.0"
    assert len(cfg.critical_events) == 9
    assert 4625 in cfg.alert_events
    assert cfg.tg_cooldown == 60
    assert cfg.max_events == 50000
    assert cfg.hostname != ""
    assert cfg.telegram_token_masked.startswith("***")

    print(f"✅ SIEMConfig OK — host={cfg.hostname}, token={cfg.telegram_token_masked}")
except Exception as e:
    print(f"❌ SIEMConfig: {e}")
    errors.append("config")

# ── 5. LogManager ────────────────────────────────────────
try:
    from siem.config import SIEMConfig
    from siem.log_manager import LogManager, setup_logging
    import logging

    cfg = SIEMConfig()
    setup_logging(cfg)
    lm = LogManager(cfg)

    lm.write_event("TEST verificacion SIEM v4.0", is_alert=False)
    lm.write_event("TEST ALERTA verificacion v4.0", is_alert=True)

    stats = lm.get_stats()
    assert stats["total_files"] >= 2

    print(f"✅ LogManager OK — {stats['total_files']} archivos, {stats['total_size_mb']} MB")
except Exception as e:
    print(f"❌ LogManager: {e}")
    errors.append("log_manager")

# ── 6. EventProcessor (sin Windows Event Log) ────────────
try:
    from siem.config import SIEMConfig
    from siem.notifier import TelegramNotifier
    from siem.log_manager import LogManager
    from siem.event_processor import EventProcessor

    cfg = SIEMConfig()
    notifier = TelegramNotifier(cfg)
    log_manager = LogManager(cfg)
    processor = EventProcessor(cfg, notifier, log_manager)

    assert processor.events_in_memory == 0
    removed = processor.cleanup_memory()
    assert removed == 0

    print("✅ EventProcessor OK (instanciado, memoria vacía)")
except Exception as e:
    print(f"❌ EventProcessor: {e}")
    errors.append("event_processor")

# ── 7. Entry point syntax ────────────────────────────────
try:
    import ast
    with open("siem_consola.py", "r", encoding="utf-8") as f:
        source = f.read()
    ast.parse(source)
    print("✅ siem_consola.py — sintaxis válida")
except SyntaxError as e:
    print(f"❌ siem_consola.py sintaxis: {e}")
    errors.append("siem_consola")

# ── Resultado Final ───────────────────────────────────────
print()
print("=" * 55)
if errors:
    print(f"❌ FALLÓ: {', '.join(errors)}")
    sys.exit(1)
else:
    print("🎉 TODOS LOS TESTS PASARON — SIEM v4.0 listo")
    print("   Ejecutar: python siem_consola.py (como Admin)")
print("=" * 55)
