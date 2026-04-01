# ═══════════════════════════════════════════════════════════════
# SIEM Personal v4.0 — Guía de commit completo
# Ejecutar en PowerShell dentro de la carpeta del repo
# ═══════════════════════════════════════════════════════════════

# ── PASO 1: Verificar estado actual ─────────────────────────
git status
git log --oneline -5

# ── PASO 2: Copiar los nuevos archivos al repo ───────────────
# (reemplazá C:\ruta\a\los\archivos por donde guardaste los archivos)

# ARCHIVOS NUEVOS — agregar directamente:
copy "README.md"      ".\README.md"         # Sobreescribe README existente
copy "CHANGELOG.md"   ".\CHANGELOG.md"      # Nuevo
copy "LICENSE"        ".\LICENSE"           # Nuevo
copy "pyproject.toml" ".\pyproject.toml"    # Nuevo
copy "vuln_hp.py"     ".\vuln_hp.py"        # Sobreescribe vuln_hp.py existente

# ── PASO 3: Agregar todos los cambios ───────────────────────
git add README.md
git add CHANGELOG.md
git add LICENSE
git add pyproject.toml
git add vuln_hp.py

# ── PASO 4: Verificar qué se va a commitear ─────────────────
git diff --staged --stat

# ── PASO 5: Commit con mensaje semántico ────────────────────
git commit -m "feat: profesionalizar repo con marca empresarial IA

- README: arquitectura ASCII, badges, tabla de eventos, estructura
- CHANGELOG: historial semántico completo v1.0.0 → v4.0.0
- LICENSE: MIT (faltaba — crítico para repo público)
- pyproject.toml: metadata completa, keywords, classifiers, ruff+pytest
- vuln_hp.py v2.4: fix validación IP (ipaddress), fix caché TTL 24h"

# ── PASO 6: Push ─────────────────────────────────────────────
git push origin main

# ── PASO 7: Agregar Topics en GitHub (manual) ────────────────
# Ir a: https://github.com/Lucas18062025/SIEM_Windows_11
# Click en el ícono ⚙️ al lado de "About"
# Agregar topics:
#   siem, cybersecurity, windows-security, python, telegram-bot,
#   nvd, cve, blue-team, event-monitoring, nmap, homelab,
#   vulnerability-scanner, windows-11, red-team, cvss

# ── VERIFICACIÓN FINAL ───────────────────────────────────────
git log --oneline -3
git status
# Debería mostrar: "nothing to commit, working tree clean"
