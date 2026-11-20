"""Suite de pruebas del SIEM (F-07) — corre con: python -m unittest discover -s tests -v

Nivel: unitarios. Pruebas de integración leves usan fakes y mocks;
las de Windows nativas leen el Security/System logs de solo lectura
(igual que hace el monitor en producción).
"""
