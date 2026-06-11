# TD Final — Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

EFREI 2026 — Python Data & Cybersecurity

## Étapes implémentées

| Étape | Module | Description |
|---|---|---|
| 1 | `anssi.feeds` | Extraction des flux RSS ANSSI (avis & alertes) |
| 2 | `anssi.cves` | Extraction exhaustive des CVE par bulletin |
| 3 | `anssi.enrichment` | Enrichissement MITRE (CVSS, CWE) et FIRST (EPSS) |
| 4 | `anssi.consolidation` | Consolidation dans un DataFrame unique, export CSV |

## Installation

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## Utilisation

```python
from anssi.consolidation import consolidate

df = consolidate(source="local")   # 126 124 lignes × 25 colonnes
```

## Tests

```bash
pytest tests/
```
