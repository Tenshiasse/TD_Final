"""Étape 2 — Extraction des CVE depuis les bulletins ANSSI."""

import json
import re
import pandas as pd
from pathlib import Path

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


def extract_cves(data):
    """Extrait les CVE d'un JSON de bulletin (clé cves + regex)."""
    cves = set()

    # Source structurée : clé "cves" du JSON
    for entry in data.get("cves") or []:
        name = entry.get("name", "")
        if re.match(CVE_PATTERN, name, re.IGNORECASE):
            cves.add(name.upper())

    # Regex sur l'ensemble du JSON converti en chaîne
    for cve in re.findall(CVE_PATTERN, str(data), re.IGNORECASE):
        cves.add(cve.upper())

    return sorted(cves)


def extract_all_cves(local_dir="data/data"):
    """Extrait les CVE de tous les bulletins locaux. Retourne un DataFrame."""
    rows = []
    for type_bulletin, folder in [("avis", "Avis"), ("alerte", "alertes")]:
        folder_path = Path(local_dir) / folder
        for file in sorted(folder_path.iterdir()):
            try:
                with open(file, encoding="utf-8") as f:
                    data = json.load(f)
                bulletin_id = data.get("reference", file.stem)
                cves = extract_cves(data)
                if cves:
                    for cve in cves:
                        rows.append({"bulletin_id": bulletin_id,
                                     "type": type_bulletin, "cve": cve})
                else:
                    rows.append({"bulletin_id": bulletin_id,
                                 "type": type_bulletin, "cve": None})
            except Exception:
                continue
    return pd.DataFrame(rows)
