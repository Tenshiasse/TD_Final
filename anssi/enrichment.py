"""Étape 3 — Enrichissement des CVE via MITRE et FIRST (EPSS)."""

import json
import time
import requests
import pandas as pd
from pathlib import Path

MITRE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
FIRST_URL  = "https://api.first.org/data/v1/epss?cve={cve_id}"
RATE_LIMIT = 2  # secondes entre requêtes (§8 du sujet)


def enrich_cve(cve_id, source="local", local_dir="data/data"):
    """Enrichit un CVE avec MITRE (CVSS, CWE, produits) et FIRST (EPSS)."""
    result = {
        "cve":             cve_id,
        "description":     None,
        "cvss_score":      None,
        "base_severity":   None,
        "cwe":             None,
        "cwe_description": None,
        "editeur":         None,
        "produit":         None,
        "versions":        None,
        "epss_score":      None,
    }

    # ── MITRE ────────────────────────────────────────────────────────────────
    mitre_data = None
    if source in ("local", "local_then_api"):
        try:
            with open(Path(local_dir) / "mitre" / cve_id, encoding="utf-8") as f:
                mitre_data = json.load(f)
        except Exception:
            pass
    if mitre_data is None and source in ("api", "local_then_api"):
        time.sleep(RATE_LIMIT)
        try:
            mitre_data = requests.get(MITRE_URL.format(cve_id=cve_id),
                                       timeout=20).json()
        except Exception:
            pass

    if mitre_data:
        try:
            cna = mitre_data["containers"]["cna"]

            # Description
            descriptions = cna.get("descriptions", [])
            if descriptions:
                result["description"] = descriptions[0].get("value")

            # CVSS — on essaie plusieurs versions
            try:
                metrics = cna.get("metrics", [])
                if metrics:
                    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                        if key in metrics[0]:
                            result["cvss_score"]    = metrics[0][key].get("baseScore")
                            result["base_severity"] = metrics[0][key].get("baseSeverity")
                            break
            except Exception:
                pass

            # CWE
            try:
                problemtype = cna.get("problemTypes", [])
                if problemtype and "descriptions" in problemtype[0]:
                    result["cwe"]             = problemtype[0]["descriptions"][0].get("cweId")
                    result["cwe_description"] = problemtype[0]["descriptions"][0].get("description")
            except Exception:
                pass

            # Produits affectés
            try:
                affected = cna.get("affected", [])
                editeurs = [p.get("vendor", "") for p in affected]
                produits = [p.get("product", "") for p in affected]
                versions = [
                    v.get("version", "")
                    for p in affected
                    for v in p.get("versions", [])
                    if v.get("status") == "affected"
                ]
                result["editeur"] = "; ".join(filter(None, editeurs)) or None
                result["produit"] = "; ".join(filter(None, produits)) or None
                result["versions"] = "; ".join(filter(None, versions)) or None
            except Exception:
                pass

        except Exception:
            pass

    # ── FIRST / EPSS ─────────────────────────────────────────────────────────
    first_data = None
    if source in ("local", "local_then_api"):
        try:
            with open(Path(local_dir) / "first" / cve_id, encoding="utf-8") as f:
                first_data = json.load(f)
        except Exception:
            pass
    if first_data is None and source in ("api", "local_then_api"):
        time.sleep(RATE_LIMIT)
        try:
            first_data = requests.get(FIRST_URL.format(cve_id=cve_id),
                                       timeout=20).json()
        except Exception:
            pass

    if first_data:
        try:
            epss_entries = first_data.get("data", [])
            if epss_entries:
                result["epss_score"] = float(epss_entries[0].get("epss", 0))
        except Exception:
            pass

    return result


def enrich_all(cve_ids, source="local", local_dir="data/data"):
    """Enrichit une liste de CVE uniques. Retourne un dict {cve_id: dict}."""
    results = {}
    for cve_id in sorted(set(cve_ids)):
        results[cve_id] = enrich_cve(cve_id, source=source, local_dir=local_dir)
    return results


def enrichments_to_dataframe(enrichments):
    """Convertit le dict d'enrichissements en DataFrame."""
    return pd.DataFrame(enrichments.values())
