"""Étape 4 — Consolidation des données dans un DataFrame pandas."""

import pandas as pd
from pathlib import Path

from .feeds import load_local_feeds
from .cves import extract_all_cves
from .enrichment import enrich_all


def build_dataframe(bulletins_df, cves_df, enrichments):
    """Assemble bulletins, CVE et enrichissements en un DataFrame unique."""
    enrich_df = pd.DataFrame(enrichments.values())

    # Une ligne par (bulletin_id, cve)
    df = cves_df.merge(
        bulletins_df[["bulletin_id", "titre", "type", "date", "lien"]],
        on=["bulletin_id", "type"],
        how="left",
    )
    df = df.merge(enrich_df, on="cve", how="left")

    # Ordre des colonnes tel que décrit dans le sujet
    cols = [
        "bulletin_id", "titre", "type", "date", "cve",
        "cvss_score", "base_severity", "cwe", "cwe_description",
        "epss_score", "lien", "description",
        "editeur", "produit", "versions",
    ]
    present = [c for c in cols if c in df.columns]
    return df[present].reset_index(drop=True)


def consolidate(local_dir="data/data", output_csv="data/consolidated.csv"):
    """Charge toutes les données, consolide et exporte en CSV."""
    bulletins_df = load_local_feeds(local_dir)
    cves_df      = extract_all_cves(local_dir)

    all_cves    = cves_df["cve"].dropna().unique().tolist()
    enrichments = enrich_all(all_cves, source="local", local_dir=local_dir)

    df = build_dataframe(bulletins_df, cves_df, enrichments)

    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False, encoding="utf-8-sig")

    return df
