"""Étape 4 — Consolidation de toutes les données dans un DataFrame unique.

Granularité : une ligne par (bulletin_id, cve).
Les bulletins sans CVE sont conservés avec cve=None.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from .feeds import BulletinEntry
    from .cves import BulletinCves
    from .enrichment import CveEnrichment

logger = logging.getLogger(__name__)

DEFAULT_LOCAL_DIR = Path("data") / "data"
DEFAULT_OUTPUT_CSV = Path("data") / "consolidated.csv"

_COLUMNS = [
    "bulletin_id", "bulletin_type", "title", "bulletin_description", "link",
    "date_publication", "year_publication",
    "cve", "cve_year",
    "cve_description", "cvss_version", "cvss_score", "cvss_severity",
    "cvss_vector", "cwe_id", "cwe_description",
    "vendors", "products", "versions",
    "epss_score", "epss_percentile", "epss_date",
    "mitre_available", "first_available", "is_critical",
]


def build_consolidated_dataframe(
    bulletins: "list[BulletinEntry]",
    bulletin_cves: "list[BulletinCves]",
    enrichments: "dict[str, CveEnrichment]",
) -> "pd.DataFrame":
    """Assemble bulletins, CVE et enrichissements en un DataFrame prêt pour l'analyse."""
    import pandas as pd
    from .cves import cves_to_dataframe

    # Métadonnées des bulletins (une ligne par bulletin)
    meta = pd.DataFrame([{
        "bulletin_id": b.bulletin_id,
        "bulletin_type": b.type,
        "title": b.title,
        "bulletin_description": b.description,
        "link": b.link,
        "date_publication": b.published,
    } for b in bulletins]).drop_duplicates("bulletin_id")

    # Une ligne par (bulletin_id, cve) — None pour les bulletins sans CVE
    df = cves_to_dataframe(bulletin_cves).drop(columns=["type"])

    # Enrichissements CVE (une ligne par cve_id)
    if enrichments:
        df_enrich = (
            pd.DataFrame([e.as_dict() for e in enrichments.values()])
            .rename(columns={"description": "cve_description"})
        )
    else:
        df_enrich = pd.DataFrame(columns=["cve", "cve_description"])

    # Joins
    df = df.merge(meta, on="bulletin_id", how="left")
    df = df.merge(df_enrich, on="cve", how="left")

    # Colonnes dérivées — avant conversion en category
    score = df["cvss_score"] if "cvss_score" in df.columns else pd.Series(dtype=float)
    severity = df["cvss_severity"] if "cvss_severity" in df.columns else pd.Series(dtype=object)
    df["is_critical"] = (score.fillna(0.0) >= 9.0) | (severity.fillna("") == "CRITICAL")

    df["date_publication"] = pd.to_datetime(df["date_publication"], utc=True, errors="coerce")
    df["year_publication"] = df["date_publication"].dt.year.astype("Int16")
    df["cve_year"] = (
        df["cve"].str.extract(r"CVE-(\d{4})-", expand=False)
        .astype("Int16")
    )

    # Typage numérique et catégoriel
    for col in ("cvss_score", "epss_score", "epss_percentile"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("float64")
    for col in ("bulletin_type", "cvss_severity"):
        if col in df.columns:
            df[col] = df[col].astype("category")
    # Booléens : fillna(False) pour les lignes sans CVE (NaN après left join)
    for col in ("mitre_available", "first_available"):
        if col in df.columns:
            df[col] = df[col].fillna(False).astype(bool)

    # Normalisation texte : strip + None pour les chaînes vides
    text_cols = [
        "title", "bulletin_description", "cve_description",
        "cwe_id", "cwe_description", "vendors", "products", "versions",
    ]
    for col in text_cols:
        if col in df.columns:
            df[col] = df[col].where(df[col].notna()).str.strip().replace("", None)

    # Ordre des colonnes
    present = [c for c in _COLUMNS if c in df.columns]
    extra = [c for c in df.columns if c not in _COLUMNS]
    return df[present + extra].reset_index(drop=True)


def consolidate(
    *,
    source: str = "local",
    local_dir: Path | str = DEFAULT_LOCAL_DIR,
    output_csv: Path | str | None = DEFAULT_OUTPUT_CSV,
) -> "pd.DataFrame":
    """Charge toutes les données depuis les étapes 1–3, consolide et exporte en CSV."""
    from .feeds import fetch_all_feeds
    from .cves import extract_all_cves
    from .enrichment import enrich_cves

    root = Path(local_dir)

    bulletins = fetch_all_feeds(source="local", local_dir=root)
    logger.info("%d bulletins chargés.", len(bulletins))

    bulletin_cves = extract_all_cves(local_dir=root)
    logger.info("%d bulletins analysés pour les CVE.", len(bulletin_cves))

    all_cve_ids = sorted({cve for b in bulletin_cves for cve in b.cves})
    logger.info("%d CVE distincts à enrichir.", len(all_cve_ids))

    enrichments = enrich_cves(all_cve_ids, source=source, local_dir=root)

    df = build_consolidated_dataframe(bulletins, bulletin_cves, enrichments)
    logger.info("DataFrame consolidé : %d lignes × %d colonnes.", *df.shape)

    if output_csv is not None:
        out = Path(output_csv)
        out.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(out, index=False, encoding="utf-8-sig")
        logger.info("CSV exporté : %s", out)

    return df


if __name__ == "__main__":
    import os
    import logging as _logging

    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s | %(message)s")
    os.chdir(r"C:\Users\natha\Downloads\TD_Final")

    df = consolidate()
    print(f"\nDataFrame consolidé : {df.shape[0]:,} lignes × {df.shape[1]} colonnes")
    print(f"Avec CVE            : {df['cve'].notna().sum():,} lignes")
    print(f"Sans CVE            : {df['cve'].isna().sum():,} lignes")
    print(f"CVE critiques       : {df['is_critical'].sum():,}")
    print(f"\nTypes de colonnes :")
    print(df.dtypes.to_string())
