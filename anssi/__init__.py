"""Package ANSSI — Analyse des avis et alertes du CERT-FR.

Ce package regroupe les briques réutilisables du TD, étape par étape :

* ``anssi.feeds`` — Étape 1 : extraction des flux RSS (avis & alertes).
* ``anssi.cves``  — Étape 2 : extraction exhaustive des CVE par bulletin.
* ``anssi.enrichment`` — Étape 3 : enrichissement MITRE et FIRST/EPSS.
* ``anssi.consolidation`` — Étape 4 : consolidation dans un DataFrame unique.
"""

from .feeds import (
    FEED_URLS,
    BulletinEntry,
    fetch_anssi_feed,
    fetch_all_feeds,
    feed_to_dataframe,
)
from .cves import (
    BulletinCves,
    extract_cves_from_data,
    extract_bulletin_cves,
    extract_all_cves,
    cves_to_dataframe,
)
from .enrichment import (
    AffectedProduct,
    MitreData,
    FirstData,
    CveEnrichment,
    parse_mitre,
    parse_first,
    enrich_cve,
    enrich_cves,
    enrichment_to_dataframe,
)
from .consolidation import (
    build_consolidated_dataframe,
    consolidate,
)

__all__ = [
    # étape 1
    "FEED_URLS",
    "BulletinEntry",
    "fetch_anssi_feed",
    "fetch_all_feeds",
    "feed_to_dataframe",
    # étape 2
    "BulletinCves",
    "extract_cves_from_data",
    "extract_bulletin_cves",
    "extract_all_cves",
    "cves_to_dataframe",
    # étape 3
    "AffectedProduct",
    "MitreData",
    "FirstData",
    "CveEnrichment",
    "parse_mitre",
    "parse_first",
    "enrich_cve",
    "enrich_cves",
    "enrichment_to_dataframe",
    # étape 4
    "build_consolidated_dataframe",
    "consolidate",
]
