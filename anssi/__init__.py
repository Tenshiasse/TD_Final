"""Package ANSSI — Analyse des avis et alertes du CERT-FR.

Ce package regroupe les briques réutilisables du TD, étape par étape :

* ``anssi.feeds`` — Étape 1 : extraction des flux RSS (avis & alertes).
* ``anssi.cves``  — Étape 2 : extraction exhaustive des CVE par bulletin.
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
]
