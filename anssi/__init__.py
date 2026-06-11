"""Package ANSSI — Analyse des avis et alertes du CERT-FR.

Ce package regroupe les briques réutilisables du TD, étape par étape :

* ``anssi.feeds``  — Étape 1 : extraction des flux RSS (avis & alertes).

Les étapes suivantes (extraction des CVE, enrichissement, consolidation,
visualisation, ML, alertes) viendront compléter ce package au fur et à mesure.
"""

from .feeds import (
    FEED_URLS,
    BulletinEntry,
    fetch_anssi_feed,
    fetch_all_feeds,
    feed_to_dataframe,
)

__all__ = [
    "FEED_URLS",
    "BulletinEntry",
    "fetch_anssi_feed",
    "fetch_all_feeds",
    "feed_to_dataframe",
]
