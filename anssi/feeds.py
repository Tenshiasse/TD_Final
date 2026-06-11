"""Étape 1 — Extraction des flux RSS ANSSI (avis & alertes)."""

import json
import time
import feedparser
import pandas as pd
from pathlib import Path

FEED_URLS = {
    "avis":   "https://www.cert.ssi.gouv.fr/avis/feed/",
    "alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

RATE_LIMIT = 2  # secondes entre requêtes réseau (§8 du sujet)


def fetch_feeds():
    """Récupère les bulletins depuis les flux RSS live."""
    data = []
    for type_bulletin, url in FEED_URLS.items():
        feed = feedparser.parse(url)
        for entry in feed.entries:
            data.append({
                "type":        type_bulletin,
                "titre":       entry.get("title", ""),
                "description": entry.get("summary", ""),
                "lien":        entry.get("link", ""),
                "date":        entry.get("published", ""),
            })
        time.sleep(RATE_LIMIT)
    return pd.DataFrame(data)


def load_local_feeds(local_dir="data/data"):
    """Charge les bulletins depuis les JSON pré-téléchargés."""
    data = []
    for type_bulletin, folder in [("avis", "Avis"), ("alerte", "alertes")]:
        folder_path = Path(local_dir) / folder
        for file in sorted(folder_path.iterdir()):
            try:
                with open(file, encoding="utf-8") as f:
                    raw = json.load(f)
                data.append({
                    "bulletin_id": raw.get("reference", file.stem),
                    "type":        type_bulletin,
                    "titre":       raw.get("title", ""),
                    "description": raw.get("summary", ""),
                    "lien":        raw.get("url", ""),
                    "date":        raw.get("published", ""),
                })
            except Exception:
                continue
    return pd.DataFrame(data)
