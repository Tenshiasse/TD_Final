"""Étape 1 — Extraction des flux RSS de l'ANSSI (avis & alertes).

Ce module fournit une fonction réutilisable, :func:`fetch_anssi_feed`, qui
récupère les bulletins du CERT-FR et les normalise en une liste d'objets
:class:`BulletinEntry` exposant les champs demandés par le sujet :
titre, description, date de publication, lien et type (avis / alerte).

Deux sources interchangeables produisant le même schéma :

* ``source="rss"``  — le flux RSS live (derniers bulletins publiés) ;
* ``source="local"`` — les JSON pré-téléchargés, qui couvrent l'historique
  complet (utile pour l'analyse et le ML hors-ligne).

Gestion responsable des accès (cf. §8 du sujet)
-----------------------------------------------
La récupération réseau est mise en cache sur disque (un fichier XML par flux).
Lors des ré-exécutions, le flux est relu depuis le cache plutôt que re-téléchargé,
ce qui évite de surcharger les serveurs de l'ANSSI. Un délai minimal est par
ailleurs respecté entre deux requêtes réseau (rate limiting). L'approche reste
cohérente avec un vrai flux RSS : on consulte le flux, on repère les bulletins,
puis (étapes suivantes) on va chercher le détail de chacun.

Le parsing s'appuie sur ``feedparser``, qui gère nativement l'encodage, les
flux légèrement malformés et les différents formats de date.
"""

from __future__ import annotations

import calendar
import logging
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import feedparser
import json
import requests

if TYPE_CHECKING:  # import paresseux : pandas n'est pas requis pour l'extraction
    import pandas as pd

logger = logging.getLogger(__name__)

# --- Configuration ----------------------------------------------------------

#: URL des flux RSS officiels du CERT-FR, indexées par type de bulletin.
FEED_URLS: dict[str, str] = {
    "avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

#: Libellé normalisé du type de bulletin (utilisé dans le DataFrame final).
_TYPE_LABEL: dict[str, str] = {"avis": "Avis", "alerte": "Alerte"}

#: Alias acceptés en entrée pour désigner un type de flux.
_TYPE_ALIASES: dict[str, str] = {
    "avis": "avis",
    "avi": "avis",
    "alerte": "alerte",
    "alertes": "alerte",
    "ale": "alerte",
}

#: En-tête HTTP identifiant l'outil (politesse vis-à-vis du serveur).
_USER_AGENT = "TD-ANSSI-CVE/1.0 (projet pedagogique EFREI 2026)"

#: Délai (secondes) à respecter entre deux requêtes réseau (rate limiting).
RATE_LIMIT_DELAY = 2.0

#: Timeout (secondes) des requêtes HTTP.
REQUEST_TIMEOUT = 20

#: Dossier de cache par défaut des flux bruts.
DEFAULT_CACHE_DIR = Path("data") / "feeds_cache"

#: Dossier racine des données pré-téléchargées (JSON des bulletins, cf. §8).
DEFAULT_LOCAL_DIR = Path("data") / "data"

#: Sous-dossier (par type) contenant les JSON des bulletins, sous DEFAULT_LOCAL_DIR.
#: La résolution est insensible à la casse (le corpus mêle « Avis » et « alertes »).
_LOCAL_SUBDIRS: dict[str, str] = {"avis": "Avis", "alerte": "alertes"}

#: Base des URL canoniques du CERT-FR (pour reconstruire le lien d'un bulletin).
_CERTFR_BASE_URL = "https://www.cert.ssi.gouv.fr"

#: Motif d'un identifiant de bulletin ANSSI (ex. CERTFR-2024-AVI-0012).
_BULLETIN_ID_RE = re.compile(r"CERTFR-\d{4}-(?:AVI|ALE)-\d+", re.IGNORECASE)

#: Horodatage de la dernière requête réseau (pour le rate limiting).
_last_request_ts: float = 0.0


# --- Modèle de données -------------------------------------------------------


@dataclass(frozen=True)
class BulletinEntry:
    """Une entrée normalisée d'un flux RSS ANSSI.

    Attributes:
        bulletin_id: Identifiant ANSSI (ex. ``CERTFR-2024-AVI-0012``), déduit du lien.
        type: Type de bulletin, ``"Avis"`` ou ``"Alerte"``.
        title: Titre du bulletin.
        description: Résumé fourni par le flux.
        link: URL vers le bulletin détaillé.
        published: Date de publication normalisée (UTC), ou ``None`` si absente.
        published_raw: Chaîne de date brute d'origine (pour traçabilité).
    """

    bulletin_id: str
    type: str
    title: str
    description: str
    link: str
    published: datetime | None
    published_raw: str

    @property
    def json_url(self) -> str:
        """URL du JSON détaillé du bulletin (utile à l'étape 2)."""
        return self.link.rstrip("/") + "/json/"

    def as_dict(self) -> dict:
        """Représentation sérialisable (date au format ISO 8601)."""
        data = asdict(self)
        data["published"] = self.published.isoformat() if self.published else None
        return data


# --- Helpers internes --------------------------------------------------------


def _normalize_feed_type(feed_type: str) -> str:
    """Normalise un type de flux fourni par l'utilisateur ('Avis' -> 'avis')."""
    key = _TYPE_ALIASES.get(feed_type.strip().lower())
    if key is None:
        valid = ", ".join(sorted(set(_TYPE_ALIASES)))
        raise ValueError(f"Type de flux inconnu : {feed_type!r}. Attendu : {valid}.")
    return key


def _extract_bulletin_id(*candidates: str) -> str:
    """Extrait le premier identifiant CERTFR trouvé parmi les chaînes fournies."""
    for text in candidates:
        if not text:
            continue
        match = _BULLETIN_ID_RE.search(text)
        if match:
            return match.group(0).upper()
    return ""


def _infer_type_from_link(link: str, default: str) -> str:
    """Déduit le type (Avis/Alerte) à partir de l'URL, avec repli sur ``default``."""
    low = link.lower()
    if "/avis/" in low:
        return _TYPE_LABEL["avis"]
    if "/alerte/" in low:
        return _TYPE_LABEL["alerte"]
    return default


def _parse_published(entry: feedparser.FeedParserDict) -> datetime | None:
    """Convertit la date d'une entrée en ``datetime`` UTC (ou ``None``).

    ``feedparser`` expose ``published_parsed`` (un ``time.struct_time`` déjà
    ramené en UTC) lorsqu'il parvient à interpréter la date.
    """
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed is None:
        return None
    try:
        return datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc)
    except (ValueError, OverflowError, TypeError):  # date aberrante
        logger.warning("Date illisible ignorée : %r", entry.get("published"))
        return None


def _respect_rate_limit() -> None:
    """Patiente si nécessaire pour respecter ``RATE_LIMIT_DELAY`` entre requêtes."""
    global _last_request_ts
    elapsed = time.monotonic() - _last_request_ts
    if _last_request_ts and elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)
    _last_request_ts = time.monotonic()


def _download_feed(url: str) -> bytes:
    """Télécharge le flux brut (bytes) en respectant le rate limiting."""
    _respect_rate_limit()
    logger.info("Téléchargement du flux : %s", url)
    response = requests.get(
        url, headers={"User-Agent": _USER_AGENT}, timeout=REQUEST_TIMEOUT
    )
    response.raise_for_status()
    return response.content


def _load_feed_bytes(
    feed_type: str,
    *,
    use_cache: bool,
    force_refresh: bool,
    cache_dir: Path,
) -> bytes:
    """Renvoie le flux brut, depuis le cache disque si possible, sinon le réseau.

    On télécharge si : le cache est désactivé, un rafraîchissement est forcé,
    ou aucun fichier de cache n'existe encore. Le flux téléchargé est mis en
    cache pour les exécutions suivantes.
    """
    cache_file = cache_dir / f"{feed_type}.xml"

    if use_cache and not force_refresh and cache_file.is_file():
        logger.info("Lecture du flux depuis le cache : %s", cache_file)
        return cache_file.read_bytes()

    raw = _download_feed(FEED_URLS[feed_type])

    if use_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file.write_bytes(raw)
        logger.info("Flux mis en cache : %s", cache_file)

    return raw


def _parse_entries(raw: bytes, feed_type: str) -> list[BulletinEntry]:
    """Parse le flux brut et normalise ses entrées (avec dédoublonnage)."""
    parsed = feedparser.parse(raw)
    if parsed.bozo:  # flux mal formé : on logue mais on tente d'exploiter le reste
        logger.warning(
            "Flux %s potentiellement mal formé : %s",
            feed_type,
            parsed.get("bozo_exception"),
        )

    default_label = _TYPE_LABEL[feed_type]
    entries: list[BulletinEntry] = []
    seen_ids: set[str] = set()

    for raw_entry in parsed.entries:
        link = (raw_entry.get("link") or "").strip()
        title = (raw_entry.get("title") or "").strip()
        # feedparser mappe <description> sur "summary".
        description = (raw_entry.get("summary") or raw_entry.get("description") or "").strip()
        guid = raw_entry.get("id") or raw_entry.get("guid") or ""
        published_raw = (raw_entry.get("published") or raw_entry.get("updated") or "").strip()

        bulletin_id = _extract_bulletin_id(link, guid, title)
        # Dédoublonnage : un même bulletin ne doit apparaître qu'une fois.
        dedup_key = bulletin_id or link
        if dedup_key and dedup_key in seen_ids:
            logger.debug("Doublon ignoré : %s", dedup_key)
            continue
        if dedup_key:
            seen_ids.add(dedup_key)

        entries.append(
            BulletinEntry(
                bulletin_id=bulletin_id,
                type=_infer_type_from_link(link, default_label),
                title=title,
                description=description,
                link=link,
                published=_parse_published(raw_entry),
                published_raw=published_raw,
            )
        )

    logger.info("%d entrées extraites du flux %s.", len(entries), feed_type)
    return entries


# --- Lecture des données locales (mode hors-ligne, §8 du sujet) --------------


def _resolve_local_dir(feed_type: str, local_dir: Path) -> Path:
    """Localise le sous-dossier des bulletins d'un type, sans tenir compte de la casse.

    Le corpus fourni mélange les casses (« Avis », « alertes ») ; on accepte donc
    n'importe quelle variante présente sur le disque.
    """
    expected = _LOCAL_SUBDIRS[feed_type]
    candidate = local_dir / expected
    if candidate.is_dir():
        return candidate
    if local_dir.is_dir():  # repli : recherche insensible à la casse
        for child in local_dir.iterdir():
            if child.is_dir() and child.name.lower() == expected.lower():
                return child
    raise FileNotFoundError(
        f"Dossier local introuvable pour {feed_type!r} : {candidate} "
        f"(racine attendue : {local_dir})."
    )


def _link_from_reference(reference: str, feed_type: str) -> str:
    """Reconstruit l'URL canonique d'un bulletin à partir de sa référence."""
    segment = "avis" if feed_type == "avis" else "alerte"
    return f"{_CERTFR_BASE_URL}/{segment}/{reference}/"


def _publication_date_from_revisions(data: dict) -> tuple[datetime | None, str]:
    """Détermine la date de publication (la plus ancienne révision) d'un bulletin.

    Returns:
        Un couple ``(date_normalisée_UTC | None, chaîne_brute)``.
    """
    revisions = data.get("revisions") or []
    raw_dates = [r.get("revision_date") for r in revisions if r.get("revision_date")]
    if not raw_dates:
        return None, ""
    raw = min(raw_dates)  # les dates ISO se comparent dans l'ordre chronologique
    try:
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:  # les dates locales sont naïves -> on les ancre en UTC
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed, raw
    except ValueError:
        logger.warning("Date de révision illisible ignorée : %r", raw)
        return None, raw


def _read_local_bulletin(path: Path, feed_type: str) -> BulletinEntry | None:
    """Lit un fichier JSON de bulletin local et le normalise en :class:`BulletinEntry`."""
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Bulletin local illisible ignoré (%s) : %s", path.name, exc)
        return None

    reference = (data.get("reference") or "").strip()
    bulletin_id = _extract_bulletin_id(reference, path.name)
    published, published_raw = _publication_date_from_revisions(data)

    return BulletinEntry(
        bulletin_id=bulletin_id,
        type=_TYPE_LABEL[feed_type],
        title=(data.get("title") or "").strip(),
        description=(data.get("summary") or "").strip(),
        link=_link_from_reference(reference or path.stem, feed_type),
        published=published,
        published_raw=published_raw,
    )


def _load_local_entries(feed_type: str, local_dir: Path) -> list[BulletinEntry]:
    """Charge et normalise tous les bulletins locaux d'un type donné."""
    folder = _resolve_local_dir(feed_type, local_dir)
    entries: list[BulletinEntry] = []
    seen_ids: set[str] = set()

    for path in sorted(folder.iterdir()):
        if not path.is_file():
            continue
        entry = _read_local_bulletin(path, feed_type)
        if entry is None:
            continue
        dedup_key = entry.bulletin_id or entry.link
        if not dedup_key or dedup_key in seen_ids:
            continue
        seen_ids.add(dedup_key)
        entries.append(entry)

    logger.info("%d bulletins chargés depuis %s.", len(entries), folder)
    return entries


# --- API publique ------------------------------------------------------------


def fetch_anssi_feed(
    feed_type: str,
    *,
    source: str = "rss",
    use_cache: bool = True,
    force_refresh: bool = False,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    local_dir: Path | str = DEFAULT_LOCAL_DIR,
) -> list[BulletinEntry]:
    """Récupère et normalise les bulletins ANSSI d'un type donné.

    Deux sources, produisant le **même** schéma :class:`BulletinEntry` :

    * ``source="rss"`` — le flux RSS live du CERT-FR (les ~derniers bulletins),
      mis en cache sur disque pour éviter de re-télécharger (cf. §8 du sujet).
    * ``source="local"`` — les JSON pré-téléchargés (``local_dir``), qui couvrent
      l'historique complet ; idéal pour l'analyse et le ML hors-ligne.

    Args:
        feed_type: ``"avis"`` ou ``"alerte"`` (alias : ``"alertes"``, ``"AVI"``,
            ``"ALE"``...).
        source: ``"rss"`` (réseau, défaut) ou ``"local"`` (JSON hors-ligne).
        use_cache: (source RSS) lit/écrit le flux brut dans ``cache_dir``.
        force_refresh: (source RSS) force le re-téléchargement.
        cache_dir: (source RSS) dossier de cache des flux bruts.
        local_dir: (source locale) racine des JSON pré-téléchargés.

    Returns:
        La liste des bulletins normalisés, dédoublonnée par identifiant.

    Raises:
        ValueError: Si ``feed_type`` ou ``source`` n'est pas reconnu.
        FileNotFoundError: (source locale) si le dossier est introuvable.
        requests.RequestException: (source RSS) en cas d'échec réseau sans cache.
    """
    key = _normalize_feed_type(feed_type)

    if source == "local":
        return _load_local_entries(key, Path(local_dir))
    if source == "rss":
        raw = _load_feed_bytes(
            key,
            use_cache=use_cache,
            force_refresh=force_refresh,
            cache_dir=Path(cache_dir),
        )
        return _parse_entries(raw, key)

    raise ValueError(f"Source inconnue : {source!r}. Attendu : 'rss' ou 'local'.")


def fetch_all_feeds(
    *,
    source: str = "rss",
    use_cache: bool = True,
    force_refresh: bool = False,
    cache_dir: Path | str = DEFAULT_CACHE_DIR,
    local_dir: Path | str = DEFAULT_LOCAL_DIR,
) -> list[BulletinEntry]:
    """Récupère l'ensemble des bulletins (avis + alertes) en une liste unique.

    Le résultat est dédoublonné globalement par identifiant de bulletin.
    Voir :func:`fetch_anssi_feed` pour le détail des paramètres.
    """
    all_entries: list[BulletinEntry] = []
    seen_ids: set[str] = set()

    for feed_type in FEED_URLS:
        for entry in fetch_anssi_feed(
            feed_type,
            source=source,
            use_cache=use_cache,
            force_refresh=force_refresh,
            cache_dir=cache_dir,
            local_dir=local_dir,
        ):
            key = entry.bulletin_id or entry.link
            if key and key in seen_ids:
                continue
            if key:
                seen_ids.add(key)
            all_entries.append(entry)

    return all_entries


def feed_to_dataframe(entries: list[BulletinEntry]) -> "pd.DataFrame":
    """Convertit une liste de :class:`BulletinEntry` en ``DataFrame`` pandas.

    Importé paresseusement : pandas n'est nécessaire que pour cette commodité,
    pas pour l'extraction elle-même.
    """
    import pandas as pd

    return pd.DataFrame([entry.as_dict() for entry in entries])


# --- Démonstration en ligne de commande -------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(description="Extraction des bulletins ANSSI.")
    parser.add_argument(
        "--source",
        choices=("rss", "local"),
        default="rss",
        help="Source des bulletins : flux RSS (défaut) ou JSON locaux.",
    )
    args = parser.parse_args()

    bulletins = fetch_all_feeds(source=args.source)
    print(f"\n{len(bulletins)} bulletins extraits (avis + alertes) — source={args.source}.\n")
    for b in bulletins[:5]:
        date = b.published.date().isoformat() if b.published else "?"
        print(f"[{b.type:7}] {b.bulletin_id or '(id inconnu)':22} {date}  {b.title}")
