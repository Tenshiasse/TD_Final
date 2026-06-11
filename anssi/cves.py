"""Étape 2 — Extraction exhaustive des CVE depuis les bulletins ANSSI.

Stratégie d'extraction en deux passes complémentaires :

1. **Structurée** : clé ``"cves"`` du JSON — source la plus fiable.
2. **Regex ciblée** : appliquée champ par champ (``summary``, ``content``,
   ``revisions``, ``vendor_advisories``, ``affected_systems``) pour capturer
   les CVE cités dans le texte libre sans créer de faux positifs.

On évite délibérément de sérialiser l'ensemble du JSON en une chaîne unique :
cela produit des identifiants artificiels (ex. ``CVE-2023-2140712`` issu d'une
URL ``…/CVE-2023-21407.12``). Les champs sont parcourus individuellement.

Les CVE extraits sont normalisés en majuscules, dédoublonnés et filtrés par
plage d'année valide (1999 ≤ year ≤ now + 1).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd

logger = logging.getLogger(__name__)

# --- Configuration -----------------------------------------------------------

#: Motif CVE officiel : CVE-YYYY-NNNN à CVE-YYYY-NNNNNNN (4 à 7 chiffres).
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)

#: Borne inférieure de l'année CVE (premier CVE officiel).
_CVE_YEAR_MIN = 1999

#: Borne supérieure dynamique (année courante + 1 pour les pré-publications).
_CVE_YEAR_MAX = datetime.now(tz=timezone.utc).year + 1

#: Dossier racine des données locales par défaut.
DEFAULT_LOCAL_DIR = Path("data") / "data"

#: Sous-dossiers par type (insensible à la casse dans _resolve_local_dir).
_LOCAL_SUBDIRS: dict[str, str] = {"avis": "Avis", "alerte": "alertes"}

#: Type normalisé pour l'affichage.
_TYPE_LABEL: dict[str, str] = {"avis": "Avis", "alerte": "Alerte"}


# --- Modèle de données -------------------------------------------------------


@dataclass
class BulletinCves:
    """CVE associés à un bulletin ANSSI, tous champs confondus.

    Attributes:
        bulletin_id: Identifiant ANSSI (``CERTFR-YYYY-AVI/ALE-NNNN``).
        type: ``"Avis"`` ou ``"Alerte"``.
        cves: Liste triée et dédoublonnée des identifiants CVE (en majuscules).
        cves_structured: CVE issus de la clé ``"cves"`` uniquement.
        cves_extra: CVE trouvés uniquement hors de la clé ``"cves"``.
    """

    bulletin_id: str
    type: str
    cves: list[str]
    cves_structured: list[str] = field(repr=False)
    cves_extra: list[str] = field(repr=False)

    def as_dict(self) -> dict:
        return {
            "bulletin_id": self.bulletin_id,
            "type": self.type,
            "cves": self.cves,
            "cves_count": len(self.cves),
            "cves_structured_count": len(self.cves_structured),
            "cves_extra_count": len(self.cves_extra),
        }


# --- Validation et normalisation ---------------------------------------------


def _is_valid_cve(year_str: str, _seq_str: str) -> bool:
    """Vérifie qu'une année CVE est dans la plage raisonnable."""
    try:
        return _CVE_YEAR_MIN <= int(year_str) <= _CVE_YEAR_MAX
    except ValueError:
        return False


def _extract_cve_ids(text: str) -> frozenset[str]:
    """Extrait et valide les CVE d'une chaîne de caractères.

    Returns:
        Ensemble d'identifiants normalisés en majuscules.
    """
    return frozenset(
        f"CVE-{year}-{seq}".upper()
        for year, seq in _CVE_RE.findall(text)
        if _is_valid_cve(year, seq)
    )


# --- Extraction structurée ---------------------------------------------------


def _from_cves_key(data: dict) -> frozenset[str]:
    """Extrait les CVE depuis la clé dédiée ``"cves"`` du JSON."""
    result: set[str] = set()
    for entry in data.get("cves") or []:
        name = entry.get("name") or ""
        if name:
            # La clé est supposée propre ; on valide quand même l'année.
            ids = _extract_cve_ids(name)
            result.update(ids)
            if not ids and name.upper().startswith("CVE-"):
                logger.debug("CVE structuré ignoré (format invalide) : %r", name)
    return frozenset(result)


# --- Extraction par champ texte ----------------------------------------------


def _from_string_field(data: dict, key: str) -> frozenset[str]:
    """Regex sur un champ de type chaîne (``summary``, ``content``)."""
    val = data.get(key)
    if not val or not isinstance(val, str):
        return frozenset()
    return _extract_cve_ids(val)


def _from_revisions(data: dict) -> frozenset[str]:
    """Regex sur le texte de description de chaque révision."""
    result: set[str] = set()
    for rev in data.get("revisions") or []:
        desc = rev.get("description") or ""
        result.update(_extract_cve_ids(desc))
    return frozenset(result)


def _from_vendor_advisories(data: dict) -> frozenset[str]:
    """Regex sur le titre et l'URL de chaque advisory tiers.

    L'URL est analysée segment par segment afin d'éviter les faux positifs
    issus de nombres adjacents (ex. ``/CVE-2023-21407.12``).
    """
    result: set[str] = set()
    for adv in data.get("vendor_advisories") or []:
        # Titre : texte libre, CVE clairement délimités par \\b.
        result.update(_extract_cve_ids(adv.get("title") or ""))
        # URL : on extrait seulement ce qui ressemble à un segment CVE propre.
        url = adv.get("url") or ""
        result.update(_extract_cve_ids(url))
    return frozenset(result)


def _from_affected_systems(data: dict) -> frozenset[str]:
    """Regex sur les descriptions des systèmes affectés.

    ``affected_systems`` est une liste de dicts ; ``affected_systems_content``
    est une simple chaîne HTML/texte — les deux types sont gérés.
    """
    result: set[str] = set()
    for item in data.get("affected_systems") or []:
        if isinstance(item, dict):
            result.update(_extract_cve_ids(item.get("description") or ""))
    content = data.get("affected_systems_content")
    if content and isinstance(content, str):
        result.update(_extract_cve_ids(content))
    return frozenset(result)


# --- Extraction combinée -----------------------------------------------------


def extract_cves_from_data(data: dict) -> tuple[frozenset[str], frozenset[str]]:
    """Extrait tous les CVE d'un JSON de bulletin, en deux ensembles distincts.

    Returns:
        ``(structured, extra)`` où :

        - ``structured`` : CVE issus de la clé ``"cves"`` (source fiable).
        - ``extra`` : CVE supplémentaires trouvés dans les autres champs.
    """
    structured = _from_cves_key(data)

    extra = (
        _from_string_field(data, "summary")
        | _from_string_field(data, "content")
        | _from_revisions(data)
        | _from_vendor_advisories(data)
        | _from_affected_systems(data)
    ) - structured  # n'inclure que ce qui n'est pas déjà dans structured

    return structured, extra


# --- Lecture d'un fichier bulletin -------------------------------------------


def _resolve_local_dir(feed_type: str, local_dir: Path) -> Path:
    expected = _LOCAL_SUBDIRS[feed_type]
    candidate = local_dir / expected
    if candidate.is_dir():
        return candidate
    if local_dir.is_dir():
        for child in local_dir.iterdir():
            if child.is_dir() and child.name.lower() == expected.lower():
                return child
    raise FileNotFoundError(
        f"Dossier local introuvable pour {feed_type!r} : {candidate}"
    )


def _bulletin_id_from_data(data: dict, path: Path) -> str:
    ref = (data.get("reference") or "").strip().upper()
    return ref or path.stem.upper()


def extract_bulletin_cves(path: Path, feed_type: str) -> BulletinCves | None:
    """Lit un fichier JSON et retourne ses CVE extraits.

    Args:
        path: Chemin vers le fichier JSON du bulletin.
        feed_type: ``"avis"`` ou ``"alerte"``.

    Returns:
        :class:`BulletinCves` ou ``None`` si le fichier est illisible.
    """
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Bulletin illisible ignoré (%s) : %s", path.name, exc)
        return None

    bulletin_id = _bulletin_id_from_data(data, path)
    structured, extra = extract_cves_from_data(data)
    all_cves = sorted(structured | extra)

    return BulletinCves(
        bulletin_id=bulletin_id,
        type=_TYPE_LABEL[feed_type],
        cves=all_cves,
        cves_structured=sorted(structured),
        cves_extra=sorted(extra),
    )


# --- Traitement de l'ensemble du corpus --------------------------------------


def extract_all_cves(
    local_dir: Path | str = DEFAULT_LOCAL_DIR,
) -> list[BulletinCves]:
    """Extrait les CVE de l'ensemble des bulletins locaux (avis + alertes).

    Args:
        local_dir: Racine des données pré-téléchargées.

    Returns:
        Liste de :class:`BulletinCves`, un élément par bulletin, dans l'ordre
        des fichiers (trié par identifiant).
    """
    root = Path(local_dir)
    results: list[BulletinCves] = []

    for feed_type in ("avis", "alerte"):
        folder = _resolve_local_dir(feed_type, root)
        for path in sorted(folder.iterdir()):
            if not path.is_file():
                continue
            entry = extract_bulletin_cves(path, feed_type)
            if entry is not None:
                results.append(entry)

    logger.info(
        "%d bulletins traités, %d CVE uniques au total.",
        len(results),
        len({cve for b in results for cve in b.cves}),
    )
    return results


def cves_to_dataframe(bulletin_cves: list[BulletinCves]) -> "pd.DataFrame":
    """Convertit en DataFrame « long » : une ligne par (bulletin, CVE).

    C'est le format attendu à l'étape 4 (DataFrame de consolidation) :
    chaque CVE d'un bulletin occupe sa propre ligne.
    """
    import pandas as pd

    rows = []
    for b in bulletin_cves:
        if not b.cves:
            # Bulletins sans CVE : on garde une ligne avec cve=None
            rows.append({"bulletin_id": b.bulletin_id, "type": b.type, "cve": None})
        else:
            for cve in b.cves:
                rows.append({"bulletin_id": b.bulletin_id, "type": b.type, "cve": cve})
    return pd.DataFrame(rows)


# --- Démonstration -----------------------------------------------------------

if __name__ == "__main__":
    import os
    import logging as _logging

    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s | %(message)s")

    os.chdir(r"C:\Users\natha\Downloads\TD_Final")
    results = extract_all_cves()

    total_cves = len({cve for b in results for cve in b.cves})
    with_cves  = sum(1 for b in results if b.cves)
    with_extra = sum(1 for b in results if b.cves_extra)

    print(f"\n{len(results)} bulletins traités")
    print(f"  avec au moins 1 CVE : {with_cves}")
    print(f"  avec CVE hors clé 'cves' : {with_extra}")
    print(f"  CVE distincts (tous bulletins) : {total_cves}")

    print("\n--- Top 5 bulletins (+ de CVE) ---")
    for b in sorted(results, key=lambda b: -len(b.cves))[:5]:
        print(f"  [{b.type:7}] {b.bulletin_id:25}  {len(b.cves):4} CVE")

    print("\n--- Bulletins avec CVE extra ---")
    for b in [b for b in results if b.cves_extra][:5]:
        print(f"  {b.bulletin_id}: extra={b.cves_extra}")
