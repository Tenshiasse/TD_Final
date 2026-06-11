"""Étape 3 — Enrichissement des CVE via MITRE et FIRST (EPSS).

Pour chaque CVE on interroge deux sources :

* **MITRE** (``cveawg.mitre.org/api/cve/{id}``) : description, score CVSS,
  type CWE, éditeur / produit / versions affectées.
* **FIRST** (``api.first.org/data/v1/epss?cve={id}``) : score EPSS et
  percentile.

Les données sont disponibles localement dans ``data/data/mitre/`` et
``data/data/first/`` ; la fonction utilise ces fichiers en priorité et ne
touche les vraies APIs que si un fichier local est absent (mode ``"local"``
ou ``"api"``). Un délai de 2 s est respecté entre deux requêtes réseau.

Hétérogénéité MITRE gérée
--------------------------
* Score CVSS absent (54 % des cas) → champs ``None``.
* Priorité de version : ``cvssV4_0 > cvssV3_1 > cvssV3_0 > cvssV2_0``.
* Plusieurs entrées de métriques → on prend la priorité la plus haute.
* ``problemTypes`` absent (32 %) ou de type ``"text"`` → ``cwe_id`` à ``None``.
* ``type`` de CWE peut être ``"CWE"`` ou ``"cwe"`` → normalisé en casse.
* Description : on préfère ``lang == "en"``, repli sur la première.
* ``affected[].versions[]`` : champs ``lessThan``/``lessThanOrEqual``
  convertis en chaînes lisibles.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    import pandas as pd

logger = logging.getLogger(__name__)

# --- Configuration -----------------------------------------------------------

MITRE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
FIRST_API_URL  = "https://api.first.org/data/v1/epss?cve={cve_id}"

_USER_AGENT     = "TD-ANSSI-CVE/1.0 (projet pedagogique EFREI 2026)"
RATE_LIMIT_DELAY = 2.0
REQUEST_TIMEOUT  = 20

DEFAULT_LOCAL_DIR = Path("data") / "data"

#: Ordre de priorité décroissant des clés de métriques CVSS.
_CVSS_PRIORITY = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")

_last_request_ts: float = 0.0


# --- Modèles de données ------------------------------------------------------


@dataclass
class AffectedProduct:
    """Un produit affecté par un CVE.

    Attributes:
        vendor: Éditeur (ex. ``"Microsoft"``).
        product: Nom du produit (ex. ``"Windows 10"``).
        versions: Liste de chaînes décrivant les versions impactées.
    """
    vendor: str
    product: str
    versions: list[str] = field(default_factory=list)


@dataclass
class MitreData:
    """Données extraites de l'API MITRE pour un CVE.

    Tous les champs peuvent être ``None`` si absents du JSON source.
    """
    description:    str | None = None
    cvss_version:   str | None = None   # ex. "3.1", "4.0"
    cvss_score:     float | None = None
    cvss_severity:  str | None = None   # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
    cvss_vector:    str | None = None
    cwe_id:         str | None = None   # ex. "CWE-79"
    cwe_description: str | None = None
    affected:       list[AffectedProduct] = field(default_factory=list)


@dataclass
class FirstData:
    """Données extraites de l'API FIRST (EPSS) pour un CVE."""
    epss_score:      float | None = None
    epss_percentile: float | None = None
    epss_date:       str | None = None


@dataclass
class CveEnrichment:
    """Enrichissement complet d'un CVE (MITRE + FIRST).

    Attributes:
        cve_id: Identifiant CVE normalisé (majuscules).
        mitre: Données MITRE. Toujours présent (champs internes peuvent être None).
        first: Données FIRST (EPSS). Toujours présent.
        mitre_available: ``False`` si le JSON MITRE était absent ou illisible.
        first_available: ``False`` si le JSON FIRST était absent ou illisible.
    """
    cve_id:          str
    mitre:           MitreData = field(default_factory=MitreData)
    first:           FirstData = field(default_factory=FirstData)
    mitre_available: bool = False
    first_available: bool = False

    def as_dict(self) -> dict:
        """Représentation plate (une ligne de DataFrame)."""
        aff_vendors  = "; ".join(a.vendor  for a in self.mitre.affected)
        aff_products = "; ".join(a.product for a in self.mitre.affected)
        aff_versions = "; ".join(
            ", ".join(a.versions) for a in self.mitre.affected if a.versions
        )
        return {
            "cve":              self.cve_id,
            "description":      self.mitre.description,
            "cvss_version":     self.mitre.cvss_version,
            "cvss_score":       self.mitre.cvss_score,
            "cvss_severity":    self.mitre.cvss_severity,
            "cvss_vector":      self.mitre.cvss_vector,
            "cwe_id":           self.mitre.cwe_id,
            "cwe_description":  self.mitre.cwe_description,
            "vendors":          aff_vendors  or None,
            "products":         aff_products or None,
            "versions":         aff_versions or None,
            "epss_score":       self.first.epss_score,
            "epss_percentile":  self.first.epss_percentile,
            "epss_date":        self.first.epss_date,
            "mitre_available":  self.mitre_available,
            "first_available":  self.first_available,
        }


# --- Parsing MITRE -----------------------------------------------------------


def _pick_best_cvss(metrics: list[dict]) -> tuple[str | None, dict]:
    """Choisit le score CVSS de priorité la plus haute parmi toutes les entrées.

    Returns:
        ``(version_key, cvss_dict)`` ex. ``("cvssV3_1", {...})`` ou
        ``(None, {})`` si aucun score.
    """
    best_priority = len(_CVSS_PRIORITY)  # sentinel "aucun"
    best_key: str | None = None
    best_obj: dict = {}

    for entry in metrics:
        for priority, key in enumerate(_CVSS_PRIORITY):
            if key in entry and priority < best_priority:
                best_priority = priority
                best_key = key
                best_obj = entry[key]

    return best_key, best_obj


def _parse_cvss_version(key: str | None) -> str | None:
    """Convertit une clé interne en numéro de version lisible."""
    if key is None:
        return None
    mapping = {"cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0", "cvssV2_0": "2.0"}
    return mapping.get(key, key)


def _parse_description(cna: dict) -> str | None:
    """Extrait la description en anglais, avec repli sur la première disponible."""
    descriptions = cna.get("descriptions") or []
    if not descriptions:
        return None
    en = next((d["value"] for d in descriptions if d.get("lang", "").startswith("en")), None)
    return en or descriptions[0].get("value")


def _parse_cwe(cna: dict) -> tuple[str | None, str | None]:
    """Extrait le CWE le plus pertinent.

    Préfère les entrées avec ``type == "CWE"`` (ou ``"cwe"``), qui exposent
    ``cweId``. Repli sur la description libre si aucun ``cweId`` trouvé.

    Returns:
        ``(cwe_id, cwe_description)``
    """
    for pt in (cna.get("problemTypes") or []):
        for desc in (pt.get("descriptions") or []):
            dtype = (desc.get("type") or "").upper()
            if dtype == "CWE":
                cwe_id  = desc.get("cweId") or None
                cwe_desc = desc.get("description") or None
                if cwe_id:
                    return cwe_id, cwe_desc
    # Repli : entrée de type "text" avec une vraie description
    for pt in (cna.get("problemTypes") or []):
        for desc in (pt.get("descriptions") or []):
            text = (desc.get("description") or "").strip()
            if text and text.lower() not in ("n/a", ""):
                return None, text
    return None, None


def _format_version_range(v: dict) -> str:
    """Construit une chaîne lisible pour une entrée de version.

    Exemples :
      ``{"version": "0", "lessThan": "2.3.1"}``     → ``"< 2.3.1"``
      ``{"version": "1.0", "lessThanOrEqual": "1.5"}`` → ``"1.0 - 1.5"``
      ``{"version": "2.0", "status": "affected"}``   → ``"2.0"``
    """
    if v.get("status") == "unaffected":
        return ""
    ver = v.get("version", "")
    lt  = v.get("lessThan")
    lte = v.get("lessThanOrEqual")
    if lt:
        base = ver if ver not in ("0", "*", "") else ""
        return f"{base} < {lt}".strip()
    if lte:
        base = ver if ver not in ("0", "*", "") else ""
        return f"{base} <= {lte}".strip() if base else f"<= {lte}"
    return ver


def _parse_affected(cna: dict) -> list[AffectedProduct]:
    """Extrait la liste des produits affectés."""
    products: list[AffectedProduct] = []
    for entry in (cna.get("affected") or []):
        vendor  = (entry.get("vendor")  or "").strip()
        product = (entry.get("product") or "").strip()
        if not vendor and not product:
            continue
        raw_versions = entry.get("versions") or []
        versions = [
            s for v in raw_versions
            if (s := _format_version_range(v))
        ]
        products.append(AffectedProduct(vendor=vendor, product=product, versions=versions))
    return products


def parse_mitre(data: dict) -> MitreData:
    """Parse un JSON MITRE brut en :class:`MitreData`.

    Tolère tous les cas d'absence ou de mauvaise structure observés dans
    le corpus (cf. audit en tête de module).
    """
    try:
        cna = data.get("containers", {}).get("cna", {})
    except AttributeError:
        return MitreData()

    # Description
    description = _parse_description(cna)

    # CVSS
    metrics = cna.get("metrics") or []
    cvss_key, cvss_obj = _pick_best_cvss(metrics)
    cvss_version  = _parse_cvss_version(cvss_key)
    cvss_score    = _safe_float(cvss_obj.get("baseScore"))
    cvss_severity = (cvss_obj.get("baseSeverity") or "").upper() or None
    cvss_vector   = cvss_obj.get("vectorString") or None

    # CWE
    cwe_id, cwe_description = _parse_cwe(cna)

    # Produits affectés
    affected = _parse_affected(cna)

    return MitreData(
        description=description,
        cvss_version=cvss_version,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        cvss_vector=cvss_vector,
        cwe_id=cwe_id,
        cwe_description=cwe_description,
        affected=affected,
    )


# --- Parsing FIRST -----------------------------------------------------------


def parse_first(data: dict) -> FirstData:
    """Parse un JSON FIRST brut en :class:`FirstData`."""
    entries = data.get("data") or []
    if not entries:
        return FirstData()
    entry = entries[0]
    return FirstData(
        epss_score=_safe_float(entry.get("epss")),
        epss_percentile=_safe_float(entry.get("percentile")),
        epss_date=entry.get("date") or None,
    )


# --- Helpers -----------------------------------------------------------------


def _safe_float(value) -> float | None:
    """Convertit en float, renvoie None si absent ou non convertible."""
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _respect_rate_limit() -> None:
    global _last_request_ts
    elapsed = time.monotonic() - _last_request_ts
    if _last_request_ts and elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)
    _last_request_ts = time.monotonic()


def _load_local_json(folder: Path, cve_id: str) -> dict | None:
    """Charge un JSON local ; renvoie None si absent ou illisible."""
    path = folder / cve_id
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("Fichier local illisible (%s) : %s", path, exc)
        return None


def _fetch_api(url: str) -> dict | None:
    """Effectue une requête GET (avec rate limiting) ; renvoie None en cas d'erreur."""
    _respect_rate_limit()
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": _USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("Échec API %s : %s", url, exc)
        return None


# --- API publique -------------------------------------------------------------


def enrich_cve(
    cve_id: str,
    *,
    source: str = "local",
    local_dir: Path | str = DEFAULT_LOCAL_DIR,
) -> CveEnrichment:
    """Enrichit un CVE avec MITRE et FIRST.

    Args:
        cve_id: Identifiant CVE (ex. ``"CVE-2023-12345"``).
        source: ``"local"`` — lit les JSON locaux (défaut, recommandé) ;
                ``"api"`` — interroge les vraies APIs (rate limiting actif) ;
                ``"local_then_api"`` — local en priorité, API en repli.
        local_dir: Racine des données pré-téléchargées.

    Returns:
        :class:`CveEnrichment` avec les champs disponibles remplis
        (les absents sont ``None``).
    """
    cve_id   = cve_id.upper()
    root     = Path(local_dir)
    mitre_dir = root / "mitre"
    first_dir = root / "first"

    # ── MITRE ────────────────────────────────────────────────────────────────
    mitre_raw: dict | None = None
    if source in ("local", "local_then_api"):
        mitre_raw = _load_local_json(mitre_dir, cve_id)
    if mitre_raw is None and source in ("api", "local_then_api"):
        mitre_raw = _fetch_api(MITRE_API_URL.format(cve_id=cve_id))

    mitre_data      = parse_mitre(mitre_raw) if mitre_raw else MitreData()
    mitre_available = mitre_raw is not None

    # ── FIRST ────────────────────────────────────────────────────────────────
    first_raw: dict | None = None
    if source in ("local", "local_then_api"):
        first_raw = _load_local_json(first_dir, cve_id)
    if first_raw is None and source in ("api", "local_then_api"):
        first_raw = _fetch_api(FIRST_API_URL.format(cve_id=cve_id))

    first_data      = parse_first(first_raw) if first_raw else FirstData()
    first_available = first_raw is not None

    return CveEnrichment(
        cve_id=cve_id,
        mitre=mitre_data,
        first=first_data,
        mitre_available=mitre_available,
        first_available=first_available,
    )


def enrich_cves(
    cve_ids: list[str],
    *,
    source: str = "local",
    local_dir: Path | str = DEFAULT_LOCAL_DIR,
) -> dict[str, CveEnrichment]:
    """Enrichit une liste de CVE ; renvoie un dict indexé par CVE ID.

    Les CVE sans données locales **ni** API disponible sont tout de même
    présents dans le dict, avec ``mitre_available=False``.
    """
    result: dict[str, CveEnrichment] = {}
    unique = list(dict.fromkeys(c.upper() for c in cve_ids))  # dédoublonnage ordre-stable
    for i, cve_id in enumerate(unique):
        result[cve_id] = enrich_cve(cve_id, source=source, local_dir=local_dir)
        if (i + 1) % 5000 == 0:
            logger.info("Enrichissement : %d / %d CVE traités.", i + 1, len(unique))
    logger.info("Enrichissement terminé : %d CVE.", len(result))
    return result


def enrichment_to_dataframe(enrichments: dict[str, CveEnrichment]) -> "pd.DataFrame":
    """Convertit le dict d'enrichissements en DataFrame (une ligne par CVE)."""
    import pandas as pd
    return pd.DataFrame([e.as_dict() for e in enrichments.values()])


# --- Démonstration -----------------------------------------------------------

if __name__ == "__main__":
    import os
    import logging as _logging

    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s | %(message)s")
    os.chdir(Path(__file__).resolve().parent.parent)

    sample = [
        "CVE-2023-44453",   # 1 CVE, CVSS V3.1 attendu
        "CVE-2024-20919",   # gros bulletin Java
        "CVE-2020-36187",   # sans CVSS
        "CVE-2024-35314",   # sans CVSS
        "CVE-2026-40164",   # cvssV4_0
        "CVE-XXXX-00000",   # CVE inexistant
    ]

    results = enrich_cves(sample)
    for cve_id, e in results.items():
        m = e.mitre
        f = e.first
        print(f"\n{cve_id}  mitre={e.mitre_available}  first={e.first_available}")
        print(f"  CVSS {m.cvss_version} {m.cvss_score} ({m.cvss_severity})  CWE={m.cwe_id}")
        print(f"  EPSS={f.epss_score}  produits={len(m.affected)}")
        if m.description:
            print(f"  desc={m.description[:80]}")
