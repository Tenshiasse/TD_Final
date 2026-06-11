"""Tests unitaires — Étape 4 : consolidation du DataFrame."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timezone
import pandas as pd
import pytest

from anssi.feeds import BulletinEntry
from anssi.cves import BulletinCves
from anssi.enrichment import CveEnrichment, MitreData, FirstData
from anssi.consolidation import build_consolidated_dataframe, _COLUMNS


# --- Fixtures -----------------------------------------------------------------

def _entry(bulletin_id: str, type_: str = "Avis", published=None) -> BulletinEntry:
    if published is None:
        published = datetime(2024, 3, 15, 0, 0, 0, tzinfo=timezone.utc)
    return BulletinEntry(
        bulletin_id=bulletin_id,
        type=type_,
        title=f"Titre {bulletin_id}",
        description=f"Description {bulletin_id}",
        link=f"https://www.cert.ssi.gouv.fr/{bulletin_id.lower()}/",
        published=published,
        published_raw="",
    )


def _bcves(bulletin_id: str, cves: list[str], type_: str = "Avis") -> BulletinCves:
    return BulletinCves(
        bulletin_id=bulletin_id,
        type=type_,
        cves=cves,
        cves_structured=cves,
        cves_extra=[],
    )


def _enrich(cve_id: str, score: float | None = None, severity: str | None = None,
            epss: float | None = None) -> CveEnrichment:
    return CveEnrichment(
        cve_id=cve_id,
        mitre=MitreData(
            description=f"Desc {cve_id}",
            cvss_score=score,
            cvss_severity=severity,
            cvss_version="3.1" if score is not None else None,
        ),
        first=FirstData(epss_score=epss, epss_percentile=epss, epss_date="2024-03-01"),
        mitre_available=True,
        first_available=epss is not None,
    )


# --- Tests -------------------------------------------------------------------

BULLETINS = [
    _entry("CERTFR-2024-AVI-0001"),
    _entry("CERTFR-2024-AVI-0002"),
    _entry("CERTFR-2024-ALE-0001", type_="Alerte"),
]
BULLETIN_CVES = [
    _bcves("CERTFR-2024-AVI-0001", ["CVE-2024-00001", "CVE-2024-00002"]),
    _bcves("CERTFR-2024-AVI-0002", []),          # bulletin sans CVE
    _bcves("CERTFR-2024-ALE-0001", ["CVE-2024-00001"], type_="Alerte"),
]
ENRICHMENTS = {
    "CVE-2024-00001": _enrich("CVE-2024-00001", score=9.8, severity="CRITICAL", epss=0.9),
    "CVE-2024-00002": _enrich("CVE-2024-00002", score=5.5, severity="MEDIUM", epss=0.1),
}


def _df() -> pd.DataFrame:
    return build_consolidated_dataframe(BULLETINS, BULLETIN_CVES, ENRICHMENTS)


class TestShape:
    def test_row_count(self):
        # AVI-0001 → 2 CVE; AVI-0002 → 0 CVE → 1 null row; ALE-0001 → 1 CVE
        df = _df()
        assert len(df) == 4

    def test_expected_columns(self):
        df = _df()
        assert set(_COLUMNS).issubset(set(df.columns))

    def test_no_duplicate_bulletin_cve_pairs(self):
        df = _df()
        pairs = df[df["cve"].notna()][["bulletin_id", "cve"]]
        assert not pairs.duplicated().any()


class TestBulletinsWithoutCve:
    def test_preserved_as_null_row(self):
        df = _df()
        no_cve = df[df["cve"].isna()]
        assert len(no_cve) == 1
        assert no_cve.iloc[0]["bulletin_id"] == "CERTFR-2024-AVI-0002"

    def test_bulletin_metadata_filled(self):
        df = _df()
        row = df[df["bulletin_id"] == "CERTFR-2024-AVI-0002"].iloc[0]
        assert row["title"] == "Titre CERTFR-2024-AVI-0002"


class TestDtypes:
    def test_date_publication_is_datetime(self):
        df = _df()
        assert pd.api.types.is_datetime64_any_dtype(df["date_publication"])

    def test_cvss_score_is_float64(self):
        df = _df()
        assert df["cvss_score"].dtype == "float64"

    def test_epss_score_is_float64(self):
        df = _df()
        assert df["epss_score"].dtype == "float64"

    def test_bulletin_type_is_category(self):
        df = _df()
        assert str(df["bulletin_type"].dtype) == "category"

    def test_cvss_severity_is_category(self):
        df = _df()
        assert str(df["cvss_severity"].dtype) == "category"

    def test_year_publication_is_int16(self):
        df = _df()
        assert str(df["year_publication"].dtype) == "Int16"

    def test_cve_year_is_int16(self):
        df = _df()
        assert str(df["cve_year"].dtype) == "Int16"


class TestDerivedColumns:
    def test_year_publication(self):
        df = _df()
        assert (df["year_publication"].dropna() == 2024).all()

    def test_cve_year_extraction(self):
        df = _df()
        rows = df[df["cve"].notna()]
        assert (rows["cve_year"] == 2024).all()

    def test_is_critical_score(self):
        df = _df()
        row = df[df["cve"] == "CVE-2024-00001"].iloc[0]
        assert row["is_critical"] is True or row["is_critical"] == True

    def test_is_critical_medium_false(self):
        df = _df()
        row = df[(df["cve"] == "CVE-2024-00002") &
                 (df["bulletin_id"] == "CERTFR-2024-AVI-0001")].iloc[0]
        assert row["is_critical"] is False or row["is_critical"] == False

    def test_is_critical_no_cve_false(self):
        df = _df()
        row = df[df["cve"].isna()].iloc[0]
        assert row["is_critical"] is False or row["is_critical"] == False


class TestEnrichmentJoin:
    def test_enrichment_data_present(self):
        df = _df()
        row = df[(df["bulletin_id"] == "CERTFR-2024-AVI-0001") &
                 (df["cve"] == "CVE-2024-00001")].iloc[0]
        assert row["cvss_score"] == pytest.approx(9.8)
        assert row["epss_score"] == pytest.approx(0.9)

    def test_same_cve_in_two_bulletins(self):
        # CVE-2024-00001 apparaît dans AVI-0001 et ALE-0001 → enrichissement identique
        df = _df()
        rows = df[df["cve"] == "CVE-2024-00001"]
        assert len(rows) == 2
        assert (rows["cvss_score"] == 9.8).all()

    def test_column_order(self):
        df = _df()
        present = [c for c in _COLUMNS if c in df.columns]
        assert list(df.columns[:len(present)]) == present
