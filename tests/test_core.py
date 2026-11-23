from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.aggregator import (
    build_profile_summary,
    export_report_csv,
    export_report_markdown,
    merge_findings,
)
from app.core.detector import detect_query_type, normalize_query
from app.main import app
from app.models import Finding, QueryType, ScanDepth, SearchReport
from app.storage import ReportStorage


def test_detect_query_type():
    assert detect_query_type("torvalds") == QueryType.USERNAME
    assert detect_query_type("@torvalds") == QueryType.USERNAME
    assert detect_query_type("user.name+tag@example.com") == QueryType.EMAIL
    assert detect_query_type("+16502530000") == QueryType.PHONE
    assert detect_query_type("+7 (999) 123-45-67") == QueryType.PHONE
    assert detect_query_type("github.com") == QueryType.DOMAIN
    assert detect_query_type("https://www.example.org/") == QueryType.DOMAIN


def test_normalize_query():
    assert normalize_query("@Torvalds", QueryType.USERNAME) == "Torvalds"
    assert normalize_query("Test@Example.COM", QueryType.EMAIL) == "test@example.com"
    assert normalize_query("https://www.GitHub.com/", QueryType.DOMAIN) == "github.com"
    assert normalize_query("+7 (999) 123-45-67", QueryType.PHONE) == "+79991234567"


def test_merge_findings_deduplicates_and_boosts_confidence():
    f1 = Finding(
        site="GitHub",
        url="https://github.com/torvalds/",
        category="coding",
        sources=["direct-apis"],
        confidence=0.90,
        metadata={"display_name": "Linus Torvalds", "location": "Portland, OR"},
        snippet="Linus Torvalds · Portland, OR",
    )
    f2 = Finding(
        site="GitHub",
        url="https://www.github.com/torvalds",
        category="other",
        sources=["sherlock"],
        confidence=0.80,
        metadata={"http_status": "200"},
    )
    f3 = Finding(
        site="GitHub",
        url="https://github.com/torvalds",
        category="coding",
        sources=["maigret"],
        confidence=0.84,
        metadata={"bio": "Linux creator"},
    )

    merged = merge_findings([f1, f2, f3])
    assert len(merged) == 1
    item = merged[0]
    assert set(item.sources) == {"direct-apis", "sherlock", "maigret"}
    assert item.confidence > 0.95
    assert item.metadata["display_name"] == "Linus Torvalds"
    assert item.metadata["bio"] == "Linux creator"

    summary = build_profile_summary(merged)
    assert "Linus Torvalds" in summary.display_names
    assert "Portland, OR" in summary.locations
    assert "Linux creator" in summary.bios


def test_exports_and_storage(tmp_path: Path):
    report = SearchReport(
        id="abc123",
        query="torvalds",
        detected_type=QueryType.USERNAME,
        depth=ScanDepth.FAST,
        elapsed_ms=1500,
        findings=[
            Finding(
                site="GitHub",
                url="https://github.com/torvalds",
                category="coding",
                sources=["direct-apis", "sherlock"],
                confidence=0.98,
                snippet="Linus Torvalds",
            )
        ],
        total_unique=1,
        multi_source_confirmed=1,
    )
    csv_text = export_report_csv(report)
    assert "GitHub" in csv_text and "direct-apis, sherlock" in csv_text
    md_text = export_report_markdown(report)
    assert "# OSINT-отчёт Sherlock Hub: `torvalds`" in md_text

    async def _db_roundtrip():
        store = ReportStorage(db_path=tmp_path / "test.db")
        await store.init()
        await store.save(report)
        loaded = await store.get("abc123")
        assert loaded is not None and loaded.query == "torvalds"
        hist = await store.list_history()
        assert len(hist) == 1 and hist[0].id == "abc123"
        assert await store.delete("abc123") is True
        assert await store.get("abc123") is None

    asyncio.run(_db_roundtrip())


def test_api_health_engines_and_phone_search():
    with TestClient(app) as client:
        r_health = client.get("/api/health")
        assert r_health.status_code == 200
        body = r_health.json()
        assert body["status"] == "ok"
        assert body["engines_available"] >= 6

        r_engines = client.get("/api/engines")
        assert r_engines.status_code == 200
        ids = {e["id"] for e in r_engines.json()}
        assert {"direct-apis", "sherlock", "maigret", "email-osint", "phone-osint", "domain-osint"} <= ids

        # Real passive phone search (Google HQ public number)
        r_phone = client.post("/api/search", json={"query": "+16502530000", "depth": "fast"})
        assert r_phone.status_code == 200
        rep = r_phone.json()
        assert rep["detected_type"] == "phone"
        assert rep["total_unique"] >= 2
        assert rep["summary"]["extra"]["phone"]["e164"] == "+16502530000"

        # Clean up test entry from history
        client.delete(f"/api/reports/{rep['id']}")
