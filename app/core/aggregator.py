from __future__ import annotations

import asyncio
import csv
import io
import time
import uuid
from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import urlparse

from app.core.detector import detect_query_type, normalize_query
from app.models import (
    EngineExecution,
    EngineInfo,
    Finding,
    ProfileSummary,
    QueryType,
    ScanDepth,
    SearchReport,
    SearchRequest,
)
from app.providers.base import BaseProvider
from app.providers.direct_apis import DirectAPIsProvider
from app.providers.domain_engine import DomainOSINTProvider
from app.providers.email_engine import EmailOSINTProvider
from app.providers.maigret_engine import MaigretProvider
from app.providers.optional_cli import (
    BlackbirdProvider,
    SocialAnalyzerProvider,
    TheHarvesterProvider,
)
from app.providers.phone_engine import PhoneOSINTProvider
from app.providers.sherlock_engine import SherlockProvider


def build_providers() -> list[BaseProvider]:
    return [
        DirectAPIsProvider(),
        SherlockProvider(),
        MaigretProvider(),
        EmailOSINTProvider(),
        PhoneOSINTProvider(),
        DomainOSINTProvider(),
        BlackbirdProvider(),
        SocialAnalyzerProvider(),
        TheHarvesterProvider(),
    ]


def canonical_finding_key(f: Finding) -> str:
    """Create a normalized deduplication key across Sherlock, Maigret, Direct APIs, etc."""
    if f.url:
        parsed = urlparse(f.url.strip())
        host = parsed.netloc.lower().removeprefix("www.")
        path = parsed.path.rstrip("/").lower()
        query = f"?{parsed.query.lower()}" if parsed.query else ""
        return f"url:{host}{path}{query}"
    return f"site:{f.site.strip().lower()}:{f.category}"


def merge_findings(all_findings: list[Finding]) -> list[Finding]:
    """Merge duplicate findings across engines, boosting confidence & combining metadata."""
    buckets: dict[str, Finding] = {}
    for item in all_findings:
        key = canonical_finding_key(item)
        if key not in buckets:
            buckets[key] = item.model_copy(deep=True)
            continue

        existing = buckets[key]
        # Merge sources uniquely
        for src in item.sources:
            if src not in existing.sources:
                existing.sources.append(src)

        # Prefer richer snippet and cleaner site name
        if (not existing.snippet and item.snippet) or (
            item.snippet and existing.snippet and len(item.snippet) > len(existing.snippet)
        ):
            existing.snippet = item.snippet
        if existing.category == "other" and item.category != "other":
            existing.category = item.category

        # Merge metadata (don't overwrite rich keys with None)
        for mk, mv in item.metadata.items():
            if mv is not None and mk not in existing.metadata:
                existing.metadata[mk] = mv

        # Boost confidence when confirmed by multiple independent engines
        base_conf = max(existing.confidence, item.confidence)
        multi_bonus = 0.06 * (len(existing.sources) - 1)
        existing.confidence = round(min(0.99, base_conf + multi_bonus), 2)

    merged = list(buckets.values())
    # Sort: multi-source first, then highest confidence, then site name
    merged.sort(key=lambda x: (-len(x.sources), -x.confidence, x.site.lower()))
    return merged


def build_profile_summary(findings: list[Finding]) -> ProfileSummary:
    """Extract aggregated identity signals (names, avatars, locations, bios, websites)."""
    names: list[str] = []
    avatars: list[str] = []
    locations: list[str] = []
    bios: list[str] = []
    websites: list[str] = []
    emails: list[str] = []
    extra: dict[str, Any] = {}

    def _add_unique(target: list[str], value: Any, limit: int = 6) -> None:
        if not value or not isinstance(value, str):
            return
        v = value.strip()
        if v and v not in target and len(target) < limit:
            target.append(v)

    for f in findings:
        m = f.metadata or {}
        _add_unique(names, m.get("display_name"))
        _add_unique(avatars, m.get("avatar"), limit=4)
        _add_unique(locations, m.get("location"))
        _add_unique(bios, m.get("bio"), limit=4)
        _add_unique(websites, m.get("website"))
        if isinstance(m.get("emails"), list):
            for e in m["emails"]:
                _add_unique(emails, e, limit=10)
        if f.category == "phone" and m.get("e164"):
            extra["phone"] = {
                "e164": m.get("e164"),
                "location": m.get("location"),
                "carrier": m.get("carrier"),
                "line_type": m.get("line_type"),
            }
        if f.category == "email" and m.get("mail_provider"):
            extra["mail_provider"] = m.get("mail_provider")
            extra["has_mx"] = m.get("has_mx")
            extra["disposable"] = m.get("disposable")
        if f.site == "RDAP / WHOIS" and m.get("registrar"):
            extra["registrar"] = m.get("registrar")

    return ProfileSummary(
        display_names=names,
        avatars=avatars,
        locations=locations,
        bios=bios,
        websites=websites,
        emails_found=emails,
        extra=extra,
    )


class OSINTAggregator:
    """Orchestrates all enabled OSINT providers in parallel with live progress streaming."""

    def __init__(self) -> None:
        self.providers: list[BaseProvider] = build_providers()
        self.provider_map: dict[str, BaseProvider] = {p.id: p for p in self.providers}

    def list_engines(self) -> list[EngineInfo]:
        return [p.info() for p in self.providers]

    def _select_plan(
        self, req: SearchRequest
    ) -> tuple[QueryType, str, list[tuple[BaseProvider, str, QueryType]]]:
        detected = (
            detect_query_type(req.query)
            if req.query_type == QueryType.AUTO
            else req.query_type
        )
        normalized = normalize_query(req.query, detected)

        requested_ids = set(req.engines) if req.engines else None
        plan: list[tuple[BaseProvider, str, QueryType]] = []

        def _eligible(p: BaseProvider, qtype: QueryType) -> bool:
            if qtype not in p.supported_types:
                return False
            avail, _ = p.is_available()
            if not avail:
                return False
            if requested_ids is not None:
                return p.id in requested_ids
            return p.default_enabled

        for p in self.providers:
            if _eligible(p, detected):
                plan.append((p, normalized, detected))

        # Smart cross-check: when searching an email, also check its username prefix via Direct APIs & Maigret
        if detected == QueryType.EMAIL and req.cross_check_username and "@" in normalized:
            local_part, domain_part = normalized.split("@", 1)
            # Only cross-check reasonably unique handles (avoid info@, admin@, support@)
            generic_prefixes = {"info", "admin", "support", "contact", "hello", "sales", "mail", "noreply", "test"}
            if len(local_part) >= 3 and local_part not in generic_prefixes:
                for pid in ("direct-apis", "sherlock", "maigret"):
                    p = self.provider_map.get(pid)
                    if p and _eligible(p, QueryType.USERNAME):
                        plan.append((p, local_part, QueryType.USERNAME))
            # Also check domain DNS/RDAP if it's a custom domain (not gmail/yandex/mail.ru/outlook)
            public_mail_domains = {
                "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
                "live.com", "icloud.com", "me.com", "yandex.ru", "ya.ru", "mail.ru",
                "bk.ru", "inbox.ru", "list.ru", "proton.me", "protonmail.com",
            }
            if domain_part not in public_mail_domains:
                dom_p = self.provider_map.get("domain-osint")
                if dom_p and _eligible(dom_p, QueryType.DOMAIN):
                    plan.append((dom_p, domain_part, QueryType.DOMAIN))

        return detected, normalized, plan

    async def run_stream(
        self, req: SearchRequest
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Yield live SSE events as each engine starts, finishes, and merges into the dossier."""
        report_id = uuid.uuid4().hex[:12]
        t0 = time.perf_counter()
        detected, normalized, plan = self._select_plan(req)

        exec_map: dict[str, EngineExecution] = {
            p.id: EngineExecution(
                engine_id=p.id,
                engine_name=p.name,
                status="running",
                message=f"Поиск «{q_val}» ({q_t.value})",
            )
            for p, q_val, q_t in plan
        }

        yield {
            "event": "started",
            "data": {
                "id": report_id,
                "query": normalized,
                "detected_type": detected.value,
                "depth": req.depth.value,
                "engines": [e.model_dump() for e in exec_map.values()],
            },
        }

        queue: asyncio.Queue[tuple[str, list[Finding], EngineExecution]] = asyncio.Queue()

        async def _worker(provider: BaseProvider, q_val: str, q_t: QueryType) -> None:
            e_t0 = time.perf_counter()
            try:
                findings = await provider.search(q_val, q_t, req.depth)
                elapsed = int((time.perf_counter() - e_t0) * 1000)
                status = EngineExecution(
                    engine_id=provider.id,
                    engine_name=provider.name,
                    status="completed",
                    findings_count=len(findings),
                    elapsed_ms=elapsed,
                    message=f"Найдено: {len(findings)}" + (f" (по нику {q_val})" if q_t != detected else ""),
                )
                await queue.put((provider.id, findings, status))
            except Exception as exc:
                elapsed = int((time.perf_counter() - e_t0) * 1000)
                status = EngineExecution(
                    engine_id=provider.id,
                    engine_name=provider.name,
                    status="error",
                    findings_count=0,
                    elapsed_ms=elapsed,
                    message=str(exc)[:180],
                )
                await queue.put((provider.id, [], status))

        tasks = [asyncio.create_task(_worker(p, q_val, q_t)) for p, q_val, q_t in plan]

        raw_findings: list[Finding] = []
        completed_count = 0
        total_tasks = len(tasks)

        while completed_count < total_tasks:
            engine_id, new_findings, status_obj = await queue.get()
            completed_count += 1
            exec_map[engine_id] = status_obj
            raw_findings.extend(new_findings)

            merged_so_far = merge_findings(raw_findings)
            summary_so_far = build_profile_summary(merged_so_far)

            yield {
                "event": "engine_update",
                "data": {
                    "engine": status_obj.model_dump(),
                    "completed": completed_count,
                    "total": total_tasks,
                    "findings": [f.model_dump() for f in merged_so_far],
                    "summary": summary_so_far.model_dump(),
                    "total_unique": len(merged_so_far),
                    "multi_source_confirmed": sum(1 for f in merged_so_far if len(f.sources) > 1),
                },
            }

        await asyncio.gather(*tasks, return_exceptions=True)

        merged_final = merge_findings(raw_findings)
        summary_final = build_profile_summary(merged_final)
        total_elapsed = int((time.perf_counter() - t0) * 1000)

        report = SearchReport(
            id=report_id,
            query=normalized,
            detected_type=detected,
            depth=req.depth,
            elapsed_ms=total_elapsed,
            engines=list(exec_map.values()),
            summary=summary_final,
            findings=merged_final,
            total_unique=len(merged_final),
            multi_source_confirmed=sum(1 for f in merged_final if len(f.sources) > 1),
        )

        yield {
            "event": "completed",
            "data": report.model_dump(),
        }

    async def run(self, req: SearchRequest) -> SearchReport:
        final_report: SearchReport | None = None
        async for evt in self.run_stream(req):
            if evt["event"] == "completed":
                final_report = SearchReport.model_validate(evt["data"])
        assert final_report is not None
        return final_report


def export_report_csv(report: SearchReport) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Site", "Category", "URL", "Confidence", "Sources", "Snippet"])
    for f in report.findings:
        writer.writerow([
            f.site,
            f.category,
            f.url or "",
            f"{int(f.confidence * 100)}%",
            ", ".join(f.sources),
            f.snippet or "",
        ])
    return buf.getvalue()


def export_report_markdown(report: SearchReport) -> str:
    lines = [
        f"# OSINT-отчёт Sherlock Hub: `{report.query}`",
        "",
        f"- **Тип запроса:** `{report.detected_type.value}`",
        f"- **Глубина:** `{report.depth.value}`",
        f"- **Дата (UTC):** {report.created_at}",
        f"- **Время выполнения:** {report.elapsed_ms / 1000:.1f} сек",
        f"- **Уникальных находок:** {report.total_unique} (подтверждено ≥2 движками: {report.multi_source_confirmed})",
        "",
    ]

    s = report.summary
    if s.display_names or s.locations or s.bios or s.websites:
        lines.append("## Сводка профиля")
        if s.display_names:
            lines.append(f"- **Имена:** {', '.join(s.display_names)}")
        if s.locations:
            lines.append(f"- **Локации:** {', '.join(s.locations)}")
        if s.websites:
            lines.append(f"- **Сайты:** {', '.join(s.websites)}")
        if s.bios:
            lines.append(f"- **Описание:** {s.bios[0]}")
        lines.append("")

    lines.append("## Результаты движков")
    lines.append("| Движок | Статус | Найдено | Время |")
    lines.append("| :--- | :--- | ---: | ---: |")
    for e in report.engines:
        lines.append(f"| {e.engine_name} | {e.status} | {e.findings_count} | {e.elapsed_ms / 1000:.1f}s |")
    lines.append("")

    lines.append("## Найденные источники")
    lines.append("| Платформа | Категория | Уверенность | Источники | Ссылка / Детали |")
    lines.append("| :--- | :--- | ---: | :--- | :--- |")
    for f in report.findings:
        link = f"[{f.url}]({f.url})" if f.url else (f.snippet or "—")
        lines.append(
            f"| {f.site} | {f.category} | {int(f.confidence * 100)}% | {', '.join(f.sources)} | {link} |"
        )
    lines.append("")
    return "\n".join(lines)
