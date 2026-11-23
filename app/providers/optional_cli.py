from __future__ import annotations

import asyncio
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from app.models import Finding, QueryType, ScanDepth
from app.providers.base import BaseProvider, find_executable
from app.providers.sherlock_engine import classify_site


class SocialAnalyzerProvider(BaseProvider):
    id = "social-analyzer"
    name = "Social Analyzer"
    description = (
        "Опциональный адаптер для qeeqbox/social-analyzer (анализ до 1000 платформ). "
        "Автоматически активируется, если установлен CLI social-analyzer."
    )
    supported_types = [QueryType.USERNAME]
    mode = "public-http"
    default_enabled = False

    def is_available(self) -> tuple[bool, str | None]:
        exe = find_executable("social-analyzer")
        if exe:
            return True, exe
        return False, "Опционально: pip install social-analyzer"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        exe = find_executable("social-analyzer")
        if not exe or query_type != QueryType.USERNAME:
            return []

        top = {"fast": 50, "standard": 150, "deep": 400}[depth.value]
        proc = await asyncio.create_subprocess_exec(
            exe,
            "--username",
            query,
            "--mode",
            "fast",
            "--top",
            str(top),
            "--output",
            "json",
            "--silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            proc.kill()
            return []

        try:
            data = json.loads(stdout_b.decode("utf-8", errors="ignore"))
        except Exception:
            return []

        findings: list[Finding] = []
        detected = data.get("detected") if isinstance(data, dict) else []
        for item in detected or []:
            if not isinstance(item, dict):
                continue
            url = item.get("link")
            site = item.get("title") or item.get("source") or "Social Analyzer Hit"
            if not url:
                continue
            rate = float(item.get("rate") or 75) / 100.0
            findings.append(
                Finding(
                    site=str(site),
                    url=str(url),
                    category=classify_site(str(site)),
                    sources=[self.id],
                    confidence=min(max(rate, 0.5), 0.95),
                    metadata={"language": item.get("language"), "type": item.get("type")},
                )
            )
        return findings


class TheHarvesterProvider(BaseProvider):
    id = "theharvester"
    name = "theHarvester"
    description = (
        "Опциональный адаптер для laramies/theHarvester: сбор публичных email, "
        "поддоменов и хостов по домену. Автоматически активируется при установке."
    )
    supported_types = [QueryType.DOMAIN]
    mode = "passive"
    default_enabled = False

    def is_available(self) -> tuple[bool, str | None]:
        exe = find_executable("theHarvester")
        if exe:
            return True, exe
        return False, "Опционально: установите laramies/theHarvester в PATH"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        exe = find_executable("theHarvester")
        if not exe or query_type != QueryType.DOMAIN:
            return []

        with tempfile.TemporaryDirectory(prefix="harvester_") as tmpdir:
            out_base = str(Path(tmpdir) / "report")
            proc = await asyncio.create_subprocess_exec(
                exe,
                "-d",
                query,
                "-b",
                "crtsh,duckduckgo,hackertarget,rapiddns",
                "-f",
                out_base,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                return []

            json_file = Path(f"{out_base}.json")
            if not json_file.is_file():
                return []
            try:
                data: dict[str, Any] = json.loads(json_file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                return []

            findings: list[Finding] = []
            emails = data.get("emails") or []
            hosts = data.get("hosts") or []
            if emails:
                findings.append(
                    Finding(
                        site="theHarvester Public Emails",
                        category="email",
                        status="info",
                        sources=[self.id],
                        confidence=0.85,
                        metadata={"emails": emails[:30]},
                        snippet=f"Найдено {len(emails)} публичных email: {', '.join(emails[:4])}",
                    )
                )
            if hosts:
                findings.append(
                    Finding(
                        site="theHarvester Subdomains",
                        category="dns",
                        status="info",
                        sources=[self.id],
                        confidence=0.85,
                        metadata={"hosts": hosts[:50]},
                        snippet=f"Найдено {len(hosts)} хостов: {', '.join(hosts[:4])}",
                    )
                )
            return findings


class BlackbirdProvider(BaseProvider):
    id = "blackbird"
    name = "Blackbird"
    description = (
        "Опциональный адаптер для antoniaci/blackbird (быстрый поиск по username и email). "
        "Автоматически активируется, если blackbird доступен в PATH."
    )
    supported_types = [QueryType.USERNAME, QueryType.EMAIL]
    mode = "public-http"
    default_enabled = False

    def is_available(self) -> tuple[bool, str | None]:
        exe = find_executable("blackbird")
        if exe:
            return True, exe
        return False, "Опционально: клонируйте antoniaci/blackbird и добавьте в PATH"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        exe = find_executable("blackbird")
        if not exe:
            return []
        flag = "-u" if query_type == QueryType.USERNAME else "-e"
        proc = await asyncio.create_subprocess_exec(
            exe,
            flag,
            query,
            "--no-update",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=55)
        except asyncio.TimeoutError:
            proc.kill()
            return []

        url_re = re.compile(r"(https?://\S+)")
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in stdout_b.decode("utf-8", errors="ignore").splitlines():
            m = url_re.search(line)
            if not m:
                continue
            url = m.group(1).rstrip(".,);]")
            if url in seen:
                continue
            seen.add(url)
            domain = re.sub(r"^https?://(www\.)?", "", url).split("/")[0]
            findings.append(
                Finding(
                    site=domain,
                    url=url,
                    category=classify_site(domain),
                    sources=[self.id],
                    confidence=0.82,
                )
            )
        return findings
