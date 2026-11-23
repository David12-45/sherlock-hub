from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from app.models import Finding, QueryType, ScanDepth
from app.providers.base import BaseProvider, find_executable
from app.providers.sherlock_engine import classify_site

HIT_RE = re.compile(r"\[\+\]\s+([^:\r\n]+?):\s+(https?://\S+)")
FIELD_RE = re.compile(r"^[│\s]*[├└]─\s*([^:]+):\s*(.+)$")


def _extract_meta_from_dict(ids_data: dict[str, Any]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    key_map = {
        "fullname": "display_name",
        "name": "display_name",
        "bio": "bio",
        "description": "bio",
        "location": "location",
        "country": "location",
        "image": "avatar",
        "avatar": "avatar",
        "website": "website",
        "follower_count": "followers",
        "created_at": "created_at",
    }
    for raw_k, raw_v in ids_data.items():
        if raw_v in (None, "", "None"):
            continue
        lk = str(raw_k).strip().lower()
        if lk in key_map and key_map[lk] not in meta:
            meta[key_map[lk]] = raw_v
    if ids_data:
        meta["extracted_ids"] = ids_data
    return meta


def _make_snippet(meta: dict[str, Any]) -> str | None:
    parts = []
    if meta.get("display_name"):
        parts.append(str(meta["display_name"]))
    if meta.get("location"):
        parts.append(str(meta["location"]))
    if meta.get("followers"):
        parts.append(f"{meta['followers']} followers")
    if meta.get("bio"):
        parts.append(str(meta["bio"])[:110])
    return " · ".join(parts) if parts else None


class MaigretProvider(BaseProvider):
    id = "maigret"
    name = "Maigret"
    description = (
        "Движок soxoj/maigret: поиск по базе из 11 000+ сайтов "
        "с автоматическим извлечением метаданных профиля (socid-extractor)."
    )
    supported_types = [QueryType.USERNAME]
    mode = "public-http"

    def is_available(self) -> tuple[bool, str | None]:
        exe = find_executable("maigret")
        if exe:
            return True, exe
        return False, "Установите пакет: pip install maigret"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        if query_type != QueryType.USERNAME:
            return []

        exe = find_executable("maigret")
        if not exe:
            return []

        top_sites = {"fast": 60, "standard": 220, "deep": 750}[depth.value]
        req_timeout = {"fast": 4, "standard": 7, "deep": 10}[depth.value]
        total_timeout = {"fast": 32, "standard": 65, "deep": 130}[depth.value]

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        with tempfile.TemporaryDirectory(prefix="maigret_hub_") as tmpdir:
            cmd = [
                exe,
                query,
                "--top-sites",
                str(top_sites),
                "--timeout",
                str(req_timeout),
                "--retries",
                "1",
                "--dns-resolver",
                "threaded",
                "--no-autoupdate",
                "-J",
                "simple",
                "--folderoutput",
                tmpdir,
                "--no-progressbar",
                "--no-color",
                "--no-recursion",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=tmpdir,
                env=env,
            )

            findings_by_url: dict[str, Finding] = {}
            current_finding: Finding | None = None
            current_ids: dict[str, Any] = {}
            deadline = time.monotonic() + total_timeout

            def _flush_current() -> None:
                nonlocal current_finding, current_ids
                if current_finding and current_ids:
                    meta = _extract_meta_from_dict(current_ids)
                    current_finding.metadata.update(meta)
                    current_finding.snippet = _make_snippet(current_finding.metadata)
                current_ids = {}

            assert proc.stdout is not None
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
                    except asyncio.TimeoutError:
                        break
                    if not raw_line:
                        break
                    decoded = raw_line.decode("utf-8", errors="ignore")
                    for part in decoded.split("\r"):
                        line = part.rstrip("\n")
                        m_hit = HIT_RE.search(line.strip())
                        if m_hit:
                            _flush_current()
                            site = m_hit.group(1).strip()
                            url = m_hit.group(2).strip()
                            if site.upper().startswith("MAIGRET") or "patreon.com" in url:
                                current_finding = None
                                continue
                            f = Finding(
                                site=site,
                                url=url,
                                category=classify_site(site),
                                sources=[self.id],
                                confidence=0.85,
                            )
                            findings_by_url[url] = f
                            current_finding = f
                            current_ids = {}
                            continue

                        if current_finding is not None:
                            m_field = FIELD_RE.match(line)
                            if m_field:
                                k = m_field.group(1).strip()
                                v = m_field.group(2).strip()
                                if k and v:
                                    current_ids[k] = v
                _flush_current()
            finally:
                if proc.returncode is None:
                    try:
                        proc.kill()
                        await proc.wait()
                    except ProcessLookupError:
                        pass

            # Merge richer JSON report if Maigret completed cleanly
            json_files = list(Path(tmpdir).glob("*.json"))
            if json_files:
                try:
                    raw: dict[str, Any] = json.loads(
                        json_files[0].read_text(encoding="utf-8", errors="ignore")
                    )
                    for site_name, entry in raw.items():
                        if not isinstance(entry, dict):
                            continue
                        status_obj = entry.get("status") or {}
                        status_val = (
                            status_obj.get("status")
                            if isinstance(status_obj, dict)
                            else str(status_obj)
                        )
                        if str(status_val).lower() != "claimed":
                            continue
                        url = entry.get("url_user") or (
                            status_obj.get("url") if isinstance(status_obj, dict) else None
                        )
                        if not url:
                            continue
                        ids_data = (
                            status_obj.get("ids")
                            if isinstance(status_obj, dict) and isinstance(status_obj.get("ids"), dict)
                            else {}
                        )
                        tags = (
                            status_obj.get("tags")
                            if isinstance(status_obj, dict) and isinstance(status_obj.get("tags"), list)
                            else []
                        )
                        meta = _extract_meta_from_dict(ids_data)
                        if tags:
                            meta["tags"] = tags
                        findings_by_url[url] = Finding(
                            site=site_name,
                            url=url,
                            category=self._category_from_tags(site_name, tags),
                            sources=[self.id],
                            confidence=0.86,
                            metadata=meta,
                            snippet=_make_snippet(meta),
                        )
                except Exception:
                    pass

            return list(findings_by_url.values())

    @staticmethod
    def _category_from_tags(site_name: str, tags: list[str]) -> str:
        tag_set = {str(t).lower() for t in tags}
        if tag_set & {"coding", "tech", "dev", "programming"}:
            return "coding"
        if tag_set & {"social", "dating", "blog", "art", "design"}:
            return "social"
        if tag_set & {"video", "music", "photo", "gaming", "streaming"}:
            return "media"
        if tag_set & {"forum", "news", "wiki", "qa"}:
            return "forum"
        return classify_site(site_name)
