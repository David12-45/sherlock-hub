from __future__ import annotations

import asyncio
import csv
import os
import re
import tempfile
import time
from pathlib import Path

from app.models import Finding, QueryType, ScanDepth
from app.providers.base import BaseProvider, find_executable

CODING_SITES = {
    "github", "gitlab", "bitbucket", "codepen", "codesandbox", "replit", "kaggle",
    "leetcode", "hackerrank", "codewars", "npmjs", "pypi", "dockerhub", "sourceforge",
    "launchpad", "stackoverflow", "dev.to", "hashnode", "gumroad", "hugging face",
    "codeforces", "hackthebox", "tryhackme", "gitea", "codeberg", "gist",
}
SOCIAL_SITES = {
    "instagram", "facebook", "twitter", "x", "tiktok", "telegram", "vk", "pinterest",
    "snapchat", "linkedin", "threads", "bluesky", "mastodon", "tumblr", "flickr",
    "goodreads", "strava", "medium", "substack", "patreon", "linktr.ee", "linktree",
    "behance", "dribbble", "deviantart", "artstation", "last.fm", "spotify", "soundcloud",
}
MEDIA_SITES = {
    "youtube", "twitch", "vimeo", "dailymotion", "bandcamp", "mixcloud", "imgur",
    "500px", "unsplash", "vsco", "letterboxd", "myanimelist", "anilist", "steam",
    "xbox", "chess.com", "lichess", "roblox", "minecraft", "osu!",
}
FORUM_SITES = {
    "reddit", "hackernews", "hacker news", "quora", "habr", "pikabu", "lobsters",
    "wikipedia", "fandom", "producthunt", "disqus", "slashdot", "forum",
}


def classify_site(site_name: str) -> str:
    low = site_name.lower()
    if any(k in low for k in CODING_SITES):
        return "coding"
    if any(k in low for k in SOCIAL_SITES):
        return "social"
    if any(k in low for k in MEDIA_SITES):
        return "media"
    if any(k in low for k in FORUM_SITES):
        return "forum"
    return "other"


STDOUT_LINE_RE = re.compile(r"\[\+\]\s+([^:\r\n]+?):\s+(https?://\S+)")


class SherlockProvider(BaseProvider):
    id = "sherlock"
    name = "Sherlock"
    description = (
        "Классический движок sherlock-project/sherlock: поиск аккаунтов по username "
        "более чем на 400 популярных сайтах и соцсетях."
    )
    supported_types = [QueryType.USERNAME]
    mode = "public-http"

    def is_available(self) -> tuple[bool, str | None]:
        exe = find_executable("sherlock")
        if exe:
            return True, exe
        return False, "Установите пакет: pip install sherlock-project"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        if query_type != QueryType.USERNAME:
            return []

        exe = find_executable("sherlock")
        if not exe:
            return []

        req_timeout = {"fast": 3, "standard": 6, "deep": 10}[depth.value]
        total_timeout = {"fast": 18, "standard": 45, "deep": 95}[depth.value]

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        with tempfile.TemporaryDirectory(prefix="sherlock_hub_") as tmpdir:
            csv_path = Path(tmpdir) / f"{query}.csv"
            cmd = [
                exe,
                query,
                "--timeout",
                str(req_timeout),
                "--print-found",
                "--no-color",
                "--local",
                "--csv",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=tmpdir,
                env=env,
            )

            findings_by_url: dict[str, Finding] = {}
            deadline = time.monotonic() + total_timeout

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
                        m = STDOUT_LINE_RE.search(part.strip())
                        if not m:
                            continue
                        site, url = m.group(1).strip(), m.group(2).strip()
                        if url not in findings_by_url:
                            findings_by_url[url] = Finding(
                                site=site,
                                url=url,
                                category=classify_site(site),
                                sources=[self.id],
                                confidence=0.82,
                            )
            finally:
                if proc.returncode is None:
                    try:
                        proc.kill()
                        await proc.wait()
                    except ProcessLookupError:
                        pass

            # Enrich from CSV if Sherlock finished cleanly before timeout
            if csv_path.is_file():
                try:
                    with csv_path.open("r", encoding="utf-8", errors="ignore") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            if (row.get("exists") or "").strip().lower() != "claimed":
                                continue
                            url = (row.get("url_user") or "").strip()
                            site = (row.get("name") or "").strip()
                            if not url or not site:
                                continue
                            meta = {
                                "http_status": row.get("http_status"),
                                "response_time_s": row.get("response_time_s"),
                            }
                            if url in findings_by_url:
                                findings_by_url[url].metadata.update(meta)
                            else:
                                findings_by_url[url] = Finding(
                                    site=site,
                                    url=url,
                                    category=classify_site(site),
                                    sources=[self.id],
                                    confidence=0.82,
                                    metadata=meta,
                                )
                except Exception:
                    pass

            return list(findings_by_url.values())
