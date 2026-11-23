from __future__ import annotations

import asyncio
import html
import re
from typing import Any

import httpx

from app.models import Finding, QueryType, ScanDepth
from app.providers.base import BaseProvider

HEADERS = {
    "User-Agent": "SherlockHub-OSINT/1.0 (+https://github.com; public-profile-lookup)",
    "Accept": "application/json, text/html;q=0.9",
}


def _clean_text(text: str | None, max_len: int = 220) -> str | None:
    if not text:
        return None
    cleaned = re.sub(r"<[^>]+>", " ", html.unescape(str(text)))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return None
    return cleaned[:max_len] + ("…" if len(cleaned) > max_len else "")


class DirectAPIsProvider(BaseProvider):
    id = "direct-apis"
    name = "Direct Public APIs"
    description = (
        "Быстрый параллельный запрос к официальным публичным API "
        "(GitHub, GitLab, Reddit, Hacker News, Dev.to, Keybase, Bluesky, Mastodon, "
        "Docker Hub, npm, PyPI, Gravatar, Wikipedia, Telegram)."
    )
    supported_types = [QueryType.USERNAME]
    mode = "public-http"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        if query_type != QueryType.USERNAME:
            return []

        timeout = httpx.Timeout(8.0, connect=4.0)
        async with httpx.AsyncClient(
            headers=HEADERS,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            tasks = [
                self._check_github(client, query),
                self._check_gitlab(client, query),
                self._check_reddit(client, query),
                self._check_hackernews(client, query),
                self._check_devto(client, query),
                self._check_keybase(client, query),
                self._check_bluesky(client, query),
                self._check_mastodon(client, query),
                self._check_dockerhub(client, query),
                self._check_pypi(client, query),
                self._check_npm(client, query),
                self._check_gravatar(client, query),
                self._check_wikipedia(client, query),
                self._check_telegram(client, query),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for res in results:
            if isinstance(res, Finding):
                findings.append(res)
            elif isinstance(res, list):
                findings.extend(item for item in res if isinstance(item, Finding))
        return findings

    async def _check_github(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(f"https://api.github.com/users/{u}")
        if r.status_code != 200:
            return None
        d: dict[str, Any] = r.json()
        meta = {
            k: v
            for k, v in {
                "display_name": d.get("name"),
                "bio": _clean_text(d.get("bio")),
                "location": d.get("location"),
                "company": d.get("company"),
                "website": d.get("blog") or None,
                "avatar": d.get("avatar_url"),
                "followers": d.get("followers"),
                "public_repos": d.get("public_repos"),
                "twitter": d.get("twitter_username"),
                "created_at": d.get("created_at"),
            }.items()
            if v not in (None, "", 0)
        }
        parts = []
        if d.get("name"):
            parts.append(d["name"])
        if d.get("location"):
            parts.append(d["location"])
        parts.append(f"{d.get('public_repos', 0)} repos · {d.get('followers', 0)} followers")
        return Finding(
            site="GitHub",
            url=d.get("html_url") or f"https://github.com/{u}",
            category="coding",
            sources=[self.id],
            confidence=0.98,
            metadata=meta,
            snippet=" · ".join(parts),
        )

    async def _check_gitlab(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get("https://gitlab.com/api/v4/users", params={"username": u})
        if r.status_code != 200:
            return None
        items = r.json()
        if not items or not isinstance(items, list):
            return None
        d = items[0]
        meta = {
            k: v
            for k, v in {
                "display_name": d.get("name"),
                "avatar": d.get("avatar_url"),
                "state": d.get("state"),
            }.items()
            if v
        }
        return Finding(
            site="GitLab",
            url=d.get("web_url") or f"https://gitlab.com/{u}",
            category="coding",
            sources=[self.id],
            confidence=0.95,
            metadata=meta,
            snippet=d.get("name") or f"@{u}",
        )

    async def _check_reddit(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(
            f"https://www.reddit.com/user/{u}/about.json",
            headers={"User-Agent": "python:sherlock-hub:v1.0 (OSINT research)"},
        )
        if r.status_code != 200:
            return None
        payload = r.json()
        d = payload.get("data") or {}
        if not d.get("name"):
            return None
        sub = d.get("subreddit") or {}
        karma = (d.get("link_karma") or 0) + (d.get("comment_karma") or 0)
        meta = {
            k: v
            for k, v in {
                "display_name": sub.get("title") or d.get("name"),
                "bio": _clean_text(sub.get("public_description")),
                "avatar": (d.get("icon_img") or "").split("?")[0] or None,
                "karma": karma,
            }.items()
            if v not in (None, "")
        }
        return Finding(
            site="Reddit",
            url=f"https://www.reddit.com/user/{d['name']}",
            category="forum",
            sources=[self.id],
            confidence=0.95,
            metadata=meta,
            snippet=f"u/{d['name']} · karma: {karma}",
        )

    async def _check_hackernews(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
        if r.status_code != 200:
            return None
        d = r.json()
        if not d or not isinstance(d, dict) or not d.get("id"):
            return None
        about = _clean_text(d.get("about"))
        meta = {k: v for k, v in {"bio": about, "karma": d.get("karma")}.items() if v is not None}
        return Finding(
            site="Hacker News",
            url=f"https://news.ycombinator.com/user?id={d['id']}",
            category="forum",
            sources=[self.id],
            confidence=0.96,
            metadata=meta,
            snippet=f"karma: {d.get('karma', 0)}" + (f" · {about[:100]}" if about else ""),
        )

    async def _check_devto(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get("https://dev.to/api/users/by_username", params={"url": u})
        if r.status_code != 200:
            return None
        d = r.json()
        if not d.get("username"):
            return None
        meta = {
            k: v
            for k, v in {
                "display_name": d.get("name"),
                "bio": _clean_text(d.get("summary")),
                "location": d.get("location"),
                "website": d.get("website_url"),
                "avatar": d.get("profile_image"),
                "github": d.get("github_username"),
            }.items()
            if v
        }
        return Finding(
            site="Dev.to",
            url=f"https://dev.to/{d['username']}",
            category="coding",
            sources=[self.id],
            confidence=0.95,
            metadata=meta,
            snippet=d.get("name") or d.get("summary"),
        )

    async def _check_keybase(self, client: httpx.AsyncClient, u: str) -> list[Finding]:
        r = await client.get(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"usernames": u},
        )
        if r.status_code != 200:
            return []
        them = (r.json().get("them") or [None])[0]
        if not them:
            return []
        profile = them.get("profile") or {}
        pictures = (them.get("pictures") or {}).get("primary") or {}
        proofs = (them.get("proofs_summary") or {}).get("all") or []
        proof_labels = [f"{p.get('proof_type')}:{p.get('nametag')}" for p in proofs if p.get("nametag")]
        meta = {
            k: v
            for k, v in {
                "display_name": profile.get("full_name"),
                "bio": _clean_text(profile.get("bio")),
                "location": profile.get("location"),
                "avatar": pictures.get("url"),
                "verified_proofs": proof_labels or None,
            }.items()
            if v
        }
        results = [
            Finding(
                site="Keybase",
                url=f"https://keybase.io/{u}",
                category="identity",
                sources=[self.id],
                confidence=0.97,
                metadata=meta,
                snippet=(profile.get("full_name") or u)
                + (f" · proofs: {', '.join(proof_labels[:4])}" if proof_labels else ""),
            )
        ]
        # Add verified linked identities from Keybase proofs
        for p in proofs[:6]:
            svc_url = p.get("service_url")
            ptype = (p.get("proof_type") or "").capitalize()
            if svc_url and ptype:
                results.append(
                    Finding(
                        site=f"{ptype} (Keybase proof)",
                        url=svc_url,
                        category="identity",
                        sources=[self.id],
                        confidence=0.96,
                        metadata={"verified_via": "keybase", "nametag": p.get("nametag")},
                        snippet=f"Криптографически подтверждено через Keybase ({p.get('nametag')})",
                    )
                )
        return results

    async def _check_bluesky(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        handle = u if "." in u else f"{u}.bsky.social"
        r = await client.get(
            "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
            params={"actor": handle},
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if not d.get("handle"):
            return None
        meta = {
            k: v
            for k, v in {
                "display_name": d.get("displayName"),
                "bio": _clean_text(d.get("description")),
                "avatar": d.get("avatar"),
                "followers": d.get("followersCount"),
            }.items()
            if v not in (None, "")
        }
        return Finding(
            site="Bluesky",
            url=f"https://bsky.app/profile/{d['handle']}",
            category="social",
            sources=[self.id],
            confidence=0.95,
            metadata=meta,
            snippet=f"{d.get('displayName') or d['handle']} · {d.get('followersCount', 0)} followers",
        )

    async def _check_mastodon(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(
            "https://mastodon.social/api/v1/accounts/lookup",
            params={"acct": u},
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if not d.get("url"):
            return None
        meta = {
            k: v
            for k, v in {
                "display_name": d.get("display_name"),
                "bio": _clean_text(d.get("note")),
                "avatar": d.get("avatar"),
                "followers": d.get("followers_count"),
            }.items()
            if v not in (None, "")
        }
        return Finding(
            site="Mastodon (mastodon.social)",
            url=d["url"],
            category="social",
            sources=[self.id],
            confidence=0.94,
            metadata=meta,
            snippet=f"{d.get('display_name') or u} · {d.get('followers_count', 0)} followers",
        )

    async def _check_dockerhub(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(f"https://hub.docker.com/v2/users/{u}/")
        if r.status_code != 200:
            return None
        d = r.json()
        if not d.get("username"):
            return None
        meta = {
            k: v
            for k, v in {
                "display_name": d.get("full_name"),
                "location": d.get("location"),
                "company": d.get("company"),
                "avatar": d.get("gravatar_url"),
                "created_at": d.get("date_joined"),
            }.items()
            if v
        }
        return Finding(
            site="Docker Hub",
            url=f"https://hub.docker.com/u/{d['username']}",
            category="coding",
            sources=[self.id],
            confidence=0.93,
            metadata=meta,
            snippet=d.get("full_name") or d.get("company") or d["username"],
        )

    async def _check_pypi(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(f"https://pypi.org/user/{u}/")
        if r.status_code != 200:
            return None
        return Finding(
            site="PyPI",
            url=f"https://pypi.org/user/{u}/",
            category="coding",
            sources=[self.id],
            confidence=0.92,
            snippet=f"Публичный профиль разработчика на PyPI ({u})",
        )

    async def _check_npm(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(
            "https://registry.npmjs.org/-/v1/search",
            params={"text": f"maintainer:{u}", "size": 3},
        )
        if r.status_code != 200:
            return None
        d = r.json()
        total = d.get("total") or 0
        if total <= 0:
            return None
        pkgs = [obj.get("package", {}).get("name") for obj in (d.get("objects") or [])]
        pkgs = [p for p in pkgs if p]
        return Finding(
            site="npm",
            url=f"https://www.npmjs.com/~{u}",
            category="coding",
            sources=[self.id],
            confidence=0.94,
            metadata={"packages_count": total, "sample_packages": pkgs},
            snippet=f"{total} пакетов: {', '.join(pkgs[:3])}",
        )

    async def _check_gravatar(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(f"https://en.gravatar.com/{u}.json")
        if r.status_code != 200:
            return None
        entries = r.json().get("entry") or []
        if not entries:
            return None
        e = entries[0]
        meta = {
            k: v
            for k, v in {
                "display_name": e.get("displayName"),
                "bio": _clean_text(e.get("aboutMe")),
                "location": e.get("currentLocation"),
                "avatar": e.get("thumbnailUrl"),
            }.items()
            if v
        }
        return Finding(
            site="Gravatar",
            url=e.get("profileUrl") or f"https://gravatar.com/{u}",
            category="identity",
            sources=[self.id],
            confidence=0.93,
            metadata=meta,
            snippet=e.get("displayName") or e.get("preferredUsername"),
        )

    async def _check_wikipedia(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action": "query",
                "list": "users",
                "ususers": u,
                "usprop": "registration|editcount",
                "format": "json",
            },
        )
        if r.status_code != 200:
            return None
        users = (r.json().get("query") or {}).get("users") or []
        if not users or "missing" in users[0] or "invalid" in users[0]:
            return None
        usr = users[0]
        edits = usr.get("editcount", 0)
        return Finding(
            site="Wikipedia (EN)",
            url=f"https://en.wikipedia.org/wiki/User:{usr.get('name', u)}",
            category="forum",
            sources=[self.id],
            confidence=0.92,
            metadata={"editcount": edits, "created_at": usr.get("registration")},
            snippet=f"{edits} правок · регистрация: {(usr.get('registration') or '—')[:10]}",
        )

    async def _check_telegram(self, client: httpx.AsyncClient, u: str) -> Finding | None:
        r = await client.get(f"https://t.me/{u}")
        if r.status_code != 200:
            return None
        text = r.text
        # Non-existent Telegram usernames still return 200 but lack tgme_page_title
        title_m = re.search(r'<div class="tgme_page_title"[^>]*><span[^>]*>(.*?)</span>', text, re.S)
        if not title_m:
            return None
        display_name = _clean_text(title_m.group(1), 120)
        desc_m = re.search(r'<div class="tgme_page_description"[^>]*>(.*?)</div>', text, re.S)
        bio = _clean_text(desc_m.group(1), 220) if desc_m else None
        img_m = re.search(r'<img class="tgme_page_photo_image" src="([^"]+)"', text)
        avatar = img_m.group(1) if img_m else None
        meta = {
            k: v
            for k, v in {
                "display_name": display_name,
                "bio": bio,
                "avatar": avatar,
            }.items()
            if v
        }
        return Finding(
            site="Telegram",
            url=f"https://t.me/{u}",
            category="social",
            sources=[self.id],
            confidence=0.94,
            metadata=meta,
            snippet=display_name + (f" — {bio[:100]}" if bio else ""),
        )
