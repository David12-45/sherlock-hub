from __future__ import annotations

import asyncio
import hashlib
from typing import Any

import dns.resolver
import httpx

from app.models import Finding, QueryType, ScanDepth
from app.providers.base import BaseProvider

PROVIDER_HINTS = {
    "google.com": "Google / Google Workspace",
    "googlemail.com": "Google / Gmail",
    "outlook.com": "Microsoft 365 / Outlook",
    "protection.outlook.com": "Microsoft 365 / Exchange Online",
    "yandex.net": "Yandex Mail / Yandex 360",
    "yandex.ru": "Yandex Mail",
    "mail.ru": "VK Mail (Mail.ru)",
    "protonmail.ch": "Proton Mail",
    "proton.me": "Proton Mail",
    "icloud.com": "Apple iCloud Mail",
    "yahoodns.net": "Yahoo Mail",
    "messagingengine.com": "Fastmail",
    "zoho.com": "Zoho Mail",
    "cloudflare.net": "Cloudflare Email Routing",
    "migadu.com": "Migadu",
    "tutanota.de": "Tuta Mail",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "yopmail.com", "throwawaymail.com", "sharklasers.com", "trashmail.com",
    "getnada.com", "temp-mail.org", "dispostable.com",
}


def _resolve_email_dns(domain: str) -> dict[str, Any]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 5.0

    mx_hosts: list[str] = []
    spf: str | None = None
    dmarc: str | None = None

    try:
        for rdata in resolver.resolve(domain, "MX"):
            mx_hosts.append(str(rdata.exchange).rstrip(".").lower())
    except Exception:
        pass

    try:
        for rdata in resolver.resolve(domain, "TXT"):
            txt = "".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            if txt.lower().startswith("v=spf1"):
                spf = txt
    except Exception:
        pass

    try:
        for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = "".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            if txt.lower().startswith("v=dmarc1"):
                dmarc = txt
    except Exception:
        pass

    provider = "Собственный / неизвестный почтовый сервер"
    for mx in mx_hosts:
        for suffix, label in PROVIDER_HINTS.items():
            if mx.endswith(suffix):
                provider = label
                break
        if provider != "Собственный / неизвестный почтовый сервер":
            break

    return {
        "domain": domain,
        "mx_records": mx_hosts,
        "has_mx": len(mx_hosts) > 0,
        "mail_provider": provider,
        "spf": spf,
        "dmarc": dmarc,
        "disposable": domain in DISPOSABLE_DOMAINS,
    }


class EmailOSINTProvider(BaseProvider):
    id = "email-osint"
    name = "Email Passive OSINT"
    description = (
        "Пассивный анализ email: DNS/MX/SPF/DMARC, определение почтового провайдера, "
        "Gravatar (SHA-256/MD5), OpenPGP keyserver и публичный поиск по GitHub."
    )
    supported_types = [QueryType.EMAIL]
    mode = "passive"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        if query_type != QueryType.EMAIL or "@" not in query:
            return []

        email = query.strip().lower()
        _, domain = email.split("@", 1)

        findings: list[Finding] = []
        dns_info = await asyncio.to_thread(_resolve_email_dns, domain)
        mx_summary = (
            f"Провайдер: {dns_info['mail_provider']} · MX: {', '.join(dns_info['mx_records'][:3])}"
            if dns_info["has_mx"]
            else "MX-записи не найдены (домен не принимает почту)"
        )
        if dns_info["disposable"]:
            mx_summary += " · Временный (disposable) домен"

        findings.append(
            Finding(
                site=f"Email DNS & MX ({domain})",
                url=None,
                category="email",
                status="info",
                sources=[self.id],
                confidence=1.0,
                metadata=dns_info,
                snippet=mx_summary,
            )
        )

        timeout = httpx.Timeout(8.0, connect=4.0)
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": "SherlockHub-OSINT/1.0"},
            follow_redirects=True,
        ) as client:
            tasks = [
                self._check_gravatar(client, email),
                self._check_openpgp(client, email),
                self._check_github_email(client, email),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Finding):
                findings.append(res)
            elif isinstance(res, list):
                findings.extend(item for item in res if isinstance(item, Finding))

        return findings

    async def _check_gravatar(self, client: httpx.AsyncClient, email: str) -> list[Finding]:
        md5_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
        sha256_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
        r = await client.get(f"https://en.gravatar.com/{md5_hash}.json")
        if r.status_code != 200:
            return []
        entries = r.json().get("entry") or []
        if not entries:
            return []
        e = entries[0]
        meta = {
            k: v
            for k, v in {
                "display_name": e.get("displayName"),
                "username": e.get("preferredUsername"),
                "bio": e.get("aboutMe"),
                "location": e.get("currentLocation"),
                "avatar": e.get("thumbnailUrl") or f"https://www.gravatar.com/avatar/{sha256_hash}?s=200",
            }.items()
            if v
        }
        results = [
            Finding(
                site="Gravatar",
                url=e.get("profileUrl") or f"https://gravatar.com/{md5_hash}",
                category="identity",
                sources=[self.id],
                confidence=0.98,
                metadata=meta,
                snippet=f"{e.get('displayName') or e.get('preferredUsername') or email}"
                + (f" · {e.get('currentLocation')}" if e.get("currentLocation") else ""),
            )
        ]
        for acc in (e.get("accounts") or [])[:8]:
            if acc.get("url"):
                results.append(
                    Finding(
                        site=f"{acc.get('shortname', 'Account').capitalize()} (Gravatar)",
                        url=acc["url"],
                        category="social",
                        sources=[self.id],
                        confidence=0.95,
                        metadata={"verified": acc.get("verified")},
                        snippet=f"Связанный профиль из Gravatar: {acc.get('display') or acc.get('username') or acc['url']}",
                    )
                )
        return results

    async def _check_openpgp(self, client: httpx.AsyncClient, email: str) -> Finding | None:
        r = await client.get(f"https://keys.openpgp.org/vks/v1/by-email/{email}")
        if r.status_code != 200 or "BEGIN PGP PUBLIC KEY BLOCK" not in r.text:
            return None
        return Finding(
            site="OpenPGP Keyserver",
            url=f"https://keys.openpgp.org/search?q={email}",
            category="identity",
            sources=[self.id],
            confidence=0.98,
            metadata={"key_size_bytes": len(r.text)},
            snippet="Найден опубликованный публичный PGP-ключ на keys.openpgp.org",
        )

    async def _check_github_email(self, client: httpx.AsyncClient, email: str) -> Finding | None:
        r = await client.get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email", "per_page": 3},
        )
        if r.status_code != 200:
            return None
        items = r.json().get("items") or []
        if not items:
            return None
        u = items[0]
        return Finding(
            site="GitHub (by Email)",
            url=u.get("html_url"),
            category="coding",
            sources=[self.id],
            confidence=0.97,
            metadata={"username": u.get("login"), "avatar": u.get("avatar_url")},
            snippet=f"Аккаунт @{u.get('login')} найден по публичному email в профиле GitHub",
        )
