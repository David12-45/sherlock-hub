from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any

import dns.resolver
import httpx

from app.models import Finding, QueryType, ScanDepth
from app.providers.base import BaseProvider


def _query_dns(domain: str) -> dict[str, list[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 5.0
    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            ans = resolver.resolve(domain, rtype)
            records[rtype] = [str(r).strip() for r in ans][:8]
        except Exception:
            records[rtype] = []
    return records


def _inspect_tls(domain: str) -> dict[str, Any] | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                subject = dict(x[0] for x in cert.get("subject", ()))
                sans = [v for _, v in cert.get("subjectAltName", ())][:15]
                return {
                    "common_name": subject.get("commonName"),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san_domains": sans,
                }
    except Exception:
        return None


class DomainOSINTProvider(BaseProvider):
    id = "domain-osint"
    name = "Domain DNS, TLS & RDAP"
    description = (
        "Пассивная разведка по домену: DNS-записи (A/AAAA/MX/NS/TXT), "
        "TLS-сертификат (SAN/Issuer), RDAP/WHOIS-регистрация и security.txt."
    )
    supported_types = [QueryType.DOMAIN]
    mode = "passive"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        if query_type != QueryType.DOMAIN:
            return []

        domain = query.strip().lower()
        findings: list[Finding] = []

        dns_task = asyncio.to_thread(_query_dns, domain)
        tls_task = asyncio.to_thread(_inspect_tls, domain)
        dns_res, tls_res = await asyncio.gather(dns_task, tls_task)

        if any(dns_res.values()):
            parts = []
            if dns_res["A"]:
                parts.append(f"A: {', '.join(dns_res['A'][:2])}")
            if dns_res["MX"]:
                parts.append(f"MX: {len(dns_res['MX'])}")
            if dns_res["NS"]:
                parts.append(f"NS: {', '.join(dns_res['NS'][:2])}")
            findings.append(
                Finding(
                    site=f"DNS Records ({domain})",
                    url=f"https://{domain}",
                    category="dns",
                    status="found",
                    sources=[self.id],
                    confidence=1.0,
                    metadata=dns_res,
                    snippet=" · ".join(parts),
                )
            )

        if tls_res:
            findings.append(
                Finding(
                    site="TLS Certificate",
                    url=None,
                    category="dns",
                    status="info",
                    sources=[self.id],
                    confidence=0.98,
                    metadata=tls_res,
                    snippet=f"CN: {tls_res.get('common_name')} · Issuer: {tls_res.get('issuer')} · до {tls_res.get('not_after')}",
                )
            )

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(8.0, connect=4.0),
            headers={"User-Agent": "SherlockHub-OSINT/1.0"},
            follow_redirects=True,
        ) as client:
            rdap_res, sec_res = await asyncio.gather(
                self._check_rdap(client, domain),
                self._check_security_txt(client, domain),
                return_exceptions=True,
            )
            if isinstance(rdap_res, Finding):
                findings.append(rdap_res)
            if isinstance(sec_res, Finding):
                findings.append(sec_res)

        return findings

    async def _check_rdap(self, client: httpx.AsyncClient, domain: str) -> Finding | None:
        r = await client.get(f"https://rdap.org/domain/{domain}")
        if r.status_code != 200:
            return None
        d = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in (d.get("events") or [])}
        ns = [n.get("ldhName") for n in (d.get("nameservers") or []) if n.get("ldhName")]
        registrar = None
        for ent in d.get("entities") or []:
            if "registrar" in (ent.get("roles") or []):
                vcard = (ent.get("vcardArray") or [None, []])[1]
                for item in vcard:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        registrar = item[3]
                        break
        meta = {
            "registrar": registrar,
            "registered": events.get("registration"),
            "expires": events.get("expiration"),
            "status": d.get("status"),
            "nameservers": ns,
        }
        parts = []
        if registrar:
            parts.append(f"Регистратор: {registrar}")
        if events.get("registration"):
            parts.append(f"Создан: {str(events['registration'])[:10]}")
        if events.get("expiration"):
            parts.append(f"Истекает: {str(events['expiration'])[:10]}")
        return Finding(
            site="RDAP / WHOIS",
            url=f"https://rdap.org/domain/{domain}",
            category="dns",
            status="info",
            sources=[self.id],
            confidence=0.98,
            metadata=meta,
            snippet=" · ".join(parts) or "Данные RDAP получены",
        )

    async def _check_security_txt(self, client: httpx.AsyncClient, domain: str) -> Finding | None:
        r = await client.get(f"https://{domain}/.well-known/security.txt")
        if r.status_code != 200 or "contact:" not in r.text.lower():
            return None
        contacts = [
            line.split(":", 1)[1].strip()
            for line in r.text.splitlines()
            if line.lower().startswith("contact:")
        ]
        return Finding(
            site="security.txt",
            url=f"https://{domain}/.well-known/security.txt",
            category="dns",
            status="info",
            sources=[self.id],
            confidence=0.95,
            metadata={"contacts": contacts[:5]},
            snippet=f"Контакты безопасности: {', '.join(contacts[:2])}",
        )
