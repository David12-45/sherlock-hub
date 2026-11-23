from __future__ import annotations

import asyncio
import json
from urllib.parse import quote_plus

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone as pn_timezone

from app.models import Finding, QueryType, ScanDepth
from app.providers.base import BaseProvider, find_executable

TYPE_LABELS = {
    PhoneNumberType.MOBILE: "Мобильный",
    PhoneNumberType.FIXED_LINE: "Стационарный",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Стационарный или мобильный",
    PhoneNumberType.TOLL_FREE: "Бесплатный (Toll-Free)",
    PhoneNumberType.PREMIUM_RATE: "Платный (Premium)",
    PhoneNumberType.VOIP: "VoIP / Виртуальный",
    PhoneNumberType.PERSONAL_NUMBER: "Персональный",
    PhoneNumberType.PAGER: "Пейджер",
    PhoneNumberType.UAN: "Универсальный (UAN)",
    PhoneNumberType.VOICEMAIL: "Голосовая почта",
    PhoneNumberType.UNKNOWN: "Неизвестен",
}


class PhoneOSINTProvider(BaseProvider):
    id = "phone-osint"
    name = "Phone Metadata & PhoneInfoga"
    description = (
        "Анализ номера телефона (страна, регион, оператор, тип линии, часовые пояса, "
        "форматы E.164/RFC3966), поисковые дорки и интеграция с PhoneInfoga (если установлен)."
    )
    supported_types = [QueryType.PHONE]
    mode = "passive"

    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        if query_type != QueryType.PHONE:
            return []

        raw = query.strip()
        if not raw.startswith("+"):
            raw = f"+{raw}"

        findings: list[Finding] = []
        try:
            parsed = phonenumbers.parse(raw, None)
        except phonenumbers.NumberParseException as exc:
            return [
                Finding(
                    site="Phone Parser",
                    category="phone",
                    status="info",
                    sources=[self.id],
                    confidence=0.5,
                    snippet=f"Не удалось разобрать номер (используйте международный формат, напр. +16502530000): {exc}",
                )
            ]

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)
        region_code = phonenumbers.region_code_for_number(parsed)
        location_ru = geocoder.description_for_number(parsed, "ru") or geocoder.description_for_number(parsed, "en")
        carrier_name = carrier.name_for_number(parsed, "en") or None
        num_type = TYPE_LABELS.get(phonenumbers.number_type(parsed), "Неизвестен")
        tzs = list(pn_timezone.time_zones_for_number(parsed))

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        natl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

        meta = {
            "valid": is_valid,
            "possible": is_possible,
            "e164": e164,
            "international": intl,
            "national": natl,
            "country_code": f"+{parsed.country_code}",
            "region_code": region_code,
            "location": location_ru or region_code,
            "carrier": carrier_name or "Не определён",
            "line_type": num_type,
            "timezones": tzs,
        }
        parts = [
            f"{'Валидный' if is_valid else 'Невалидный'} ({num_type})",
            location_ru or region_code or "Регион неизвестен",
        ]
        if carrier_name:
            parts.append(f"Оператор: {carrier_name}")
        if tzs:
            parts.append(f"TZ: {', '.join(tzs[:2])}")

        findings.append(
            Finding(
                site=f"Phone Metadata ({intl})",
                category="phone",
                status="found" if is_valid else "info",
                sources=[self.id],
                confidence=1.0 if is_valid else 0.5,
                metadata=meta,
                snippet=" · ".join(parts),
            )
        )

        # Public search engine dorks (PhoneInfoga style, strictly passive links)
        dork_query = f'"{e164}" OR "{intl}" OR "{natl}"'
        findings.append(
            Finding(
                site="Google Public Mentions (Dork)",
                url=f"https://www.google.com/search?q={quote_plus(dork_query)}",
                category="phone",
                status="info",
                sources=[self.id],
                confidence=0.7,
                metadata={"query": dork_query},
                snippet=f"Поиск публичных упоминаний по форматам: {e164} / {intl} / {natl}",
            )
        )
        findings.append(
            Finding(
                site="DuckDuckGo Public Mentions",
                url=f"https://duckduckgo.com/?q={quote_plus(dork_query)}",
                category="phone",
                status="info",
                sources=[self.id],
                confidence=0.7,
                metadata={"query": dork_query},
                snippet="Альтернативный поисковый запрос по открытым источникам",
            )
        )

        # Optional PhoneInfoga binary integration if installed on PATH
        phoneinfoga_exe = find_executable("phoneinfoga")
        if phoneinfoga_exe:
            extra = await self._run_phoneinfoga(phoneinfoga_exe, e164)
            findings.extend(extra)

        return findings

    async def _run_phoneinfoga(self, exe: str, e164: str) -> list[Finding]:
        proc = await asyncio.create_subprocess_exec(
            exe, "scan", "-n", e164, "--output", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        except asyncio.TimeoutError:
            proc.kill()
            return []
        try:
            data = json.loads(stdout_b.decode("utf-8", errors="ignore"))
        except Exception:
            return []
        return [
            Finding(
                site="PhoneInfoga CLI",
                category="phone",
                status="info",
                sources=["phoneinfoga"],
                confidence=0.95,
                metadata=data if isinstance(data, dict) else {"raw": data},
                snippet="Дополнительные данные от PhoneInfoga CLI",
            )
        ]
