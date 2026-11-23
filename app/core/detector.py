from __future__ import annotations

import re
from app.models import QueryType

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
# International or formatted phone number (7 to 16 digits with optional +, spaces, hyphens, parens)
PHONE_RE = re.compile(r"^\+?[\d][\d\s\-\(\)\.]{6,20}\d$")
DOMAIN_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)/?$"
)


def normalize_query(raw: str, qtype: QueryType) -> str:
    value = raw.strip()
    if qtype == QueryType.USERNAME:
        return value.lstrip("@").strip()
    if qtype == QueryType.EMAIL:
        return value.lower()
    if qtype == QueryType.DOMAIN:
        m = DOMAIN_RE.match(value)
        if m:
            return m.group(1).lower()
        return value.lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if qtype == QueryType.PHONE:
        # Keep leading '+' and digits
        cleaned = re.sub(r"[^\d+]", "", value)
        return cleaned
    return value


def detect_query_type(raw: str) -> QueryType:
    """Automatically classify input into email, phone, domain, or username."""
    value = raw.strip()
    if not value:
        return QueryType.USERNAME

    if EMAIL_RE.match(value):
        return QueryType.EMAIL

    # Check phone before username (digits-heavy with optional leading +)
    digits_only = re.sub(r"\D", "", value)
    if PHONE_RE.match(value) and 7 <= len(digits_only) <= 15 and not re.search(r"[a-zA-Z]", value):
        return QueryType.PHONE

    # Check domain (has a dot + valid TLD, no spaces, not starting with @)
    if not value.startswith("@") and DOMAIN_RE.match(value):
        return QueryType.DOMAIN

    return QueryType.USERNAME
