from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class QueryType(str, Enum):
    AUTO = "auto"
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"


class ScanDepth(str, Enum):
    FAST = "fast"        # ~10-20s: Direct APIs + Maigret top-100 / passive checks
    STANDARD = "standard" # ~30-60s: Direct APIs + Sherlock + Maigret top-300
    DEEP = "deep"        # ~90-180s: Direct APIs + Sherlock + Maigret top-1000


class Finding(BaseModel):
    """Normalized finding produced by any OSINT provider."""

    site: str
    url: str | None = None
    category: str = "other"  # social, coding, media, forum, email, phone, dns, identity, other
    status: Literal["found", "info", "possible"] = "found"
    sources: list[str] = Field(default_factory=list)
    confidence: float = 0.75  # 0.0 - 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    snippet: str | None = None


class EngineExecution(BaseModel):
    """Per-engine runtime status & metrics."""

    engine_id: str
    engine_name: str
    status: Literal["pending", "running", "completed", "error", "skipped", "timeout"] = "pending"
    findings_count: int = 0
    elapsed_ms: int = 0
    message: str | None = None


class EngineInfo(BaseModel):
    """Metadata about a registered OSINT provider."""

    id: str
    name: str
    description: str
    supported_types: list[QueryType]
    available: bool
    availability_note: str | None = None
    mode: Literal["passive", "public-http"] = "public-http"
    default_enabled: bool = True


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=256)
    query_type: QueryType = QueryType.AUTO
    depth: ScanDepth = ScanDepth.STANDARD
    engines: list[str] | None = None  # None = all eligible default-enabled engines
    cross_check_username: bool = True  # For email queries, also probe the local-part as username


class ProfileSummary(BaseModel):
    """Aggregated high-level profile signals merged across engines."""

    display_names: list[str] = Field(default_factory=list)
    avatars: list[str] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)
    bios: list[str] = Field(default_factory=list)
    websites: list[str] = Field(default_factory=list)
    emails_found: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class SearchReport(BaseModel):
    id: str
    query: str
    detected_type: QueryType
    depth: ScanDepth
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    elapsed_ms: int = 0
    engines: list[EngineExecution] = Field(default_factory=list)
    summary: ProfileSummary = Field(default_factory=ProfileSummary)
    findings: list[Finding] = Field(default_factory=list)
    total_unique: int = 0
    multi_source_confirmed: int = 0


class HistoryEntry(BaseModel):
    id: str
    query: str
    detected_type: QueryType
    depth: ScanDepth
    created_at: str
    elapsed_ms: int
    total_unique: int
    multi_source_confirmed: int
