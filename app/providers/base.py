from __future__ import annotations

import shutil
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Literal

from app.models import EngineInfo, Finding, QueryType, ScanDepth


def find_executable(name: str) -> str | None:
    """Locate a CLI executable inside the current Python venv first, then PATH."""
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.is_file():
        return str(venv_bin)
    return shutil.which(name)


class BaseProvider(ABC):
    """Base contract for every OSINT engine adapter."""

    id: str = ""
    name: str = ""
    description: str = ""
    supported_types: list[QueryType] = []
    mode: Literal["passive", "public-http"] = "public-http"
    default_enabled: bool = True

    def is_available(self) -> tuple[bool, str | None]:
        return True, None

    def info(self) -> EngineInfo:
        available, note = self.is_available()
        return EngineInfo(
            id=self.id,
            name=self.name,
            description=self.description,
            supported_types=self.supported_types,
            available=available,
            availability_note=note,
            mode=self.mode,
            default_enabled=self.default_enabled,
        )

    @abstractmethod
    async def search(
        self,
        query: str,
        query_type: QueryType,
        depth: ScanDepth,
    ) -> list[Finding]:
        """Run the engine asynchronously and return normalized Finding items."""
        raise NotImplementedError
