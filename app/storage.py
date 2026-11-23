from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

from app.models import HistoryEntry, QueryType, ScanDepth, SearchReport

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "sherlock_hub.db"


class ReportStorage:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def init(self) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    detected_type TEXT NOT NULL,
                    depth TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL,
                    total_unique INTEGER NOT NULL,
                    multi_source_confirmed INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC)"
            )
            await db.commit()

    async def save(self, report: SearchReport) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO reports
                (id, query, detected_type, depth, created_at, elapsed_ms,
                 total_unique, multi_source_confirmed, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.id,
                    report.query,
                    report.detected_type.value,
                    report.depth.value,
                    report.created_at,
                    report.elapsed_ms,
                    report.total_unique,
                    report.multi_source_confirmed,
                    report.model_dump_json(),
                ),
            )
            await db.commit()

    async def list_history(self, limit: int = 30) -> list[HistoryEntry]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT id, query, detected_type, depth, created_at, elapsed_ms,
                       total_unique, multi_source_confirmed
                FROM reports
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = await cursor.fetchall()
        return [
            HistoryEntry(
                id=r[0],
                query=r[1],
                detected_type=QueryType(r[2]),
                depth=ScanDepth(r[3]),
                created_at=r[4],
                elapsed_ms=r[5],
                total_unique=r[6],
                multi_source_confirmed=r[7],
            )
            for r in rows
        ]

    async def get(self, report_id: str) -> SearchReport | None:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT payload_json FROM reports WHERE id = ?", (report_id,)
            )
            row = await cursor.fetchone()
        if not row:
            return None
        return SearchReport.model_validate(json.loads(row[0]))

    async def delete(self, report_id: str) -> bool:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
            await db.commit()
            return cursor.rowcount > 0
