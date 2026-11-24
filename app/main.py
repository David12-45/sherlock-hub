from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from app.core.aggregator import (
    OSINTAggregator,
    export_report_csv,
    export_report_markdown,
)
from app.core.detector import detect_query_type
from app.models import (
    EngineInfo,
    HistoryEntry,
    QueryType,
    ScanDepth,
    SearchReport,
    SearchRequest,
)
from app.storage import ReportStorage

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

aggregator = OSINTAggregator()
storage = ReportStorage()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await storage.init()
    yield


app = FastAPI(
    title="Sherlock Hub — Unified Public OSINT Aggregator",
    description=(
        "Единый сервис агрегации открытых OSINT-источников: "
        "Sherlock, Maigret, Direct Public APIs, Email DNS/Gravatar/PGP, Phone Metadata и Domain RDAP."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/styles.css", include_in_schema=False)
async def serve_css() -> FileResponse:
    return FileResponse(STATIC_DIR / "styles.css")


@app.get("/app.js", include_in_schema=False)
async def serve_app_js() -> FileResponse:
    return FileResponse(STATIC_DIR / "app.js")


@app.get("/browser-engines.js", include_in_schema=False)
async def serve_browser_js() -> FileResponse:
    return FileResponse(STATIC_DIR / "browser-engines.js")


@app.get("/api/health")
async def health() -> dict[str, object]:
    engines = aggregator.list_engines()
    return {
        "status": "ok",
        "engines_total": len(engines),
        "engines_available": sum(1 for e in engines if e.available),
    }


@app.get("/api/engines", response_model=list[EngineInfo])
async def list_engines() -> list[EngineInfo]:
    return aggregator.list_engines()


@app.get("/api/detect")
async def detect(q: str = Query(..., min_length=1, max_length=256)) -> dict[str, str]:
    return {"query": q, "detected_type": detect_query_type(q).value}


@app.post("/api/search", response_model=SearchReport)
async def search_sync(req: SearchRequest) -> SearchReport:
    report = await aggregator.run(req)
    await storage.save(report)
    return report


@app.get("/api/search/stream")
async def search_stream(
    q: str = Query(..., min_length=1, max_length=256),
    query_type: QueryType = Query(QueryType.AUTO),
    depth: ScanDepth = Query(ScanDepth.STANDARD),
    engines: str | None = Query(None, description="Comma-separated engine IDs"),
    cross_check_username: bool = Query(True),
) -> StreamingResponse:
    engine_list = [e.strip() for e in engines.split(",") if e.strip()] if engines else None
    req = SearchRequest(
        query=q,
        query_type=query_type,
        depth=depth,
        engines=engine_list,
        cross_check_username=cross_check_username,
    )

    async def event_generator():
        async for evt in aggregator.run_stream(req):
            if evt["event"] == "completed":
                report = SearchReport.model_validate(evt["data"])
                await storage.save(report)
            payload = json.dumps(evt["data"], ensure_ascii=False)
            yield f"event: {evt['event']}\ndata: {payload}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/history", response_model=list[HistoryEntry])
async def get_history(limit: int = Query(30, ge=1, le=100)) -> list[HistoryEntry]:
    return await storage.list_history(limit=limit)


@app.get("/api/reports/{report_id}", response_model=SearchReport)
async def get_report(report_id: str) -> SearchReport:
    report = await storage.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    return report


@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str) -> dict[str, bool]:
    deleted = await storage.delete(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    return {"deleted": True}


@app.get("/api/reports/{report_id}/export")
async def export_report(
    report_id: str,
    fmt: Literal["json", "csv", "md"] = Query("json"),
):
    report = await storage.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт не найден")

    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in report.query)
    if fmt == "csv":
        return PlainTextResponse(
            content=export_report_csv(report),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="sherlock-hub-{safe_name}.csv"'},
        )
    if fmt == "md":
        return PlainTextResponse(
            content=export_report_markdown(report),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="sherlock-hub-{safe_name}.md"'},
        )
    return PlainTextResponse(
        content=report.model_dump_json(indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="sherlock-hub-{safe_name}.json"'},
    )
