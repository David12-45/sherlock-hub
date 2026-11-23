#!/usr/bin/env python3
"""Command-line interface for Sherlock Hub OSINT Aggregator."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.core.aggregator import (
    OSINTAggregator,
    export_report_csv,
    export_report_markdown,
)
from app.models import QueryType, ScanDepth, SearchRequest


async def _run_cli(args: argparse.Namespace) -> int:
    agg = OSINTAggregator()

    if args.command == "engines":
        print(f"{'ID':<18} {'Статус':<12} {'Режим':<12} {'Типы':<26} Название")
        print("-" * 92)
        for e in agg.list_engines():
            status = "доступен" if e.available else "нет CLI"
            types = ",".join(t.value for t in e.supported_types)
            print(f"{e.id:<18} {status:<12} {e.mode:<12} {types:<26} {e.name}")
        return 0

    req = SearchRequest(
        query=args.query,
        query_type=QueryType(args.type),
        depth=ScanDepth(args.depth),
        engines=args.engines.split(",") if args.engines else None,
        cross_check_username=not args.no_crosscheck,
    )

    print(f"🔎 Запуск поиска: {req.query} (глубина: {req.depth.value})...")
    report = None
    async for evt in agg.run_stream(req):
        if evt["event"] == "engine_update":
            eng = evt["data"]["engine"]
            print(
                f"  [{eng['status'].upper():9}] {eng['engine_name']:<24} "
                f"находок: {eng['findings_count']:<4} ({eng['elapsed_ms']/1000:.1f}s)"
            )
        elif evt["event"] == "completed":
            report = evt["data"]

    if not report:
        print("Ошибка: не удалось сформировать отчёт.", file=sys.stderr)
        return 1

    from app.models import SearchReport
    rep = SearchReport.model_validate(report)

    print(
        f"\n✅ Готово за {rep.elapsed_ms/1000:.1f}s · Уникальных находок: {rep.total_unique} "
        f"(подтверждено ≥2 движками: {rep.multi_source_confirmed})\n"
    )

    for f in rep.findings[: args.limit]:
        sources = ",".join(f.sources)
        url_part = f.url or (f.snippet or "")
        print(f"  [{int(f.confidence*100):>2}%] {f.site:<24} [{sources}]  {url_part}")

    if args.out:
        out_path = Path(args.out)
        if out_path.suffix == ".csv":
            out_path.write_text(export_report_csv(rep), encoding="utf-8")
        elif out_path.suffix == ".md":
            out_path.write_text(export_report_markdown(rep), encoding="utf-8")
        else:
            out_path.write_text(rep.model_dump_json(indent=2), encoding="utf-8")
        print(f"\n💾 Отчёт сохранён в {out_path}")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sherlock-hub",
        description="Sherlock Hub — единый агрегатор открытых OSINT-источников",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("engines", help="Показать список доступных OSINT-движков")

    p_search = sub.add_parser("search", help="Выполнить поиск по всем подходящим базам")
    p_search.add_argument("query", help="Никнейм, email, телефон (+7...) или домен")
    p_search.add_argument(
        "-t", "--type",
        choices=["auto", "username", "email", "phone", "domain"],
        default="auto",
        help="Тип запроса (по умолчанию auto)",
    )
    p_search.add_argument(
        "-d", "--depth",
        choices=["fast", "standard", "deep"],
        default="standard",
        help="Глубина сканирования",
    )
    p_search.add_argument(
        "-e", "--engines",
        help="Список движков через запятую (например: direct-apis,sherlock,maigret)",
    )
    p_search.add_argument("--no-crosscheck", action="store_true", help="Не искать префикс email как никнейм")
    p_search.add_argument("-n", "--limit", type=int, default=40, help="Максимум строк в выводе")
    p_search.add_argument("-o", "--out", help="Сохранить отчёт (.json, .csv или .md)")

    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run_cli(args)))


if __name__ == "__main__":
    main()
