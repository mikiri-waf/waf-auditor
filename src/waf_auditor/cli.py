"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Command-line entry point.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from . import __version__, corpus, engine
from .config import DEFAULT_BLOCK_STATUSES, RunConfig, TargetConfig
from .encoders import ENCODERS, TRANSPORT_MODIFIERS
from .models import Kind, Placement, Transport
from .paths import REPORTS_DIR, ensure_dirs
from .report import console as console_report
from .report import json_report
from .report.scoring import score_results


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="waf-auditor",
        description="WAF Auditor — test any WAF for bypasses and false positives.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    tgt = p.add_argument_group("target")
    tgt.add_argument("-u", "--url", help="target base URL, e.g. https://example.com/")
    tgt.add_argument(
        "--block-status",
        type=int,
        action="append",
        dest="block_statuses",
        metavar="CODE",
        help=f"HTTP status meaning 'blocked' (repeatable; default {DEFAULT_BLOCK_STATUSES})",
    )
    tgt.add_argument("-H", "--header", action="append", default=[], metavar="K:V",
                     help="extra request header (repeatable)")
    tgt.add_argument("-k", "--insecure", action="store_true", help="do not verify TLS certs")

    sel = p.add_argument_group("selection")
    sel.add_argument("-t", "--transport", action="append", dest="transports",
                     choices=[t.value for t in Transport], metavar="T",
                     help="transport to use (repeatable): "
                          + ", ".join(t.value for t in Transport))
    sel.add_argument("-s", "--suite", action="append", dest="suites", metavar="NAME",
                     help="only run these payload suites (repeatable)")
    sel.add_argument("--placement", action="append", dest="placements",
                     choices=[pl.value for pl in Placement], metavar="P",
                     help="restrict placements (repeatable)")
    sel.add_argument("--encoders", metavar="LIST",
                     help="comma-separated encoder names; only chains using these run")
    sel.add_argument("--attacks-only", action="store_true", help="skip false-positive suites")
    sel.add_argument("--fp-only", action="store_true", help="run only false-positive suites")

    run = p.add_argument_group("run")
    run.add_argument("-c", "--concurrency", type=int, default=20)
    run.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS")
    run.add_argument("--retries", type=int, default=1)
    run.add_argument("--rate-limit", type=float, default=None, metavar="RPS",
                     help="global cap on requests per second")
    run.add_argument("--debug", action="store_true")

    out = p.add_argument_group("output")
    out.add_argument("--no-console", action="store_true", help="suppress the console report")
    out.add_argument("--json", nargs="?", const="AUTO", metavar="PATH",
                     help="write JSON report (default path under reports/ if flag given alone)")
    out.add_argument("--pdf", nargs="?", const="AUTO", metavar="PATH",
                     help="write PDF report (default path under reports/ if flag given alone)")

    info = p.add_argument_group("info")
    info.add_argument("--list-suites", action="store_true", help="list bundled payload suites")
    info.add_argument("--list-encoders", action="store_true", help="list available encoders")
    return p


def _parse_headers(raw: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw:
        if ":" not in item:
            raise SystemExit(f"invalid --header {item!r}, expected 'Name: value'")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _kinds(args: argparse.Namespace) -> set[Kind] | None:
    if args.attacks_only and args.fp_only:
        raise SystemExit("--attacks-only and --fp-only are mutually exclusive")
    if args.attacks_only:
        return {Kind.ATTACK}
    if args.fp_only:
        return {Kind.FALSE_POSITIVE}
    return None


def _auto_path(kind: str, ext: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return REPORTS_DIR / f"waf-auditor-{stamp}.{ext}"


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    console = Console()

    if args.list_suites:
        for name in corpus.available_suites():
            console.print(name)
        return 0
    if args.list_encoders:
        for name in sorted(ENCODERS):
            console.print(name)
        for name in sorted(TRANSPORT_MODIFIERS):
            console.print(f"{name} [dim](transport modifier)[/dim]")
        return 0

    if not args.url:
        raise SystemExit("--url is required (or use --list-suites / --list-encoders)")

    ensure_dirs()

    target = TargetConfig(
        url=args.url,
        block_statuses=args.block_statuses or list(DEFAULT_BLOCK_STATUSES),
        verify_tls=not args.insecure,
        extra_headers=_parse_headers(args.header),
    )
    cfg = RunConfig(
        target=target,
        transports=[Transport(t) for t in (args.transports or ["http1"])],
        placements=[Placement(p) for p in args.placements] if args.placements else None,
        suites=args.suites,
        only_encoders=[e.strip() for e in args.encoders.split(",")] if args.encoders else None,
        concurrency=args.concurrency,
        timeout_s=args.timeout,
        retries=args.retries,
        rate_limit_rps=args.rate_limit,
        debug=args.debug,
    )

    try:
        payloads = corpus.load_corpus(
            suites=set(cfg.suites) if cfg.suites else None,
            kinds=_kinds(args),
        )
    except corpus.CorpusError as exc:
        raise SystemExit(f"payload error: {exc}") from exc

    eng = engine.Engine(cfg)
    total = len(eng.build_cases(payloads))
    console.print(
        f"[bold]WAF Auditor[/bold] → {target.url}  "
        f"({total} test cases, transports: {', '.join(t.value for t in cfg.transports)})"
    )

    import asyncio

    async def _run():
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("auditing", total=total)
            results = await eng.run(
                payloads, progress=lambda _r: progress.advance(task)
            )
        return results

    results = asyncio.run(_run())
    score = score_results(results)

    if not args.no_console:
        console_report.render(score, results, console=console)

    if args.json is not None:
        path = _auto_path("report", "json") if args.json == "AUTO" else Path(args.json)
        written = json_report.write(cfg, score, results, path)
        console.print(f"[green]JSON report:[/green] {written}")

    if args.pdf is not None:
        from .paths import DEV_DIR
        from .report import pdf as pdf_report

        path = _auto_path("report", "pdf") if args.pdf == "AUTO" else Path(args.pdf)
        try:
            written = pdf_report.write(cfg, score, results, path, chart_dir=DEV_DIR / "charts")
            console.print(f"[green]PDF report:[/green] {written}")
        except pdf_report.PdfDependencyError as exc:
            console.print(f"[yellow]PDF skipped:[/yellow] {exc}")

    # Exit code: non-zero when the WAF let attacks through (useful in CI).
    return 1 if score.overall.bypass else 0


if __name__ == "__main__":
    sys.exit(main())
