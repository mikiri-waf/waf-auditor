"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Rich console report: headline grade panel, per-category table, and a bypass/FP list.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Result
from .scoring import Breakdown, Score, bypasses, false_positives

_GRADE_COLOR = {
    "A+": "bright_green",
    "A": "green",
    "B": "cyan",
    "C": "yellow",
    "D": "orange3",
    "F": "red",
}


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _rate_text(rate: float, good_high: bool = True) -> Text:
    good = rate >= 0.9 if good_high else rate <= 0.1
    mid = 0.7 <= rate < 0.9 if good_high else 0.1 < rate <= 0.3
    color = "green" if good else ("yellow" if mid else "red")
    return Text(_pct(rate), style=color)


def render(score: Score, results: list[Result], console: Console | None = None) -> None:
    console = console or Console()

    grade = score.grade
    color = _GRADE_COLOR.get(grade, "white")
    header = Text()
    header.append(f"  {grade}  ", style=f"bold white on {color}")
    header.append(f"   combined score {_pct(score.combined)}\n\n", style="bold")
    header.append("Detection rate: ")
    header.append(_rate_text(score.detection_rate))
    header.append(f"   ({score.overall.detected}/{score.overall.attacks} attacks blocked)\n")
    header.append("False positives: ")
    header.append(_rate_text(score.fp_rate, good_high=False))
    header.append(f"   ({score.overall.false_positive}/{score.overall.legit} legit blocked)\n")
    header.append(f"Total test cases: {score.total}")
    if score.overall.error:
        header.append(f"   (errors: {score.overall.error})", style="dim")
    console.print(Panel(header, title="Mikiri WAF Auditor", border_style=color, expand=False))

    _breakdown_table(console, "Detection by attack category", score.by_category)
    _breakdown_table(console, "By transport", score.by_transport)
    _breakdown_table(console, "By placement", score.by_placement)
    _breakdown_table(console, "By encoder chain", score.by_encoder, limit=15)

    _findings_table(console, "Bypasses (attacks NOT blocked)", bypasses(results), "red")
    _findings_table(
        console, "False positives (legit requests blocked)", false_positives(results), "yellow"
    )


def _breakdown_table(
    console: Console, title: str, data: dict[str, Breakdown], limit: int | None = None
) -> None:
    if not data:
        return
    table = Table(title=title, title_style="bold", header_style="bold cyan", expand=False)
    table.add_column("Slice")
    table.add_column("Attacks", justify="right")
    table.add_column("Detect", justify="right")
    table.add_column("Bypass", justify="right")
    table.add_column("Legit", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("Det. rate", justify="right")
    table.add_column("FP rate", justify="right")

    items = sorted(data.items(), key=lambda kv: kv[1].detection_rate)
    if limit:
        items = items[:limit]
    for name, b in items:
        table.add_row(
            name,
            str(b.attacks),
            str(b.detected),
            Text(str(b.bypass), style="red" if b.bypass else "dim"),
            str(b.legit),
            Text(str(b.false_positive), style="yellow" if b.false_positive else "dim"),
            _rate_text(b.detection_rate) if b.attacks else Text("-", style="dim"),
            _rate_text(b.fp_rate, good_high=False) if b.legit else Text("-", style="dim"),
        )
    console.print(table)


def _findings_table(console: Console, title: str, findings: list[Result], color: str) -> None:
    if not findings:
        return
    table = Table(title=f"{title}: {len(findings)}", title_style=f"bold {color}",
                  header_style="bold", expand=False)
    table.add_column("Payload id")
    table.add_column("Cat")
    table.add_column("Placement")
    table.add_column("Encoders")
    table.add_column("Transport")
    table.add_column("Status", justify="right")
    for r in findings[:40]:
        table.add_row(
            r.case.payload.id,
            r.case.payload.category,
            r.case.placement.value,
            "+".join(r.case.encoder_chain) or "none",
            r.case.transport.value,
            str(r.status_code),
        )
    if len(findings) > 40:
        table.caption = f"... and {len(findings) - 40} more (see JSON report)"
    console.print(table)
