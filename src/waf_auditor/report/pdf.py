"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Marketing-grade PDF report: headline grade, detection-by-category bars, transport
comparison, a placement x encoder detection heatmap, and a findings summary.

Charts are rendered with matplotlib to PNG (into .env/mac/dev) and composed with
reportlab. Both are imported lazily so core runs work without the PDF extra.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..config import RunConfig
from ..models import Result
from .scoring import Score, bypasses, false_positives

# Mikiri brand palette (derived from the mikiri.ai product UI: deep navy + brand blue
# on slate greys, with emerald/amber/red reserved for detection semantics).
NAVY = "#080d17"      # darkest brand surface — KPI header / title bar
INK = "#1e293b"       # slate-800 — headings and primary text
MUTED = "#64748b"     # slate-500 — secondary text
ACCENT = "#3b82f6"    # Mikiri brand blue
ACCENT_DK = "#2563eb"  # brand blue, pressed
GOOD = "#10b981"      # emerald — strong detection
WARN = "#f59e0b"      # amber — partial detection
BAD = "#ef4444"       # red — bypass / weak detection
BG = "#f1f5f9"        # slate-100 — zebra rows
BORDER = "#e2e8f0"    # slate-200 — hairlines

_GRADE_HEX = {"A+": GOOD, "A": GOOD, "B": ACCENT, "C": WARN, "D": WARN, "F": BAD}


def _brand_cmap():
    """Sequential red -> amber -> emerald colormap in Mikiri's semantic colors."""
    from matplotlib.colors import LinearSegmentedColormap

    return LinearSegmentedColormap.from_list("mikiri_rag", [BAD, WARN, GOOD])


def _transport_label(value: str) -> str:
    """Collapse HTTP/1.1 and HTTP/2 into a single 'HTTP'; keep WebSocket separate."""
    return "WS" if value == "ws" else "HTTP"


def _display_transports(values: list[str]) -> str:
    seen: list[str] = []
    for v in values:
        label = _transport_label(v)
        if label not in seen:
            seen.append(label)
    return ", ".join(seen)


class PdfDependencyError(RuntimeError):
    pass


def _require_deps():
    try:
        import matplotlib  # noqa: F401
        import reportlab  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise PdfDependencyError(
            "PDF report needs matplotlib and reportlab. "
            "Install with: pip install 'waf-auditor' matplotlib reportlab"
        ) from exc


def _rate_color(rate: float, good_high: bool = True) -> str:
    if good_high:
        return GOOD if rate >= 0.9 else (WARN if rate >= 0.7 else BAD)
    return GOOD if rate <= 0.1 else (WARN if rate <= 0.3 else BAD)


def _bar_detection_by_category(score: Score, out: Path) -> Path | None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cats = [(k, v) for k, v in score.by_category.items() if v.attacks]
    if not cats:
        return None
    cats.sort(key=lambda kv: kv[1].detection_rate)
    labels = [k for k, _ in cats]
    rates = [v.detection_rate * 100 for _, v in cats]
    colors = [_rate_color(v.detection_rate) for _, v in cats]

    fig, ax = plt.subplots(figsize=(7.2, max(2.2, 0.5 * len(labels) + 0.8)))
    ax.barh(labels, rates, color=colors)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Detection rate, %")
    ax.set_title("Attack detection by category", color=INK, fontweight="bold")
    for i, r in enumerate(rates):
        ax.text(min(r + 1, 98), i, f"{r:.0f}%", va="center", fontsize=8, color=MUTED)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(out, dpi=150, facecolor="white")
    plt.close(fig)
    return out


def _bar_transport(score: Score, out: Path) -> Path | None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Collapse HTTP/1.1 and HTTP/2 into a single "HTTP" bucket; keep WS separate.
    merged: dict[str, list[int]] = {}  # label -> [detected, attacks, false_positive, legit]
    for k, v in score.by_transport.items():
        if not (v.attacks or v.legit):
            continue
        m = merged.setdefault(_transport_label(k), [0, 0, 0, 0])
        m[0] += v.detected
        m[1] += v.attacks
        m[2] += v.false_positive
        m[3] += v.legit
    if not merged:
        return None

    labels = list(merged)
    det = [(m[0] / m[1] * 100 if m[1] else 0.0) for m in merged.values()]
    fp = [(m[2] / m[3] * 100 if m[3] else 0.0) for m in merged.values()]
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    w = 0.34
    b1 = ax.bar([i - w / 2 for i in x], det, width=w, label="Detection %", color=ACCENT)
    b2 = ax.bar([i + w / 2 for i in x], fp, width=w, label="False-positive %", color=BAD)
    for bars in (b1, b2):
        ax.bar_label(bars, fmt="%.0f%%", padding=2, fontsize=8, color=MUTED)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 105)
    ax.set_xlim(-0.7, len(labels) - 0.3)  # keep bars compact when there's a single group
    ax.set_title("Detection vs false positives by transport", color=INK, fontweight="bold")
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(colors=INK)
    fig.tight_layout()
    fig.savefig(out, dpi=150, facecolor="white")
    plt.close(fig)
    return out


def _heatmap_placement_encoder(results: list[Result], out: Path) -> Path | None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    placements: list[str] = []
    encoders: list[str] = []
    agg: dict[tuple[str, str], list[int]] = {}
    for r in results:
        if r.case.payload.expected.value != "blocked":
            continue
        pl = r.case.placement.value
        en = "+".join(r.case.encoder_chain) or "none"
        placements.append(pl)
        encoders.append(en)
        cell = agg.setdefault((pl, en), [0, 0])
        cell[1] += 1
        if r.verdict.value == "detected":
            cell[0] += 1

    if not agg:
        return None
    pl_labels = sorted(set(placements))
    en_labels = sorted(set(encoders))
    grid = np.full((len(pl_labels), len(en_labels)), np.nan)
    for i, pl in enumerate(pl_labels):
        for j, en in enumerate(en_labels):
            if (pl, en) in agg:
                det, tot = agg[(pl, en)]
                grid[i, j] = det / tot * 100

    fig, ax = plt.subplots(
        figsize=(max(6.0, 0.5 * len(en_labels) + 2), max(2.5, 0.45 * len(pl_labels) + 1.5))
    )
    cmap = _brand_cmap()
    cmap.set_bad(BORDER)  # cells with no samples render as a neutral hairline grey
    im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(en_labels)))
    ax.set_xticklabels(en_labels, rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(len(pl_labels)))
    ax.set_yticklabels(pl_labels, fontsize=8)
    ax.set_title("Detection heatmap: placement x encoder", color=INK, fontweight="bold")
    fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02, label="Detection %")
    fig.tight_layout()
    fig.savefig(out, dpi=150, facecolor="white")
    plt.close(fig)
    return out


_GRADE_CAPTION = {
    "A+": "Excellent — the WAF blocked nearly all attacks with negligible false positives.",
    "A": "Strong — the WAF blocked the large majority of attacks.",
    "B": "Good — solid detection, with a number of gaps worth closing.",
    "C": "Fair — a meaningful share of attacks bypassed the WAF.",
    "D": "Weak — many attacks bypassed the WAF; remediation is recommended.",
    "F": "Critical — the WAF missed the majority of attacks tested.",
}


def write(
    cfg: RunConfig,
    score: Score,
    results: list[Result],
    path: Path,
    *,
    chart_dir: Path,
) -> Path:
    _require_deps()
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import (
        HRFlowable,
        Image,
        ListFlowable,
        ListItem,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    from .. import __version__

    chart_dir.mkdir(parents=True, exist_ok=True)
    page_w, page_h = A4
    margin = 1.8 * cm
    content_w = page_w - 2 * margin
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    C_NAVY = colors.HexColor(NAVY)
    C_INK = colors.HexColor(INK)
    C_MUTED = colors.HexColor(MUTED)
    C_ACCENT = colors.HexColor(ACCENT)
    C_BG = colors.HexColor(BG)
    C_BORDER = colors.HexColor(BORDER)

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], textColor=C_INK,
                          fontSize=9.5, leading=14, spaceAfter=4)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=11, textColor=C_MUTED)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=C_INK,
                        fontSize=13, spaceBefore=2, spaceAfter=2, alignment=TA_LEFT)
    kicker = ParagraphStyle("kicker", fontName="Helvetica-Bold", fontSize=9,
                            textColor=C_ACCENT, leading=11)
    cover_title = ParagraphStyle("cover_title", fontName="Helvetica-Bold", fontSize=25,
                                 textColor=colors.white, leading=29)
    cover_sub = ParagraphStyle("cover_sub", fontName="Helvetica", fontSize=11.5,
                               textColor=colors.HexColor("#cbd5e1"), leading=15)

    def _fit(img_path: Path, width: float) -> Image:
        iw, ih = ImageReader(str(img_path)).getSize()
        return Image(str(img_path), width=width, height=width * ih / iw)

    def _section(title: str) -> list:
        return [
            Spacer(1, 0.35 * cm),
            Paragraph(title, h2),
            HRFlowable(width="100%", thickness=1.5, color=C_ACCENT,
                       spaceBefore=3, spaceAfter=8),
        ]

    # ---- page furniture (header band + branded footer with page numbers) ------------------------
    def _footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(margin, 1.2 * cm, page_w - margin, 1.2 * cm)
        y = 0.9 * cm
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(margin, y, "Mikiri WAF Auditor — a product of Mikiri Security, LLC")
        canvas.drawCentredString(page_w / 2, y, f"Page {doc.page}")
        canvas.drawRightString(page_w - margin, y, f"v{__version__} · {generated}")
        canvas.restoreState()

    def _header(canvas, doc) -> None:
        canvas.saveState()
        band = 1.15 * cm
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, page_h - band, page_w, band, stroke=0, fill=1)
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, page_h - band - 0.06 * cm, page_w, 0.06 * cm, stroke=0, fill=1)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.setFillColor(colors.white)
        canvas.drawString(margin, page_h - band + 0.38 * cm, "MIKIRI  ·  WAF AUDITOR")
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C_ACCENT)
        canvas.drawRightString(page_w - margin, page_h - band + 0.38 * cm, "CONFIDENTIAL")
        canvas.restoreState()
        _footer(canvas, doc)

    story: list = []

    # ---- cover banner ---------------------------------------------------------------------------
    banner = Table(
        [[Paragraph("MIKIRI SECURITY", kicker)],
         [Paragraph("WAF Security Assessment", cover_title)],
         [Paragraph("Check your WAF before an attacker does", cover_sub)]],
        colWidths=[content_w],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
        ("TOPPADDING", (0, 0), (0, 0), 20),
        ("BOTTOMPADDING", (0, 0), (0, 0), 2),
        ("TOPPADDING", (0, 1), (0, 1), 0),
        ("BOTTOMPADDING", (0, 1), (0, 1), 2),
        ("TOPPADDING", (0, 2), (0, 2), 0),
        ("BOTTOMPADDING", (0, 2), (0, 2), 20),
        ("LINEBELOW", (0, -1), (-1, -1), 3, C_ACCENT),
    ]))
    story.append(banner)
    story.append(Spacer(1, 0.5 * cm))

    # ---- engagement metadata (definition list) --------------------------------------------------
    meta_rows = [
        ["Target", cfg.target.url],
        ["Transports", _display_transports([t.value for t in cfg.transports])],
        ["Test cases executed", f"{score.total:,}"],
        ["Block criteria",
         "HTTP status ∈ {" + ", ".join(map(str, cfg.target.block_statuses)) + "}"],
        ["Report generated", generated],
        ["Classification", "Confidential"],
    ]
    meta = Table([[Paragraph(k, small), Paragraph(str(v), body)] for k, v in meta_rows],
                 colWidths=[4.5 * cm, content_w - 4.5 * cm])
    meta.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, C_BORDER),
        ("LINEABOVE", (0, 0), (-1, 0), 0.4, C_BORDER),
    ]))
    story.append(meta)

    # ---- executive summary + KPI cards ----------------------------------------------------------
    story += _section("Executive summary")
    grade_hex = _GRADE_HEX.get(score.grade, MUTED)
    values = [
        score.grade,
        f"{score.detection_rate * 100:.1f}%",
        f"{score.fp_rate * 100:.1f}%",
        f"{score.combined * 100:.1f}%",
    ]
    labels = ["GRADE", "DETECTION RATE", "FALSE-POSITIVE RATE", "COMBINED SCORE"]
    kpi = Table([values, labels], colWidths=[content_w / 4] * 4, rowHeights=[1.5 * cm, 0.7 * cm])
    kpi.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BG),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(grade_hex)),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("TEXTCOLOR", (1, 0), (-1, 0), C_INK),
        ("TEXTCOLOR", (1, 1), (-1, 1), C_MUTED),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (0, 0), 27),
        ("FONTSIZE", (1, 0), (-1, 0), 17),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 7.5),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
        ("VALIGN", (0, 1), (-1, 1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (0, 0), 16),  # lift the big grade letter off the divider
        ("LINEABOVE", (0, 0), (0, 0), 3, colors.HexColor(grade_hex)),
        ("LINEABOVE", (1, 0), (-1, 0), 3, C_ACCENT),
        ("INNERGRID", (0, 0), (-1, -1), 3, colors.white),
    ]))
    story.append(kpi)
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"<b>Grade {score.grade}.</b> {_GRADE_CAPTION.get(score.grade, '')} "
        f"Of {score.overall.attacks:,} attack requests, {score.overall.detected:,} were blocked "
        f"and <b>{score.overall.bypass:,} bypassed</b> the WAF. Of {score.overall.legit:,} "
        f"legitimate requests, <b>{score.overall.false_positive:,}</b> were incorrectly blocked "
        f"(false positives).", body))

    # ---- risk / coverage charts -----------------------------------------------------------------
    story += _section("Detection by attack category")
    cat_png = _bar_detection_by_category(score, chart_dir / "cat.png")
    if cat_png:
        story.append(_fit(cat_png, content_w))

    story.append(PageBreak())
    story += _section("Detection coverage")
    story.append(Paragraph(
        "Detection and false-positive rates by transport, and a matrix showing how detection "
        "holds up across injection points and payload encodings. Cold (red) cells mark encodings "
        "or placements the WAF failed to inspect.", small))
    for png in (_bar_transport(score, chart_dir / "transport.png"),
                _heatmap_placement_encoder(results, chart_dir / "heat.png")):
        if png:
            story.append(Spacer(1, 0.25 * cm))
            story.append(_fit(png, content_w))

    # ---- key findings ---------------------------------------------------------------------------
    story += _section("Key findings")
    n_bypass = len(bypasses(results))
    n_fp = len(false_positives(results))
    story.append(Paragraph(
        f"<b>{n_bypass:,}</b> attack payloads bypassed the WAF and <b>{n_fp:,}</b> legitimate "
        f"requests were falsely blocked. The five weakest attack categories are listed below; "
        f"complete per-request evidence is available in the accompanying JSON report.", body))

    worst = sorted(
        (kv for kv in score.by_category.items() if kv[1].attacks),
        key=lambda kv: kv[1].detection_rate,
    )[:5]
    if worst:
        rows = [["Attack category", "Detected", "Bypassed", "Detection rate"]]
        for name, b in worst:
            rows.append([name, str(b.detected), str(b.bypass), f"{b.detection_rate * 100:.0f}%"])
        t = Table(rows, colWidths=[content_w - 3 * 3 * cm, 3 * cm, 3 * cm, 3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("TEXTCOLOR", (0, 1), (-1, -1), C_INK),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_BG]),
            ("LINEBELOW", (0, 0), (-1, 0), 2, C_ACCENT),
            ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Spacer(1, 0.25 * cm))
        story.append(t)

    # ---- recommendations ------------------------------------------------------------------------
    story += _section("Recommendations")
    recs = [
        "Normalise and recursively decode input (multi-round URL, base64, HTML-entity and "
        "unicode) before signature inspection — most bypasses above rely on encoding the WAF "
        "did not unwrap.",
        "Apply detection uniformly across every injection point (query, path, headers, cookies "
        "and request bodies), not only the URL.",
        "Re-test after each rule change and track the combined grade over time as a "
        "regression gate.",
    ]
    story.append(ListFlowable(
        [ListItem(Paragraph(r, body), leftIndent=6) for r in recs],
        bulletType="bullet", bulletColor=C_ACCENT, bulletFontSize=8, start="•",
    ))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "<i>Mikiri WAF blocks the encoding- and placement-based bypasses highlighted in this "
        "report out of the box.</i>", small))

    # ---- methodology & scope --------------------------------------------------------------------
    story += _section("Methodology & scope")
    story.append(Paragraph(
        f"Each test case is the combination of a payload, an injection point (placement), an "
        f"encoding chain and a transport. A request counts as <b>blocked</b> when the target "
        f"replies with an HTTP status in the configured set "
        f"{{{', '.join(map(str, cfg.target.block_statuses))}}}; any other response counts as "
        f"passed. Attack payloads are expected to be blocked (a miss is a <i>bypass</i>); "
        f"legitimate payloads are expected to pass (a block is a <i>false positive</i>). "
        f"This engagement executed {score.total:,} test cases over "
        f"{_display_transports([t.value for t in cfg.transports])}.", small))
    story.append(Spacer(1, 0.15 * cm))
    story.append(Paragraph(
        "Authorised-use notice: this assessment must only be run against systems the operator "
        "owns or is explicitly permitted to test. This document is confidential and intended "
        "solely for the recipient.", small))

    # ---- closing call-to-action -----------------------------------------------------------------
    cta_kicker = ParagraphStyle("cta_kicker", fontName="Helvetica-Bold", fontSize=12,
                                textColor=C_ACCENT, leading=15)
    cta_line = ParagraphStyle("cta_line", fontName="Helvetica-Bold", fontSize=13.5,
                              textColor=colors.white, leading=18)
    cta_contact = ParagraphStyle("cta_contact", fontName="Helvetica", fontSize=10,
                                 textColor=colors.HexColor("#cbd5e1"), leading=14)
    cta = Table(
        [[Paragraph("REQUEST EVALUATION", cta_kicker)],
         [Paragraph("Deploy Mikiri WAF in your environment and evaluate its "
                    "application security capabilities.", cta_line)],
         [Paragraph(
             '<a href="https://mikiri.ai" color="#93c5fd"><u>mikiri.ai</u></a>'
             "&nbsp;&nbsp;·&nbsp;&nbsp;"
             '<a href="mailto:info@mikiri.ai" color="#93c5fd"><u>info@mikiri.ai</u></a>',
             cta_contact)]],
        colWidths=[content_w],
    )
    cta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
        ("TOPPADDING", (0, 0), (0, 0), 16),
        ("BOTTOMPADDING", (0, 0), (0, 0), 3),
        ("TOPPADDING", (0, 1), (0, 1), 0),
        ("BOTTOMPADDING", (0, 1), (0, 1), 8),
        ("TOPPADDING", (0, 2), (0, 2), 0),
        ("BOTTOMPADDING", (0, 2), (0, 2), 16),
        ("LINEABOVE", (0, 0), (-1, 0), 3, C_ACCENT),
    ]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(cta)

    doc = SimpleDocTemplate(
        str(path), pagesize=A4, title="Mikiri WAF Security Assessment",
        author="Mikiri WAF Auditor",
        leftMargin=margin, rightMargin=margin, topMargin=1.7 * cm, bottomMargin=1.7 * cm,
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_header)
    return path
