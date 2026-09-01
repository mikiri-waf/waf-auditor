"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Aggregate raw Results into headline metrics, a letter grade, and the breakdowns
the console/JSON/PDF reports render.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..models import Kind, Result, Verdict


@dataclass(slots=True)
class Breakdown:
    """Detection/FP counters for one slice (a category, placement, encoder, transport)."""

    detected: int = 0
    bypass: int = 0
    ok: int = 0
    false_positive: int = 0
    error: int = 0

    @property
    def attacks(self) -> int:
        return self.detected + self.bypass

    @property
    def legit(self) -> int:
        return self.ok + self.false_positive

    @property
    def detection_rate(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0

    @property
    def fp_rate(self) -> float:
        return self.false_positive / self.legit if self.legit else 0.0

    def add(self, verdict: Verdict) -> None:
        if verdict == Verdict.DETECTED:
            self.detected += 1
        elif verdict == Verdict.BYPASS:
            self.bypass += 1
        elif verdict == Verdict.OK:
            self.ok += 1
        elif verdict == Verdict.FALSE_POSITIVE:
            self.false_positive += 1
        else:
            self.error += 1


@dataclass(slots=True)
class Score:
    total: int
    overall: Breakdown
    by_category: dict[str, Breakdown] = field(default_factory=dict)
    by_placement: dict[str, Breakdown] = field(default_factory=dict)
    by_encoder: dict[str, Breakdown] = field(default_factory=dict)
    by_transport: dict[str, Breakdown] = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        return self.overall.detection_rate

    @property
    def fp_rate(self) -> float:
        return self.overall.fp_rate

    @property
    def combined(self) -> float:
        """combined score: mean of detection and (1 - fp_rate),
        each weighted by how many samples back it."""
        parts: list[float] = []
        if self.overall.attacks:
            parts.append(self.overall.detection_rate)
        if self.overall.legit:
            parts.append(1.0 - self.overall.fp_rate)
        return sum(parts) / len(parts) if parts else 0.0

    @property
    def grade(self) -> str:
        return grade_for(self.combined)


def grade_for(score: float) -> str:
    pct = score * 100
    if pct >= 97:
        return "A+"
    if pct >= 90:
        return "A"
    if pct >= 80:
        return "B"
    if pct >= 70:
        return "C"
    if pct >= 60:
        return "D"
    return "F"


def _encoder_label(chain: tuple[str, ...]) -> str:
    return "+".join(chain) if chain else "none"


def score_results(results: list[Result]) -> Score:
    overall = Breakdown()
    by_category: dict[str, Breakdown] = defaultdict(Breakdown)
    by_placement: dict[str, Breakdown] = defaultdict(Breakdown)
    by_encoder: dict[str, Breakdown] = defaultdict(Breakdown)
    by_transport: dict[str, Breakdown] = defaultdict(Breakdown)

    for r in results:
        overall.add(r.verdict)
        by_category[r.case.payload.category].add(r.verdict)
        by_placement[r.case.placement.value].add(r.verdict)
        by_encoder[_encoder_label(r.case.encoder_chain)].add(r.verdict)
        by_transport[r.case.transport.value].add(r.verdict)

    return Score(
        total=len(results),
        overall=overall,
        by_category=dict(sorted(by_category.items())),
        by_placement=dict(sorted(by_placement.items())),
        by_encoder=dict(sorted(by_encoder.items())),
        by_transport=dict(sorted(by_transport.items())),
    )


def bypasses(results: list[Result]) -> list[Result]:
    return [r for r in results if r.verdict == Verdict.BYPASS]


def false_positives(results: list[Result]) -> list[Result]:
    return [r for r in results if r.verdict == Verdict.FALSE_POSITIVE]


def summary_dict(score: Score) -> dict:
    def bd(b: Breakdown) -> dict:
        return {
            "attacks": b.attacks,
            "detected": b.detected,
            "bypass": b.bypass,
            "legit": b.legit,
            "false_positive": b.false_positive,
            "error": b.error,
            "detection_rate": round(b.detection_rate, 4),
            "fp_rate": round(b.fp_rate, 4),
        }

    return {
        "total": score.total,
        "grade": score.grade,
        "combined_score": round(score.combined, 4),
        "detection_rate": round(score.detection_rate, 4),
        "fp_rate": round(score.fp_rate, 4),
        "overall": bd(score.overall),
        "by_category": {k: bd(v) for k, v in score.by_category.items()},
        "by_placement": {k: bd(v) for k, v in score.by_placement.items()},
        "by_encoder": {k: bd(v) for k, v in score.by_encoder.items()},
        "by_transport": {k: bd(v) for k, v in score.by_transport.items()},
    }


# Referenced by report modules to distinguish attack vs legit tallies in text.
KIND_ATTACK = Kind.ATTACK
