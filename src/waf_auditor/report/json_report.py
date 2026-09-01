"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Machine-readable JSON report: metadata + summary + every test case result.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..config import RunConfig
from ..models import Result
from .scoring import Score, summary_dict


def build_document(cfg: RunConfig, score: Score, results: list[Result]) -> dict:
    return {
        "tool": "WAF Auditor",
        "version": "0.1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": {
            "url": cfg.target.url,
            "block_statuses": cfg.target.block_statuses,
            "transports": [t.value for t in cfg.transports],
        },
        "summary": summary_dict(score),
        "results": [r.as_dict() for r in results],
    }


def write(cfg: RunConfig, score: Score, results: list[Result], path: Path) -> Path:
    doc = build_document(cfg, score, results)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
