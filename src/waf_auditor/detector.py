"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Decide the verdict for a completed test case from the HTTP status code.
Block detection is status-code based (configurable set of statuses per target).
"""

from __future__ import annotations

from collections.abc import Sequence

from .models import Expected, Verdict


def is_blocked(status_code: int | None, block_statuses: Sequence[int]) -> bool:
    return status_code is not None and status_code in block_statuses


def verdict(
    expected: Expected,
    status_code: int | None,
    block_statuses: Sequence[int],
    *,
    error: str | None = None,
) -> Verdict:
    if error is not None or status_code is None:
        return Verdict.ERROR

    blocked = is_blocked(status_code, block_statuses)
    if expected == Expected.BLOCKED:
        # This is an attack: we WANT it blocked.
        return Verdict.DETECTED if blocked else Verdict.BYPASS
    else:
        # This is a legitimate request: we WANT it to pass.
        return Verdict.FALSE_POSITIVE if blocked else Verdict.OK
