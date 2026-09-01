"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Async execution engine: build the test matrix, dispatch each case over its transport
with bounded concurrency + retries + optional global rate limit, and collect Results.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from . import builder, detector, matrix
from .config import RunConfig
from .models import Payload, Result, TestCase, Transport, Verdict
from .transports import BaseTransport, build_transport


class _RateLimiter:
    """Simple global token-bucket-ish limiter (requests per second)."""

    def __init__(self, rps: float | None) -> None:
        self._interval = (1.0 / rps) if rps else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if self._next <= now:
                self._next = now + self._interval
                return
            delay = self._next - now
            self._next += self._interval
        await asyncio.sleep(delay)


ProgressCb = Callable[[Result], None]


class Engine:
    def __init__(self, cfg: RunConfig) -> None:
        self.cfg = cfg
        self._limiter = _RateLimiter(cfg.rate_limit_rps)

    def build_cases(self, payloads: list[Payload]) -> list[TestCase]:
        placements = set(self.cfg.placements) if self.cfg.placements else None
        only = set(self.cfg.only_encoders) if self.cfg.only_encoders else None
        return list(
            matrix.generate(
                payloads,
                self.cfg.transports,
                placements=placements,
                only_encoders=only,
            )
        )

    async def run(
        self,
        payloads: list[Payload],
        *,
        progress: ProgressCb | None = None,
    ) -> list[Result]:
        cases = self.build_cases(payloads)
        by_transport: dict[Transport, list[TestCase]] = {}
        for c in cases:
            by_transport.setdefault(c.transport, []).append(c)

        results: list[Result] = []
        for transport, tcases in by_transport.items():
            client = build_transport(transport, self.cfg)
            try:
                results.extend(await self._run_transport(client, tcases, progress))
            finally:
                await client.aclose()
        return results

    async def _run_transport(
        self,
        client: BaseTransport,
        cases: list[TestCase],
        progress: ProgressCb | None,
    ) -> list[Result]:
        sem = asyncio.Semaphore(self.cfg.concurrency)

        async def one(case: TestCase) -> Result:
            async with sem:
                await self._limiter.wait()
                return await self._execute(client, case)

        tasks = [asyncio.create_task(one(c)) for c in cases]
        out: list[Result] = []
        for coro in asyncio.as_completed(tasks):
            res = await coro
            out.append(res)
            if progress is not None:
                progress(res)
        return out

    async def _execute(self, client: BaseTransport, case: TestCase) -> Result:
        spec = builder.build(case, self.cfg.target)
        summary = builder.summarize(spec, case)

        last: object = None
        for attempt in range(self.cfg.retries + 1):
            resp = await client.send(spec)
            last = resp
            if resp.error is None:
                break
            if attempt < self.cfg.retries:
                await asyncio.sleep(0.2 * (attempt + 1))

        assert last is not None
        v = detector.verdict(
            case.payload.expected,
            last.status_code,
            self.cfg.target.block_statuses,
            error=last.error,
        )
        return Result(
            case=case,
            verdict=v,
            status_code=last.status_code,
            elapsed_ms=last.elapsed_ms,
            request_summary=summary,
            error=last.error,
        )


def run_sync(
    cfg: RunConfig, payloads: list[Payload], progress: ProgressCb | None = None
) -> list[Result]:
    return asyncio.run(Engine(cfg).run(payloads, progress=progress))


# Re-export for convenience.
__all__ = ["Engine", "run_sync", "Verdict"]
