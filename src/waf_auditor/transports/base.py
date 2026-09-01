"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Transport abstraction. A transport takes a RequestSpec and returns a TransportResponse
(status code + timing), hiding all protocol details from the engine.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

from ..models import RequestSpec, Transport


@dataclass(slots=True)
class TransportResponse:
    status_code: int | None
    elapsed_ms: float
    error: str | None = None


class BaseTransport(abc.ABC):
    transport: Transport

    @abc.abstractmethod
    async def send(self, spec: RequestSpec) -> TransportResponse:
        ...

    async def aclose(self) -> None:  # pragma: no cover - default no-op
        return None
