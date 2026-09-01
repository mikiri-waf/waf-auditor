"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

HTTP/3 (QUIC) transport — Phase 3.

The interface is intentionally in place now so the engine can treat HTTP/3 like any
other transport once implemented on top of `aioquic` (install via the `http3` extra).
"""

from __future__ import annotations

from ..models import RequestSpec, Transport
from .base import BaseTransport, TransportResponse


class Http3Transport(BaseTransport):
    transport = Transport.HTTP3

    def __init__(self, **_: object) -> None:
        raise NotImplementedError(
            "HTTP/3 transport is planned for Phase 3. "
            "Install the 'http3' extra and track the roadmap in the plan file."
        )

    async def send(self, spec: RequestSpec) -> TransportResponse:  # pragma: no cover
        raise NotImplementedError
