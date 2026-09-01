"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Transport factory.
"""

from __future__ import annotations

from ..config import RunConfig
from ..models import Transport
from .base import BaseTransport, TransportResponse

__all__ = ["BaseTransport", "TransportResponse", "build_transport"]


def build_transport(transport: Transport, cfg: RunConfig) -> BaseTransport:
    if transport in (Transport.HTTP1, Transport.HTTP2):
        from .http1_2 import HttpxTransport

        return HttpxTransport(
            transport,
            verify_tls=cfg.target.verify_tls,
            timeout_s=cfg.timeout_s,
            limits_concurrency=cfg.concurrency,
        )
    if transport == Transport.WS:
        from .websocket import WebSocketTransport

        return WebSocketTransport(verify_tls=cfg.target.verify_tls, timeout_s=cfg.timeout_s)
    raise ValueError(f"unknown transport {transport!r}")
