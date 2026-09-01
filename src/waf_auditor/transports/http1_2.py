"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

HTTP/1.1 and HTTP/2 transport built on httpx.
"""

from __future__ import annotations

import time

import httpx

from ..models import RequestSpec, Transport
from .base import BaseTransport, TransportResponse


class HttpxTransport(BaseTransport):
    def __init__(
        self,
        transport: Transport,
        *,
        verify_tls: bool = False,
        timeout_s: float = 15.0,
        limits_concurrency: int = 20,
    ) -> None:
        if transport not in (Transport.HTTP1, Transport.HTTP2):
            raise ValueError(f"HttpxTransport does not support {transport}")
        self.transport = transport
        self._client = httpx.AsyncClient(
            http1=(transport == Transport.HTTP1),
            http2=(transport == Transport.HTTP2),
            verify=verify_tls,
            timeout=timeout_s,
            follow_redirects=False,
            limits=httpx.Limits(
                max_connections=limits_concurrency,
                max_keepalive_connections=limits_concurrency,
            ),
        )

    async def send(self, spec: RequestSpec) -> TransportResponse:
        headers = dict(spec.headers)
        if spec.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in spec.cookies.items())

        content = None
        if spec.body is not None:
            content = spec.body.data
            if spec.body.content_type and "Content-Type" not in headers:
                headers["Content-Type"] = spec.body.content_type

        start = time.perf_counter()
        try:
            resp = await self._client.request(
                spec.method,
                spec.url,
                headers=headers,
                content=content,
            )
            elapsed = (time.perf_counter() - start) * 1000
            return TransportResponse(status_code=resp.status_code, elapsed_ms=elapsed)
        except httpx.HTTPError as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return TransportResponse(status_code=None, elapsed_ms=elapsed, error=str(exc))

    async def aclose(self) -> None:
        await self._client.aclose()
