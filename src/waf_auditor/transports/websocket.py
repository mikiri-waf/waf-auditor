"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

WebSocket transport. Opens a ws:// or wss:// connection, sends the payload frame,
and maps the outcome to a pseudo HTTP status so detection/scoring stay uniform:

- handshake rejected with an HTTP status (e.g. 403) -> that status (WAF blocked upgrade)
- frame sent and connection stays open / echoes         -> 200 (passed)
- connection closed with a policy-violation close code   -> 403 (blocked mid-stream)
"""

from __future__ import annotations

import time

import websockets
from websockets.exceptions import (
    ConnectionClosed,
    InvalidStatus,
)

from ..models import RequestSpec, Transport
from .base import BaseTransport, TransportResponse

# WebSocket close codes that indicate the payload was rejected/blocked.
_BLOCK_CLOSE_CODES = {1008, 1009, 1003}  # policy violation, too big, unsupported data


class WebSocketTransport(BaseTransport):
    transport = Transport.WS

    def __init__(self, *, verify_tls: bool = False, timeout_s: float = 15.0) -> None:
        self._verify_tls = verify_tls
        self._timeout = timeout_s

    def _ws_url(self, spec: RequestSpec) -> str:
        scheme = "wss" if spec.scheme == "https" else "ws"
        netloc = spec.host
        if not ((scheme == "wss" and spec.port == 443) or (scheme == "ws" and spec.port == 80)):
            netloc = f"{spec.host}:{spec.port}"
        return f"{scheme}://{netloc}{spec.path}"

    async def send(self, spec: RequestSpec) -> TransportResponse:
        import asyncio
        import ssl

        url = self._ws_url(spec)
        ssl_ctx = None
        if spec.scheme == "https":
            ssl_ctx = ssl.create_default_context()
            if not self._verify_tls:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

        extra_headers = [(k, v) for k, v in spec.headers.items()]
        message = spec.ws_message if spec.ws_message is not None else ""
        start = time.perf_counter()
        try:
            async with asyncio.timeout(self._timeout):
                async with websockets.connect(
                    url,
                    additional_headers=extra_headers,
                    ssl=ssl_ctx,
                    open_timeout=self._timeout,
                ) as ws:
                    await ws.send(message)
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=2.0)
                    except TimeoutError:
                        pass  # no echo is fine; the payload was accepted
            elapsed = (time.perf_counter() - start) * 1000
            return TransportResponse(status_code=200, elapsed_ms=elapsed)
        except InvalidStatus as exc:
            elapsed = (time.perf_counter() - start) * 1000
            code = getattr(getattr(exc, "response", None), "status_code", None)
            return TransportResponse(status_code=code, elapsed_ms=elapsed)
        except ConnectionClosed as exc:
            elapsed = (time.perf_counter() - start) * 1000
            close_code = getattr(exc, "code", None)
            status = 403 if close_code in _BLOCK_CLOSE_CODES else 200
            return TransportResponse(status_code=status, elapsed_ms=elapsed)
        except Exception as exc:  # noqa: BLE001 - map any transport failure to ERROR
            elapsed = (time.perf_counter() - start) * 1000
            return TransportResponse(status_code=None, elapsed_ms=elapsed, error=str(exc))
