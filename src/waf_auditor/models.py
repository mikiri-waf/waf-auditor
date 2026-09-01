"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Kind(StrEnum):
    ATTACK = "attack"
    FALSE_POSITIVE = "false-positive"


class Expected(StrEnum):
    BLOCKED = "blocked"
    PASSED = "passed"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Placement(StrEnum):
    """Transport-neutral point where a payload is injected into a request."""

    URL_PATH = "url_path"
    URL_QUERY = "url_query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY_URLENCODED = "body_urlencoded"
    BODY_JSON = "body_json"
    BODY_MULTIPART = "body_multipart"
    BODY_XML = "body_xml"
    BODY_RAW = "body_raw"
    WS_MESSAGE = "ws_message"


class Transport(StrEnum):
    HTTP1 = "http1"
    HTTP2 = "http2"
    WS = "ws"


class Verdict(StrEnum):
    # attack results
    DETECTED = "detected"          # attack was blocked -> WAF good
    BYPASS = "bypass"              # attack passed through -> WAF miss
    # false-positive results
    OK = "ok"                      # legit request passed -> WAF good
    FALSE_POSITIVE = "false_positive"  # legit request blocked -> WAF bad
    # neutral
    ERROR = "error"                # network/timeout/other, excluded from score


# Placements that require (and define) a request body.
BODY_PLACEMENTS = {
    Placement.BODY_URLENCODED,
    Placement.BODY_JSON,
    Placement.BODY_MULTIPART,
    Placement.BODY_XML,
    Placement.BODY_RAW,
}


@dataclass(frozen=True, slots=True)
class Payload:
    """One raw payload plus its metadata. Knows nothing about transport/placement/encoding."""

    id: str
    raw: str
    suite: str
    kind: Kind
    category: str
    expected: Expected
    severity: Severity
    description: str = ""
    references: tuple[str, ...] = ()
    placements: tuple[Placement, ...] = ()          # allowed placements for this payload
    encoder_chains: tuple[tuple[str, ...], ...] = ()  # allowed encoder chains
    tags: tuple[str, ...] = ()


# ---- Transport-independent request specification -------------------------------------------------

@dataclass(slots=True)
class Body:
    """Serialized request body plus the content type transports should advertise."""

    content_type: str | None
    data: bytes


@dataclass(slots=True)
class RequestSpec:
    """What to send, independent of the concrete transport/protocol."""

    method: str
    scheme: str
    host: str
    port: int
    path: str
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Body | None = None
    # WebSocket-specific
    ws_message: str | None = None

    @property
    def url(self) -> str:
        netloc = self.host
        default = (self.scheme == "https" and self.port == 443) or (
            self.scheme == "http" and self.port == 80
        )
        if not default:
            netloc = f"{self.host}:{self.port}"
        q = ""
        if self.query:
            from urllib.parse import urlencode

            q = "?" + urlencode(self.query, safe="", quote_via=_identity_quote)
        return f"{self.scheme}://{netloc}{self.path}{q}"


def _identity_quote(string: str, safe: str, encoding: str, errors: str) -> str:
    # Query values are already encoded by the encoder chain; do not re-encode here.
    return string


@dataclass(slots=True)
class TestCase:
    """A single unit of work: one payload placed & encoded, to be sent over one transport."""

    payload: Payload
    placement: Placement
    encoder_chain: tuple[str, ...]
    transport: Transport

    @property
    def uid(self) -> str:
        enc = "+".join(self.encoder_chain) or "none"
        return f"{self.payload.id}|{self.placement.value}|{enc}|{self.transport.value}"


@dataclass(slots=True)
class Result:
    """Outcome of executing one TestCase."""

    case: TestCase
    verdict: Verdict
    status_code: int | None = None
    elapsed_ms: float | None = None
    request_summary: str = ""
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        p = self.case.payload
        return {
            "uid": self.case.uid,
            "payload_id": p.id,
            "suite": p.suite,
            "kind": p.kind.value,
            "category": p.category,
            "severity": p.severity.value,
            "expected": p.expected.value,
            "placement": self.case.placement.value,
            "encoders": list(self.case.encoder_chain),
            "transport": self.case.transport.value,
            "raw_payload": p.raw,
            "request": self.request_summary,
            "status_code": self.status_code,
            "elapsed_ms": round(self.elapsed_ms, 2) if self.elapsed_ms is not None else None,
            "verdict": self.verdict.value,
            "error": self.error,
        }
