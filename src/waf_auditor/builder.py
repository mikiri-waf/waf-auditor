"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Turn an abstract TestCase into a concrete, transport-independent RequestSpec:
apply the encoder chain to the payload, then place it where the TestCase says.
"""

from __future__ import annotations

import json

from .config import TargetConfig
from .encoders import apply_body_modifiers, apply_chain, body_modifiers
from .models import Body, Placement, RequestSpec, TestCase

_MULTIPART_BOUNDARY = "----WafAuditorBoundary7MA4YWxkTrZu0gW"


def build(case: TestCase, target: TargetConfig) -> RequestSpec:
    encoded = apply_chain(case.payload.raw, case.encoder_chain)

    spec = RequestSpec(
        method="GET",
        scheme=target.scheme,
        host=target.host,
        port=target.port,
        path=target.base_path,
        headers=dict(target.extra_headers),
    )

    p = case.placement
    if p == Placement.URL_PATH:
        base = target.base_path.rstrip("/")
        spec.path = f"{base}/{encoded}"
    elif p == Placement.URL_QUERY:
        spec.query = {target.query_param: encoded}
    elif p == Placement.HEADER:
        spec.headers[target.header_name] = encoded
    elif p == Placement.COOKIE:
        spec.cookies[target.cookie_name] = encoded
    elif p == Placement.WS_MESSAGE:
        spec.ws_message = encoded
    elif p == Placement.BODY_URLENCODED:
        _set_body(spec, case, f"{target.body_field}={encoded}".encode(),
                  "application/x-www-form-urlencoded")
    elif p == Placement.BODY_JSON:
        payload_obj = {target.body_field: encoded, "nested": {"value": encoded}}
        _set_body(spec, case, json.dumps(payload_obj).encode(), "application/json")
    elif p == Placement.BODY_MULTIPART:
        _set_body(spec, case, _multipart(target.body_field, encoded),
                  f"multipart/form-data; boundary={_MULTIPART_BOUNDARY}")
    elif p == Placement.BODY_XML:
        xml = f'<?xml version="1.0"?><root><value>{encoded}</value></root>'
        _set_body(spec, case, xml.encode(), "application/xml")
    elif p == Placement.BODY_RAW:
        _set_body(spec, case, encoded.encode(), "text/plain")
    else:  # pragma: no cover - defensive
        raise ValueError(f"unhandled placement {p!r}")

    return spec


def _set_body(spec: RequestSpec, case: TestCase, data: bytes, content_type: str) -> None:
    spec.method = "POST"
    mods = body_modifiers(case.encoder_chain)
    data, extra = apply_body_modifiers(data, mods)
    spec.headers.update(extra)
    spec.body = Body(content_type=content_type, data=data)


def _multipart(field: str, value: str) -> bytes:
    b = _MULTIPART_BOUNDARY
    lines = [
        f"--{b}",
        f'Content-Disposition: form-data; name="{field}"',
        "",
        value,
        f"--{b}",
        f'Content-Disposition: form-data; name="upload"; filename="{value}"',
        "Content-Type: text/plain",
        "",
        value,
        f"--{b}--",
        "",
    ]
    return "\r\n".join(lines).encode()


def summarize(spec: RequestSpec, case: TestCase) -> str:
    """Short human-readable request line for reports/debug."""
    parts = [f"{spec.method} {spec.url}"]
    if spec.headers:
        hs = ", ".join(f"{k}: {v[:40]}" for k, v in spec.headers.items())
        parts.append(f"H[{hs}]")
    if spec.cookies:
        cs = ", ".join(f"{k}={v[:40]}" for k, v in spec.cookies.items())
        parts.append(f"C[{cs}]")
    if spec.body:
        parts.append(f"B[{spec.body.content_type}; {len(spec.body.data)}b]")
    if spec.ws_message is not None:
        parts.append(f"WS[{spec.ws_message[:60]}]")
    return " ".join(parts)
