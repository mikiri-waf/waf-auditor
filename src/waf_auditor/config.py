"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Run configuration. Populated from CLI args (and optionally a YAML config file).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

from .models import Placement, Transport

DEFAULT_BLOCK_STATUSES = [403, 406, 429]


class TargetConfig(BaseModel):
    """Everything about the WAF-protected target under test."""

    url: str
    block_statuses: list[int] = Field(default_factory=lambda: list(DEFAULT_BLOCK_STATUSES))
    verify_tls: bool = False
    extra_headers: dict[str, str] = Field(default_factory=dict)
    # Names used when a payload lands in a header / cookie / query / body field.
    query_param: str = "q"
    header_name: str = "X-WAF-Auditor"
    cookie_name: str = "waf_auditor"
    body_field: str = "field"

    @field_validator("url")
    @classmethod
    def _has_scheme(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https"):
            raise ValueError("url must start with http:// or https://")
        if not parts.hostname:
            raise ValueError("url must contain a host")
        return v

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def port(self) -> int:
        parts = urlsplit(self.url)
        if parts.port:
            return parts.port
        return 443 if parts.scheme == "https" else 80

    @property
    def base_path(self) -> str:
        return urlsplit(self.url).path or "/"


class RunConfig(BaseModel):
    """How to run the audit."""

    target: TargetConfig
    transports: list[Transport] = Field(default_factory=lambda: [Transport.HTTP1])
    placements: list[Placement] | None = None   # None = whatever each payload allows
    suites: list[str] | None = None             # None = all
    only_encoders: list[str] | None = None       # restrict chains to those containing only these
    concurrency: int = 20
    timeout_s: float = 15.0
    retries: int = 1
    rate_limit_rps: float | None = None          # global cap, requests per second
    debug: bool = False
