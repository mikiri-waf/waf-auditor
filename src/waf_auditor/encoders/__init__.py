"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Encoder registry.

An encoder transforms a payload string into another string. Encoders are composed
into *chains*: the chain ["base64", "url"] applies base64 first, then URL-encoding.
Every encoder is a pure ``str -> str`` function so chains are trivial to reason about.

Transport-level modifiers (gzip / deflate / chunked) are recognised here as chain
names but are applied by the transport layer against the *body bytes*, not the
payload string; ``is_transport_modifier`` lets the builder split them out.
"""

from __future__ import annotations

import base64
import html
import zlib
from collections.abc import Callable
from urllib.parse import quote

Encoder = Callable[[str], str]

ENCODERS: dict[str, Encoder] = {}

# Modifiers that operate on the assembled body, handled by transports, not the payload.
TRANSPORT_MODIFIERS = {"gzip", "deflate", "chunked"}


def register(name: str) -> Callable[[Encoder], Encoder]:
    def deco(fn: Encoder) -> Encoder:
        ENCODERS[name] = fn
        return fn

    return deco


def is_transport_modifier(name: str) -> bool:
    return name in TRANSPORT_MODIFIERS


# ---- payload-string encoders ---------------------------------------------------------------------

@register("none")
def enc_none(s: str) -> str:
    return s


@register("url")
def enc_url(s: str) -> str:
    return quote(s, safe="")


@register("url_double")
def enc_url_double(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


@register("url_triple")
def enc_url_triple(s: str) -> str:
    return quote(quote(quote(s, safe=""), safe=""), safe="")


@register("url_all")
def enc_url_all(s: str) -> str:
    """Percent-encode every byte, including normally-safe ones."""
    return "".join(f"%{b:02X}" for b in s.encode("utf-8"))


@register("base64")
def enc_base64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


@register("base64_url")
def enc_base64_url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii")


@register("html_entity_dec")
def enc_html_entity_dec(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


@register("html_entity_hex")
def enc_html_entity_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


@register("html_entity_named")
def enc_html_entity_named(s: str) -> str:
    # Named where one exists (&lt; &gt; &amp; &quot; …), numeric fallback otherwise.
    return html.escape(s, quote=True)


@register("unicode_escape")
def enc_unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


@register("js_string")
def enc_js_string(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if o < 0x100:
            out.append(f"\\x{o:02x}")
        else:
            out.append(f"\\u{o:04x}")
    return "".join(out)


@register("charset_utf16")
def enc_charset_utf16(s: str) -> str:
    """Re-encode as UTF-16-LE and expose as percent-encoded bytes (survives text transports)."""
    return "".join(f"%{b:02X}" for b in s.encode("utf-16-le"))


@register("charset_utf8")
def enc_charset_utf8(s: str) -> str:
    return "".join(f"%{b:02X}" for b in s.encode("utf-8"))


@register("mixed_case")
def enc_mixed_case(s: str) -> str:
    out = []
    upper = True
    for c in s:
        out.append(c.upper() if upper else c.lower())
        if c.isalpha():
            upper = not upper
    return "".join(out)


# ---- chain application ---------------------------------------------------------------------------

def apply_chain(payload: str, chain: tuple[str, ...] | list[str]) -> str:
    """Apply a chain of *payload-string* encoders, left to right.

    Transport modifiers in the chain are ignored here (applied by the transport).
    Unknown encoder names raise KeyError so mistakes surface loudly.
    """
    out = payload
    for name in chain:
        if is_transport_modifier(name):
            continue
        out = ENCODERS[name](out)
    return out


def body_modifiers(chain: tuple[str, ...] | list[str]) -> list[str]:
    """Return the transport modifiers present in a chain, in order."""
    return [name for name in chain if is_transport_modifier(name)]


def apply_body_modifiers(data: bytes, modifiers: list[str]) -> tuple[bytes, dict[str, str]]:
    """Apply gzip/deflate to body bytes; return (data, extra_headers).

    ``chunked`` is signalled via headers only; the transport frames it.
    """
    headers: dict[str, str] = {}
    for m in modifiers:
        if m == "gzip":
            co = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
            data = co.compress(data) + co.flush()
            headers["Content-Encoding"] = "gzip"
        elif m == "deflate":
            data = zlib.compress(data)
            headers["Content-Encoding"] = "deflate"
        elif m == "chunked":
            headers["Transfer-Encoding"] = "chunked"
    return data, headers


def known(name: str) -> bool:
    return name in ENCODERS or is_transport_modifier(name)
