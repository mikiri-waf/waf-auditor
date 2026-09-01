"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Expand payloads into concrete TestCases across placement × encoder-chain × transport,
dropping combinations that make no sense (e.g. ws_message over HTTP).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from .encoders import body_modifiers, is_transport_modifier
from .models import (
    BODY_PLACEMENTS,
    Payload,
    Placement,
    TestCase,
    Transport,
)


def _placement_ok(placement: Placement, transport: Transport) -> bool:
    if placement == Placement.WS_MESSAGE:
        return transport == Transport.WS
    # WebSocket transport only carries ws_message payloads.
    return transport != Transport.WS


def _effective_chain(chain: tuple[str, ...], placement: Placement) -> tuple[str, ...]:
    """For non-body placements, transport body-modifiers are inert; strip them so we
    don't emit duplicate test cases that would send identical bytes."""
    if placement in BODY_PLACEMENTS:
        return chain
    return tuple(n for n in chain if not is_transport_modifier(n)) or ("none",)


def _chain_allowed(chain: tuple[str, ...], only: set[str] | None) -> bool:
    if only is None:
        return True
    return all((is_transport_modifier(n) or n in only) for n in chain)


def generate(
    payloads: Iterable[Payload],
    transports: Iterable[Transport],
    *,
    placements: set[Placement] | None = None,
    only_encoders: set[str] | None = None,
) -> Iterator[TestCase]:
    """Yield unique TestCases. ``placements`` and ``only_encoders`` further restrict
    what each payload already declares."""
    transports = list(transports)
    for payload in payloads:
        allowed_placements = payload.placements
        if placements is not None:
            allowed_placements = tuple(p for p in allowed_placements if p in placements)

        for transport in transports:
            seen: set[tuple[str, str]] = set()  # (placement, effective-chain) dedup
            for placement in allowed_placements:
                if not _placement_ok(placement, transport):
                    continue
                for chain in payload.encoder_chains:
                    if not _chain_allowed(chain, only_encoders):
                        continue
                    eff = _effective_chain(chain, placement)
                    key = (placement.value, "+".join(eff))
                    if key in seen:
                        continue
                    seen.add(key)
                    # body modifiers only meaningful on body placements
                    mods = body_modifiers(eff) if placement in BODY_PLACEMENTS else []
                    keep = tuple(n for n in eff if not is_transport_modifier(n)) + tuple(mods)
                    yield TestCase(
                        payload=payload,
                        placement=placement,
                        encoder_chain=keep,
                        transport=transport,
                    )


def count(cases: Iterable[TestCase]) -> int:
    return sum(1 for _ in cases)
