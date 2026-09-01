"""
WAF Auditor - tests
Copyright (c) Mikiri Security, LLC
"""

from waf_auditor import matrix
from waf_auditor.detector import verdict
from waf_auditor.models import (
    Expected,
    Kind,
    Payload,
    Placement,
    Severity,
    Transport,
    Verdict,
)


def _payload(**kw) -> Payload:
    base = dict(
        id="p1",
        raw="' OR 1=1",
        suite="sqli",
        kind=Kind.ATTACK,
        category="sqli",
        expected=Expected.BLOCKED,
        severity=Severity.HIGH,
        placements=(Placement.URL_QUERY, Placement.WS_MESSAGE, Placement.BODY_JSON),
        encoder_chains=(("none",), ("url",), ("url", "gzip")),
    )
    base.update(kw)
    return Payload(**base)


def test_ws_message_only_over_ws_transport():
    cases = list(matrix.generate([_payload()], [Transport.HTTP1]))
    assert all(c.placement != Placement.WS_MESSAGE for c in cases)

    ws_cases = list(matrix.generate([_payload()], [Transport.WS]))
    assert ws_cases and all(c.placement == Placement.WS_MESSAGE for c in ws_cases)


def test_transport_modifier_deduped_on_non_body_placement():
    # url_query with ["url"] and ["url","gzip"] collapse to one case (gzip inert here).
    cases = [
        c
        for c in matrix.generate([_payload()], [Transport.HTTP1])
        if c.placement == Placement.URL_QUERY
    ]
    chains = {"+".join(c.encoder_chain) for c in cases}
    assert chains == {"none", "url"}


def test_body_placement_keeps_modifier():
    cases = [
        c
        for c in matrix.generate([_payload()], [Transport.HTTP1])
        if c.placement == Placement.BODY_JSON
    ]
    chains = {"+".join(c.encoder_chain) for c in cases}
    assert "url+gzip" in chains


def test_only_encoders_filter():
    cases = list(
        matrix.generate([_payload()], [Transport.HTTP1], only_encoders={"none"})
    )
    assert cases and all(c.encoder_chain == ("none",) for c in cases)


def test_verdict_attack():
    assert verdict(Expected.BLOCKED, 403, [403]) == Verdict.DETECTED
    assert verdict(Expected.BLOCKED, 200, [403]) == Verdict.BYPASS
    assert verdict(Expected.BLOCKED, None, [403], error="timeout") == Verdict.ERROR


def test_verdict_false_positive():
    assert verdict(Expected.PASSED, 403, [403]) == Verdict.FALSE_POSITIVE
    assert verdict(Expected.PASSED, 200, [403]) == Verdict.OK
