"""
Mikiri WAF Auditor - tests
Copyright (c) Mikiri Security, LLC
"""

import json

from waf_auditor import corpus
from waf_auditor.builder import build, summarize
from waf_auditor.config import TargetConfig
from waf_auditor.matrix import generate
from waf_auditor.models import Placement, Transport


def test_bundled_corpus_loads_and_validates():
    payloads = corpus.load_corpus()
    assert len(payloads) > 20
    ids = [p.id for p in payloads]
    assert len(ids) == len(set(ids)), "payload ids must be globally unique"


def test_available_suites_includes_core():
    suites = set(corpus.available_suites())
    assert {"sqli", "xss", "rce", "lfi", "traversal", "fp-common"} <= suites


def _target() -> TargetConfig:
    return TargetConfig(url="https://example.com/app")


def test_build_query_placement_encodes_payload():
    payloads = corpus.load_corpus(suites={"sqli"})
    p = next(p for p in payloads if p.id == "sqli-bool-0001")
    cases = [
        c
        for c in generate([p], [Transport.HTTP1])
        if c.placement == Placement.URL_QUERY and c.encoder_chain == ("url",)
    ]
    spec = build(cases[0], _target())
    assert spec.method == "GET"
    assert "%27" in spec.query["q"]  # the apostrophe got URL-encoded


def test_build_json_body_is_valid_json():
    payloads = corpus.load_corpus(suites={"sqli"})
    p = next(p for p in payloads if Placement.BODY_JSON in p.placements)
    case = next(
        c for c in generate([p], [Transport.HTTP1]) if c.placement == Placement.BODY_JSON
    )
    spec = build(case, _target())
    assert spec.method == "POST"
    assert spec.body is not None
    assert spec.body.content_type == "application/json"
    json.loads(spec.body.data)  # must parse


def test_summarize_is_nonempty():
    payloads = corpus.load_corpus(suites={"xss"})
    case = next(generate(payloads, [Transport.HTTP1]))
    spec = build(case, _target())
    assert summarize(spec, case)
