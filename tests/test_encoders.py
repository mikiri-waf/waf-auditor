"""
WAF Auditor - tests
Copyright (c) Mikiri Security, LLC
"""

from waf_auditor.encoders import (
    ENCODERS,
    apply_body_modifiers,
    apply_chain,
    body_modifiers,
)


def test_none_is_identity():
    assert apply_chain("<x>", ["none"]) == "<x>"


def test_single_and_double_url():
    assert apply_chain("<", ["url"]) == "%3C"
    assert apply_chain("<", ["url_double"]) == "%253C"
    assert apply_chain("<", ["url_triple"]) == "%25253C"


def test_url_all_encodes_safe_chars():
    assert apply_chain("A", ["url_all"]) == "%41"


def test_chain_order_base64_then_url():
    # base64('a') = 'YQ==' ; url-encode of '=' is %3D
    assert apply_chain("a", ["base64", "url"]) == "YQ%3D%3D"


def test_html_entities():
    assert apply_chain("<", ["html_entity_dec"]) == "&#60;"
    assert apply_chain("<", ["html_entity_hex"]) == "&#x3c;"


def test_unicode_escape():
    assert apply_chain("A", ["unicode_escape"]) == "\\u0041"


def test_mixed_case_alternates_letters():
    assert apply_chain("select", ["mixed_case"]) == "SeLeCt"


def test_transport_modifiers_ignored_in_payload_chain():
    # gzip/chunked don't alter the payload string
    assert apply_chain("payload", ["gzip", "chunked"]) == "payload"
    assert body_modifiers(["url", "gzip", "chunked"]) == ["gzip", "chunked"]


def test_body_modifiers_apply_headers_and_compress():
    data, headers = apply_body_modifiers(b"hello world", ["gzip"])
    assert headers["Content-Encoding"] == "gzip"
    assert data != b"hello world"


def test_every_registered_encoder_is_pure_str():
    for name, fn in ENCODERS.items():
        out = fn("test<>'\"")
        assert isinstance(out, str), name
