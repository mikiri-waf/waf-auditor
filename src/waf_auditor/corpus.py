"""
WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Load and validate YAML payload suites into a flat list of Payload objects.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from jsonschema import Draft7Validator

from .encoders import known as encoder_known
from .models import (
    Expected,
    Kind,
    Payload,
    Placement,
    Severity,
)
from .paths import PAYLOADS_DIR, SCHEMA_FILE


class CorpusError(ValueError):
    pass


def _load_schema() -> Draft7Validator:
    with SCHEMA_FILE.open(encoding="utf-8") as fh:
        return Draft7Validator(json.load(fh))


def _to_chain(raw: list) -> tuple[str, ...]:
    # A chain is a list of encoder names; a bare string is treated as a 1-step chain.
    if isinstance(raw, str):
        return (raw,)
    return tuple(raw)


def load_suite_file(path: Path, validator: Draft7Validator) -> list[Payload]:
    with path.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    errors = sorted(validator.iter_errors(doc), key=lambda e: e.path)
    if errors:
        loc = " / ".join(str(p) for p in errors[0].absolute_path) or "<root>"
        raise CorpusError(f"{path.name}: schema error at {loc}: {errors[0].message}")

    suite = doc["suite"]
    kind = Kind(doc["kind"])
    category = doc["category"]
    expected = Expected(doc["expected"])
    severity = Severity(doc["severity"])
    description = doc.get("description", "")
    references = tuple(doc.get("references", []))

    default_placements = tuple(Placement(p) for p in doc.get("default_placements", []))
    default_encoders = tuple(_to_chain(c) for c in doc.get("default_encoders", [["none"]]))

    payloads: list[Payload] = []
    seen_ids: set[str] = set()
    for item in doc["payloads"]:
        pid = item["id"]
        if pid in seen_ids:
            raise CorpusError(f"{path.name}: duplicate payload id {pid!r}")
        seen_ids.add(pid)

        placements = (
            tuple(Placement(p) for p in item["placements"])
            if "placements" in item
            else default_placements
        )
        if not placements:
            raise CorpusError(f"{path.name}: payload {pid!r} has no placements")

        chains = (
            tuple(_to_chain(c) for c in item["encoders"])
            if "encoders" in item
            else default_encoders
        )
        for chain in chains:
            for name in chain:
                if not encoder_known(name):
                    raise CorpusError(
                        f"{path.name}: payload {pid!r} uses unknown encoder {name!r}"
                    )

        payloads.append(
            Payload(
                id=pid,
                raw=item["raw"],
                suite=suite,
                kind=kind,
                category=category,
                expected=expected,
                severity=severity,
                description=description,
                references=references,
                placements=placements,
                encoder_chains=chains,
                tags=tuple(item.get("tags", [])),
            )
        )
    return payloads


def load_corpus(
    root: Path | None = None,
    *,
    suites: set[str] | None = None,
    kinds: set[Kind] | None = None,
) -> list[Payload]:
    """Load every suite under ``root`` (default: bundled data), optionally filtered.

    ``suites`` filters by suite name, ``kinds`` by attack/false-positive.
    """
    root = root or PAYLOADS_DIR
    validator = _load_schema()
    all_payloads: list[Payload] = []
    for path in sorted(root.rglob("*.yaml")):
        loaded = load_suite_file(path, validator)
        all_payloads.extend(loaded)

    if suites is not None:
        all_payloads = [p for p in all_payloads if p.suite in suites]
    if kinds is not None:
        all_payloads = [p for p in all_payloads if p.kind in kinds]

    if not all_payloads:
        raise CorpusError("no payloads matched the given filters")
    return all_payloads


def available_suites(root: Path | None = None) -> list[str]:
    root = root or PAYLOADS_DIR
    names: set[str] = set()
    for path in sorted(root.rglob("*.yaml")):
        with path.open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if doc and "suite" in doc:
            names.add(doc["suite"])
    return sorted(names)
