# WAF Auditor

**Check your WAF before an attacker does**

WAF Auditor - a technical tool for testing any WAF for **attack bypasses** and **false positives**. Output comes as a console table, machine-readable JSON, and a PDF with charts.

## Legal & Ethical Use

**This tool is intended solely for authorized security testing.** Only use it against systems
you own or for which you have explicit, written permission to test. Sending attack payloads to
systems without authorization may be illegal under computer-misuse, unauthorized-access, and
other laws in your jurisdiction, and may violate contracts and acceptable-use policies.

**Do not use WAF Auditor for any criminal, malicious, or otherwise unlawful purpose.** You are
solely responsible for how you use it and for obtaining proper authorization. The authors and
Mikiri Security, LLC accept no liability for misuse or for any damage resulting from its use.
By using this tool you agree to these terms.

<hr>

## Installation

```bash
python3.11 -m venv /opt/venv
/opt/venv/bin/pip install -e '.[dev]'          # core + tests/linter
```

Run the package with the interpreter from that environment. No shell activation is required.
Commands below assume the current directory is the repository root (`pip install -e` installs
the tree you are in).

## Quick start

```bash
# basic run against a target (a block is decided by the response status code)
/opt/venv/bin/python -m waf_auditor --url https://target.example/ --block-status 403

# multiple transports and all report formats
/opt/venv/bin/python -m waf_auditor -u https://target.example/ -t http1 -t http2 \
    --block-status 403 --block-status 406 \
    --json report.json --pdf report.pdf

# only SQLi and XSS, only none/url encodings, with a rate limit
/opt/venv/bin/python -m waf_auditor -u https://target.example/ -s sqli -s xss \
    --encoders none,url --rate-limit 50

# informational commands
/opt/venv/bin/python -m waf_auditor --list-suites
/opt/venv/bin/python -m waf_auditor --list-encoders
```

Exit code is `1` if any attack got through (a bypass) — handy for CI gates.

## How it works: the universal payload model

A test case = **`payload × placement × encoder-chain × transport`**. A payload in YAML knows
nothing about transport, injection point, or encoding — the engine combines all axes.

- **Payload** — the raw string plus metadata (`data/payloads/**/*.yaml`).
- **Placement** — where it is injected: `url_query`, `url_path`, `header`, `cookie`,
  `body_urlencoded`, `body_json`, `body_multipart`, `body_xml`, `body_raw`, `ws_message`.
- **Encoder-chain** — how it is encoded (composable): `url`, `url_double`, `url_triple`,
  `base64`, `html_entity_*`, `unicode_escape`, `charset_utf16`, … plus the body transport
  modifiers `gzip`/`deflate`/`chunked`.
- **Transport** — `http1`, `http2`, `ws`.

Block detection is **based on the HTTP response status code** (a configurable set of statuses
per target).

### Adding your own payloads

Drop a YAML file into `data/payloads/attacks/` (or `false-positives/`) following the schema in
`data/schema/payload.schema.json`:

```yaml
suite: my-sqli
kind: attack               # attack | false-positive
category: sqli
expected: blocked          # attack -> blocked ; false-positive -> passed
severity: high
default_placements: [url_query, body_json]
default_encoders: [[none], [url], [url_double]]
payloads:
  - id: my-sqli-0001
    raw: "1' OR '1'='1"
```

## Reports

- **Console** — an A+…F grade, breakdowns by category/transport/placement/encoder, and lists of
  bypasses and false positives.
- **JSON** — a full dump of every test case plus aggregates (for CI/integrations).
- **PDF** — a title page with the grade, bar charts by category and transport, a
  `placement × encoder` heatmap, and key findings.

## Development

```bash
/opt/venv/bin/python -m pytest            # unit tests
/opt/venv/bin/python -m ruff check src tests
```

Local e2e: `/opt/venv/bin/python .env/mac/dev/mock_waf.py 8899` starts a naive signature-based "WAF" (it catches
some raw payloads, lets double-encoded ones through, and over-blocks a couple of legitimate
tokens) — useful for exercising the full pipeline.

## Roadmap

- **Phase 1 (done):** HTTP/1.1+2, WebSocket transport, all axes, console/JSON/PDF.
- **Phase 2:** richer WebSocket scenarios, a "glossy" PDF (WeasyPrint), deeper multipart/XML
  placements, expanded payload sets.

---
Copyright (c) Mikiri Security, LLC
