"""
Mikiri WAF Auditor
Copyright (c) Mikiri Security, LLC
Author: Romanov R.

Resolve on-disk locations for bundled data, working dir and reports.
"""

from __future__ import annotations

from pathlib import Path

# src/waf_auditor/paths.py  ->  project root is three parents up.
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent

DATA_DIR = PROJECT_ROOT / "data"
PAYLOADS_DIR = DATA_DIR / "payloads"
SCHEMA_FILE = DATA_DIR / "schema" / "payload.schema.json"

# Per project convention, transient artifacts live under .env/mac/dev instead of /tmp.
DEV_DIR = PROJECT_ROOT / ".env" / "mac" / "dev"
REPORTS_DIR = PROJECT_ROOT / "reports"


def ensure_dirs() -> None:
    DEV_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
