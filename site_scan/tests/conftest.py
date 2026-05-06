"""Shared pytest fixtures for site_scan tests."""
from __future__ import annotations

import sys
from pathlib import Path

# Make the parent dir importable when tests run from the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
