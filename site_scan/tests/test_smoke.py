"""End-to-end smoke: run both subcommands against the in-repo example data.
No content assertions — purely 'doesn't crash on real data'."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = REPO_ROOT / "Testing" / "example_data"


@pytest.mark.skipif(not EXAMPLE_DIR.exists(), reason="Testing/example_data/ not present")
def test_smoke_hash_then_scan(tmp_path):
    digests = tmp_path / "site_digests.tsv"
    matches = tmp_path / "matches.tsv"
    threats = tmp_path / "threats.tsv"
    # Empty threat list would exit 2; build a tiny one from any one file we hash.
    # Easiest: hash first, then take one digest as the (sole) threat.
    res = subprocess.run(
        [sys.executable, "-m", "site_scan.tlsh_site_scan", "hash",
         "--site", str(EXAMPLE_DIR),
         "--out", str(digests),
         "--workers", "1",
         "--ext", "txt,php,html,htm,js"],  # example_data has plain text
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr

    # Take first digest line (after header) as our seed threat.
    lines = digests.read_text().splitlines()
    if len(lines) < 2:
        pytest.skip("example_data produced no hashable files")
    first = lines[1].split("\t")
    threats.write_text(f"{first[1]}\t{first[0]}\n")

    res = subprocess.run(
        [sys.executable, "-m", "site_scan.tlsh_site_scan", "scan",
         "--threats", str(threats),
         "--site-digests", str(digests),
         "--out", str(matches),
         "--threshold", "70"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    # Header at minimum; self-match should produce at least one row.
    out_lines = matches.read_text().splitlines()
    assert out_lines[0] == "site_path\trank\tdistance\tthreat_digest\tthreat_path"
    assert len(out_lines) >= 2
