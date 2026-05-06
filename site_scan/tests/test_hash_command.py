"""Integration tests for the `hash` subcommand."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import tlsh

from site_scan.tests.fixtures_data import FILES


REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_hash(site: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable, "-m", "site_scan.tlsh_site_scan", "hash",
        "--site", str(site),
        "--out", str(out),
        "--workers", "1",  # serial for deterministic test output
        *extra,
    ]
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)


def _build_site(tmp_path: Path) -> Path:
    """Create a tiny site tree with a known set of fixture files."""
    site = tmp_path / "site"
    for name in ("alpha.php", "beta.php", "gamma.html", "delta.js"):
        p = site / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(FILES[name])
    # A file that should be filtered out by extension:
    (site / "skip.txt").write_bytes(FILES["epsilon.txt"])
    # An excluded dir:
    (site / "node_modules").mkdir(parents=True)
    (site / "node_modules" / "evil.php").write_bytes(FILES["beta.php"])
    return site


def test_hash_command_writes_expected_digests(tmp_path):
    site = _build_site(tmp_path)
    out = tmp_path / "site_digests.tsv"
    res = _run_hash(site, out)
    assert res.returncode == 0, res.stderr
    assert out.exists()

    # Parse output, ignoring header.
    lines = out.read_text().splitlines()
    assert lines[0] == "site_path\tdigest\tsize\tmtime"
    rows = [line.split("\t") for line in lines[1:]]
    by_basename = {Path(r[0]).name: r for r in rows}
    # All four eligible files present, excluded ones absent.
    assert set(by_basename.keys()) == {"alpha.php", "beta.php", "gamma.html", "delta.js"}
    # Digests are valid T1 strings.
    for r in rows:
        assert r[1].startswith("T1")
        assert len(r[1]) == 72
        assert int(r[2]) > 0  # size column
        assert float(r[3]) > 0  # mtime column


def test_hash_command_empty_site(tmp_path):
    site = tmp_path / "empty_site"
    site.mkdir()
    out = tmp_path / "site_digests.tsv"
    res = _run_hash(site, out)
    assert res.returncode == 0
    # Header present, no rows.
    text = out.read_text()
    assert text == "site_path\tdigest\tsize\tmtime\n"
