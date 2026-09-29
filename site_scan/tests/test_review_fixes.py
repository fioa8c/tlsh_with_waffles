"""Regression tests for code-review findings: wide bands, shared scan logic, output permissions."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import tlsh

from site_scan import tlsh_site_scan as ss
from site_scan.tests.fixtures_data import FILES

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_candidate_indices_has_no_duplicates_for_huge_band():
    index = {b: [b] for b in range(256)}
    got = list(ss.candidate_indices(10, 5000, index))
    assert sorted(got) == list(range(256))


def test_scan_one_digest_counted_reports_candidates():
    t = tlsh.Tlsh(); t.update(FILES["alpha.php"]); t.final()
    d = t.hexdigest()
    threats = [(t, d, "/t/alpha")]
    index = ss.build_lvalue_index(threats)
    matches, n = ss.scan_one_digest_counted(d, threats, index, threshold=40, top_n=3, band=1)
    assert n == 1 and matches == [(0, d, "/t/alpha")]
    assert ss.scan_one_digest(d, threats, index, threshold=40, top_n=3, band=1) == matches


def test_huge_threshold_does_not_duplicate_rows(tmp_path):
    t = tlsh.Tlsh(); t.update(FILES["alpha.php"]); t.final()
    d = t.hexdigest()
    threats, sites, out = tmp_path / "t.tsv", tmp_path / "s.tsv", tmp_path / "m.tsv"
    threats.write_text(f"{d}\tthreat\n")
    sites.write_text(f"site.php\t{d}\n")
    r = subprocess.run([sys.executable, "-m", "site_scan.tlsh_site_scan", "scan",
                        "--threats", str(threats), "--site-digests", str(sites), "--out", str(out),
                        "--threshold", "5000", "--top-n", "10"],
                       cwd=REPO_ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert len(out.read_text().splitlines()) == 2  # header + one row


def test_outputs_follow_umask_not_0600(tmp_path):
    t = tlsh.Tlsh(); t.update(FILES["alpha.php"]); t.final()
    d = t.hexdigest()
    site = tmp_path / "site"; site.mkdir()
    (site / "a.php").write_bytes(FILES["alpha.php"])
    threats = tmp_path / "t.tsv"; threats.write_text(f"{d}\tthreat\n")
    digests, matches = tmp_path / "d.tsv", tmp_path / "m.tsv"
    old = os.umask(0o022)
    try:
        run = lambda *a: subprocess.run([sys.executable, "-m", "site_scan.tlsh_site_scan", *a],
                                        cwd=REPO_ROOT, capture_output=True, text=True)
        assert run("hash", "--site", str(site), "--out", str(digests), "--workers", "1").returncode == 0
        assert run("scan", "--threats", str(threats), "--site-digests", str(digests),
                   "--out", str(matches)).returncode == 0
    finally:
        os.umask(old)
    for f in (digests, matches):
        assert (f.stat().st_mode & 0o777) == 0o644, oct(f.stat().st_mode)
