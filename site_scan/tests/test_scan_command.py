"""Integration tests for the `scan` subcommand."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import tlsh

from site_scan.tests.fixtures_data import FILES


REPO_ROOT = Path(__file__).resolve().parents[2]


def _hash(data: bytes) -> str:
    t = tlsh.Tlsh(); t.update(data); t.final()
    assert t.is_valid             # property — no parens
    return t.hexdigest()


def _run_scan(threats: Path, sites: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable, "-m", "site_scan.tlsh_site_scan", "scan",
        "--threats", str(threats),
        "--site-digests", str(sites),
        "--out", str(out),
        *extra,
    ]
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)


def test_scan_finds_self_match(tmp_path):
    digest = _hash(FILES["alpha.php"])
    threats = tmp_path / "threats.tsv"
    threats.write_text(f"{digest}\t/threats/alpha.php\n")
    sites = tmp_path / "sites.tsv"
    sites.write_text(
        "site_path\tdigest\tsize\tmtime\n"
        f"/site/alpha.php\t{digest}\t{len(FILES['alpha.php'])}\t1700000000.0\n"
    )
    out = tmp_path / "matches.tsv"
    res = _run_scan(threats, sites, out, "--threshold", "40", "--top-n", "3")
    assert res.returncode == 0, res.stderr
    rows = out.read_text().splitlines()
    assert rows[0] == "site_path\trank\tdistance\tthreat_digest\tthreat_path"
    # Single self-match at distance 0, rank 1.
    assert rows[1] == f"/site/alpha.php\t1\t0\t{digest}\t/threats/alpha.php"


def test_scan_unrelated_files_produce_no_matches(tmp_path):
    threats_digest = _hash(FILES["alpha.php"])
    site_digest = _hash(FILES["epsilon.txt"])  # unrelated
    threats = tmp_path / "threats.tsv"
    threats.write_text(f"{threats_digest}\t/threats/alpha.php\n")
    sites = tmp_path / "sites.tsv"
    sites.write_text(
        "site_path\tdigest\tsize\tmtime\n"
        f"/site/x\t{site_digest}\t250\t1700000000.0\n"
    )
    out = tmp_path / "matches.tsv"
    res = _run_scan(threats, sites, out, "--threshold", "30")
    assert res.returncode == 0
    text = out.read_text()
    # Header only, no matches.
    assert text == "site_path\trank\tdistance\tthreat_digest\tthreat_path\n"


def test_scan_empty_threat_list_exits_2(tmp_path):
    threats = tmp_path / "threats.tsv"
    threats.write_text("# all comments\n")
    sites = tmp_path / "sites.tsv"
    sites.write_text("site_path\tdigest\n")
    out = tmp_path / "matches.tsv"
    res = _run_scan(threats, sites, out)
    assert res.returncode == 2
