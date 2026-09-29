"""Filenames with tabs, newlines, backslashes or undecodable bytes must survive the TSV round-trip."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import tlsh

from site_scan.tests.fixtures_data import FILES

from site_scan import tlsh_site_scan as ss

REPO_ROOT = Path(__file__).resolve().parents[2]

NASTY_NAMES = [
    "a\tb.php",
    "a\nb.php",
    "a\r\nb.php",
    "back\\slash.php",
    "literal\\tbackslash-t.php",
    "bad\udcff.php",  # undecodable byte as surrogateescape
]


@pytest.mark.parametrize("name", NASTY_NAMES)
def test_escape_roundtrip_is_single_field(name):
    esc = ss.escape_tsv_field(name)
    assert "\t" not in esc and "\n" not in esc and "\r" not in esc
    assert ss.unescape_tsv_field(esc) == name


def test_plain_name_unchanged():
    assert ss.escape_tsv_field("/var/www/index.php") == "/var/www/index.php"


def test_digest_file_with_surrogate_path_roundtrips(tmp_path):
    digest = tlsh.hash(FILES["alpha.php"])
    out = tmp_path / "d.tsv"
    with ss.open_tsv(out, "w") as fh:
        fh.write(ss._HASH_TSV_HEADER)
        for n in NASTY_NAMES:
            fh.write(f"{ss.escape_tsv_field(n)}\t{digest}\t1\t0\n")
    got = [p for p, _ in ss.parse_site_digests_file(out)]
    assert got == NASTY_NAMES


def test_hash_then_scan_finds_tab_named_file(tmp_path):
    body = FILES["alpha.php"]
    site = tmp_path / "site"
    site.mkdir()
    (site / "a\tb.php").write_bytes(body)
    (site / "c\nd.php").write_bytes(body + b"x")
    digests, threats, matches = tmp_path / "d.tsv", tmp_path / "t.tsv", tmp_path / "m.tsv"
    run = lambda *a: subprocess.run([sys.executable, "-m", "site_scan.tlsh_site_scan", *a],
                                    cwd=REPO_ROOT, capture_output=True, text=True)
    r = run("hash", "--site", str(site), "--out", str(digests), "--workers", "1")
    assert r.returncode == 0, r.stderr
    threats.write_text(f"{tlsh.hash(body)}\tthreat\n")
    r = run("scan", "--threats", str(threats), "--site-digests", str(digests),
            "--out", str(matches), "--threshold", "50")
    assert r.returncode == 0, r.stderr
    assert "warn" not in r.stderr
    rows = matches.read_text().splitlines()[1:]
    assert len(rows) == 2, rows  # one line per file, none dropped or split
    paths = sorted(ss.unescape_tsv_field(r.split("\t")[0]) for r in rows)
    assert paths == sorted([str(site / "a\tb.php"), str(site / "c\nd.php")])
