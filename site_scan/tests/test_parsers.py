"""Unit tests for threat-list and site-digests parsers."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import tlsh

from site_scan.tlsh_site_scan import parse_threats_file
from site_scan.tests.fixtures_data import FILES


def _hash_bytes(data: bytes) -> str:
    t = tlsh.Tlsh()
    t.update(data)
    t.final()
    assert t.is_valid, "fixture must be hashable"   # property (no parens)
    return t.hexdigest()


@pytest.fixture
def real_digest():
    """A real, valid digest computed from a fixture, so fromTlshStr accepts it."""
    return _hash_bytes(FILES["alpha.php"])


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_parse_threats_basic(tmp_path, real_digest):
    f = _write(tmp_path, "threats.tsv", f"{real_digest}\t/threats/x.php\n")
    accepted, stats = parse_threats_file(f)
    assert len(accepted) == 1
    t_obj, digest, threat_path = accepted[0]
    assert digest == real_digest
    assert threat_path == "/threats/x.php"
    assert t_obj.hexdigest() == real_digest
    assert stats == {"accepted": 1, "invalid": 0, "malformed": 0}


def test_parse_threats_skips_blank_and_comments(tmp_path, real_digest):
    body = textwrap.dedent(f"""\
        # this is a comment

        {real_digest}\t/threats/x.php
        # another comment

        {real_digest}\t/threats/y.php
    """)
    f = _write(tmp_path, "threats.tsv", body)
    accepted, stats = parse_threats_file(f)
    assert len(accepted) == 2
    assert stats == {"accepted": 2, "invalid": 0, "malformed": 0}


def test_parse_threats_malformed_wrong_columns(tmp_path, real_digest):
    body = textwrap.dedent(f"""\
        {real_digest}\t/threats/x.php
        {real_digest}_only_one_column
        {real_digest}\t/threats/y.php\textra_column
    """)
    f = _write(tmp_path, "threats.tsv", body)
    accepted, stats = parse_threats_file(f)
    # First line valid; second has 1 column (malformed); third has 3 columns (we accept first 2).
    # Spec says "wrong column count" -> malformed. Treat anything != 2 as malformed.
    assert len(accepted) == 1
    assert stats == {"accepted": 1, "invalid": 0, "malformed": 2}


def test_parse_threats_invalid_digest(tmp_path):
    body = "NOT_A_DIGEST\t/threats/x.php\n"
    f = _write(tmp_path, "threats.tsv", body)
    accepted, stats = parse_threats_file(f)
    assert accepted == []
    assert stats == {"accepted": 0, "invalid": 1, "malformed": 0}


def test_parse_threats_empty_file(tmp_path):
    f = _write(tmp_path, "threats.tsv", "")
    accepted, stats = parse_threats_file(f)
    assert accepted == []
    assert stats == {"accepted": 0, "invalid": 0, "malformed": 0}


from site_scan.tlsh_site_scan import parse_site_digests_file


def test_parse_site_digests_with_header(tmp_path, real_digest):
    body = (
        "site_path\tdigest\tsize\tmtime\n"
        f"/site/a.php\t{real_digest}\t512\t1700000000.0\n"
        f"/site/b.php\t{real_digest}\t800\t1700000001.0\n"
    )
    f = _write(tmp_path, "site.tsv", body)
    rows = list(parse_site_digests_file(f))
    assert rows == [
        ("/site/a.php", real_digest),
        ("/site/b.php", real_digest),
    ]


def test_parse_site_digests_two_columns_no_header(tmp_path, real_digest):
    """External tools may produce just <path>\t<digest> with no header. Accept."""
    body = (
        f"/site/a.php\t{real_digest}\n"
        f"/site/b.php\t{real_digest}\n"
    )
    f = _write(tmp_path, "site.tsv", body)
    rows = list(parse_site_digests_file(f))
    assert rows == [
        ("/site/a.php", real_digest),
        ("/site/b.php", real_digest),
    ]


def test_parse_site_digests_skips_invalid_and_blanks(tmp_path, real_digest):
    body = (
        f"/site/a.php\t{real_digest}\n"
        "\n"
        f"/site/bad.php\tNOT_A_DIGEST\n"
        f"/site/single_col\n"
        f"/site/c.php\t{real_digest}\n"
    )
    f = _write(tmp_path, "site.tsv", body)
    rows = list(parse_site_digests_file(f))
    assert rows == [
        ("/site/a.php", real_digest),
        ("/site/c.php", real_digest),
    ]
