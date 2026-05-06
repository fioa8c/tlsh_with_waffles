"""Unit tests for hash_one_file."""
from __future__ import annotations

from pathlib import Path

import tlsh

from site_scan.tlsh_site_scan import hash_one_file
from site_scan.tests.fixtures_data import FILES


def test_hash_one_file_returns_valid_t1_digest(tmp_path):
    f = tmp_path / "alpha.php"
    f.write_bytes(FILES["alpha.php"])
    path, digest, size, mtime, skip = hash_one_file(str(f))
    assert path == str(f)
    assert skip is None
    assert digest is not None
    assert digest.startswith("T1")
    assert len(digest) == 72
    assert size == len(FILES["alpha.php"])
    assert mtime == f.stat().st_mtime
    # Confirm round-trip: parse the digest back via tlsh.
    t = tlsh.Tlsh()
    t.fromTlshStr(digest)   # raises ValueError if bad; returns None on success
    assert t.is_valid       # property, no parens


def test_hash_one_file_low_entropy_returns_skip(tmp_path):
    # All-zeros (or repeated single byte) often fails TLSH's entropy check.
    f = tmp_path / "boring.php"
    f.write_bytes(b"\x00" * 300)
    path, digest, size, mtime, skip = hash_one_file(str(f))
    # Either is_valid succeeded (some compile-time variants tolerate it) or skip is set.
    assert (digest is not None) ^ (skip == "low_entropy")


def test_hash_one_file_missing(tmp_path):
    f = tmp_path / "does_not_exist.php"
    path, digest, size, mtime, skip = hash_one_file(str(f))
    assert digest is None
    assert skip == "io_error"
    assert size is None
    assert mtime is None
