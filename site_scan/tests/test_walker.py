"""Unit tests for the site walker / extension+exclude/size filter."""
from __future__ import annotations

from pathlib import Path

import pytest

from site_scan.tlsh_site_scan import (
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_EXTENSIONS,
    walk_site,
)


def _touch(p: Path, body: bytes = b"x" * 200):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)


def test_walker_picks_default_extensions_only(tmp_path):
    _touch(tmp_path / "good.php")
    _touch(tmp_path / "good.html")
    _touch(tmp_path / "good.js")
    _touch(tmp_path / "good.htm")
    _touch(tmp_path / "good.phtml")
    _touch(tmp_path / "skip.txt")
    _touch(tmp_path / "skip.png")
    _touch(tmp_path / "no_ext")

    results = sorted(p.name for p in walk_site(
        root=tmp_path,
        ext_set=DEFAULT_EXTENSIONS,
        exclude_dirs=DEFAULT_EXCLUDE_DIRS,
        follow_symlinks=False,
        include_hidden=False,
        min_size=50,
        max_size=5_242_880,
    ))
    assert results == ["good.htm", "good.html", "good.js", "good.php", "good.phtml"]


def test_walker_picks_php_variants(tmp_path):
    for ext in ("php", "php3", "php4", "php5", "php7", "php8"):
        _touch(tmp_path / f"x.{ext}")
    results = sorted(p.suffix for p in walk_site(
        root=tmp_path,
        ext_set=DEFAULT_EXTENSIONS,
        exclude_dirs=DEFAULT_EXCLUDE_DIRS,
        follow_symlinks=False,
        include_hidden=False,
        min_size=50,
        max_size=5_242_880,
    ))
    assert results == [".php", ".php3", ".php4", ".php5", ".php7", ".php8"]


def test_walker_skips_excluded_dirs(tmp_path):
    _touch(tmp_path / "keep.php")
    _touch(tmp_path / "node_modules" / "evil.php")
    _touch(tmp_path / "src" / "vendor" / "composer" / "x.php")
    _touch(tmp_path / "wp-includes" / "core.php")
    _touch(tmp_path / ".git" / "hooks" / "pre-commit.php")
    results = sorted(str(p.relative_to(tmp_path)) for p in walk_site(
        root=tmp_path,
        ext_set=DEFAULT_EXTENSIONS,
        exclude_dirs=DEFAULT_EXCLUDE_DIRS,
        follow_symlinks=False,
        include_hidden=False,
        min_size=50,
        max_size=5_242_880,
    ))
    assert results == ["keep.php"]


def test_walker_size_bounds(tmp_path):
    _touch(tmp_path / "tiny.php", b"<?php\n")     # < 50 bytes
    _touch(tmp_path / "ok.php", b"x" * 200)
    _touch(tmp_path / "huge.php", b"y" * 6_000_000)  # > 5 MiB
    results = sorted(p.name for p in walk_site(
        root=tmp_path,
        ext_set=DEFAULT_EXTENSIONS,
        exclude_dirs=DEFAULT_EXCLUDE_DIRS,
        follow_symlinks=False,
        include_hidden=False,
        min_size=50,
        max_size=5_242_880,
    ))
    assert results == ["ok.php"]


def test_walker_hidden_dirs_skipped_by_default(tmp_path):
    _touch(tmp_path / "keep.php")
    _touch(tmp_path / ".secret" / "x.php")
    results = sorted(p.name for p in walk_site(
        root=tmp_path,
        ext_set=DEFAULT_EXTENSIONS,
        exclude_dirs=DEFAULT_EXCLUDE_DIRS,
        follow_symlinks=False,
        include_hidden=False,
        min_size=50,
        max_size=5_242_880,
    ))
    assert results == ["keep.php"]


def test_walker_hidden_dirs_included_with_flag(tmp_path):
    _touch(tmp_path / ".secret" / "x.php")
    results = sorted(p.name for p in walk_site(
        root=tmp_path,
        ext_set=DEFAULT_EXTENSIONS,
        exclude_dirs=DEFAULT_EXCLUDE_DIRS,
        follow_symlinks=False,
        include_hidden=True,
        min_size=50,
        max_size=5_242_880,
    ))
    assert results == ["x.php"]
