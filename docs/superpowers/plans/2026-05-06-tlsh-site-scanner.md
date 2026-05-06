# TLSH Site Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI tool (`site_scan/tlsh_site_scan.py`) that recursively scans a website, hashes `.php`/`.js`/`.html` files with TLSH, and matches them against a pre-generated threat-digest list using an Lvalue prefilter — turning a multi-day brute-force scan into a multi-minute job.

**Architecture:** Two independent subcommands (`hash`, `scan`) sharing a single Python module. `hash` walks the site with a `multiprocessing.Pool` and writes a digest TSV. `scan` loads the threat list into a `dict[Lvalue → indices]` index, then for each site digest gathers candidates from a circular Lvalue band of `±lvalue_band(threshold)` buckets, computes full TLSH distance only on candidates, and writes top-3 matches.

**Tech Stack:** Python ≥ 3.8 stdlib (`argparse`, `os`, `multiprocessing`, `pathlib`, `csv`/hand-rolled TSV, `sys`) + the in-repo `tlsh` CPython extension from `py_ext/`. Tests use `pytest`. No new build-system integration — pure Python tool.

**Spec:** [docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md](../specs/2026-05-06-tlsh-site-scanner-design.md)

**Working directory:** `/Users/fioa8c/WORK/tlsh_with_waffles`

---

## File structure

| File | Responsibility |
|---|---|
| `site_scan/__init__.py` | Empty marker, makes `site_scan` a package so `python -m site_scan.tlsh_site_scan` works. |
| `site_scan/tlsh_site_scan.py` | The single-file CLI. Holds all production code: parsers, prefilter, walker, hasher, two subcommands, argparse `main`. |
| `site_scan/README.md` | Usage examples + how to install `py_ext` first. |
| `site_scan/tests/__init__.py` | Empty marker. |
| `site_scan/tests/conftest.py` | Pytest fixtures: tiny site tree builder, fixture digest computation. |
| `site_scan/tests/fixtures_data.py` | Inline byte-content of test fixture files (commit raw content here, not as separate files, for reproducibility). |
| `site_scan/tests/test_lvalue_band.py` | Unit: `lvalue_band()` table. |
| `site_scan/tests/test_parsers.py` | Unit: threat-list and site-digests parsers. |
| `site_scan/tests/test_index.py` | Unit: Lvalue index build + circular bucket gathering. |
| `site_scan/tests/test_walker.py` | Unit: site walker (extension filter, exclude dirs, hidden, size). |
| `site_scan/tests/test_hasher.py` | Unit: single-file hasher returns valid digest tuple. |
| `site_scan/tests/test_hash_command.py` | Integration: `hash` subcommand via `subprocess`. |
| `site_scan/tests/test_scan_command.py` | Integration: `scan` subcommand via `subprocess`. |
| `site_scan/tests/test_invariant.py` | **Critical**: prefilter ≡ brute-force equivalence at T=40 and T=70. |
| `site_scan/tests/test_smoke.py` | Smoke: runs both subcommands against `Testing/example_data/`, checks no crash. |

**Why a single production file:** The whole tool is ~300 lines once you account for `argparse` boilerplate. Splitting prematurely just adds import noise. The function boundaries inside the file are what matter for testability.

**Why split tests by concern:** Unit tests (one concern each) stay fast and isolated; the invariant test gets its own file because it's the load-bearing safety net for the prefilter math.

---

## Pre-flight (do this once before Task 1)

The Python tool depends on the `tlsh` CPython extension. Build the C++ library and install the extension before running any tests:

```bash
cd /Users/fioa8c/WORK/tlsh_with_waffles
./make.sh
cd py_ext && python setup.py build && python setup.py install --user
python -c "import tlsh; t = tlsh.Tlsh(); t.update(b'x'*200); t.final(); print(t.hexdigest())"
```

Expected output: a `T1...`-prefixed 72-character hex string. If `import tlsh` fails, re-run `python setup.py install --user` and check Python is finding `~/.local/lib/python*/site-packages/`. If `make.sh` fails, see top-level `README.md`.

---

## Task 1: Bootstrap directory + module skeleton

**Files:**
- Create: `site_scan/__init__.py`
- Create: `site_scan/tests/__init__.py`
- Create: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/conftest.py`

- [ ] **Step 1: Create the package skeleton**

```bash
mkdir -p /Users/fioa8c/WORK/tlsh_with_waffles/site_scan/tests
```

Write `site_scan/__init__.py`:
```python
```
(empty file)

Write `site_scan/tests/__init__.py`:
```python
```
(empty file)

Write `site_scan/tlsh_site_scan.py`:
```python
"""TLSH site scanner: recursive directory scan against a pre-generated TLSH threat list.

Two subcommands:
  hash  walks a site, hashes filtered files, writes a digest TSV.
  scan  reads a digest TSV + a threat list, writes a top-N matches TSV.

See docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md for design.
"""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("argparse + subcommands not yet wired")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

Write `site_scan/tests/conftest.py`:
```python
"""Shared pytest fixtures for site_scan tests."""
from __future__ import annotations

import sys
from pathlib import Path

# Make the parent dir importable when tests run from the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
```

- [ ] **Step 2: Verify imports work**

Run from `/Users/fioa8c/WORK/tlsh_with_waffles`:
```bash
python -c "import site_scan.tlsh_site_scan; print('ok')"
python -c "import tlsh; print('tlsh ok')"
```
Expected: both print `ok` / `tlsh ok`. If `import tlsh` fails, redo the pre-flight install.

- [ ] **Step 3: Commit**

```bash
cd /Users/fioa8c/WORK/tlsh_with_waffles
git add site_scan/__init__.py site_scan/tests/__init__.py site_scan/tlsh_site_scan.py site_scan/tests/conftest.py
git commit -m "site_scan: scaffold module skeleton

Empty package + module stub. No behavior yet; subsequent tasks fill it in TDD-style."
```

---

## Task 2: `lvalue_band()` (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/test_lvalue_band.py`

- [ ] **Step 1: Write the failing test**

Write `site_scan/tests/test_lvalue_band.py`:
```python
"""Unit tests for lvalue_band(threshold) — the prefilter band computation."""
import pytest

from site_scan.tlsh_site_scan import lvalue_band


@pytest.mark.parametrize("threshold,expected", [
    (0, 0),       # zero threshold -> only exact Lvalue match
    (1, 1),       # ldiff=1 contributes 1 (special case in totalDiff)
    (11, 1),      # below the *12 regime, ldiff=1 still in budget
    (12, 1),      # exactly at boundary: ldiff=1 contributes 1, ldiff=2 contributes 24
    (24, 2),      # ldiff=2 contributes 24, ldiff=3 contributes 36
    (30, 2),      # 30 // 12 == 2
    (40, 3),      # design-doc default threshold
    (70, 5),      # tlsh CLI default
    (1000, 83),   # large but valid: 1000 // 12
])
def test_lvalue_band_table(threshold, expected):
    assert lvalue_band(threshold) == expected


def test_lvalue_band_negative_returns_zero():
    # Defensive: caller validates non-negative thresholds, but if anyone passes
    # a negative we don't want a misleading band; return 0.
    assert lvalue_band(-5) == 0
```

- [ ] **Step 2: Run the test — verify it fails**

```bash
cd /Users/fioa8c/WORK/tlsh_with_waffles
pytest site_scan/tests/test_lvalue_band.py -v
```
Expected: `ImportError` / `AttributeError: module 'site_scan.tlsh_site_scan' has no attribute 'lvalue_band'`.

- [ ] **Step 3: Implement `lvalue_band`**

In `site_scan/tlsh_site_scan.py`, replace the `main` stub block with:
```python
"""TLSH site scanner: recursive directory scan against a pre-generated TLSH threat list.

Two subcommands:
  hash  walks a site, hashes filtered files, writes a digest TSV.
  scan  reads a digest TSV + a threat list, writes a top-N matches TSV.

See docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md for design.
"""
from __future__ import annotations

import sys


# Distance scoring constants (must mirror tlsh_impl.cpp lsh_bin_totalDiff):
#   length contribution = 0 if ldiff==0, 1 if ldiff==1, ldiff*12 otherwise.
_LENGTH_MULT = 12


def lvalue_band(threshold: int) -> int:
    """Return the largest Lvalue-mod-diff that could still produce a match.

    Any pair with mod_diff(L1, L2, 256) > lvalue_band(T) cannot have total
    distance <= T (because the length term alone would exceed T).
    """
    if threshold <= 0:
        return 0
    if threshold < _LENGTH_MULT:
        # ldiff=1 contributes 1; ldiff>=2 contributes 2*12=24, already over.
        return 1
    return threshold // _LENGTH_MULT


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("argparse + subcommands not yet wired")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 4: Run the test — verify it passes**

```bash
pytest site_scan/tests/test_lvalue_band.py -v
```
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_lvalue_band.py
git commit -m "site_scan: add lvalue_band prefilter helper

Computes the maximum Lvalue mod-diff that could still yield a match for
a given threshold. Mirrors the length-term math in lsh_bin_totalDiff."
```

---

## Task 3: Threat-list parser (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/test_parsers.py`
- Create: `site_scan/tests/fixtures_data.py`

- [ ] **Step 1: Add fixture data module**

Write `site_scan/tests/fixtures_data.py`:
```python
"""Inline byte-content for test fixture files. Committed here (rather than as
binary files) so test data is reviewable in diffs and reproducible regardless
of TLSH compile-time flags. Each value is bytes that hashes to a valid TLSH
digest (length >= 50, sufficient entropy)."""

# These contents are used to compute digests at test time.
FILES = {
    "alpha.php":   b"<?php\n" + b"echo 'aaaa';\n" * 30 + b"echo 'end';\n",
    "alpha2.php":  b"<?php\n" + b"echo 'aaaa';\n" * 30 + b"echo 'fin';\n",  # near-clone of alpha.php
    "beta.php":    b"<?php\n" + b"echo 'bbbb';\n" * 30 + b"echo 'end';\n",
    "gamma.html":  b"<html><body>" + b"<p>hello world</p>\n" * 25 + b"</body></html>",
    "delta.js":    b"// header\n" + b"var x = 1;\nfunction f(){return x;}\n" * 20,
    "epsilon.txt": b"plain text fixture, not in default extension set, " + b"a" * 200,
    "tiny.php":    b"<?php echo 1; ?>",  # under MIN_DATA_LENGTH (50)
}
```

- [ ] **Step 2: Write the failing tests**

Write `site_scan/tests/test_parsers.py`:
```python
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
    assert t.is_valid(), "fixture must be hashable"
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
```

Run:
```bash
pytest site_scan/tests/test_parsers.py -v
```
Expected: ImportError on `parse_threats_file`.

- [ ] **Step 3: Implement `parse_threats_file`**

Add to `site_scan/tlsh_site_scan.py` (above `def main`):

```python
from pathlib import Path
from typing import Iterable

import tlsh


def parse_threats_file(path: Path | str) -> tuple[list[tuple["tlsh.Tlsh", str, str]], dict[str, int]]:
    """Parse a threat list (`<digest>\t<threat_path>` per line) into Tlsh objects.

    Returns (accepted, stats) where:
      accepted = [(Tlsh_object, digest_str, threat_path), ...]
      stats    = {"accepted": N, "invalid": K, "malformed": L}

    Comments (lines starting with #) and blank lines are skipped silently.
    Invalid digests and lines with wrong column count are skipped and counted.
    """
    accepted: list[tuple[tlsh.Tlsh, str, str]] = []
    stats = {"accepted": 0, "invalid": 0, "malformed": 0}

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n").rstrip("\r")
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) != 2:
                stats["malformed"] += 1
                _warn(f"{path}:{line_no}: malformed (expected 2 cols, got {len(cols)})")
                continue
            digest, threat_path = cols
            t = tlsh.Tlsh()
            try:
                err = t.fromTlshStr(digest)
            except (ValueError, TypeError):
                err = 1
            if err:
                stats["invalid"] += 1
                _warn(f"{path}:{line_no}: invalid digest")
                continue
            accepted.append((t, digest, threat_path))
            stats["accepted"] += 1

    return accepted, stats


_WARN_LIMIT_PER_KIND = 10
_warn_counts: dict[str, int] = {}


def _warn(msg: str) -> None:
    """Stderr warning, rate-limited per first-word kind to avoid floods."""
    kind = msg.split(":", 1)[0] if ":" in msg else msg
    n = _warn_counts.get(kind, 0)
    if n < _WARN_LIMIT_PER_KIND:
        print(f"warn: {msg}", file=sys.stderr)
    elif n == _WARN_LIMIT_PER_KIND:
        print(f"warn: (further '{kind}' warnings suppressed)", file=sys.stderr)
    _warn_counts[kind] = n + 1
```

- [ ] **Step 4: Run tests**

```bash
pytest site_scan/tests/test_parsers.py -v
```
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_parsers.py site_scan/tests/fixtures_data.py
git commit -m "site_scan: parse threat-list TSV into Tlsh objects

Reads <digest>\\t<threat_path> lines, skips comments/blanks, counts and
rate-limits warnings for malformed lines and invalid digests."
```

---

## Task 4: Site-digests parser (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Modify: `site_scan/tests/test_parsers.py`

- [ ] **Step 1: Write the failing tests**

Append to `site_scan/tests/test_parsers.py`:
```python
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
```

Run:
```bash
pytest site_scan/tests/test_parsers.py -v
```
Expected: 3 new ImportError failures.

- [ ] **Step 2: Implement `parse_site_digests_file`**

Add to `site_scan/tlsh_site_scan.py`:
```python
from typing import Iterator


def parse_site_digests_file(path: Path | str) -> Iterator[tuple[str, str]]:
    """Yield (site_path, digest) tuples from a site-digests TSV.

    Format: <site_path>\\t<digest>[\\t<extra>...]. Header line (`site_path\\t`-prefixed
    first non-blank line) is detected and skipped. Lines that fail digest validation
    are skipped with a stderr warning.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first_data_line_seen = False
        for line_no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n").rstrip("\r")
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) < 2:
                _warn(f"{path}:{line_no}: malformed (expected >=2 cols, got {len(cols)})")
                continue
            site_path, digest = cols[0], cols[1]
            if not first_data_line_seen and site_path == "site_path" and digest == "digest":
                first_data_line_seen = True
                continue  # header
            first_data_line_seen = True
            t = tlsh.Tlsh()
            try:
                err = t.fromTlshStr(digest)
            except (ValueError, TypeError):
                err = 1
            if err:
                _warn(f"{path}:{line_no}: invalid digest")
                continue
            yield site_path, digest
```

- [ ] **Step 3: Run tests**

```bash
pytest site_scan/tests/test_parsers.py -v
```
Expected: all 8 tests pass.

- [ ] **Step 4: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_parsers.py
git commit -m "site_scan: parse site-digests TSV (with or without header)

Supports both 2-col (<path>\\t<digest>) and 4-col (<path>\\t<digest>\\t<size>\\t<mtime>)
formats. Detects and skips header line. Skips invalid digests with rate-limited warnings."
```

---

## Task 5: Lvalue index + circular bucket gathering (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/test_index.py`

- [ ] **Step 1: Write the failing tests**

Write `site_scan/tests/test_index.py`:
```python
"""Unit tests for the Lvalue index and candidate gathering."""
from __future__ import annotations

import tlsh

from site_scan.tlsh_site_scan import build_lvalue_index, candidate_indices
from site_scan.tests.fixtures_data import FILES


def _make_threats():
    """Build a small list of (Tlsh, digest, threat_path) using fixture content."""
    threats = []
    for name, body in FILES.items():
        if len(body) < 50:
            continue
        t = tlsh.Tlsh(); t.update(body); t.final()
        if not t.is_valid():
            continue
        threats.append((t, t.hexdigest(), f"/threats/{name}"))
    assert len(threats) >= 4
    return threats


def test_build_lvalue_index_maps_lvalue_to_indices():
    threats = _make_threats()
    index = build_lvalue_index(threats)
    # Every threat should appear in the bucket matching its own Lvalue.
    for i, (t, _, _) in enumerate(threats):
        assert i in index[t.lvalue]
    # Sum of bucket sizes equals threat count.
    assert sum(len(v) for v in index.values()) == len(threats)


def test_candidate_indices_circular_at_zero():
    # band=2 around L=0 should include {254, 255, 0, 1, 2}.
    fake_index = {L: [L] for L in range(256)}
    cands = sorted(candidate_indices(0, 2, fake_index))
    assert cands == sorted([254, 255, 0, 1, 2])


def test_candidate_indices_circular_at_max():
    fake_index = {L: [L] for L in range(256)}
    cands = sorted(candidate_indices(255, 2, fake_index))
    assert cands == sorted([253, 254, 255, 0, 1])


def test_candidate_indices_band_zero():
    fake_index = {L: [L] for L in range(256)}
    assert list(candidate_indices(42, 0, fake_index)) == [42]


def test_candidate_indices_missing_buckets_return_empty():
    sparse = {10: [99]}
    assert list(candidate_indices(10, 2, sparse)) == [99]
    assert list(candidate_indices(50, 2, sparse)) == []
```

Run:
```bash
pytest site_scan/tests/test_index.py -v
```
Expected: ImportError on `build_lvalue_index`.

- [ ] **Step 2: Implement**

Add to `site_scan/tlsh_site_scan.py`:
```python
from collections import defaultdict


def build_lvalue_index(
    threats: list[tuple["tlsh.Tlsh", str, str]],
) -> dict[int, list[int]]:
    """Map each Lvalue byte (0-255) to the list of threat indices with that Lvalue."""
    index: dict[int, list[int]] = defaultdict(list)
    for i, (t, _digest, _path) in enumerate(threats):
        index[t.lvalue].append(i)
    return dict(index)


def candidate_indices(
    lvalue: int, band: int, index: dict[int, list[int]]
) -> Iterator[int]:
    """Yield threat indices in Lvalue buckets [lvalue-band ... lvalue+band] (mod 256)."""
    for delta in range(-band, band + 1):
        bucket = (lvalue + delta) % 256
        for idx in index.get(bucket, ()):
            yield idx
```

- [ ] **Step 3: Run tests**

```bash
pytest site_scan/tests/test_index.py -v
```
Expected: 5 passed.

- [ ] **Step 4: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_index.py
git commit -m "site_scan: Lvalue-bucket index for prefilter

build_lvalue_index() partitions threats by Lvalue byte; candidate_indices()
walks a circular band of buckets around a query Lvalue."
```

---

## Task 6: Site walker (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/test_walker.py`

- [ ] **Step 1: Write the failing tests**

Write `site_scan/tests/test_walker.py`:
```python
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
```

Run:
```bash
pytest site_scan/tests/test_walker.py -v
```
Expected: ImportError on `walk_site` and constants.

- [ ] **Step 2: Implement**

Add to `site_scan/tlsh_site_scan.py`:
```python
import os


DEFAULT_EXTENSIONS: frozenset[str] = frozenset({
    "php", "php3", "php4", "php5", "php7", "php8", "phtml",
    "htm", "html", "js",
})

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", ".svn", "node_modules", "composer", "wp-includes",
})


def walk_site(
    root: Path | str,
    *,
    ext_set: Iterable[str],
    exclude_dirs: Iterable[str],
    follow_symlinks: bool,
    include_hidden: bool,
    min_size: int,
    max_size: int,
) -> Iterator[Path]:
    """Yield Path objects for files under `root` that pass all filters.

    - Extension matched case-insensitively against `ext_set` (no leading dot).
    - Directories whose basename is in `exclude_dirs` are pruned at any depth.
    - Hidden dirs (basename starts with '.') are pruned unless `include_hidden`.
    - Files outside [min_size, max_size] are skipped.
    """
    ext_set = {e.lower().lstrip(".") for e in ext_set}
    exclude_dirs = set(exclude_dirs)
    root = Path(root)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # In-place prune of dirnames so os.walk doesn't descend.
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs
            and (include_hidden or not d.startswith("."))
        ]
        for fn in filenames:
            ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
            if ext not in ext_set:
                continue
            full = Path(dirpath) / fn
            try:
                st = full.stat()
            except OSError:
                continue
            if st.st_size < min_size or st.st_size > max_size:
                continue
            yield full
```

- [ ] **Step 3: Run tests**

```bash
pytest site_scan/tests/test_walker.py -v
```
Expected: 6 passed.

- [ ] **Step 4: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_walker.py
git commit -m "site_scan: site walker with extension/exclude/size filters

Yields Path objects for files matching default extensions, skipping
excluded dirs (basename match at any depth), hidden dirs, and files
outside the size band. os.walk in-place prune avoids descending."
```

---

## Task 7: Single-file hasher (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/test_hasher.py`

- [ ] **Step 1: Write the failing test**

Write `site_scan/tests/test_hasher.py`:
```python
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
    assert t.fromTlshStr(digest) == 0


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
```

Run:
```bash
pytest site_scan/tests/test_hasher.py -v
```
Expected: ImportError on `hash_one_file`.

- [ ] **Step 2: Implement**

Add to `site_scan/tlsh_site_scan.py`:
```python
def hash_one_file(
    path: str,
) -> tuple[str, str | None, int | None, float | None, str | None]:
    """Hash one file, returning (path, digest_or_None, size, mtime, skip_reason).

    skip_reason ∈ {None, 'io_error', 'low_entropy'}. Used as a worker-process
    callable in multiprocessing.Pool, so it MUST be top-level (picklable) and
    catch all expected file-system errors.
    """
    try:
        st = os.stat(path)
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return (path, None, None, None, "io_error")
    t = tlsh.Tlsh()
    t.update(data)
    t.final()
    if not t.is_valid():
        return (path, None, st.st_size, st.st_mtime, "low_entropy")
    return (path, t.hexdigest(), st.st_size, st.st_mtime, None)
```

- [ ] **Step 3: Run tests**

```bash
pytest site_scan/tests/test_hasher.py -v
```
Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_hasher.py
git commit -m "site_scan: per-file hasher worker

Top-level function so multiprocessing.Pool can pickle it. Returns a tuple
including skip_reason for OS errors and low-entropy inputs."
```

---

## Task 8: `hash` subcommand (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/test_hash_command.py`

- [ ] **Step 1: Write the failing test**

Write `site_scan/tests/test_hash_command.py`:
```python
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
```

Run:
```bash
pytest site_scan/tests/test_hash_command.py -v
```
Expected: failure — `hash` subcommand not implemented.

- [ ] **Step 2: Implement `cmd_hash` and wire `main`**

Add to `site_scan/tlsh_site_scan.py`:
```python
import argparse
import multiprocessing
import tempfile


_HASH_TSV_HEADER = "site_path\tdigest\tsize\tmtime\n"


def cmd_hash(args: argparse.Namespace) -> int:
    ext_set = {e.strip().lower().lstrip(".") for e in args.ext.split(",") if e.strip()}
    exclude_dirs = set(args.exclude_dir) if args.exclude_dir else set(DEFAULT_EXCLUDE_DIRS)

    paths = list(walk_site(
        root=args.site,
        ext_set=ext_set if ext_set else DEFAULT_EXTENSIONS,
        exclude_dirs=exclude_dirs,
        follow_symlinks=args.follow_symlinks,
        include_hidden=args.include_hidden,
        min_size=args.min_size,
        max_size=args.max_size,
    ))

    out_path = Path(args.out)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=out_path.name + ".", dir=str(out_path.parent))
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)

    counts = {"hashed": 0, "skipped_entropy": 0, "errors": 0}
    workers = max(1, args.workers)

    try:
        with open(tmp_path, "w", encoding="utf-8") as out:
            out.write(_HASH_TSV_HEADER)
            iterator: Iterable
            if workers == 1:
                iterator = (hash_one_file(str(p)) for p in paths)
            else:
                pool = multiprocessing.Pool(workers)
                iterator = pool.imap_unordered(hash_one_file, [str(p) for p in paths], chunksize=32)

            for path, digest, size, mtime, skip in iterator:
                if skip == "io_error":
                    counts["errors"] += 1
                    continue
                if skip == "low_entropy" or digest is None:
                    counts["skipped_entropy"] += 1
                    continue
                out.write(f"{path}\t{digest}\t{size}\t{mtime}\n")
                counts["hashed"] += 1
                if counts["hashed"] % 500 == 0:
                    print(
                        f"hashed {counts['hashed']} skipped {counts['skipped_entropy']} errors {counts['errors']}",
                        file=sys.stderr,
                    )

            if workers != 1:
                pool.close()
                pool.join()

        os.replace(tmp_path, out_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    print(
        f"done: hashed={counts['hashed']} skipped_entropy={counts['skipped_entropy']} errors={counts['errors']}",
        file=sys.stderr,
    )
    return 0


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tlsh_site_scan", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hash", help="walk a site, hash files, write digest TSV")
    h.add_argument("--site", required=True)
    h.add_argument("--out", required=True)
    h.add_argument("--ext", default=",".join(sorted(DEFAULT_EXTENSIONS)))
    h.add_argument("--exclude-dir", action="append", default=None,
                   help="repeat to exclude multiple dir basenames; replaces defaults if provided")
    h.add_argument("--min-size", type=int, default=50)
    h.add_argument("--max-size", type=int, default=5_242_880)
    h.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    h.add_argument("--follow-symlinks", action="store_true")
    h.add_argument("--include-hidden", action="store_true")
    h.set_defaults(func=cmd_hash)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    return args.func(args)
```

- [ ] **Step 3: Run tests**

```bash
pytest site_scan/tests/test_hash_command.py -v
```
Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_hash_command.py
git commit -m "site_scan: hash subcommand (walk + hash + atomic TSV)

multiprocessing.Pool for parallel hashing (--workers 1 forces serial).
Atomic write via tempfile + os.replace. Header line on output."
```

---

## Task 9: Per-digest scan logic (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Modify: `site_scan/tests/test_index.py`

- [ ] **Step 1: Write the failing tests**

Append to `site_scan/tests/test_index.py`:
```python
from site_scan.tlsh_site_scan import scan_one_digest


def test_scan_one_digest_finds_self_match():
    """A site digest identical to a threat digest should match at distance 0."""
    threats = _make_threats()
    index = build_lvalue_index(threats)
    # Use the first threat's digest as the site digest.
    site_digest = threats[0][1]
    matches = scan_one_digest(site_digest, threats, index, threshold=40, top_n=3, band=3)
    assert matches, "expected at least one match"
    # Closest match must be the self-match.
    assert matches[0][0] == 0


def test_scan_one_digest_top_n_limit():
    threats = _make_threats()
    index = build_lvalue_index(threats)
    site_digest = threats[0][1]
    # Set huge threshold to admit everything.
    matches = scan_one_digest(site_digest, threats, index, threshold=10_000, top_n=2, band=128)
    assert len(matches) <= 2


def test_scan_one_digest_no_match_returns_empty():
    threats = _make_threats()
    index = build_lvalue_index(threats)
    site_digest = threats[0][1]
    # Threshold of -1 admits nothing (band=0, but also distance >= 0 > -1).
    matches = scan_one_digest(site_digest, threats, index, threshold=-1, top_n=3, band=0)
    assert matches == []
```

Run:
```bash
pytest site_scan/tests/test_index.py -v
```
Expected: ImportError on `scan_one_digest`.

- [ ] **Step 2: Implement**

Add to `site_scan/tlsh_site_scan.py`:
```python
def scan_one_digest(
    site_digest: str,
    threats: list[tuple["tlsh.Tlsh", str, str]],
    index: dict[int, list[int]],
    *,
    threshold: int,
    top_n: int,
    band: int,
) -> list[tuple[int, str, str]]:
    """For one site digest, return top-N matches: list of (distance, threat_digest, threat_path).

    Sorted by (distance, threat_path); empty list if no candidates pass threshold.
    """
    s = tlsh.Tlsh()
    if s.fromTlshStr(site_digest) != 0:
        return []
    scored: list[tuple[int, str, str]] = []
    for ti in candidate_indices(s.lvalue, band, index):
        t_obj, t_digest, t_path = threats[ti]
        d = s.diff(t_obj)
        if d <= threshold:
            scored.append((d, t_digest, t_path))
    scored.sort(key=lambda r: (r[0], r[2]))
    return scored[:top_n]
```

- [ ] **Step 3: Run tests**

```bash
pytest site_scan/tests/test_index.py -v
```
Expected: 8 passed (5 + 3 new).

- [ ] **Step 4: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_index.py
git commit -m "site_scan: scan_one_digest top-N match logic

Walks the Lvalue band, computes diffs only on candidates, returns top-N
by (distance, threat_path) with threshold cutoff."
```

---

## Task 10: `scan` subcommand (TDD)

**Files:**
- Modify: `site_scan/tlsh_site_scan.py`
- Create: `site_scan/tests/test_scan_command.py`

- [ ] **Step 1: Write the failing test**

Write `site_scan/tests/test_scan_command.py`:
```python
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
    assert t.is_valid()
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
```

Run:
```bash
pytest site_scan/tests/test_scan_command.py -v
```
Expected: failure — `scan` subcommand not wired.

- [ ] **Step 2: Implement `cmd_scan` and extend the parser**

Add to `site_scan/tlsh_site_scan.py`:
```python
_SCAN_TSV_HEADER = "site_path\trank\tdistance\tthreat_digest\tthreat_path\n"


def cmd_scan(args: argparse.Namespace) -> int:
    if args.threshold < 0:
        print("error: --threshold must be >= 0", file=sys.stderr)
        return 2
    if args.top_n <= 0:
        print("error: --top-n must be >= 1", file=sys.stderr)
        return 2
    if args.threshold > 1000:
        print(
            f"warn: --threshold={args.threshold} is very loose; "
            "TLSH distances above ~800 are essentially 'unrelated'",
            file=sys.stderr,
        )

    threats, stats = parse_threats_file(args.threats)
    print(
        f"loaded {stats['accepted']} threat digests "
        f"({stats['invalid'] + stats['malformed']} skipped: "
        f"{stats['invalid']} invalid, {stats['malformed']} malformed)",
        file=sys.stderr,
    )
    if not threats:
        print("error: no valid threat digests loaded", file=sys.stderr)
        return 2

    index = build_lvalue_index(threats)
    band = lvalue_band(args.threshold)

    out_path = Path(args.out)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=out_path.name + ".", dir=str(out_path.parent))
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)

    rows_buf: list[tuple[str, int, int, str, str]] = []
    counts = {"scanned": 0, "with_match": 0, "total_matches": 0, "candidates_sum": 0}

    try:
        for site_path, site_digest in parse_site_digests_file(args.site_digests):
            counts["scanned"] += 1
            # We could pass band into scan_one_digest, but to compute
            # candidate count we expand inline:
            s = tlsh.Tlsh()
            if s.fromTlshStr(site_digest) != 0:
                continue
            cands = list(candidate_indices(s.lvalue, band, index))
            counts["candidates_sum"] += len(cands)
            scored = []
            for ti in cands:
                t_obj, t_digest, t_path = threats[ti]
                d = s.diff(t_obj)
                if d <= args.threshold:
                    scored.append((d, t_digest, t_path))
            if not scored:
                continue
            scored.sort(key=lambda r: (r[0], r[2]))
            counts["with_match"] += 1
            for rank, (d, t_digest, t_path) in enumerate(scored[: args.top_n], start=1):
                rows_buf.append((site_path, rank, d, t_digest, t_path))
                counts["total_matches"] += 1

            if counts["scanned"] % 2000 == 0:
                print(
                    f"scanned {counts['scanned']} matches {counts['with_match']}",
                    file=sys.stderr,
                )

        rows_buf.sort(key=lambda r: (r[0], r[1]))
        with open(tmp_path, "w", encoding="utf-8") as out:
            out.write(_SCAN_TSV_HEADER)
            for r in rows_buf:
                out.write(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}\n")
        os.replace(tmp_path, out_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    avg_cands = counts["candidates_sum"] / counts["scanned"] if counts["scanned"] else 0
    print(
        f"done: scanned={counts['scanned']} with_match={counts['with_match']} "
        f"total_matches={counts['total_matches']} avg_candidates={avg_cands:.1f}",
        file=sys.stderr,
    )
    return 0
```

Then extend `_build_arg_parser`:
```python
def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tlsh_site_scan", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hash", help="walk a site, hash files, write digest TSV")
    h.add_argument("--site", required=True)
    h.add_argument("--out", required=True)
    h.add_argument("--ext", default=",".join(sorted(DEFAULT_EXTENSIONS)))
    h.add_argument("--exclude-dir", action="append", default=None,
                   help="repeat to exclude multiple dir basenames; replaces defaults if provided")
    h.add_argument("--min-size", type=int, default=50)
    h.add_argument("--max-size", type=int, default=5_242_880)
    h.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    h.add_argument("--follow-symlinks", action="store_true")
    h.add_argument("--include-hidden", action="store_true")
    h.set_defaults(func=cmd_hash)

    s = sub.add_parser("scan", help="match site digests against a threat list")
    s.add_argument("--threats", required=True)
    s.add_argument("--site-digests", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--threshold", type=int, default=40)
    s.add_argument("--top-n", type=int, default=3)
    s.set_defaults(func=cmd_scan)

    return p
```

- [ ] **Step 3: Run tests**

```bash
pytest site_scan/tests/test_scan_command.py -v
```
Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add site_scan/tlsh_site_scan.py site_scan/tests/test_scan_command.py
git commit -m "site_scan: scan subcommand (load + index + match + atomic TSV)

Loads threats, builds Lvalue index, streams site digests through the
prefilter, writes deterministic top-N matches TSV. Exits 2 on empty
threat list or bad args."
```

---

## Task 11: Brute-force equivalence test (the load-bearing safety net)

**Files:**
- Create: `site_scan/tests/test_invariant.py`

This test does NOT modify production code — it's pure verification. If it ever fails, the prefilter math has a bug.

- [ ] **Step 1: Write the test**

Write `site_scan/tests/test_invariant.py`:
```python
"""Critical correctness test: prefilter scanner must produce IDENTICAL match
sets to a brute-force scanner (no prefilter, full N x M). If this ever fails,
the Lvalue band math is wrong and we are silently dropping true matches."""
from __future__ import annotations

import pytest
import tlsh

from site_scan.tlsh_site_scan import (
    build_lvalue_index,
    lvalue_band,
    scan_one_digest,
)
from site_scan.tests.fixtures_data import FILES


def _make_threats():
    threats = []
    # Use every fixture (>=50 bytes) plus simple variants to broaden Lvalue distribution.
    for name, body in FILES.items():
        if len(body) < 50:
            continue
        for i in range(5):
            data = body + b"\n#variant=" + str(i).encode() + b"\n" + b"x" * (i * 30)
            t = tlsh.Tlsh(); t.update(data); t.final()
            if not t.is_valid():
                continue
            threats.append((t, t.hexdigest(), f"/threats/{name}_{i}"))
    assert len(threats) >= 20
    return threats


def _make_site_digests(threats):
    """Make a varied site list: some near-duplicates, some unrelated."""
    digests = [t[1] for t in threats[: len(threats) // 2]]
    # plus unrelated content
    extra = b"unrelated content " * 50
    t = tlsh.Tlsh(); t.update(extra); t.final()
    assert t.is_valid()
    digests.append(t.hexdigest())
    return digests


def _bruteforce(threats, site_digest, *, threshold, top_n):
    s = tlsh.Tlsh()
    if s.fromTlshStr(site_digest) != 0:
        return []
    scored = []
    for t_obj, t_digest, t_path in threats:
        d = s.diff(t_obj)
        if d <= threshold:
            scored.append((d, t_digest, t_path))
    scored.sort(key=lambda r: (r[0], r[2]))
    return scored[:top_n]


@pytest.mark.parametrize("threshold", [40, 70])
def test_prefilter_matches_bruteforce(threshold):
    threats = _make_threats()
    index = build_lvalue_index(threats)
    band = lvalue_band(threshold)
    site_digests = _make_site_digests(threats)

    for site_digest in site_digests:
        prefilter = scan_one_digest(
            site_digest, threats, index,
            threshold=threshold, top_n=3, band=band,
        )
        brute = _bruteforce(threats, site_digest, threshold=threshold, top_n=3)
        assert prefilter == brute, (
            f"divergence at threshold={threshold}, site_digest={site_digest!r}\n"
            f"prefilter: {prefilter}\nbruteforce: {brute}"
        )
```

- [ ] **Step 2: Run the test**

```bash
pytest site_scan/tests/test_invariant.py -v
```
Expected: 2 passed (T=40 and T=70). **If this fails, do not proceed — the prefilter math is wrong.** Investigate `lvalue_band` and `candidate_indices` before continuing.

- [ ] **Step 3: Commit**

```bash
git add site_scan/tests/test_invariant.py
git commit -m "site_scan: prefilter ≡ brute-force equivalence test

Generates a varied corpus of threats and site digests, asserts the
prefilter scanner produces identical top-N match sets as a brute-force
scanner at thresholds 40 and 70. This is the critical safety net for
the Lvalue band math."
```

---

## Task 12: Edge-case integration tests

**Files:**
- Modify: `site_scan/tests/test_hash_command.py`
- Modify: `site_scan/tests/test_scan_command.py`

- [ ] **Step 1: Add edge-case tests**

Append to `site_scan/tests/test_hash_command.py`:
```python
def test_hash_command_all_files_too_small_yields_empty_tsv(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    (site / "tiny.php").write_bytes(b"<?php\n")  # < 50 bytes
    out = tmp_path / "site_digests.tsv"
    res = _run_hash(site, out)
    assert res.returncode == 0
    assert out.read_text() == "site_path\tdigest\tsize\tmtime\n"


def test_hash_command_help_works():
    res = subprocess.run(
        [sys.executable, "-m", "site_scan.tlsh_site_scan", "hash", "--help"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert res.returncode == 0
    assert "--site" in res.stdout
    assert "--out" in res.stdout
```

Append to `site_scan/tests/test_scan_command.py`:
```python
def test_scan_command_help_works():
    res = subprocess.run(
        [sys.executable, "-m", "site_scan.tlsh_site_scan", "scan", "--help"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert res.returncode == 0
    assert "--threats" in res.stdout
    assert "--site-digests" in res.stdout


def test_scan_rejects_negative_threshold(tmp_path):
    threats = tmp_path / "t.tsv"; threats.write_text("")
    sites = tmp_path / "s.tsv"; sites.write_text("")
    out = tmp_path / "m.tsv"
    res = _run_scan(threats, sites, out, "--threshold", "-1")
    assert res.returncode == 2


def test_scan_rejects_zero_top_n(tmp_path):
    threats = tmp_path / "t.tsv"; threats.write_text("")
    sites = tmp_path / "s.tsv"; sites.write_text("")
    out = tmp_path / "m.tsv"
    res = _run_scan(threats, sites, out, "--top-n", "0")
    assert res.returncode == 2


def test_scan_top_n_3_with_three_close_threats(tmp_path):
    """When N>=3 threats are within T, all three should appear with rank 1, 2, 3."""
    base = FILES["alpha.php"]
    digests = []
    for i in range(5):
        data = base + b"\n#var=" + str(i).encode()
        t = tlsh.Tlsh(); t.update(data); t.final()
        digests.append(t.hexdigest())
    threats = tmp_path / "threats.tsv"
    threats.write_text("".join(f"{d}\t/threats/v{i}.php\n" for i, d in enumerate(digests)))
    sites = tmp_path / "sites.tsv"
    sites.write_text(
        "site_path\tdigest\tsize\tmtime\n"
        f"/site/q\t{digests[0]}\t{len(base)}\t1700000000.0\n"
    )
    out = tmp_path / "matches.tsv"
    res = _run_scan(threats, sites, out, "--threshold", "200", "--top-n", "3")
    assert res.returncode == 0
    rows = out.read_text().splitlines()[1:]
    assert len(rows) == 3
    ranks = [int(r.split("\t")[1]) for r in rows]
    assert ranks == [1, 2, 3]
```

- [ ] **Step 2: Run tests**

```bash
pytest site_scan/tests/test_hash_command.py site_scan/tests/test_scan_command.py -v
```
Expected: all green (the previously written tests still pass + the new ones).

- [ ] **Step 3: Commit**

```bash
git add site_scan/tests/test_hash_command.py site_scan/tests/test_scan_command.py
git commit -m "site_scan: edge-case integration tests

--help on both subcommands, all-too-small site, negative threshold,
zero top-n, and a top-3 deterministic ordering test."
```

---

## Task 13: Smoke test against `Testing/example_data/`

**Files:**
- Create: `site_scan/tests/test_smoke.py`

- [ ] **Step 1: Write the smoke test**

Write `site_scan/tests/test_smoke.py`:
```python
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
```

- [ ] **Step 2: Run the test**

```bash
pytest site_scan/tests/test_smoke.py -v
```
Expected: 1 passed (or skipped if example_data is absent).

- [ ] **Step 3: Commit**

```bash
git add site_scan/tests/test_smoke.py
git commit -m "site_scan: end-to-end smoke test on Testing/example_data/

Runs hash then scan against real in-repo example data, using the first
hashed digest as a seed threat to guarantee at least one self-match."
```

---

## Task 14: README + final whole-suite run

**Files:**
- Create: `site_scan/README.md`

- [ ] **Step 1: Write the README**

Write `site_scan/README.md`:
````markdown
# `site_scan` — TLSH site scanner

Recursively scan a website for files similar to a pre-generated TLSH threat
list. A one-byte Lvalue prefilter cuts the comparison count by ~95% at the
default threshold, turning a multi-day brute-force scan into a multi-minute
job.

## Prerequisites

Build and install the in-repo CPython extension first:

```sh
cd /Users/fioa8c/WORK/tlsh_with_waffles
./make.sh
cd py_ext && python setup.py build && python setup.py install --user
```

## Two-stage usage

### 1. Hash a site

```sh
python -m site_scan.tlsh_site_scan hash \
    --site /path/to/site \
    --out  site_digests.tsv
```

Default extensions: `php, php3, php4, php5, php7, php8, phtml, htm, html, js`.
Default exclude-dirs (basename match at any depth): `.git, .svn, node_modules,
composer, wp-includes`. Default size band: 50 bytes to 5 MiB.

Pass `--ext <comma,list>` to replace the extension set. Pass `--exclude-dir
<name>` (repeatable) to replace the exclude set.

### 2. Scan against a threat list

```sh
python -m site_scan.tlsh_site_scan scan \
    --threats       jetpack_threats.tlsh \
    --site-digests  site_digests.tsv \
    --out           matches.tsv \
    --threshold     40 \
    --top-n         3
```

The threat list is the existing `<digest>\t<threat_path>` per-line format.
Output is TSV with columns `site_path, rank, distance, threat_digest,
threat_path`, sorted by `(site_path, rank)`. Files with no matches under the
threshold produce no rows.

## Tests

```sh
pytest site_scan/tests -v
```

The `test_invariant.py` test is the load-bearing safety net: it asserts the
prefilter scanner produces match sets identical to a brute-force scanner. If
that ever regresses, do not ship the change.

## Design

See [docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md](../docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md).
````

- [ ] **Step 2: Run the entire test suite**

```bash
cd /Users/fioa8c/WORK/tlsh_with_waffles
pytest site_scan/tests -v
```

Expected: every test passes. Approximate count: 40+ tests across 8 files. If anything fails, fix it before committing the README.

- [ ] **Step 3: Commit**

```bash
git add site_scan/README.md
git commit -m "site_scan: README with prerequisites, usage, tests, design link"
```

---

## Verification checklist (run before declaring done)

```bash
cd /Users/fioa8c/WORK/tlsh_with_waffles

# 1. All tests green
pytest site_scan/tests -v

# 2. Module is invocable
python -m site_scan.tlsh_site_scan --help
python -m site_scan.tlsh_site_scan hash --help
python -m site_scan.tlsh_site_scan scan --help

# 3. Live run on Testing/example_data/ produces sensible output
python -m site_scan.tlsh_site_scan hash \
    --site Testing/example_data \
    --out /tmp/site_digests.tsv \
    --ext txt,php,html,htm,js \
    --workers 1
head -3 /tmp/site_digests.tsv

# 4. Self-scan: each file should match itself at distance 0.
head -1 /tmp/site_digests.tsv  # discard header
awk 'NR>1 {print $2 "\t" $1}' /tmp/site_digests.tsv > /tmp/threats.tsv
python -m site_scan.tlsh_site_scan scan \
    --threats /tmp/threats.tsv \
    --site-digests /tmp/site_digests.tsv \
    --out /tmp/matches.tsv \
    --threshold 0
# Every line in matches.tsv should have distance 0 in column 3.
awk 'NR>1 && $3 != "0" { exit 1 }' /tmp/matches.tsv && echo "self-scan OK"
```

If all four checks pass, the implementation is complete and matches the spec.
