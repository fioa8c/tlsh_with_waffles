"""TLSH site scanner: recursive directory scan against a pre-generated TLSH threat list.

Two subcommands:
  hash  walks a site, hashes filtered files, writes a digest TSV.
  scan  reads a digest TSV + a threat list, writes a top-N matches TSV.

See docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md for design.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Iterator

import tlsh


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


def parse_threats_file(path: "Path | str") -> "tuple[list[tuple[tlsh.Tlsh, str, str]], dict[str, int]]":
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


def parse_site_digests_file(path: "Path | str") -> "Iterator[tuple[str, str]]":
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


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("argparse + subcommands not yet wired")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
