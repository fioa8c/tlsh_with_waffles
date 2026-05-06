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
