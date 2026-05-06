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
