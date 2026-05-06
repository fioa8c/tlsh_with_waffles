"""TLSH site scanner: recursive directory scan against a pre-generated TLSH threat list.

Two subcommands:
  hash  walks a site, hashes filtered files, writes a digest TSV.
  scan  reads a digest TSV + a threat list, writes a top-N matches TSV.

See docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md for design.
"""
from __future__ import annotations

import argparse
import multiprocessing
import os
import sys
import tempfile
from collections import defaultdict
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


def build_lvalue_index(
    threats: "list[tuple[tlsh.Tlsh, str, str]]",
) -> "dict[int, list[int]]":
    """Map each Lvalue byte (0-255) to the list of threat indices with that Lvalue."""
    index: "dict[int, list[int]]" = defaultdict(list)
    for i, (t, _digest, _path) in enumerate(threats):
        index[t.lvalue].append(i)
    return dict(index)


def candidate_indices(
    lvalue: int, band: int, index: "dict[int, list[int]]"
) -> "Iterator[int]":
    """Yield threat indices in Lvalue buckets [lvalue-band ... lvalue+band] (mod 256)."""
    for delta in range(-band, band + 1):
        bucket = (lvalue + delta) % 256
        for idx in index.get(bucket, ()):
            yield idx


DEFAULT_EXTENSIONS: "frozenset[str]" = frozenset({
    "php", "php3", "php4", "php5", "php7", "php8", "phtml",
    "htm", "html", "js",
})

DEFAULT_EXCLUDE_DIRS: "frozenset[str]" = frozenset({
    ".git", ".svn", "node_modules", "composer", "wp-includes",
})


def walk_site(
    root: "Path | str",
    *,
    ext_set: "Iterable[str]",
    exclude_dirs: "Iterable[str]",
    follow_symlinks: bool,
    include_hidden: bool,
    min_size: int,
    max_size: int,
) -> "Iterator[Path]":
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


def hash_one_file(
    path: str,
) -> "tuple[str, str | None, int | None, float | None, str | None]":
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
    if not t.is_valid:                  # property — no parens
        return (path, None, st.st_size, st.st_mtime, "low_entropy")
    return (path, t.hexdigest(), st.st_size, st.st_mtime, None)


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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
