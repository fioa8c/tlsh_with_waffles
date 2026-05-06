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
cd py_ext && python3 setup.py build && python3 setup.py install --user
```

## Two-stage usage

### 1. Hash a site

```sh
python3 -m site_scan.tlsh_site_scan hash \
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
python3 -m site_scan.tlsh_site_scan scan \
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
python3 -m pytest site_scan/tests -v
```

The `test_invariant.py` test is the load-bearing safety net: it asserts the
prefilter scanner produces match sets identical to a brute-force scanner. If
that ever regresses, do not ship the change.

## Design

See [docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md](../docs/superpowers/specs/2026-05-06-tlsh-site-scanner-design.md).
