# TLSH Site Scanner — Design

- **Date:** 2026-05-06
- **Status:** Approved (pending implementation)
- **Owner:** fioravante.cavallari.souza@a8c.com
- **Repo location to be added:** `site_scan/` (new directory at repo root)

## 1. Context

The user has a pre-generated TLSH digest list of known-bad samples (e.g. `jetpack_threats.tlsh`, ~10k–100k digests in the format `<digest>\t<threat_path>`). They want to scan a website tree (~300k files, mostly media; ~50k after extension filter) and find any `.php`/`.js`/`.html` files that are similar (TLSH distance ≤ T) to anything in the threat list.

The existing `bin/tlsh` CLI offers brute-force matching (`-l listfile -xref`, or `-c <digest> -r <dir>` per threat), which is O(N×M). At the user's sizes that's ~5×10⁹ comparisons — multi-day wall-clock. We need a smarter approach.

## 2. Goals

- **Recursive site scan**: walk a directory tree, filter to relevant text-source extensions, hash each file with TLSH, compare against a pre-generated threat list.
- **Performance**: complete a typical scan in minutes, not days, by exploiting the fact that TLSH's length term dominates the distance for non-similar files. A cheap one-byte prefilter (Lvalue band) drops ~97% of pairs at threshold 40 before any expensive distance compute.
- **Decoupled hashing and matching**: produce a reusable site digest list once; re-scan against new threat lists or new thresholds without re-hashing.
- **Researcher-friendly output**: TSV with the threat path so a researcher can pivot to the threat database.

## 3. Non-goals

- No `--xlen` (length-excluded matching) support — not needed by user.
- No incremental/cached hashing in v1 — the two-stage CLI already lets the user re-run `scan` cheaply; site re-hashing is a separate problem we'll defer.
- No clustering, dendrograms, or "all matches in the entire site" cross-comparison — this is unidirectional (site vs. fixed threat list).
- No build-system integration — pure Python tool, no CMake changes.
- Initial release is not committed/pushed by the assistant; user will fork the repo and copy these files in.

## 4. Architecture

A new top-level directory `site_scan/` with a single Python file `tlsh_site_scan.py` (~300 lines) and a `tests/` subdirectory.

### 4.1 Substrate

- Python ≥ 3.8.
- Depends on the in-repo CPython extension `tlsh` (built and installed from `py_ext/`). The extension exposes:
  - `tlsh.Tlsh()` — hash builder; `update(bytes)`, `final()`, `is_valid()`, `hexdigest()`.
  - `tlsh.Tlsh.fromTlshStr(str)` — parse a digest string.
  - `tlsh.Tlsh.lvalue` getter — the Lvalue byte (0–255) used by the prefilter.
  - `tlsh.Tlsh.diff(other)` — full distance compute (length-included).
- Standard library only otherwise: `argparse`, `os`, `multiprocessing`, `pathlib`, `csv` (or hand-rolled TSV), `sys`.

### 4.2 Why a new directory

- `tlsh_bh_tool/` is its own existing tool with its own conventions and config; conflating two tools harms both.
- Subagents and reviewers will find a focused, single-purpose directory easier to reason about than a wedged-in extension to an unrelated tool.

## 5. CLI surface

Single entry point with two subcommands:

```
python -m site_scan.tlsh_site_scan hash \
    --site         <dir>           \
    --out          <site_digests.tsv> \
    [--ext         php,php3,php4,php5,php7,php8,phtml,htm,html,js] \
    [--exclude-dir .git --exclude-dir .svn --exclude-dir node_modules \
     --exclude-dir composer --exclude-dir wp-includes]              \
    [--min-size    50]    \
    [--max-size    5242880]   \
    [--workers     <N>]   \
    [--follow-symlinks]   \
    [--include-hidden]

python -m site_scan.tlsh_site_scan scan \
    --threats       <threats.tsv>      \
    --site-digests  <site_digests.tsv> \
    --out           <matches.tsv>      \
    [--threshold    40] \
    [--top-n        3]
```

`--ext` is a single comma-separated argument. `--exclude-dir` is a repeatable flag — pass it once per directory basename to exclude. The defaults shown above are applied when the flag is omitted; passing `--ext` or `--exclude-dir` explicitly *replaces* the default rather than extending it (predictable behavior; user can re-include defaults if needed).

Both subcommands exit 0 on successful completion regardless of whether matches were found. Non-zero exits are reserved for errors (bad args, fatal parse failures, IO errors).

## 6. File formats

### 6.1 Threat list (input to `scan`)

Existing `jetpack_threats.tlsh` format. Each line is `<T1_digest>\t<threat_path>\n`. Lines starting with `#` are comments. Blank lines skipped. Malformed lines (wrong column count, invalid digest) are logged and skipped.

### 6.2 Site digests TSV (output of `hash`, input to `scan`)

```
site_path<TAB>digest<TAB>size<TAB>mtime
```

First line is a header (`site_path\tdigest\tsize\tmtime`), used by `scan` to detect and skip headers. `size` is bytes, `mtime` is the float `os.stat().st_mtime`. The extra columns exist now so a future `--cache` mode can do incremental rehashing keyed on `path|size|mtime` without breaking the format. `scan` ignores any columns beyond the first two — so externally-produced lists with just `<path>\t<digest>` also work.

### 6.3 Matches TSV (output of `scan`)

```
site_path<TAB>rank<TAB>distance<TAB>threat_digest<TAB>threat_path
```

First line is a header. One row per match. `rank` is 1, 2, or 3 (1 = closest). Sorted by `(site_path, rank)` so output is reproducible across runs. Files with no matches under threshold produce no rows.

## 7. Algorithm

### 7.1 `hash` subcommand

1. Walk `--site` with `os.walk(top, followlinks=False)` (flip via `--follow-symlinks`).
2. Skip directories whose basename is in `--exclude-dir` set (matched at any depth). Skip hidden dirs (basename starts with `.`) unless `--include-hidden`.
3. For each file, accept iff lowercased extension is in `--ext` set.
4. `os.stat(path)`. Skip if `size < --min-size` or `size > --max-size`.
5. Submit `(path, size, mtime)` to a `multiprocessing.Pool(workers)`. Each worker:
   - Reads the file fully (small, bounded by max-size).
   - `t = tlsh.Tlsh(); t.update(data); t.final()`.
   - If `t.is_valid()`: return `(path, t.hexdigest(), size, mtime, None)`.
   - Else: return `(path, None, size, mtime, "low_entropy")`.
6. Main process drains the iterator and writes `path\tdigest\tsize\tmtime\n` to `<out>.tmp`. On clean completion, `os.replace(<out>.tmp, <out>)` atomically.
7. Default `--workers = max(1, os.cpu_count() // 2)`. `--workers 1` runs serial for deterministic debugging.
8. Progress: stderr line every 500 files (`hashed K skipped J errors E`). Final summary at exit.

### 7.2 `scan` subcommand

1. **Load threat list**:
   - For each accepted line, build a `tlsh.Tlsh` object via `fromTlshStr`. Append to `threats: list[(Tlsh, digest, threat_path)]`.
   - Build `index: dict[int, list[int]]` mapping `tlsh_obj.lvalue` → indices into `threats`.
   - Stderr: `loaded N threat digests (M skipped: K invalid, L malformed)`.
   - If accepted count is 0: fatal, exit 2.
2. **Compute Lvalue band**:
   ```python
   def lvalue_band(threshold):
       if threshold <= 0:  return 0
       if threshold < 12:  return 1
       return threshold // 12
   ```
   At `T=40`: `band=3` → 7 of 256 buckets per query (~2.7%).
3. **Stream site digests**:
   - Detect and skip header (`site_path\t`-prefixed first line).
   - For each `(site_path, digest)`: parse digest into `s = tlsh.Tlsh(); s.fromTlshStr(digest)`.
   - Gather candidate threat indices from `(s.lvalue + delta) % 256` for `delta in range(-band, band+1)`.
   - For each candidate, compute `d = s.diff(t_obj)`. Keep `(d, t_digest, t_path)` iff `d <= threshold`.
   - Sort by `(d, t_path)`, take top-N, write rows with rank `1..N`.
4. Atomic output via `<out>.tmp` + `os.replace`.
5. Progress: stderr line every 2000 site digests. Final summary includes average candidates-per-query as a tuning aid.

### 7.3 Why the prefilter is correct

In `lsh_bin_totalDiff` ([src/tlsh_impl.cpp:1017](../../../src/tlsh_impl.cpp#L1017)) the length component is:
```
ldiff = mod_diff(L1, L2, 256)        # circular distance, range 0..128
if   ldiff == 0: contribution = 0
elif ldiff == 1: contribution = 1
else:            contribution = ldiff * length_mult     # length_mult = 12
```

Q-ratio, checksum, and body-h-distance terms are all ≥ 0. So if `ldiff_contribution > threshold`, the total distance is necessarily `> threshold` and the pair cannot match. The prefilter rejects exactly these pairs and no others. `lvalue_band(T)` returns the largest `ldiff` for which `ldiff_contribution <= T`, so any matching pair has `mod_diff(L_site, L_threat, 256) <= band` and is therefore in one of the `2*band + 1` candidate buckets. **No true matches are dropped by the prefilter** — verified directly by the equivalence test in §9.

## 8. Error handling & edge cases

### 8.1 `hash`-phase failures

| Failure | Behavior | Counted as |
|---|---|---|
| `PermissionError` reading file | Skip; stderr warn (rate-limited, first 10) | `errors` |
| File vanished mid-walk | Skip silently | `errors` |
| Symlink loop / unreadable target | Skip silently when `--follow-symlinks=False` | — |
| Size below `--min-size` | Skip silently | `skipped (size)` |
| Size above `--max-size` | Skip; stderr warn (rate-limited) | `skipped (size)` |
| `Tlsh` returns invalid | Skip silently | `skipped (entropy)` |
| Worker process crash | Surface error; abort with non-zero exit | fatal |

### 8.2 `scan`-phase parsing

| Failure | Behavior |
|---|---|
| Blank line or comment (`#`) | Skip silently |
| Wrong column count | Skip; stderr warn `<file>:<line>: malformed`; count |
| Invalid digest (`fromTlshStr` rejects) | Skip; stderr warn; count |
| Empty threat list after parse | Fatal, exit 2 |
| Empty site-digests file | Empty matches output; exit 0 |

### 8.3 Output integrity

- Both subcommands write to `<out>.tmp` and `os.replace` on success.
- `Ctrl-C` during run: clean partial-file removal, exit 130.

### 8.4 Argument validation

- `--threshold < 0` → reject at parse.
- `--threshold > 1000` → accept but stderr warn (TLSH distances above ~800 are essentially "unrelated").
- `--top-n <= 0` → reject.

### 8.5 Determinism

- `scan` output sorted by `(site_path, rank)`; ties on equal distance broken by `threat_path`.
- `hash` output is non-deterministic in row order (multiprocess); user can sort post-hoc if comparing across runs. Documented in `--help` and README.

### 8.6 Resource ceilings

- Threat list resident in memory: ~250 B/entry × 100k = ~25 MB. Index dict adds ~5 MB. Within budget.
- `hash` peak per-worker memory: ≤ `--max-size` (5 MiB). With 4 workers, ~20 MB.

## 9. Testing strategy

Tests live in `site_scan/tests/`, run via `pytest`. Self-contained — not wired into the C++ `Testing/test.sh` regression suite.

### 9.1 Unit tests

- `lvalue_band(threshold)`: table covering `0, 1, 11, 12, 24, 30, 40, 70, 1000`. Asserts `0, 1, 1, 1, 2, 2, 3, 5, 83`.
- Threat-list parser: fixtures with comments, blanks, valid/invalid digests, malformed lines. Asserts accepted/rejected counts.
- Site-digests parser: with header, without header, with extra columns, only 2 columns.
- Lvalue circular bucket gathering: at `(L=0, band=2)`, candidates = `{0,1,2,254,255}`; at `(L=255, band=2)`, candidates = `{253,254,255,0,1}`. Catches off-by-one in modular arithmetic.
- Top-N sort/tiebreak: equal-distance synthetic tuples sort by `(distance, threat_path)`.

### 9.2 Correctness invariant — most important test

- Generate ~50 site digests and ~200 threat digests (hashed at test time from small fixture files committed under `tests/fixtures/`).
- Run prefilter scanner. Run brute-force scanner (no prefilter, full N×M).
- Assert identical match sets at `T=40` and `T=70`.
- This directly validates the prefilter math: any divergence is a fatal regression.

### 9.3 Integration tests

- Construct a tiny site tree under `tmp_path` (pytest fixture): files that match a threat, files near a threat, unrelated files, an excluded `node_modules/`, a `.git/`, a too-small file, a too-large file.
- Run `hash` via `subprocess`; assert TSV contents (after sorting) match expected.
- Run `scan` against the produced digest list and a known threat list; assert exact match rows.
- Edge cases: empty site dir → empty TSV; empty threat list → exit 2; all site files too small → empty TSV.

### 9.4 Smoke test

- Run both subcommands against `Testing/example_data/`. No content assertions — just "does not crash on real data".

### 9.5 Performance smoke (opt-in)

- `pytest -m slow`: hash ~1000 small files, scan against ~1000 threats, assert completion under 30 seconds. Catches regressions from accidentally dropping the prefilter or introducing a quadratic loop.

### 9.6 Fixture files

- 5–10 small synthetic files (≥50 bytes) committed under `tests/fixtures/`. Plain text + a few PHP/JS/HTML stubs.
- Their digests are computed at test time, not pre-baked, so we don't have to regenerate goldens if TLSH internals or build flags change.

## 10. Out of scope / future work

- **Incremental hash cache** keyed on `path|size|mtime`, reading the existing site_digests TSV as input to `hash`. The current TSV layout already includes `size` and `mtime` to support this without a format change.
- **Q-byte secondary prefilter** if Lvalue alone proves too loose at sizes beyond what we test in v1.
- **VPT-tree index** ([tlshCluster/pylib/hac_lib.py:93](../../../tlshCluster/pylib/hac_lib.py#L93)) if threat-list size grows past ~1M.
- **`--xlen` support** — currently dropped because user does not need it.
- **JSON-Lines output** — TSV is the only output v1; JSON can be added later behind a flag.
- **Multi-site batch mode** — one invocation = one site for v1.

## 11. Open questions

None at design freeze. Any open behavior decisions are documented as defaults above with their override flags.
