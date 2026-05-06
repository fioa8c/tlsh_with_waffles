# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

TLSH (Trend Micro Locality Sensitive Hash) is a C++ fuzzy-matching library that produces a similarity digest from a byte stream (≥50 bytes by default). The static library plus a CLI binary are the primary build artifacts; Python/Java/JavaScript ports live in subdirectories.

## Build & test commands

The standard Linux build is driven by `./make.sh` at the repo root, which configures CMake under `build/release` (or `build/debug`), runs `make`, then runs the regression test suite. Variants:

- `./make.sh debug` — debug build under `build/debug`.
- `./make.sh -shared` — also build a shared library (default is static-only; see `src/CMakeLists.txt`).
- `./make.sh -nochecksum` / `-zerochecksum` — pass `-DTLSH_CHECKSUM_0B=1` / `-DTLSH_CHECKSUM_NO_EVALUATION=1`.
- `./make.sh -verbose` — `make VERBOSE=1`.
- `./make.sh -notest` — skip the post-build test stage.
- `./make.sh -c` — also build the C standalone version under `src_c_standalone/` (only if that directory exists).
- `./clean.sh` — remove `bin/`, `build/`, `lib/`, `Testing/tmp/`, generated `VERSION`, and generated `include/tlsh_version.h`.

After build, the CLI is `bin/tlsh` (a symlink to `bin/tlsh_unittest`). The static library is `lib/libtlsh.a`.

### Tests

`make.sh` (without `-notest`) runs three layers in order:

1. `make test` (CTest) from the build directory.
2. `Testing/test.sh` — golden-output regression tests using files under `Testing/example_data/`. Diffs CLI output against `Testing/exp/*_EXP`.
3. `Testing/test_pattern.sh` and `Testing/test_parts.sh` — additional regression tests for `tlsh_pattern` and `tlsh_parts` binaries.

To run a single layer manually after building:

```sh
cd build/release && make test            # CTest
cd Testing && ./test.sh                  # primary regression
cd Testing && ./test_pattern.sh          # tlsh_pattern
cd Testing && ./test_parts.sh            # tlsh_parts
cd Testing && ./python_test.sh           # Python ext tests (requires py_ext built)
```

Expected-result filenames in `Testing/exp/` are keyed by build options: `example_data.<HASH>.<CHKSUM>.<XLEN>.<...>_EXP`, e.g. `example_data.128.1.len.out_EXP` = 128 buckets, 1-byte checksum, length included. Changing compile-time options changes which `_EXP` files apply — `test.sh` derives `HASH`/`CHKSUM`/`SLDWIN` from `tlsh -longversion` to pick the right ones.

To regenerate golden files (e.g., after an intentional output change), set `CREATE_EXP_FILE=1` at the top of `Testing/test.sh` and re-run; missing `_EXP` files will be created from the new output. Commit the new `_EXP` files.

### Python extension

`py_ext/setup.py` reads `CMakeLists.txt` to inherit the bucket/checksum compile flags, so build the C++ first, then:

```sh
cd py_ext && python setup.py build && python setup.py install
cd ../Testing && ./python_test.sh
```

## Compile-time configuration (CMakeLists.txt)

These flags (set in `CMakeLists.txt` or via `cmake -D...`) change the digest format and the test golden files that apply:

- `TLSH_BUCKETS_128` (default) / `TLSH_BUCKETS_256` / `TLSH_BUCKETS_48` — digest size. 128 buckets is the standard "T1" digest.
- `TLSH_CHECKSUM_1B` (default) / `TLSH_CHECKSUM_3B` / `TLSH_CHECKSUM_0B` — checksum length.
- `TLSH_DISTANCE_PARAMETERS=1` — exposes `set_tlsh_distance_parameters(...)` for experimenting with the distance scoring weights at runtime.
- `TLSH_SHARED_LIBRARY=1` — additionally build `tlsh_shared`.

A "T1" prefixed digest requires `BUCKETS_128` + `CHECKSUM_1B` (the 5.0.0 default). Other combinations produce a different string length (see the macros in `include/tlsh.h` and `include/tlsh_impl.h`) and are not "T1".

`CMakeLists.txt` writes the version macros into `include/tlsh_version.h` and a `VERSION` file at configure time — **don't hand-edit those**, change `VERSION_MAJOR`/`MINOR`/`PATCH` in `CMakeLists.txt` instead.

## Code layout

The C++ library splits the public API from the implementation:

- `include/tlsh.h` — public `Tlsh` class (pimpl over `TlshImpl`). Key methods: `update()`, `final()`, `getHash()`, `fromTlshStr()`, `totalDiff()`. The `getHash(showvers=1)` default is what produces the "T1" prefix; old-style 70-char output uses `showvers=0`.
- `src/tlsh.cpp` — thin wrapper forwarding to `TlshImpl`.
- `src/tlsh_impl.cpp` + `include/tlsh_impl.h` — the hashing engine: 5-byte sliding window, six trigrams per window, Pearson hash distributing trigram counts into counting buckets, quartile encoding into the packed `lsh_bin_struct` digest. This is where the algorithm lives.
- `src/tlsh_util.cpp` + `include/tlsh_util.h` — Pearson table, quartile helpers, hex encode/decode of digests, and the `mod_diff` distance helpers.
- `src/input_desc.cpp` / `src/shared_file_functions.cpp` — directory traversal and file IO used by the CLI; not part of the library API.
- `src/gen_arr2.cpp` — standalone utility that regenerates the random Pearson permutation; not linked into the main lib.

Test/CLI binaries (built into `bin/` from `test/`):

- `tlsh_unittest` — the production CLI (symlinked as `tlsh`); supports `-r`, `-l`, `-c`, `-xref`, `-T`, `-old`, `-conservative`, `-force`, `-split`, `-ojson`, `-longversion`, etc. Run with no args for full usage.
- `simple_unittest` — minimal API smoke test.
- `tlsh_pattern`, `tlsh_parts`, `timing_unittest`, `order_bug` — focused regression / experiment binaries used by the test scripts.
- `utils/rand_tags.cpp` → `bin/rand_tags` — random labelling utility used in cross-validation tests.

## Ports and tooling

- `py_ext/` — CPython C extension (`tlshmodule.cpp`); the published PyPI package lives in `py_ext/pypi_package`.
- `java/` — Gradle project (independent build).
- `js_ext/` — pure-JS implementation (`tlsh.js`).
- `tlshCluster/` — Python clustering code and notebooks (HAC-T, DBSCAN, dendrograms).
- `tlsh_bh_tool/` — Python tool over the C++ binary for batch hashing/clustering.
- `Windows/` — Visual Studio solution files. `mingw/` — MinGW Makefile build (copies source files at build time; see `clean.sh` for the file list).
- `register/` — registration/config tooling.

## Conventions worth knowing

- `bin/tlsh` is a symlink to `bin/tlsh_unittest`; the unit test binary doubles as the shipped CLI.
- Regression tests are golden-output diffs, not assertion-based. Output drift in `tlsh_unittest` (formatting, ordering, error messages) breaks the suite even when behavior is correct — update the relevant `Testing/exp/*_EXP` files via the `CREATE_EXP_FILE=1` workflow above and commit them in the same change.
- The `-xlen` CLI flag and `len_diff=false` argument to `Tlsh::totalDiff` exclude the file-length component from distance scoring; many tests run twice, once with and once without (`runit` / `runit -xlen` in `test.sh`).
- Python `data` arguments must be `bytes`, not `str` — TLSH operates on raw binary.
