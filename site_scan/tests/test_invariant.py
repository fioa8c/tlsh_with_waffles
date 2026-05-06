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
            if not t.is_valid:                 # property — no parens
                continue
            threats.append((t, t.hexdigest(), f"/threats/{name}_{i}"))
    assert len(threats) >= 20
    return threats


def _make_site_digests(threats):
    """Make a varied site list: some near-duplicates, some unrelated."""
    digests = [t[1] for t in threats[: len(threats) // 2]]
    # plus unrelated content (must have sufficient entropy for TLSH)
    extra = b"".join(f"unrelated content line {i:04d}\n".encode() for i in range(50))
    t = tlsh.Tlsh(); t.update(extra); t.final()
    assert t.is_valid                         # property — no parens
    digests.append(t.hexdigest())
    return digests


def _bruteforce(threats, site_digest, *, threshold, top_n):
    s = tlsh.Tlsh()
    try:
        s.fromTlshStr(site_digest)
    except (ValueError, TypeError):
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
