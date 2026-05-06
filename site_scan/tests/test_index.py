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
        if not t.is_valid:                # property, no parens
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
