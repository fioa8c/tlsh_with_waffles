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
