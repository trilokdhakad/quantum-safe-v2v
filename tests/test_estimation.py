import numpy as np
import pytest

from qsv2v.qkd.estimation import (
    QBEREstimate,
    estimate_qber,
    finite_size_correction,
    should_abort,
)


def test_sample_size_and_mask(rng):
    a = rng.integers(0, 2, 1000)
    est = estimate_qber(a, a.copy(), rng, sample_fraction=0.2)
    assert est.n_sample == 200 and est.errors == 0
    assert est.keep_mask.sum() == 800
    assert not should_abort(est)


def test_min_sample(rng):
    a = np.zeros(100, dtype=np.uint8)
    assert estimate_qber(a, a, rng, sample_fraction=0.01, min_sample=50).n_sample == 50
    assert estimate_qber(a, a, rng, sample_fraction=0.01, min_sample=500).n_sample == 100


def test_counts_errors_only_in_sample(rng):
    a = np.zeros(10_000, dtype=np.uint8)
    b = a.copy()
    b[:1000] = 1  # 10% errors
    est = estimate_qber(a, b, rng, sample_fraction=0.5)
    assert abs(est.qber - 0.1) < 4 * est.std_error()
    lo, hi = est.wilson_interval()
    assert lo < 0.1 < hi


def test_abort_rule():
    keep = np.ones(1, dtype=bool)
    assert should_abort(QBEREstimate(100, 12, keep))
    assert not should_abort(QBEREstimate(100, 11, keep))
    assert should_abort(QBEREstimate(0, 0, keep))
    assert should_abort(QBEREstimate(100, 6, keep), threshold=0.05)


def test_validation(rng):
    with pytest.raises(ValueError):
        estimate_qber([0, 1], [0], rng)
    with pytest.raises(ValueError):
        estimate_qber([0], [0], rng, sample_fraction=1.5)


def test_finite_size_correction_shrinks():
    mu_small = finite_size_correction(10_000, 1_000)
    mu_big = finite_size_correction(1_000_000, 100_000)
    assert 0 < mu_big < mu_small < 1
    assert finite_size_correction(0, 10) == 1.0


def test_wilson_empty():
    assert QBEREstimate(0, 0, np.ones(1, bool)).wilson_interval() == (0.0, 1.0)
