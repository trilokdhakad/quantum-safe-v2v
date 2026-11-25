import math

import numpy as np
import pytest

from qsv2v.qkd.cascade import cascade, initial_block_size
from qsv2v.qkd.theory import binary_entropy


def _noisy_pair(n, q, rng):
    alice = rng.integers(0, 2, n, dtype=np.uint8)
    flips = (rng.random(n) < q).astype(np.uint8)
    return alice, alice ^ flips


def test_initial_block_size():
    assert initial_block_size(0.05) == 15
    assert initial_block_size(0.0) == 73  # floored at 1%
    assert initial_block_size(0.0, min_qber=0.001) == 730
    assert initial_block_size(0.9) == 1


def test_no_errors(rng):
    a = rng.integers(0, 2, 1000, dtype=np.uint8)
    res = cascade(a, a.copy(), 0.05, rng)
    np.testing.assert_array_equal(res.corrected, a)
    assert res.errors_corrected == 0
    # Only top-level parities are disclosed: one per block per pass.
    assert res.leaked_bits == sum(math.ceil(1000 / k) for k in res.block_sizes)


def test_block_sizes_double_and_cap(rng):
    a = rng.integers(0, 2, 100, dtype=np.uint8)
    assert cascade(a, a.copy(), 0.05, rng).block_sizes == [15, 30, 60, 100]
    assert cascade(a, a.copy(), 0.05, rng, passes=2, k1=8).block_sizes == [8, 16]


def test_single_error_cost(rng):
    a = np.zeros(64, dtype=np.uint8)
    b = a.copy()
    b[37] = 1
    res = cascade(a, b, 0.05, rng, passes=1, k1=64)
    np.testing.assert_array_equal(res.corrected, a)
    assert res.errors_corrected == 1
    assert res.leaked_bits == 1 + 6  # block parity + log2(64) halvings


@pytest.mark.parametrize("q", [0.01, 0.03, 0.05, 0.08, 0.1])
def test_corrects_all_errors(rng, q):
    for _ in range(5):
        a, b = _noisy_pair(20_000, q, rng)
        res = cascade(a, b, q, rng)
        np.testing.assert_array_equal(res.corrected, a)
        assert res.errors_corrected == int((a != b).sum())


@pytest.mark.parametrize("q", [0.02, 0.05, 0.08])
def test_efficiency_near_published_cascade(rng, q):
    """Original 4-pass Cascade leaks ~1.1-1.2x the Shannon limit n h(Q)."""
    fs = []
    for _ in range(10):
        a, b = _noisy_pair(20_000, q, rng)
        res = cascade(a, b, q, rng)
        fs.append(res.leaked_bits / (a.size * binary_entropy(float((a != b).mean()))))
    assert 1.05 < np.mean(fs) < 1.3


def test_one_pass_leaves_errors(rng):
    """A single pass misses blocks with even error counts: later passes matter."""
    a, b = _noisy_pair(20_000, 0.08, rng)
    res = cascade(a, b, 0.08, rng, passes=1)
    assert (res.corrected != a).sum() > 0


def test_reproducible():
    a, b = _noisy_pair(5000, 0.05, np.random.default_rng(0))
    r1 = cascade(a, b, 0.05, np.random.default_rng(9))
    r2 = cascade(a, b, 0.05, np.random.default_rng(9))
    assert r1.leaked_bits == r2.leaked_bits
    np.testing.assert_array_equal(r1.corrected, r2.corrected)


def test_does_not_mutate_inputs(rng):
    a, b = _noisy_pair(1000, 0.05, rng)
    b0 = b.copy()
    cascade(a, b, 0.05, rng)
    np.testing.assert_array_equal(b, b0)


def test_validation(rng):
    with pytest.raises(ValueError):
        cascade(np.zeros(3), np.zeros(4), 0.05, rng)
    with pytest.raises(ValueError):
        cascade(np.zeros(3), np.zeros(3), 0.05, rng, passes=0)
    empty = cascade(np.zeros(0), np.zeros(0), 0.05, rng)
    assert empty.leaked_bits == 0 and empty.corrected.size == 0
