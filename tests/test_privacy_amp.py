import numpy as np
import pytest
from conftest import within_sigmas

from qsv2v.qkd.privacy_amp import (
    privacy_amplify,
    random_seed_bits,
    toeplitz_hash,
    toeplitz_matrix,
    verification_tag,
)


def test_matrix_is_toeplitz(rng):
    n, m = 7, 4
    s = random_seed_bits(n, m, rng)
    t = toeplitz_matrix(s, n, m)
    assert t.shape == (m, n)
    for i in range(1, m):
        np.testing.assert_array_equal(t[i, 1:], t[i - 1, :-1])  # constant diagonals


@pytest.mark.parametrize("n,m", [(10, 5), (63, 30), (500, 200), (3000, 1500), (8000, 3000)])
def test_hash_equals_matrix_product(rng, n, m):
    """FFT path and direct path both match the explicit GF(2) matrix product."""
    x = rng.integers(0, 2, n, dtype=np.uint8)
    s = random_seed_bits(n, m, rng)
    expected = (toeplitz_matrix(s, n, m).astype(np.int64) @ x) & 1
    np.testing.assert_array_equal(toeplitz_hash(x, s, m), expected)


def test_linear_over_gf2(rng):
    n, m = 2000, 700
    s = random_seed_bits(n, m, rng)
    x, y = rng.integers(0, 2, (2, n), dtype=np.uint8)
    np.testing.assert_array_equal(
        toeplitz_hash(x ^ y, s, m), toeplitz_hash(x, s, m) ^ toeplitz_hash(y, s, m)
    )


def test_two_universal_collision_rate(rng):
    """For fixed x != y, Pr_seed[h(x) = h(y)] = 2^-m."""
    n, m, trials = 200, 4, 8000
    x = rng.integers(0, 2, n, dtype=np.uint8)
    y = x.copy()
    y[[3, 50, 199]] ^= 1
    hits = sum(
        np.array_equal(toeplitz_hash(x, s, m), toeplitz_hash(y, s, m))
        for s in (random_seed_bits(n, m, rng) for _ in range(trials))
    )
    assert within_sigmas(hits / trials, 2**-m, trials)


def test_output_is_balanced(rng):
    x = rng.integers(0, 2, 10_000, dtype=np.uint8)
    out, seed = privacy_amplify(x, 5000, rng)
    assert out.size == 5000 and seed.size == 14_999
    assert within_sigmas(out.mean(), 0.5, 5000)


def test_edge_cases(rng):
    assert toeplitz_hash(np.ones(5), np.zeros(4), 0).size == 0
    with pytest.raises(ValueError):
        toeplitz_hash(np.ones(5), np.zeros(3), 2)
    with pytest.raises(ValueError):
        toeplitz_hash(np.ones(5), np.zeros(3), -1)
    with pytest.raises(ValueError):
        toeplitz_matrix(np.zeros(3), 5, 2)


def test_verification_tag_detects_one_bit_change(rng):
    x = rng.integers(0, 2, 5000, dtype=np.uint8)
    y = x.copy()
    y[1234] ^= 1
    s = random_seed_bits(5000, 64, rng)
    assert verification_tag(x, s).size == 64
    assert not np.array_equal(verification_tag(x, s), verification_tag(y, s))
