"""Phase 1 'done when' criteria, checked on both backends:

* no noise, no Eve -> sifted keys match 100%
* about 50% of bits survive sifting
"""

import numpy as np
import pytest
from conftest import SEED, within_sigmas

from qsv2v.qkd.bb84 import prepare, run_bb84, sift

N_BY_BACKEND = {"numpy": 100_000, "qiskit": 5_000}


def test_sifted_keys_match_exactly(backend):
    n = N_BY_BACKEND[backend.name]
    res = run_bb84(n, backend=backend, seed=SEED)
    assert res.sifted_length > 0
    np.testing.assert_array_equal(res.alice_key, res.bob_key)
    assert res.errors == 0
    assert res.qber == 0.0


def test_about_half_survive_sifting(backend):
    n = N_BY_BACKEND[backend.name]
    res = run_bb84(n, backend=backend, seed=SEED)
    assert within_sigmas(res.sift_ratio, 0.5, n)


@pytest.mark.parametrize("seed", range(5))
def test_many_seeds_ideal_channel(backend, seed):
    res = run_bb84(800, backend=backend, seed=seed)
    assert res.errors == 0
    assert within_sigmas(res.sift_ratio, 0.5, 800)


def test_unsifted_positions_disagree_half_the_time(backend):
    """Sanity: discarded positions really are random, so sifting matters."""
    n = N_BY_BACKEND[backend.name]
    res = run_bb84(n, backend=backend, seed=SEED)
    drop = ~res.sift_mask
    rate = float((res.alice_bits[drop] != res.bob_results[drop]).mean())
    assert within_sigmas(rate, 0.5, int(drop.sum()))


def test_reproducible_with_seed(backend):
    a = run_bb84(500, backend=backend, seed=7)
    b = run_bb84(500, backend=backend, seed=7)
    np.testing.assert_array_equal(a.alice_key, b.alice_key)
    np.testing.assert_array_equal(a.bob_bases, b.bob_bases)


def test_different_seeds_differ():
    a = run_bb84(500, seed=1)
    b = run_bb84(500, seed=2)
    assert not np.array_equal(a.alice_bits, b.alice_bits)


def test_default_backend_is_numpy():
    res = run_bb84(100, seed=SEED)
    assert res.errors == 0 and res.n_sent == 100


def test_zero_photons():
    res = run_bb84(0, seed=SEED)
    assert res.sifted_length == 0 and res.sift_ratio == 0.0 and res.qber == 0.0


def test_prepare_rejects_negative(rng):
    with pytest.raises(ValueError):
        prepare(-1, rng)


def test_prepare_is_balanced(rng):
    batch = prepare(20_000, rng)
    assert within_sigmas(batch.bits.mean(), 0.5, 20_000)
    assert within_sigmas(batch.bases.mean(), 0.5, 20_000)


def test_sift_mask():
    a = np.array([0, 1, 1, 0])
    b = np.array([0, 0, 1, 1])
    assert sift(a, b).tolist() == [True, False, True, False]
    assert sift(a, b, detected=[True, True, False, False]).tolist() == [
        True,
        False,
        False,
        False,
    ]
