import numpy as np
import pytest
from conftest import within_sigmas

from qsv2v.qkd.eve import InterceptResendEve
from qsv2v.qkd.states import QubitBatch


def test_fraction_validation():
    with pytest.raises(ValueError):
        InterceptResendEve(1.5)


def test_no_attack_leaves_batch_unchanged(backend, rng):
    batch = QubitBatch(rng.integers(0, 2, 200), rng.integers(0, 2, 200))
    out, rec = InterceptResendEve(0.0).attack(batch, rng, backend)
    np.testing.assert_array_equal(out.bits, batch.bits)
    np.testing.assert_array_equal(out.bases, batch.bases)
    assert rec.n_intercepted == 0


def test_full_attack_statistics(backend, rng):
    n = 6000
    batch = QubitBatch(rng.integers(0, 2, n), rng.integers(0, 2, n))
    out, rec = InterceptResendEve(1.0).attack(batch, rng, backend)
    assert rec.intercepted.all()
    # Resent photons are in Eve's basis and carry her outcome.
    np.testing.assert_array_equal(out.bases, rec.bases)
    np.testing.assert_array_equal(out.bits, rec.results)
    # Right basis: Eve learns the bit exactly. Wrong basis: a coin flip.
    right = rec.bases == batch.bases
    np.testing.assert_array_equal(rec.results[right], batch.bits[right])
    assert within_sigmas((rec.results[~right] != batch.bits[~right]).mean(), 0.5, (~right).sum())
    assert within_sigmas(right.mean(), 0.5, n)


def test_partial_fraction(rng, backend):
    n = 5000
    batch = QubitBatch(rng.integers(0, 2, n), rng.integers(0, 2, n))
    _, rec = InterceptResendEve(0.3).attack(batch, rng, backend)
    assert within_sigmas(rec.intercepted.mean(), 0.3, n)


def test_skips_undetected(backend, rng):
    batch = QubitBatch([0, 1], [0, 0], detected=[False, True])
    _, rec = InterceptResendEve(1.0).attack(batch, rng, backend)
    assert rec.intercepted.tolist() == [False, True]
