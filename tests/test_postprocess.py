"""Phase 3 'done when' criteria:

* Alice's and Bob's final keys are identical in >= 99% of runs below threshold;
* secret key rate vs QBER matches the theoretical curve shape.
"""

import math

import numpy as np
import pytest
from conftest import SEED

from qsv2v.qkd.backends import QiskitAerBackend
from qsv2v.qkd.channel import QuantumChannel
from qsv2v.qkd.eve import InterceptResendEve
from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.postprocess import (
    ABORT_NO_KEY,
    ABORT_QBER,
    ABORT_VERIFY,
    PostProcessingConfig,
    final_key_length,
    run_qkd,
)
from qsv2v.qkd.theory import asymptotic_key_fraction, binary_entropy


def _noisy(q):
    return QuantumChannel(noise=PauliNoise.from_qber(q) if q else None)


def _wrong_key(r):
    return not r.aborted and not np.array_equal(r.alice_final, r.bob_final)


def test_security_margin_and_length_formula():
    assert PostProcessingConfig().security_margin == 67  # 2 log2(1e10) = 66.4
    assert final_key_length(10_000, 0.0, 500, 64, 67) == 10_000 - 631
    n, q, leak = 10_000, 0.05, 1700
    expected = math.floor(n * (1 - binary_entropy(q))) - leak - 64 - 67
    assert final_key_length(n, q, leak, 64, 67) == expected
    assert final_key_length(100, 0.1, 500, 64, 67) == 0


def test_ideal_channel_end_to_end():
    r = run_qkd(20_000, seed=SEED)
    assert not r.aborted and r.keys_match and r.verified
    assert r.estimate.qber == 0 and r.residual_errors == 0
    assert r.final_length == r.n_key - r.leaked_ec - 64 - 67
    assert 0 < r.secret_key_rate < 0.5


@pytest.mark.parametrize("q", [0.01, 0.03, 0.05, 0.07])
def test_final_keys_identical_99_percent(q):
    """Done-when #1 (core): >= 99% of runs below threshold end with identical keys."""
    runs = [run_qkd(40_000, channel=_noisy(q), seed=s) for s in range(25)]
    assert sum(r.keys_match for r in runs) >= 0.99 * len(runs)
    assert not any(_wrong_key(r) for r in runs)


def test_never_outputs_mismatched_keys():
    """Across every regime (near threshold, small frames, Eve) no run returns a wrong key.

    Near the threshold runs may end without a key (finite-size cost), but a run
    that does output a key always outputs the same key on both sides.
    """
    configs = [(40_000, _noisy(q)) for q in (0.09, 0.1, 0.105, 0.115)]
    configs += [(4000, _noisy(q)) for q in (0.02, 0.05, 0.08)]
    configs += [(40_000, QuantumChannel(eve=InterceptResendEve(f))) for f in (0.2, 0.35)]
    for n, ch in configs:
        for s in range(10):
            assert not _wrong_key(run_qkd(n, channel=ch, seed=s))


def test_verification_catches_residual_errors():
    """With one Cascade pass errors survive; verification must abort every time."""
    cfg = PostProcessingConfig(cascade_passes=1)
    for s in range(10):
        r = run_qkd(20_000, channel=_noisy(0.06), config=cfg, seed=s)
        assert r.residual_errors > 0
        assert r.aborted and r.abort_reason == ABORT_VERIFY and r.final_length == 0


def test_eve_causes_abort():
    r = run_qkd(40_000, channel=QuantumChannel(eve=InterceptResendEve(0.6)), seed=SEED)
    assert r.aborted and r.abort_reason == ABORT_QBER
    assert r.cascade is None and math.isnan(r.ec_efficiency)


def test_no_key_near_threshold_small_frame():
    r = run_qkd(2000, channel=_noisy(0.1), seed=SEED)
    assert r.aborted and r.abort_reason in (ABORT_NO_KEY, ABORT_QBER)


def test_partial_eve_below_threshold_still_yields_key():
    r = run_qkd(40_000, channel=QuantumChannel(eve=InterceptResendEve(0.3)), seed=SEED)
    assert r.keys_match and r.final_length > 0


def test_key_rate_curve_shape():
    """Done-when #2: key fraction vs QBER follows 1 - (1 + f) h(Q) and the Shor-Preskill shape."""
    qs = np.array([0.0, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10, 0.12])
    measured, predicted = [], []
    for q in qs:
        runs = [run_qkd(100_000, channel=_noisy(q), seed=s) for s in range(6)]
        frac = np.mean([r.key_fraction for r in runs])
        fs = [r.ec_efficiency for r in runs if not math.isnan(r.ec_efficiency)]
        f = np.mean(fs) if fs else 1.2
        n_key = np.mean([r.n_key for r in runs])
        leak0 = np.mean([r.leaked_ec for r in runs]) if q == 0 else None
        if q == 0:
            pred = 1 - (leak0 + 131) / n_key
        else:
            pred = max(0.0, 1 - (1 + f) * binary_entropy(q) - 131 / n_key)
        measured.append(frac)
        predicted.append(pred)
    measured, predicted = np.array(measured), np.array(predicted)
    sp = asymptotic_key_fraction(qs)

    # Matches the finite-n, real-Cascade prediction point by point.
    np.testing.assert_allclose(measured, predicted, atol=0.015)
    # Never beats the Shor-Preskill bound; strictly decreasing until it hits zero.
    assert (measured <= sp + 0.005).all()
    positive = measured[measured > 0]
    assert (np.diff(positive) < 0).all()
    # Zero at and beyond the abort threshold region.
    assert measured[qs >= 0.10].max() < 0.01
    # Same shape as the theoretical curve where both are positive.
    mask = (qs > 0) & (qs <= 0.08)
    assert np.corrcoef(measured[mask], sp[mask])[0, 1] > 0.99


def test_finite_key_mode_is_more_conservative_and_converges():
    ch = _noisy(0.03)
    asym = run_qkd(40_000, channel=ch, seed=SEED)
    fin_small = run_qkd(40_000, channel=ch, config=PostProcessingConfig(finite_key=True), seed=SEED)
    fin_big = run_qkd(400_000, channel=ch, config=PostProcessingConfig(finite_key=True), seed=SEED)
    assert fin_small.keys_match and fin_big.keys_match
    assert fin_small.qber_for_pa > asym.qber_for_pa
    assert fin_small.key_fraction < asym.key_fraction
    assert fin_small.key_fraction < fin_big.key_fraction


def test_qiskit_end_to_end():
    r = run_qkd(6000, backend=QiskitAerBackend(), channel=_noisy(0.04), seed=SEED)
    assert r.keys_match and r.final_length > 0


def test_reproducible():
    a = run_qkd(20_000, channel=_noisy(0.04), seed=3)
    b = run_qkd(20_000, channel=_noisy(0.04), seed=3)
    np.testing.assert_array_equal(a.alice_final, b.alice_final)
    assert a.leaked_ec == b.leaked_ec
