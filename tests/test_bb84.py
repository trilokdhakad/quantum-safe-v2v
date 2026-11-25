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


# ---------------------------------------------------------------------------
# Phase 2 "done when": measured QBER matches theory across 20+ channel settings
# ---------------------------------------------------------------------------
from qsv2v.qkd.backends import NumpyBackend, QiskitAerBackend  # noqa: E402
from qsv2v.qkd.channel import QuantumChannel  # noqa: E402
from qsv2v.qkd.estimation import estimate_qber, should_abort  # noqa: E402
from qsv2v.qkd.eve import InterceptResendEve  # noqa: E402
from qsv2v.qkd.noise import PauliNoise  # noqa: E402
from qsv2v.qkd.theory import expected_qber  # noqa: E402


def _channel(noise, f, distance=0.0, dark=0.0):
    return QuantumChannel(
        noise=noise,
        eve=InterceptResendEve(f) if f > 0 else None,
        distance_km=distance,
        dark_count_prob=dark,
    )


# (label, noise, eve fraction, distance km, dark count prob)
QBER_SETTINGS = (
    [
        (f"depol e={e} f={f}", PauliNoise.from_qber(e) if e else None, f, 0.0, 0.0)
        for e in (0.0, 0.02, 0.05, 0.08)
        for f in (0.0, 0.25, 0.5, 0.75, 1.0)
    ]
    + [
        (f"bitflip p={p} f={f}", PauliNoise.bit_flip(p), f, 0.0, 0.0)
        for p in (0.04, 0.1)
        for f in (0.5, 1.0)
    ]
    + [
        ("lossy 50km + dark 1e-3, e=0.03", PauliNoise.from_qber(0.03), 0.0, 50.0, 1e-3),
        ("lossy 100km + dark 1e-3, f=0.5", None, 0.5, 100.0, 1e-3),
    ]
)


@pytest.mark.parametrize(
    "label,noise,f,distance,dark", QBER_SETTINGS, ids=[s[0] for s in QBER_SETTINGS]
)
def test_qber_matches_theory_numpy(label, noise, f, distance, dark):
    ch = _channel(noise, f, distance, dark)
    # Aim for ~100k sifted bits whatever the loss.
    n = int(200_000 / (ch.eta + (1 - ch.eta) * dark))
    res = run_bb84(n, backend=NumpyBackend(), channel=ch, seed=SEED)
    q_theory = expected_qber(noise, f, ch.eta, dark)
    assert res.sifted_length > 50_000
    assert within_sigmas(res.qber, q_theory, res.sifted_length), (res.qber, q_theory)


QISKIT_SETTINGS = [
    (PauliNoise.from_qber(0.0), 0.0),
    (PauliNoise.from_qber(0.05), 0.0),
    (None, 0.5),
    (None, 1.0),
    (PauliNoise.from_qber(0.05), 0.5),
    (PauliNoise.bit_flip(0.1), 1.0),
]


@pytest.mark.parametrize("noise,f", QISKIT_SETTINGS)
def test_qber_matches_theory_qiskit(noise, f):
    n = 6000
    res = run_bb84(n, backend=QiskitAerBackend(), channel=_channel(noise, f), seed=SEED)
    q_theory = expected_qber(noise, f)
    assert within_sigmas(res.qber, q_theory, res.sifted_length), (res.qber, q_theory)


def test_linear_approximation_cross_term_is_real():
    """The plan's 'noise + 0.25 f' omits -f e/2; at e=8%, f=1 that is 4 points."""
    noise, f = PauliNoise.from_qber(0.08), 1.0
    res = run_bb84(200_000, channel=_channel(noise, f), seed=SEED)
    sigma = np.sqrt(res.qber * (1 - res.qber) / res.sifted_length)
    assert within_sigmas(res.qber, 0.08 + 0.25 - 0.04, res.sifted_length)
    assert abs(res.qber - (0.08 + 0.25)) > 10 * sigma


def test_detection_rate_matches_loss():
    ch = _channel(None, 0.0, distance=25.0, dark=1e-3)
    res = run_bb84(200_000, channel=ch, seed=SEED)
    p = ch.eta + (1 - ch.eta) * 1e-3
    assert within_sigmas(res.detection_rate, p, 200_000)
    assert within_sigmas(res.sift_ratio, p / 2, 200_000)


@pytest.mark.parametrize(
    "f,expect_abort",
    [(0.0, False), (0.2, False), (0.3, False), (0.6, True), (0.8, True), (1.0, True)],
)
def test_eve_detection_and_abort(f, expect_abort):
    """Abort above 11% sampled QBER: expected beyond ~44% interception (0.11/0.25)."""
    res = run_bb84(40_000, channel=_channel(None, f), seed=SEED)
    est = estimate_qber(res.alice_key, res.bob_key, np.random.default_rng(1), 0.1)
    assert should_abort(est) is expect_abort
    assert within_sigmas(est.qber, 0.25 * f, est.n_sample)
