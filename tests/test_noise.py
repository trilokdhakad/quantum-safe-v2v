import numpy as np
import pytest
from conftest import within_sigmas

from qsv2v.qkd.noise import PauliNoise, X, Y, Z
from qsv2v.qkd.states import QubitBatch


def test_standard_channels_error_rates():
    assert PauliNoise.bit_flip(0.1).error_prob(0) == pytest.approx(0.1)
    assert PauliNoise.bit_flip(0.1).error_prob(1) == 0.0
    assert PauliNoise.phase_flip(0.1).error_prob(0) == 0.0
    assert PauliNoise.phase_flip(0.1).error_prob(1) == pytest.approx(0.1)
    d = PauliNoise.depolarizing(0.2)
    assert d.error_prob(0) == pytest.approx(0.1) == d.error_prob(1)
    assert PauliNoise.from_qber(0.07).expected_qber() == pytest.approx(0.07)


def test_validation():
    with pytest.raises(ValueError):
        PauliNoise(px=-0.1)
    with pytest.raises(ValueError):
        PauliNoise(px=0.6, pz=0.6)
    with pytest.raises(ValueError):
        PauliNoise.depolarizing(2.0)
    with pytest.raises(ValueError):
        PauliNoise.from_qber(0.9)


def test_flip_table():
    paulis = np.array([0, X, Y, Z, 0, X, Y, Z])
    bases = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    assert PauliNoise.flips(paulis, bases).tolist() == [0, 1, 1, 0, 0, 0, 1, 1]


def test_sample_frequencies(rng):
    noise = PauliNoise(px=0.1, py=0.2, pz=0.3)
    s = noise.sample(50_000, rng)
    for label, p in [(0, 0.4), (X, 0.1), (Y, 0.2), (Z, 0.3)]:
        assert within_sigmas((s == label).mean(), p, s.size)


def test_trivial():
    assert PauliNoise().is_trivial
    assert not PauliNoise.bit_flip(0.01).is_trivial


@pytest.mark.parametrize(
    "noise",
    [PauliNoise.bit_flip(0.2), PauliNoise.phase_flip(0.2), PauliNoise(0.05, 0.1, 0.15)],
    ids=["bitflip", "phaseflip", "general"],
)
def test_backend_applies_noise_per_basis(backend, rng, noise):
    """Measured error rate in each basis matches the channel, on both backends."""
    n = 6000
    for basis in (0, 1):
        bits = rng.integers(0, 2, n)
        bases = np.full(n, basis)
        out = backend.measure(QubitBatch(bits, bases), bases, rng, noise=noise)
        assert within_sigmas((out != bits).mean(), noise.error_prob(basis), n)


def test_noise_keeps_conjugate_measurement_uniform(backend, rng):
    n = 4000
    bits = rng.integers(0, 2, n)
    bases = rng.integers(0, 2, n)
    out = backend.measure(QubitBatch(bits, bases), 1 - bases, rng, noise=PauliNoise.bit_flip(0.3))
    assert within_sigmas((out != bits).mean(), 0.5, n)
