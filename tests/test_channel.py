import numpy as np
import pytest
from conftest import within_sigmas

from qsv2v.qkd.backends import NumpyBackend
from qsv2v.qkd.channel import QuantumChannel, transmittance
from qsv2v.qkd.eve import InterceptResendEve
from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.states import QubitBatch


def test_ideal_channel_is_identity(rng):
    batch = QubitBatch(rng.integers(0, 2, 100), rng.integers(0, 2, 100))
    tx = QuantumChannel().transmit(batch, rng)
    np.testing.assert_array_equal(tx.received.bits, batch.bits)
    np.testing.assert_array_equal(tx.received.bases, batch.bases)
    assert tx.received.detected.all() and tx.arrived.all() and not tx.dark.any()
    assert tx.noise is None and tx.eve is None


def test_channel_does_not_alias_input(rng):
    batch = QubitBatch([0, 1], [0, 1])
    tx = QuantumChannel().transmit(batch, rng)
    tx.received.bits[0] = 1
    assert batch.bits[0] == 0


def test_transmittance_formula():
    assert transmittance(0, 0.2) == 1.0
    assert transmittance(50, 0.2) == pytest.approx(0.1)  # 10 dB
    assert transmittance(10, 3.0) == pytest.approx(10**-3)
    with pytest.raises(ValueError):
        transmittance(-1, 0.2)


@pytest.mark.parametrize("distance", [0.0, 10.0, 25.0, 50.0])
def test_loss_matches_transmittance(rng, distance):
    n = 50_000
    ch = QuantumChannel(distance_km=distance, attenuation_db_per_km=0.2, detector_efficiency=0.8)
    tx = ch.transmit(QubitBatch(np.zeros(n), np.zeros(n)), rng)
    eta = transmittance(distance, 0.2) * 0.8
    assert ch.eta == pytest.approx(eta)
    assert within_sigmas(tx.arrived.mean(), eta, n)


def test_dark_counts(rng):
    n = 50_000
    ch = QuantumChannel(distance_km=100, attenuation_db_per_km=0.2, dark_count_prob=0.05)
    tx = ch.transmit(QubitBatch(np.zeros(n), np.zeros(n)), rng)
    eta = 0.01
    assert not (tx.arrived & tx.dark).any()
    assert within_sigmas(tx.received.detected.mean(), eta + (1 - eta) * 0.05, n)
    # Dark clicks are random states.
    d = tx.dark
    assert within_sigmas(tx.received.bits[d].mean(), 0.5, d.sum())
    assert within_sigmas(tx.received.bases[d].mean(), 0.5, d.sum())


def test_noise_passed_through(rng):
    noise = PauliNoise.bit_flip(0.1)
    tx = QuantumChannel(noise=noise).transmit(QubitBatch([0], [0]), rng)
    assert tx.noise is noise


def test_eve_requires_backend(rng):
    ch = QuantumChannel(eve=InterceptResendEve(1.0))
    with pytest.raises(ValueError):
        ch.transmit(QubitBatch([0], [0]), rng)
    tx = ch.transmit(QubitBatch([0], [0]), rng, NumpyBackend())
    assert tx.eve.n_intercepted == 1


def test_parameter_validation():
    with pytest.raises(ValueError):
        QuantumChannel(detector_efficiency=1.5)
    with pytest.raises(ValueError):
        QuantumChannel(dark_count_prob=-0.1)
