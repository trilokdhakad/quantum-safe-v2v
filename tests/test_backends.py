import numpy as np
import pytest
from conftest import SEED, within_sigmas

from qsv2v.qkd.backends import (
    NumpyBackend,
    QiskitAerBackend,
    build_bb84_circuit,
    get_backend,
)
from qsv2v.qkd.states import QubitBatch


@pytest.mark.parametrize("bit", [0, 1])
@pytest.mark.parametrize("basis", [0, 1])
def test_each_state_measured_in_own_basis(backend, rng, bit, basis):
    batch = QubitBatch(np.full(50, bit), np.full(50, basis))
    out = backend.measure(batch, np.full(50, basis), rng)
    assert (out == bit).all()


def test_same_basis_recovers_random_bits(backend, rng):
    # 1000 is not a multiple of the qiskit chunk size (137): checks bit order
    # and chunk reassembly.
    n = 1000
    bits = rng.integers(0, 2, n)
    bases = rng.integers(0, 2, n)
    out = backend.measure(QubitBatch(bits, bases), bases, rng)
    np.testing.assert_array_equal(out, bits)


def test_conjugate_basis_is_uniform(backend, rng):
    n = 4000
    bits = rng.integers(0, 2, n)
    bases = rng.integers(0, 2, n)
    out = backend.measure(QubitBatch(bits, bases), 1 - bases, rng)
    assert within_sigmas(out.mean(), 0.5, n)
    # Outcome must be independent of the encoded bit.
    agree = (out == bits).mean()
    assert within_sigmas(agree, 0.5, n)


def test_undetected_positions_are_skipped(backend, rng):
    detected = np.array([True, False, True, False])
    batch = QubitBatch([1, 1, 1, 1], [0, 0, 0, 0], detected=detected)
    out = backend.measure(batch, np.zeros(4), rng)
    assert out.tolist() == [1, 0, 1, 0]


def test_all_undetected(backend, rng):
    batch = QubitBatch([1, 1], [0, 0], detected=[False, False])
    assert backend.measure(batch, [0, 0], rng).tolist() == [0, 0]


def test_basis_length_mismatch_raises(backend, rng):
    with pytest.raises(ValueError):
        backend.measure(QubitBatch([0, 1], [0, 1]), [0], rng)


def test_seed_reproducible(backend):
    n = 600
    r = np.random.default_rng(1)
    bits, bases, meas = r.integers(0, 2, (3, n))
    batch = QubitBatch(bits, bases)
    a = backend.measure(batch, meas, np.random.default_rng(SEED))
    b = backend.measure(batch, meas, np.random.default_rng(SEED))
    np.testing.assert_array_equal(a, b)


def test_backends_agree_statistically():
    """Both backends give the same outcome distribution on identical inputs."""
    n = 3000
    r = np.random.default_rng(SEED)
    bits, bases, meas = r.integers(0, 2, (3, n))
    batch = QubitBatch(bits, bases)
    outs = {
        "numpy": NumpyBackend().measure(batch, meas, np.random.default_rng(1)),
        "qiskit": QiskitAerBackend().measure(batch, meas, np.random.default_rng(2)),
    }
    same = bases == meas
    for out in outs.values():
        np.testing.assert_array_equal(out[same], bits[same])
    # Error rate vs Alice's bit on mismatched bases: both ~ 0.5.
    rates = [float((out[~same] != bits[~same]).mean()) for out in outs.values()]
    m = int((~same).sum())
    for rate in rates:
        assert within_sigmas(rate, 0.5, m)
    # And they agree with each other within a two-sample tolerance.
    assert abs(rates[0] - rates[1]) <= 4 * np.sqrt(0.5 / m)


def test_circuit_structure():
    qc = build_bb84_circuit(np.array([1, 0, 1]), np.array([0, 1, 1]), np.array([1, 1, 0]))
    ops = qc.count_ops()
    assert qc.num_qubits == 3 and qc.num_clbits == 3
    assert ops["x"] == 2  # bits 1, 1
    assert ops["h"] == 4  # 2 preparation + 2 measurement rotations
    assert ops["measure"] == 3


def test_get_backend():
    assert isinstance(get_backend("numpy"), NumpyBackend)
    assert get_backend("qiskit", qubits_per_circuit=10).qubits_per_circuit == 10
    with pytest.raises(ValueError):
        get_backend("nope")
    with pytest.raises(ValueError):
        QiskitAerBackend(qubits_per_circuit=0)
