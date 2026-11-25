import numpy as np
import pytest

from qsv2v.qkd.backends import NumpyBackend, QiskitAerBackend

SEED = 20261125


@pytest.fixture
def rng():
    return np.random.default_rng(SEED)


@pytest.fixture(params=["numpy", "qiskit"])
def backend(request):
    """Every backend-level test runs on both backends."""
    if request.param == "numpy":
        return NumpyBackend()
    # A small chunk size that does not divide test sizes exercises batching.
    return QiskitAerBackend(qubits_per_circuit=137)


def within_sigmas(observed: float, p: float, n: int, k: float = 4.0) -> bool:
    """True if a binomial proportion is within k standard deviations of p."""
    sigma = np.sqrt(p * (1 - p) / n)
    return abs(observed - p) <= k * sigma
