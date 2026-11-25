"""Measurement backends for the BB84 simulator."""

from qsv2v.qkd.backends.base import MeasurementBackend
from qsv2v.qkd.backends.numpy_backend import NumpyBackend
from qsv2v.qkd.backends.qiskit_backend import QiskitAerBackend, build_bb84_circuit

BACKENDS = {"numpy": NumpyBackend, "qiskit": QiskitAerBackend}


def get_backend(name: str, **kwargs) -> MeasurementBackend:
    """Return a backend instance by name ('numpy' or 'qiskit')."""
    try:
        return BACKENDS[name](**kwargs)
    except KeyError:
        raise ValueError(f"unknown backend {name!r}; choose from {sorted(BACKENDS)}") from None


__all__ = [
    "BACKENDS",
    "MeasurementBackend",
    "NumpyBackend",
    "QiskitAerBackend",
    "build_bb84_circuit",
    "get_backend",
]
