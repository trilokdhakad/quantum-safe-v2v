"""Backend interface: measure a batch of BB84 states in chosen bases."""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.states import QubitBatch, _as_bit_array


class MeasurementBackend(ABC):
    """Measures prepared BB84 states, optionally after a Pauli noise channel.

    Implementations must give identical statistics: a qubit measured in its
    preparation basis yields its bit with certainty (flipped if the noise
    channel's Pauli anticommutes with that basis); one measured in the other
    basis yields a uniformly random bit.
    """

    name: str = "abstract"

    def measure(
        self,
        batch: QubitBatch,
        bases: np.ndarray,
        rng: np.random.Generator,
        noise: PauliNoise | None = None,
    ) -> np.ndarray:
        """Return measurement outcomes (uint8, same length as ``batch``).

        ``noise`` is applied to every detected qubit just before measurement.
        Positions where ``batch.detected`` is False have no outcome; they are
        returned as 0 and must be ignored by the caller via the mask.
        """
        bases = _as_bit_array(bases, "bases")
        if bases.shape != batch.bits.shape:
            raise ValueError("measurement bases must match the batch length")
        if noise is not None and noise.is_trivial:
            noise = None
        out = np.zeros(len(batch), dtype=np.uint8)
        idx = np.flatnonzero(batch.detected)
        if idx.size:
            out[idx] = self._measure(batch.bits[idx], batch.bases[idx], bases[idx], rng, noise)
        return out

    @abstractmethod
    def _measure(
        self,
        bits: np.ndarray,
        prep_bases: np.ndarray,
        meas_bases: np.ndarray,
        rng: np.random.Generator,
        noise: PauliNoise | None,
    ) -> np.ndarray:
        """Measure detected qubits only; all arrays have equal length."""
