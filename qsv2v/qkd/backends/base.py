"""Backend interface: measure a batch of BB84 states in chosen bases."""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

from qsv2v.qkd.states import QubitBatch, _as_bit_array


class MeasurementBackend(ABC):
    """Measures prepared BB84 states.

    Implementations must give identical statistics: a qubit measured in its
    preparation basis yields its bit with certainty; one measured in the other
    basis yields a uniformly random bit.
    """

    name: str = "abstract"

    def measure(self, batch: QubitBatch, bases: np.ndarray, rng: np.random.Generator) -> np.ndarray:
        """Return measurement outcomes (uint8, same length as ``batch``).

        Positions where ``batch.detected`` is False have no outcome; they are
        returned as 0 and must be ignored by the caller via the mask.
        """
        bases = _as_bit_array(bases, "bases")
        if bases.shape != batch.bits.shape:
            raise ValueError("measurement bases must match the batch length")
        out = np.zeros(len(batch), dtype=np.uint8)
        idx = np.flatnonzero(batch.detected)
        if idx.size:
            out[idx] = self._measure(batch.bits[idx], batch.bases[idx], bases[idx], rng)
        return out

    @abstractmethod
    def _measure(
        self,
        bits: np.ndarray,
        prep_bases: np.ndarray,
        meas_bases: np.ndarray,
        rng: np.random.Generator,
    ) -> np.ndarray:
        """Measure detected qubits only; all arrays have equal length."""
