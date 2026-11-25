"""Classical description of BB84 single-qubit states in flight.

A BB84 photon is fully described by the bit it encodes and the basis it was
prepared in, so a batch of photons is two equal-length uint8 arrays:

* ``bits[i]``  -- 0 or 1
* ``bases[i]`` -- 0 for the rectilinear (+) basis, 1 for the diagonal (x) basis

Encoding: ``|0>`` / ``|1>`` in the + basis, ``H|0> = |+>`` / ``H|1> = |->`` in x.

``detected`` marks photons that reach the receiver; it is all ``True`` until
loss is modelled (Phase 2), but every consumer already respects it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

RECTILINEAR = 0
DIAGONAL = 1


def _as_bit_array(values: np.ndarray, name: str) -> np.ndarray:
    arr = np.asarray(values)
    if arr.ndim != 1:
        raise ValueError(f"{name} must be one-dimensional")
    if arr.size and not np.isin(arr, (0, 1)).all():
        raise ValueError(f"{name} must contain only 0 and 1")
    return arr.astype(np.uint8)


@dataclass
class QubitBatch:
    """A batch of BB84 single-qubit states prepared by a sender."""

    bits: np.ndarray
    bases: np.ndarray
    detected: np.ndarray = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.bits = _as_bit_array(self.bits, "bits")
        self.bases = _as_bit_array(self.bases, "bases")
        if self.bits.shape != self.bases.shape:
            raise ValueError("bits and bases must have the same length")
        if self.detected is None:
            self.detected = np.ones(self.bits.shape, dtype=bool)
        else:
            self.detected = np.asarray(self.detected, dtype=bool)
            if self.detected.shape != self.bits.shape:
                raise ValueError("detected must have the same length as bits")

    def __len__(self) -> int:
        return int(self.bits.size)

    def copy(self) -> QubitBatch:
        return QubitBatch(self.bits.copy(), self.bases.copy(), self.detected.copy())
