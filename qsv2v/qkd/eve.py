"""Intercept-resend eavesdropper.

Eve sits at Alice's output. For each photon, independently with probability
``fraction``, she picks a random basis, measures the photon (on the same
backend Bob uses, so on Qiskit this is a real circuit measurement), and resends
a fresh photon encoding her outcome in her basis. That is exactly the
post-measurement state, so resending a new :class:`QubitBatch` entry is a
faithful model of intercept-resend.

On a sifted bit she attacked, Eve guesses the basis wrong half the time; then
Bob's outcome is random, so she causes an error with probability 1/4.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from qsv2v.qkd.backends.base import MeasurementBackend
from qsv2v.qkd.states import QubitBatch


@dataclass
class EveRecord:
    """What Eve did and learned (positions refer to Alice's photon indices)."""

    intercepted: np.ndarray  # bool mask
    bases: np.ndarray  # Eve's bases (meaningful where intercepted)
    results: np.ndarray  # Eve's outcomes (meaningful where intercepted)

    @property
    def n_intercepted(self) -> int:
        return int(self.intercepted.sum())


class InterceptResendEve:
    def __init__(self, fraction: float = 1.0):
        if not 0.0 <= fraction <= 1.0:
            raise ValueError("fraction must be in [0, 1]")
        self.fraction = fraction

    def attack(
        self, batch: QubitBatch, rng: np.random.Generator, backend: MeasurementBackend
    ) -> tuple[QubitBatch, EveRecord]:
        n = len(batch)
        intercepted = (rng.random(n) < self.fraction) & batch.detected
        eve_bases = rng.integers(0, 2, size=n, dtype=np.uint8)
        results = np.zeros(n, dtype=np.uint8)
        idx = np.flatnonzero(intercepted)
        out = batch.copy()
        if idx.size:
            sub = QubitBatch(batch.bits[idx], batch.bases[idx])
            results[idx] = backend.measure(sub, eve_bases[idx], rng)
            out.bits[idx] = results[idx]
            out.bases[idx] = eve_bases[idx]
        return out, EveRecord(intercepted, eve_bases, results)
