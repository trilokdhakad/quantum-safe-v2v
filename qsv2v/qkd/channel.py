"""Quantum channel carrying Alice's prepared states to Bob.

Phase 1 implements an ideal (lossless, noiseless) channel. The ``transmit``
hook is where Phase 2 adds photon loss, noise and an eavesdropper; it takes
and returns a :class:`QubitBatch`, so the protocol code does not change.
"""

from __future__ import annotations

import numpy as np

from qsv2v.qkd.states import QubitBatch


class QuantumChannel:
    """An ideal quantum channel: every photon arrives undisturbed."""

    def transmit(self, batch: QubitBatch, rng: np.random.Generator) -> QubitBatch:
        """Carry ``batch`` from sender to receiver and return what arrives."""
        return batch.copy()
