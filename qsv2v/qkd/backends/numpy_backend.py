"""Fast NumPy backend: Born-rule statistics for BB84 states without circuits.

For BB84 states the outcome probabilities are exact and simple: same basis ->
the encoded bit with probability 1; conjugate basis -> 0 or 1 with probability
1/2 each. This reproduces the Qiskit backend's statistics at a fraction of the
cost, for large runs.
"""

from __future__ import annotations

import numpy as np

from qsv2v.qkd.backends.base import MeasurementBackend


class NumpyBackend(MeasurementBackend):
    name = "numpy"

    def _measure(self, bits, prep_bases, meas_bases, rng):
        random_bits = rng.integers(0, 2, size=bits.size, dtype=np.uint8)
        return np.where(prep_bases == meas_bases, bits, random_bits).astype(np.uint8)
