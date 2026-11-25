"""QBER estimation on a publicly disclosed random sample of the sifted key.

Alice and Bob agree on a random subset of sifted positions, announce those
bits, count disagreements, and discard the sample. They abort if the estimate
exceeds the threshold (default 11%, where Shor-Preskill key rate hits zero).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from qsv2v.qkd.theory import QBER_THRESHOLD


@dataclass
class QBEREstimate:
    n_sample: int
    errors: int
    keep_mask: np.ndarray  # True for sifted positions NOT disclosed

    @property
    def qber(self) -> float:
        return self.errors / self.n_sample if self.n_sample else 0.0

    def std_error(self) -> float:
        q = self.qber
        return math.sqrt(q * (1 - q) / self.n_sample) if self.n_sample else float("inf")

    def wilson_interval(self, z: float = 1.96) -> tuple[float, float]:
        """Wilson score interval (default 95%)."""
        n = self.n_sample
        if n == 0:
            return 0.0, 1.0
        q = self.qber
        denom = 1 + z * z / n
        centre = (q + z * z / (2 * n)) / denom
        half = z * math.sqrt(q * (1 - q) / n + z * z / (4 * n * n)) / denom
        return max(0.0, centre - half), min(1.0, centre + half)


def estimate_qber(
    alice_key: np.ndarray,
    bob_key: np.ndarray,
    rng: np.random.Generator,
    sample_fraction: float = 0.1,
    min_sample: int = 0,
) -> QBEREstimate:
    """Disclose a random sample of the sifted key and count errors in it."""
    alice_key = np.asarray(alice_key)
    bob_key = np.asarray(bob_key)
    if alice_key.shape != bob_key.shape:
        raise ValueError("keys must have equal length")
    if not 0.0 <= sample_fraction <= 1.0:
        raise ValueError("sample_fraction must be in [0, 1]")
    n = alice_key.size
    k = min(n, max(min_sample, int(round(sample_fraction * n))))
    idx = rng.choice(n, size=k, replace=False)
    keep = np.ones(n, dtype=bool)
    keep[idx] = False
    errors = int(np.count_nonzero(alice_key[idx] != bob_key[idx]))
    return QBEREstimate(n_sample=k, errors=errors, keep_mask=keep)


def should_abort(estimate: QBEREstimate, threshold: float = QBER_THRESHOLD) -> bool:
    """Abort when the sampled QBER exceeds the threshold (or nothing was sampled)."""
    return estimate.n_sample == 0 or estimate.qber > threshold


def finite_size_correction(n_key: int, n_sample: int, eps: float = 1e-10) -> float:
    """Upper deviation of the key's error rate from the sample's (Serfling bound).

    With probability >= 1 - eps, Q_key <= Q_sample + mu, where
    mu = sqrt((n + k)(k + 1) ln(1/eps) / (2 n k^2))  (Tomamichel et al. 2012).
    """
    if n_key <= 0 or n_sample <= 0:
        return 1.0
    n, k = n_key, n_sample
    return math.sqrt((n + k) * (k + 1) * math.log(1 / eps) / (2 * n * k * k))
