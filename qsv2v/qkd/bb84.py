"""BB84 quantum key distribution: preparation, transmission, measurement, sifting.

Post-processing (QBER sampling, Cascade, privacy amplification) builds on the
:class:`BB84Result` returned here in later phases.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from qsv2v.qkd.backends import MeasurementBackend, NumpyBackend
from qsv2v.qkd.channel import QuantumChannel
from qsv2v.qkd.states import QubitBatch


def prepare(n: int, rng: np.random.Generator) -> QubitBatch:
    """Alice draws n random bits and n random bases."""
    if n < 0:
        raise ValueError("n must be non-negative")
    bits = rng.integers(0, 2, size=n, dtype=np.uint8)
    bases = rng.integers(0, 2, size=n, dtype=np.uint8)
    return QubitBatch(bits, bases)


def sift(
    alice_bases: np.ndarray, bob_bases: np.ndarray, detected: np.ndarray | None = None
) -> np.ndarray:
    """Boolean mask of positions kept after public basis comparison."""
    mask = np.asarray(alice_bases) == np.asarray(bob_bases)
    if detected is not None:
        mask &= np.asarray(detected, dtype=bool)
    return mask


@dataclass
class BB84Result:
    alice_bits: np.ndarray
    alice_bases: np.ndarray
    bob_bases: np.ndarray
    bob_results: np.ndarray
    detected: np.ndarray
    sift_mask: np.ndarray

    @property
    def n_sent(self) -> int:
        return int(self.alice_bits.size)

    @property
    def alice_key(self) -> np.ndarray:
        return self.alice_bits[self.sift_mask]

    @property
    def bob_key(self) -> np.ndarray:
        return self.bob_results[self.sift_mask]

    @property
    def sifted_length(self) -> int:
        return int(self.sift_mask.sum())

    @property
    def sift_ratio(self) -> float:
        return self.sifted_length / self.n_sent if self.n_sent else 0.0

    @property
    def errors(self) -> int:
        return int(np.count_nonzero(self.alice_key != self.bob_key))

    @property
    def qber(self) -> float:
        """Error rate over the whole sifted key (ground truth, simulator-only)."""
        return self.errors / self.sifted_length if self.sifted_length else 0.0


def run_bb84(
    n: int,
    backend: MeasurementBackend | None = None,
    channel: QuantumChannel | None = None,
    seed: int | None = None,
    rng: np.random.Generator | None = None,
) -> BB84Result:
    """Run the quantum phase of BB84 with n photons and sift the result.

    Pass either ``seed`` or an existing ``rng``; the same seed always gives the
    same result for a given backend.
    """
    if rng is None:
        rng = np.random.default_rng(seed)
    backend = backend or NumpyBackend()
    channel = channel or QuantumChannel()

    sent = prepare(n, rng)
    received = channel.transmit(sent, rng)
    bob_bases = rng.integers(0, 2, size=n, dtype=np.uint8)
    bob_results = backend.measure(received, bob_bases, rng)
    mask = sift(sent.bases, bob_bases, received.detected)
    return BB84Result(
        alice_bits=sent.bits,
        alice_bases=sent.bases,
        bob_bases=bob_bases,
        bob_results=bob_results,
        detected=received.detected,
        sift_mask=mask,
    )
