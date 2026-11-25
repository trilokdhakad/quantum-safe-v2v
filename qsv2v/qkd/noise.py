"""Single-qubit Pauli noise on the quantum channel.

A Pauli channel applies I, X, Y or Z with probabilities (1-px-py-pz, px, py, pz).
Paulis map BB84 states to BB84 states of the same basis (up to a global phase),
so their effect on BB84 is exact and simple:

* rectilinear (+) states are flipped by X and Y,
* diagonal (x) states are flipped by Z and Y.

The Qiskit backend inserts the same channel into its circuits as a Qiskit Aer
``pauli_error``; the NumPy backend samples the Paulis directly.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

I, X, Y, Z = 0, 1, 2, 3  # noqa: E741  (standard Pauli names)


@dataclass(frozen=True)
class PauliNoise:
    px: float = 0.0
    py: float = 0.0
    pz: float = 0.0

    def __post_init__(self) -> None:
        for name in ("px", "py", "pz"):
            if not 0.0 <= getattr(self, name) <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")
        if self.px + self.py + self.pz > 1.0 + 1e-12:
            raise ValueError("px + py + pz must not exceed 1")

    # -- standard channels -------------------------------------------------
    @classmethod
    def bit_flip(cls, p: float) -> PauliNoise:
        """X with probability p: flips only rectilinear-basis states."""
        return cls(px=p)

    @classmethod
    def phase_flip(cls, p: float) -> PauliNoise:
        """Z with probability p: flips only diagonal-basis states."""
        return cls(pz=p)

    @classmethod
    def depolarizing(cls, p: float) -> PauliNoise:
        """With probability p the qubit is replaced by the maximally mixed state.

        Same convention as ``qiskit_aer.noise.depolarizing_error(p, 1)``:
        X, Y and Z each occur with probability p/4. Error rate in either basis
        is p/2.
        """
        if not 0.0 <= p <= 4 / 3:
            raise ValueError("depolarizing p must be in [0, 4/3]")
        return cls(px=p / 4, py=p / 4, pz=p / 4)

    @classmethod
    def from_qber(cls, e: float) -> PauliNoise:
        """Symmetric depolarizing noise giving error rate e in both bases."""
        if not 0.0 <= e <= 2 / 3:
            raise ValueError("e must be in [0, 2/3]")
        return cls.depolarizing(2 * e)

    # -- effect on BB84 ----------------------------------------------------
    @property
    def is_trivial(self) -> bool:
        return self.px == self.py == self.pz == 0.0

    def error_prob(self, basis: int) -> float:
        """Probability a state prepared and measured in ``basis`` is flipped."""
        return self.px + self.py if basis == 0 else self.pz + self.py

    def expected_qber(self) -> float:
        """Error rate on sifted bits, with both bases equally likely."""
        return 0.5 * (self.error_prob(0) + self.error_prob(1))

    def sample(self, n: int, rng: np.random.Generator) -> np.ndarray:
        """Draw n Pauli labels (0=I, 1=X, 2=Y, 3=Z)."""
        p = [1.0 - self.px - self.py - self.pz, self.px, self.py, self.pz]
        p[0] = max(p[0], 0.0)
        return rng.choice(4, size=n, p=np.asarray(p) / sum(p)).astype(np.uint8)

    @staticmethod
    def flips(paulis: np.ndarray, bases: np.ndarray) -> np.ndarray:
        """1 where the Pauli flips the BB84 state of the given basis."""
        rect_flip = (paulis == X) | (paulis == Y)
        diag_flip = (paulis == Z) | (paulis == Y)
        return np.where(bases == 0, rect_flip, diag_flip).astype(np.uint8)

    def to_qiskit_error(self):
        """The equivalent ``qiskit_aer.noise.QuantumError``."""
        from qiskit_aer.noise import pauli_error

        terms = [("X", self.px), ("Y", self.py), ("Z", self.pz)]
        terms = [(label, p) for label, p in terms if p > 0]
        terms.append(("I", 1.0 - sum(p for _, p in terms)))
        return pauli_error(terms)
