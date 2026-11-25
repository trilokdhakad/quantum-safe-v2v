"""Quantum channel carrying Alice's prepared states to Bob.

Order of effects along the link::

    Alice -> [Eve: intercept-resend] -> [loss + detector] -> [Pauli noise] -> Bob

* **Eve** (optional) sees every photon at Alice's output.
* **Loss**: the photon survives with transmittance
  ``eta = 10**(-alpha * d / 10) * detector_efficiency`` (alpha in dB/km,
  d in km).
* **Dark counts**: when no photon arrives, Bob's detector still clicks with
  probability ``dark_count_prob``; the click is a uniformly random outcome,
  modelled as a random BB84 state (random bit in a random basis), which gives
  a fair coin in either measurement basis.
* **Noise**: a :class:`PauliNoise` applied by the backend at measurement (in
  the circuit itself on the Qiskit backend).

The defaults give the ideal channel of Phase 1.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from qsv2v.qkd.backends.base import MeasurementBackend
from qsv2v.qkd.eve import EveRecord, InterceptResendEve
from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.states import QubitBatch


def transmittance(distance_km: float, attenuation_db_per_km: float) -> float:
    """eta = 10^(-alpha * d / 10)."""
    if distance_km < 0 or attenuation_db_per_km < 0:
        raise ValueError("distance and attenuation must be non-negative")
    return 10.0 ** (-attenuation_db_per_km * distance_km / 10.0)


@dataclass
class Transmission:
    """What reached Bob, plus ground truth about what happened on the way."""

    received: QubitBatch
    noise: PauliNoise | None
    arrived: np.ndarray  # photon survived loss
    dark: np.ndarray  # detector clicked without a photon
    eve: EveRecord | None


class QuantumChannel:
    def __init__(
        self,
        noise: PauliNoise | None = None,
        distance_km: float = 0.0,
        attenuation_db_per_km: float = 0.2,
        detector_efficiency: float = 1.0,
        dark_count_prob: float = 0.0,
        eve: InterceptResendEve | None = None,
    ):
        if not 0.0 <= detector_efficiency <= 1.0:
            raise ValueError("detector_efficiency must be in [0, 1]")
        if not 0.0 <= dark_count_prob <= 1.0:
            raise ValueError("dark_count_prob must be in [0, 1]")
        self.noise = noise
        self.distance_km = distance_km
        self.attenuation_db_per_km = attenuation_db_per_km
        self.detector_efficiency = detector_efficiency
        self.dark_count_prob = dark_count_prob
        self.eve = eve
        self.eta = transmittance(distance_km, attenuation_db_per_km) * detector_efficiency

    def transmit(
        self,
        batch: QubitBatch,
        rng: np.random.Generator,
        backend: MeasurementBackend | None = None,
    ) -> Transmission:
        """Carry ``batch`` to Bob. ``backend`` is needed only if Eve is present."""
        n = len(batch)
        eve_record = None
        out = batch.copy()
        if self.eve is not None:
            if backend is None:
                raise ValueError("an eavesdropper needs a backend to measure with")
            out, eve_record = self.eve.attack(out, rng, backend)

        arrived = out.detected.copy()
        dark = np.zeros(n, dtype=bool)
        if self.eta < 1.0:
            arrived &= rng.random(n) < self.eta
        if self.dark_count_prob > 0.0:
            dark = ~arrived & (rng.random(n) < self.dark_count_prob)
            k = int(dark.sum())
            out.bits[dark] = rng.integers(0, 2, size=k, dtype=np.uint8)
            out.bases[dark] = rng.integers(0, 2, size=k, dtype=np.uint8)
        out.detected = arrived | dark
        return Transmission(out, self.noise, arrived, dark, eve_record)
