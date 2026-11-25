"""Closed-form predictions used to validate the simulator.

Expected QBER with noise, intercept-resend and dark counts
----------------------------------------------------------
Let e_b be the noise error probability in basis b and f Eve's intercept
fraction. On a sifted signal bit in basis b:

* Eve did not attack (prob 1-f): error e_b.
* Eve attacked with the right basis (prob f/2): she resends the right state,
  noise then flips it with prob e_b.
* Eve attacked with the wrong basis (prob f/2): she resends a conjugate-basis
  state; Pauli noise keeps it in that basis, so Bob's result is a fair coin.

    Q_b = (1-f) e_b + (f/2) e_b + (f/2)(1/2) = e_b + f/4 - f e_b / 2

averaged over the two bases. The plan's "noise + 0.25 f" is the first-order
form of this; the -f e/2 cross term is real and the tests check it.

Dark counts (prob p_d per pulse when no photon arrives) are fair coins:

    Q = [eta Q_sig + (1-eta) p_d / 2] / [eta + (1-eta) p_d]
"""

from __future__ import annotations

import numpy as np

from qsv2v.qkd.noise import PauliNoise


def binary_entropy(p) -> np.ndarray | float:
    """h(p) = -p log2 p - (1-p) log2 (1-p), with h(0) = h(1) = 0."""
    p = np.asarray(p, dtype=float)
    with np.errstate(divide="ignore", invalid="ignore"):
        h = -p * np.log2(p) - (1 - p) * np.log2(1 - p)
    h = np.where((p <= 0) | (p >= 1), 0.0, h)
    return float(h) if h.ndim == 0 else h


def detection_probability(eta: float, dark_count_prob: float = 0.0) -> float:
    """Probability Bob registers a click for one pulse."""
    return eta + (1 - eta) * dark_count_prob


def expected_qber(
    noise: PauliNoise | None = None,
    eve_fraction: float = 0.0,
    eta: float = 1.0,
    dark_count_prob: float = 0.0,
) -> float:
    noise = noise or PauliNoise()
    f = eve_fraction
    q_sig = np.mean([e + f / 4 - f * e / 2 for e in (noise.error_prob(0), noise.error_prob(1))])
    p_click = detection_probability(eta, dark_count_prob)
    if p_click == 0:
        return 0.0
    return float((eta * q_sig + (1 - eta) * dark_count_prob * 0.5) / p_click)


def asymptotic_key_fraction(q, ec_efficiency: float = 1.0):
    """Shor-Preskill secret fraction per sifted bit: 1 - h(Q) - f_EC h(Q), floored at 0."""
    r = 1 - binary_entropy(q) - ec_efficiency * binary_entropy(q)
    return np.maximum(r, 0.0)


QBER_THRESHOLD = 0.11
"""Abort threshold: 1 - 2h(Q) = 0 at Q ~ 11.0% (Shor-Preskill)."""
