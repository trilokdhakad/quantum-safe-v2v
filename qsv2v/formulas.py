"""Closed-form results derived in report/math/, as code, so tests can check them.

Every function here is the end point of a derivation written out step by step
in ``report/math/`` (the section is named in each docstring). The tests in
``tests/test_formulation.py`` check each one against the simulator, the
protocol encodings or the cryptographic libraries, and
``scripts/build_math_tables.py`` puts the "theory vs measured" tables into the
report from these functions and the recorded experiment results.

Nothing here is used by the simulator itself: it is the independent
prediction the simulator is checked against.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from itertools import product

from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.theory import QBER_THRESHOLD, binary_entropy, detection_probability, expected_qber
from qsv2v.sim.radio import RadioConfig


# =============================================================================
# 1. BB84  (report/math/01_qkd.md)
# =============================================================================
def sift_probability() -> Fraction:
    """P(Bob's basis = Alice's basis) = 1/2  (section 1.2)."""
    return sum((Fraction(1, 4) for a, b in product((0, 1), repeat=2) if a == b), Fraction(0))


def qber_by_enumeration(e_rect: Fraction, e_diag: Fraction, f: Fraction) -> Fraction:
    """Exact QBER on sifted bits, by enumerating every branch of the event tree (section 1.3).

    Independent of the closed form: it walks Alice's basis, whether Eve
    intercepts, Eve's basis, Eve's outcome and the channel's Pauli error, and
    adds up the probability that Bob's sifted bit differs from Alice's. Inputs
    are exact fractions so the result can be compared with the closed form
    exactly, not to a tolerance.
    """
    half = Fraction(1, 2)
    err = Fraction(0)
    for alice_basis in (0, 1):
        e = e_rect if alice_basis == 0 else e_diag
        e_conj = e_diag if alice_basis == 0 else e_rect
        p_basis = half  # conditioned on sifting, both bases equally likely
        # Branch 1: no interception. Bob errs iff the channel flips the state.
        err += p_basis * (1 - f) * e
        # Branch 2: interception, Eve's basis is Alice's. She reads the bit exactly
        # and resends the same state; Bob errs iff the channel flips it.
        err += p_basis * f * half * e
        # Branch 3: interception, conjugate basis. Eve gets a fair coin c and resends
        # c in the conjugate basis. A Pauli error keeps a BB84 state in its basis
        # (flipping it with probability e_conj), so Bob, measuring in Alice's basis,
        # gets a fair coin whatever the channel did.
        for _eve_outcome, flipped in product((0, 1), (False, True)):
            p = half * (e_conj if flipped else 1 - e_conj)
            err += p_basis * f * half * p * half
    return err


def qber_closed_form(e: float, f: float) -> float:
    """Q = e + f/4 - f e/2 for symmetric noise e and intercept fraction f (section 1.3)."""
    return e + f / 4 - f * e / 2


def abort_fraction(e: float, threshold: float = QBER_THRESHOLD) -> float:
    """Intercept fraction at which the expected QBER reaches the abort threshold (section 1.4).

    Solve e + f/4 - f e/2 = Q_th for f:  f* = (Q_th - e) / (1/4 - e/2).
    """
    return (threshold - e) / (0.25 - e / 2)


def qber_sample_sigma(q: float, m: int) -> float:
    """Standard deviation of the QBER estimate from m disclosed bits: sqrt(Q(1-Q)/m)."""
    return math.sqrt(q * (1 - q) / m)


def abort_probability(q: float, m: int, threshold: float = QBER_THRESHOLD) -> float:
    """P(sampled QBER > threshold), normal approximation to Binomial(m, q)/m (section 1.4)."""
    s = qber_sample_sigma(q, m)
    if s == 0:
        return float(q > threshold)
    return 0.5 * math.erfc((threshold - q) / (s * math.sqrt(2)))


def key_fraction(q: float, f_ec: float = 1.0) -> float:
    """Asymptotic secret bits per sifted bit: r = 1 - h(Q) - f h(Q) (section 1.6)."""
    return 1.0 - (1.0 + f_ec) * float(binary_entropy(q))


def zero_key_qber(f_ec: float = 1.0) -> float:
    """QBER at which r = 1 - (1 + f) h(Q) reaches zero, by bisection (section 1.6).

    f = 1 (a perfect code) gives the Shor-Preskill limit 1 - 2h(Q) = 0, Q = 11.0%.
    """
    lo, hi = 1e-9, 0.5
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if key_fraction(mid, f_ec) > 0:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def key_fraction_sampling_sigma(q: float, m: float) -> float:
    """Run-to-run spread of the key fraction from estimating Q on m sample bits (section 1.6).

    Privacy amplification uses the sampled QBER q_s, with sd sqrt(Q(1-Q)/m), so
    the fraction moves by h'(Q) times that: sigma_r = log2((1-Q)/Q) sqrt(Q(1-Q)/m).
    """
    return math.log2((1 - q) / q) * math.sqrt(q * (1 - q) / m)


def prob_positive(mu: float, sigma: float) -> float:
    """P(mu + sigma Z > 0) for standard normal Z: Phi(mu / sigma)."""
    return 0.5 * math.erfc(-mu / (sigma * math.sqrt(2)))


def clipped_mean(mu: float, sigma: float) -> float:
    """E[max(0, mu + sigma Z)] = mu Phi(mu/sigma) + sigma phi(mu/sigma) (section 1.6).

    The pipeline floors the final key length at 0, so near the threshold the
    mean over runs stays positive after the mean of the unclipped values has
    crossed zero.
    """
    z = mu / sigma
    return mu * prob_positive(mu, sigma) + sigma * math.exp(-z * z / 2) / math.sqrt(2 * math.pi)


def finite_key_overhead(n: int, tag_bits: int = 64, eps_pa: float = 1e-10) -> float:
    """Fixed bits removed per sifted bit: (tag + ceil(2 log2(1/eps_PA))) / n (section 1.6)."""
    return (tag_bits + math.ceil(2 * math.log2(1 / eps_pa))) / n


def cascade_odd_block_prob(q: float, k: int) -> float:
    """P(a block of k bits holds an odd number of errors) = (1 - (1 - 2Q)^k) / 2 (section 1.5)."""
    return 0.5 * (1.0 - (1.0 - 2.0 * q) ** k)


def cascade_binary_leak(k: int) -> int:
    """Parities disclosed by one BINARY search in a block of k bits: ceil(log2 k) (section 1.5)."""
    return math.ceil(math.log2(k)) if k > 1 else 0


@dataclass(frozen=True)
class LinkModel:
    """The E3 channel: fibre-like loss, detector efficiency, dark counts, intrinsic error."""

    alpha_db_per_km: float = 0.2
    detector_efficiency: float = 0.2
    dark_count_prob: float = 1e-5
    intrinsic_error: float = 0.01
    f_ec: float = 1.16

    def eta(self, d_km: float) -> float:
        """eta(d) = eta_det * 10^(-alpha d / 10)  (section 1.7)."""
        return self.detector_efficiency * 10 ** (-self.alpha_db_per_km * d_km / 10)

    def qber(self, d_km: float) -> float:
        noise = PauliNoise.from_qber(self.intrinsic_error)
        return expected_qber(noise, 0.0, self.eta(d_km), self.dark_count_prob)

    def key_rate(self, d_km: float) -> float:
        """R(d) = (p_click / 2) * max(0, 1 - (1 + f) h(Q(d)))  bits per pulse (section 1.7)."""
        p = detection_probability(self.eta(d_km), self.dark_count_prob)
        return p / 2 * max(0.0, key_fraction(self.qber(d_km), self.f_ec))

    def cutoff_km(self) -> float:
        """Distance where the key rate first reaches zero (bisection on Q(d) = zero_key_qber)."""
        lo, hi = 0.0, 1000.0
        for _ in range(200):
            mid = 0.5 * (lo + hi)
            if key_fraction(self.qber(mid), self.f_ec) > 0:
                lo = mid
            else:
                hi = mid
        return 0.5 * (lo + hi)


# =============================================================================
# 2. Attacks on the base papers  (report/math/02_attacks.md)
# =============================================================================
def solve_master_keys(c1: int, c2: int, h1: int, h2: int, q: int) -> tuple[int, int]:
    """PSRS-D2D: from Cert_a = S + h_a x  (S = Pr_TA + MK_TA, x = Pr_TA), recover (x, MK_TA).

    Two certificates: x = (c1 - c2)(h1 - h2)^-1 mod q, MK_TA = c1 - x (1 + h1) mod q.
    Needs h1 != h2 mod q (section 2.1.3).
    """
    if (h1 - h2) % q == 0:
        raise ValueError("h1 = h2 mod q: the two equations are dependent")
    x = (c1 - c2) * pow(h1 - h2, -1, q) % q
    return x, (c1 - x * (1 + h1)) % q


def expected_guesses(dictionary_size: int) -> float:
    """Offline guessing with a uniform secret from a dictionary of size D: (D + 1) / 2 tries."""
    return (dictionary_size + 1) / 2


# =============================================================================
# 3. Sizes from the parameter sets  (report/math/05_security_parameters.md, 04_network.md)
# =============================================================================
def mlkem_sizes(k: int, du: int, dv: int) -> dict[str, int]:
    """FIPS 203 sizes: ek = 384k + 32, dk = 768k + 96, ct = 32(du k + dv), ss = 32."""
    return {"ek": 384 * k + 32, "dk": 768 * k + 96, "ct": 32 * (du * k + dv), "ss": 32}


def mldsa_sizes(k: int, l: int, q: int, d: int, gamma1: int, omega: int, lam: int) -> dict:  # noqa: E741
    """FIPS 204 sizes.

    pk = 32 + 32k(bitlen(q-1) - d);  sig = lam/4 + 32l(1 + bitlen(gamma1-1)) + omega + k.
    """
    pk = 32 + 32 * k * ((q - 1).bit_length() - d)
    sig = lam // 4 + 32 * l * (1 + (gamma1 - 1).bit_length()) + omega + k
    return {"pk": pk, "sig": sig}


def falcon_pk_size(n: int, q: int = 12289) -> int:
    """Falcon public key: 1 header byte + n coefficients of ceil(log2 q) = 14 bits."""
    return 1 + n * math.ceil(math.log2(q)) // 8


def lp(n: int) -> int:
    """A length-prefixed field on the wire: 4-byte length + n bytes."""
    return 4 + n


CERT_DOMAIN_LEN = len(b"QSV2V-PSEUDONYM-CERT-v1")  # 23
PSEUDONYM_LEN, ISSUER_LEN, NONCE_LEN, MAC_LEN = 16, 8, 32, 32


def cert_size(alg_name: str, pk: int, ca_sig: int) -> int:
    """Certificate size.

    |cert| = 23 + lp(16) + lp(|alg|) + lp(pk) + 8 + 8 + lp(8) + lp(sig_CA) = 83 + |alg| + pk + sig.
    """
    return (
        CERT_DOMAIN_LEN + lp(PSEUDONYM_LEN) + lp(len(alg_name)) + lp(pk) + 16
        + lp(ISSUER_LEN) + lp(ca_sig)
    )  # fmt: skip


def handshake_sizes(ek: int, ct: int, cert: int, sig: int, x_pub: int = 0) -> dict[str, int]:
    """PQ-V2V-AKE message sizes (section 4.2).

    m1 = 2 + lp(ek) + lp(x) + lp(cert) + lp(32) + 8 + lp(sig)            = 62 + ek + x + cert + sig
    m2 = 2 + lp(ct) + lp(x) + lp(cert) + lp(32) + 8 + lp(sig) + lp(32)   = 98 + ct + x + cert + sig
    m3 = 2 + lp(32)                                                      = 38
    """
    m1 = 2 + lp(ek) + lp(x_pub) + lp(cert) + lp(NONCE_LEN) + 8 + lp(sig)
    m2 = 2 + lp(ct) + lp(x_pub) + lp(cert) + lp(NONCE_LEN) + 8 + lp(sig) + lp(MAC_LEN)
    return {"m1": m1, "m2": m2, "m3": 2 + lp(MAC_LEN)}


def bsm_size(alg_name: str, payload: int, sig: int, cert: int | None = None) -> int:
    """Signed safety message: 3 + lp(alg) + 8 + 1 + lp(signer) + lp(payload) + lp(sig).

    signer = 8-byte certificate digest, or the full certificate.
    """
    signer = 8 if cert is None else cert
    return 3 + lp(len(alg_name)) + 8 + 1 + lp(signer) + lp(payload) + lp(sig)


# =============================================================================
# 4. Radio channel and handshake latency  (report/math/04_network.md)
# =============================================================================
def frame_time(n: int, unicast: bool, cfg: RadioConfig | None = None) -> float:
    """Expected time to send one frame of n payload bytes on an idle channel (section 4.3).

    t = AIFS + (CW_min / 2) slot + T_air(n) [+ T_ack for unicast], with
    T_air(n) = T_PHY + 8 (n + h_MAC) / R and T_ack = SIFS + T_PHY + 8 * 14 / R.
    Unicast handshake frames use AC_BE, broadcast safety messages AC_VO.
    """
    cfg = cfg or RadioConfig()
    aifs, cw, _ = cfg.access_params(best_effort=unicast)
    t = aifs + cw / 2 * cfg.slot + cfg.airtime(n)
    return t + (cfg.ack_time if unicast else 0.0)


def message_time(size: int, unicast: bool, cfg: RadioConfig | None = None) -> float:
    """Sum of frame_time over the ceil(size / 1400) fragments of a message."""
    cfg = cfg or RadioConfig()
    return sum(frame_time(f, unicast, cfg) for f in cfg.fragments(size))


def handshake_latency_zero_load(
    sizes: tuple[int, int, int],
    compute_s: tuple[float, float, float, float],
    cfg: RadioConfig | None = None,
) -> float:
    """Expected handshake latency on an idle channel with no frame loss (section 4.4).

    L0 = t_init + t_m1 + t_resp + t_m2 + t_fin + t_m3 + t_conf.
    """
    return sum(compute_s) + sum(message_time(s, True, cfg) for s in sizes)


def bytes_on_air(size: int, cfg: RadioConfig | None = None) -> int:
    """Payload plus per-frame MAC overhead: S + h_MAC * ceil(S / 1400)."""
    cfg = cfg or RadioConfig()
    return size + cfg.mac_overhead * len(cfg.fragments(size))


def bsm_airtime_mean(digest_size: int, cert_size_: int, cert_every: int = 10,
                     cfg: RadioConfig | None = None) -> float:  # fmt: skip
    """Mean on-air time of one safety message: (T(cert msg) + (c - 1) T(digest msg)) / c."""
    cfg = cfg or RadioConfig()

    def t(s):
        return sum(cfg.airtime(f) for f in cfg.fragments(s))

    return (t(cert_size_) + (cert_every - 1) * t(digest_size)) / cert_every


def offered_load(n_vehicles: int, digest_size: int, cert_size_: int, rate_hz: float = 10.0,
                 road_m: float = 2000.0, cfg: RadioConfig | None = None) -> float:  # fmt: skip
    """Channel busy ratio predicted for broadcast-only traffic (section 4.5).

    A vehicle senses every transmission from within cs_range along the ring, so
    it hears a share 2 cs_range / L of the N vehicles (itself included):
    rho = (2 cs_range / L) N r E[T_BSM]. Valid while rho is well below 1
    (CSMA keeps transmissions from overlapping, so busy time adds up).
    """
    cfg = cfg or RadioConfig()
    share = min(1.0, 2 * cfg.cs_range / road_m)
    return share * n_vehicles * rate_hz * bsm_airtime_mean(digest_size, cert_size_, cfg=cfg)


# =============================================================================
# 5. Classical and quantum attack costs  (report/math/05_security_parameters.md)
# =============================================================================
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def pollard_rho_bits(group_order: int) -> float:
    """log2 of the expected group operations for Pollard rho: sqrt(pi n / 4)."""
    return 0.5 * math.log2(math.pi * group_order / 4)


def grover_bits(key_bits: int) -> float:
    """log2 of Grover iterations for a k-bit key search: (pi/4) 2^(k/2)."""
    return math.log2(math.pi / 4) + key_bits / 2


def birthday_bits(out_bits: int) -> float:
    """log2 of the expected evaluations to find a collision: sqrt(pi 2^n / 2)."""
    return 0.5 * math.log2(math.pi / 2) + out_bits / 2


def roetteler_qubits(n: int) -> int:
    """Logical qubits for Shor's ECDLP on an n-bit prime curve: 9n + 2 ceil(log2 n) + 10."""
    return 9 * n + 2 * math.ceil(math.log2(n)) + 10
