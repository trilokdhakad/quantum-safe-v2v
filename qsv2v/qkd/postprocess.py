"""Full BB84 post-processing: sifted key -> verified, private final key.

Steps (all classical communication is assumed authenticated):

1. **Parameter estimation**: disclose a random sample of the sifted key,
   estimate QBER, abort above the threshold (11%).
2. **Error correction**: Cascade on the remaining bits, counting leaked parities.
3. **Verification**: compare a 64-bit Toeplitz tag of the corrected keys; abort
   on mismatch (collision probability 2^-64).
4. **Privacy amplification**: Toeplitz-hash both keys to

       l = floor(n (1 - h(Q))) - leak_EC - tag_bits - 2 log2(1 / eps_PA)

   where n is the key length after sampling. n h(Q) bounds Eve's information
   from the quantum phase (Shor-Preskill), leak_EC + tag_bits is what the
   classical discussion revealed, and 2 log2(1/eps_PA) is the leftover-hash
   security margin.

By default Q is the sampled QBER (asymptotic analysis, which matches the
Shor-Preskill curve). With ``finite_key=True`` it is raised by the Serfling
bound so that the true error rate of the key is covered with probability
1 - eps_PE; that is more conservative and costs key at small block sizes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from qsv2v.qkd.backends import MeasurementBackend
from qsv2v.qkd.bb84 import BB84Result, run_bb84
from qsv2v.qkd.cascade import CascadeResult, cascade
from qsv2v.qkd.channel import QuantumChannel
from qsv2v.qkd.estimation import (
    QBEREstimate,
    estimate_qber,
    finite_size_correction,
    should_abort,
)
from qsv2v.qkd.privacy_amp import (
    privacy_amplify,
    random_seed_bits,
    toeplitz_hash,
    verification_tag,
)
from qsv2v.qkd.theory import QBER_THRESHOLD, binary_entropy


@dataclass(frozen=True)
class PostProcessingConfig:
    sample_fraction: float = 0.1
    min_sample: int = 0
    qber_threshold: float = QBER_THRESHOLD
    cascade_passes: int = 4
    cascade_min_qber: float = 0.01
    tag_bits: int = 64
    eps_pa: float = 1e-10
    finite_key: bool = False
    eps_pe: float = 1e-10

    @property
    def security_margin(self) -> int:
        return math.ceil(2 * math.log2(1 / self.eps_pa))


ABORT_QBER = "qber_above_threshold"
ABORT_VERIFY = "verification_failed"
ABORT_NO_KEY = "no_secret_key"


@dataclass
class QKDResult:
    bb84: BB84Result
    config: PostProcessingConfig
    estimate: QBEREstimate
    aborted: bool = False
    abort_reason: str | None = None
    alice_reconciled: np.ndarray | None = None
    bob_reconciled: np.ndarray | None = None
    cascade: CascadeResult | None = None
    verified: bool = False
    qber_for_pa: float = 0.0
    final_length: int = 0
    alice_final: np.ndarray = field(default_factory=lambda: np.zeros(0, np.uint8))
    bob_final: np.ndarray = field(default_factory=lambda: np.zeros(0, np.uint8))

    @property
    def n_key(self) -> int:
        """Sifted bits left after the QBER sample was discarded."""
        return int(self.estimate.keep_mask.sum())

    @property
    def leaked_ec(self) -> int:
        return self.cascade.leaked_bits if self.cascade else 0

    @property
    def keys_match(self) -> bool:
        return (
            not self.aborted
            and self.final_length > 0
            and np.array_equal(self.alice_final, self.bob_final)
        )

    @property
    def residual_errors(self) -> int:
        """Errors left after Cascade (simulator ground truth)."""
        if self.alice_reconciled is None:
            return 0
        return int(np.count_nonzero(self.alice_reconciled != self.bob_reconciled))

    @property
    def true_qber(self) -> float:
        """Actual error rate of the post-sample key (simulator ground truth)."""
        keep = self.estimate.keep_mask
        a, b = self.bb84.alice_key[keep], self.bb84.bob_key[keep]
        return float(np.mean(a != b)) if a.size else 0.0

    @property
    def ec_efficiency(self) -> float:
        """f = leaked / (n h(Q_true)); 1.0 is the Shannon limit."""
        h = binary_entropy(self.true_qber)
        if self.cascade is None or not self.n_key or h <= 0:
            return float("nan")
        return self.leaked_ec / (self.n_key * h)

    @property
    def key_fraction(self) -> float:
        """Final bits per post-sample sifted bit."""
        return self.final_length / self.n_key if self.n_key else 0.0

    @property
    def secret_key_rate(self) -> float:
        """Final bits per photon sent."""
        return self.final_length / self.bb84.n_sent if self.bb84.n_sent else 0.0


def final_key_length(
    n: int, qber: float, leaked_ec: int, tag_bits: int, security_margin: int
) -> int:
    """l = floor(n (1 - h(Q))) - leak_EC - tag_bits - margin, floored at 0."""
    l_ = math.floor(n * (1 - binary_entropy(qber))) - leaked_ec - tag_bits - security_margin
    return max(0, l_)


def postprocess(
    bb84: BB84Result,
    rng: np.random.Generator,
    config: PostProcessingConfig | None = None,
) -> QKDResult:
    cfg = config or PostProcessingConfig()
    alice, bob = bb84.alice_key, bb84.bob_key

    # 1. Parameter estimation.
    est = estimate_qber(alice, bob, rng, cfg.sample_fraction, cfg.min_sample)
    res = QKDResult(bb84=bb84, config=cfg, estimate=est)
    if should_abort(est, cfg.qber_threshold):
        res.aborted, res.abort_reason = True, ABORT_QBER
        return res
    alice, bob = alice[est.keep_mask], bob[est.keep_mask]

    # 2. Error correction.
    ec = cascade(alice, bob, est.qber, rng, cfg.cascade_passes, min_qber=cfg.cascade_min_qber)
    res.cascade = ec
    res.alice_reconciled, res.bob_reconciled = alice, ec.corrected

    # 3. Verification.
    seed = random_seed_bits(alice.size, cfg.tag_bits, rng)
    res.verified = np.array_equal(
        verification_tag(alice, seed, cfg.tag_bits),
        verification_tag(ec.corrected, seed, cfg.tag_bits),
    )
    if not res.verified:
        res.aborted, res.abort_reason = True, ABORT_VERIFY
        return res

    # 4. Privacy amplification.
    q = est.qber
    if cfg.finite_key:
        q = min(0.5, q + finite_size_correction(alice.size, est.n_sample, cfg.eps_pe))
    res.qber_for_pa = q
    res.final_length = final_key_length(
        alice.size, q, ec.leaked_bits, cfg.tag_bits, cfg.security_margin
    )
    if res.final_length == 0:
        res.aborted, res.abort_reason = True, ABORT_NO_KEY
        return res
    # One public seed, used by both sides.
    res.alice_final, pa_seed = privacy_amplify(alice, res.final_length, rng)
    res.bob_final = toeplitz_hash(ec.corrected, pa_seed, res.final_length)
    return res


def run_qkd(
    n: int,
    backend: MeasurementBackend | None = None,
    channel: QuantumChannel | None = None,
    config: PostProcessingConfig | None = None,
    seed: int | None = None,
) -> QKDResult:
    """End-to-end BB84: quantum transmission, sifting, and post-processing."""
    rng = np.random.default_rng(seed)
    return postprocess(run_bb84(n, backend, channel, rng=rng), rng, config)
