"""BB84 quantum key distribution simulator."""

from qsv2v.qkd.backends import NumpyBackend, QiskitAerBackend, get_backend
from qsv2v.qkd.bb84 import BB84Result, prepare, run_bb84, sift
from qsv2v.qkd.cascade import CascadeResult, cascade
from qsv2v.qkd.channel import QuantumChannel, Transmission, transmittance
from qsv2v.qkd.estimation import QBEREstimate, estimate_qber, should_abort
from qsv2v.qkd.eve import EveRecord, InterceptResendEve
from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.postprocess import PostProcessingConfig, QKDResult, postprocess, run_qkd
from qsv2v.qkd.privacy_amp import privacy_amplify, toeplitz_hash
from qsv2v.qkd.states import DIAGONAL, RECTILINEAR, QubitBatch
from qsv2v.qkd.theory import QBER_THRESHOLD, binary_entropy, expected_qber

__all__ = [
    "DIAGONAL",
    "QBER_THRESHOLD",
    "RECTILINEAR",
    "BB84Result",
    "CascadeResult",
    "EveRecord",
    "InterceptResendEve",
    "NumpyBackend",
    "PauliNoise",
    "PostProcessingConfig",
    "QKDResult",
    "QBEREstimate",
    "QiskitAerBackend",
    "QuantumChannel",
    "QubitBatch",
    "Transmission",
    "binary_entropy",
    "cascade",
    "estimate_qber",
    "expected_qber",
    "get_backend",
    "postprocess",
    "prepare",
    "privacy_amplify",
    "run_bb84",
    "run_qkd",
    "should_abort",
    "sift",
    "toeplitz_hash",
    "transmittance",
]
