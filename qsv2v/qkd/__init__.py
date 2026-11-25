"""BB84 quantum key distribution simulator."""

from qsv2v.qkd.backends import NumpyBackend, QiskitAerBackend, get_backend
from qsv2v.qkd.bb84 import BB84Result, prepare, run_bb84, sift
from qsv2v.qkd.channel import QuantumChannel, Transmission, transmittance
from qsv2v.qkd.estimation import QBEREstimate, estimate_qber, should_abort
from qsv2v.qkd.eve import EveRecord, InterceptResendEve
from qsv2v.qkd.noise import PauliNoise
from qsv2v.qkd.states import DIAGONAL, RECTILINEAR, QubitBatch
from qsv2v.qkd.theory import QBER_THRESHOLD, binary_entropy, expected_qber

__all__ = [
    "DIAGONAL",
    "QBER_THRESHOLD",
    "RECTILINEAR",
    "BB84Result",
    "EveRecord",
    "InterceptResendEve",
    "NumpyBackend",
    "PauliNoise",
    "QBEREstimate",
    "QiskitAerBackend",
    "QuantumChannel",
    "QubitBatch",
    "Transmission",
    "binary_entropy",
    "estimate_qber",
    "expected_qber",
    "get_backend",
    "prepare",
    "run_bb84",
    "should_abort",
    "sift",
    "transmittance",
]
