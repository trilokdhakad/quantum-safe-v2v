"""Qiskit Aer backend: real circuits for every BB84 qubit.

Each qubit is prepared as ``|0>`` / ``|1>`` (X for bit 1), rotated with H when
the sender's basis is diagonal, passed through the channel's Pauli noise (an
Aer ``pauli_error`` instruction), rotated with H again when the receiver
measures in the diagonal basis, then measured in the computational basis.

The qubits never interact, so many are batched into one circuit. All gates and
errors are Clifford/Pauli, so Aer's stabilizer method simulates hundreds of
qubits per circuit in polynomial time (a statevector of that width would be
impossible).
"""

from __future__ import annotations

import numpy as np
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit_aer import AerSimulator

from qsv2v.qkd.backends.base import MeasurementBackend
from qsv2v.qkd.noise import PauliNoise


def build_bb84_circuit(
    bits: np.ndarray,
    prep_bases: np.ndarray,
    meas_bases: np.ndarray,
    noise: PauliNoise | None = None,
) -> QuantumCircuit:
    """One circuit: qubit i carries bits[i] in prep_bases[i], read in meas_bases[i]."""
    n = len(bits)
    qr = QuantumRegister(n, "q")
    cr = ClassicalRegister(n, "c")
    qc = QuantumCircuit(qr, cr)
    for i in range(n):
        if bits[i]:
            qc.x(i)
        if prep_bases[i]:
            qc.h(i)
    qc.barrier()  # sender -> channel
    if noise is not None and not noise.is_trivial:
        err = noise.to_qiskit_error()
        for i in range(n):
            qc.append(err, [i])
        qc.barrier()  # channel -> receiver
    for i in range(n):
        if meas_bases[i]:
            qc.h(i)
    qc.measure(qr, cr)
    return qc


class QiskitAerBackend(MeasurementBackend):
    """Measures BB84 states by simulating circuits on Qiskit Aer."""

    name = "qiskit"

    def __init__(self, qubits_per_circuit: int = 500, method: str = "stabilizer"):
        if qubits_per_circuit < 1:
            raise ValueError("qubits_per_circuit must be positive")
        self.qubits_per_circuit = qubits_per_circuit
        self.method = method

    def _measure(self, bits, prep_bases, meas_bases, rng, noise):
        n = bits.size
        chunk = self.qubits_per_circuit
        starts = range(0, n, chunk)
        circuits = [
            build_bb84_circuit(
                bits[s : s + chunk],
                prep_bases[s : s + chunk],
                meas_bases[s : s + chunk],
                noise,
            )
            for s in starts
        ]
        # Derive the simulator seed from the caller's RNG so runs are reproducible.
        seed = int(rng.integers(0, 2**31 - 1))
        sim = AerSimulator(method=self.method, seed_simulator=seed)
        result = sim.run(circuits, shots=1, memory=True).result()
        out = np.empty(n, dtype=np.uint8)
        for s, qc in zip(starts, circuits, strict=True):
            # Qiskit bitstrings are little-endian: qubit 0 is the rightmost char.
            bitstring = result.get_memory(qc)[0]
            k = qc.num_qubits
            out[s : s + k] = np.frombuffer(bitstring[::-1].encode(), dtype=np.uint8) - ord("0")
        return out
