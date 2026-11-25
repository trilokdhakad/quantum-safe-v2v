"""Shor's algorithm on Qiskit Aer: factor N = 15 (and 21) by quantum period finding.

Why it is here: ECDH/ECDSA (and RSA) -- used by PSLAP, PSRS-D2D and today's
IEEE 1609.2 -- fall to Shor's algorithm. Factoring and elliptic-curve discrete
logs share the same quantum core: finding the period of a modular function
with phase estimation and an inverse QFT. This demo runs that core for real.

Circuit: 2n counting qubits in |+>, an n-qubit work register in |1>, controlled
U^(2^k) with U|y> = |a.y mod N> (identity for y >= N), inverse QFT, measure.
A peak at s/2^(2n) gives the period r by continued fractions, then
gcd(a^(r/2) +- 1, N) are the factors.

Honest scope: the modular-multiplication oracle is built as an explicit
permutation matrix computed classically, which is exponential in n. It is fine
for N = 15 or 21 and demonstrates the quantum period-finding step; a scalable
attack needs reversible arithmetic circuits. Breaking P-256 needs about
9n + 2*ceil(log2 n) + 10 = 2330 logical qubits (Roetteler et al., ASIACRYPT
2017) -- far beyond current machines, which is why "harvest now, decrypt
later" is the practical threat.
"""

from __future__ import annotations

import math
from collections import Counter
from fractions import Fraction

import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import QFTGate, UnitaryGate
from qiskit_aer import AerSimulator

from qsv2v.attacks.common import AttackResult, Timer


def modmul_unitary(a: int, N: int, n_work: int) -> np.ndarray:
    """Permutation matrix for |y> -> |a.y mod N> on n_work qubits."""
    dim = 2**n_work
    U = np.zeros((dim, dim))
    for y in range(dim):
        U[(a * y) % N if y < N else y, y] = 1
    return U


def order_finding_circuit(a: int, N: int) -> QuantumCircuit:
    n_work = N.bit_length()
    n_count = 2 * n_work
    qc = QuantumCircuit(n_count + n_work, n_count)
    qc.h(range(n_count))
    qc.x(n_count)  # work register = |1>
    for k in range(n_count):
        power = pow(a, 2**k, N)
        gate = UnitaryGate(modmul_unitary(power, N, n_work), label=f"{a}^{2**k} mod {N}")
        qc.append(gate.control(1), [k, *range(n_count, n_count + n_work)])
    qc.append(QFTGate(n_count).inverse(), range(n_count))
    qc.measure(range(n_count), range(n_count))
    return qc


def period_from_phase(measured: int, n_count: int, N: int, a: int) -> int | None:
    if measured == 0:
        return None
    r = Fraction(measured, 2**n_count).limit_denominator(N).denominator
    # A peak may give a divisor of r; try small multiples.
    for m in range(1, N):
        if pow(a, r * m, N) == 1:
            return r * m
        if r * m > N:
            break
    return None


def shor(N: int, a: int, shots: int = 512, seed: int = 15) -> dict:
    if math.gcd(a, N) != 1:
        raise ValueError("a must be coprime with N")
    qc = order_finding_circuit(a, N)
    n_count = 2 * N.bit_length()
    sim = AerSimulator(seed_simulator=seed)
    counts = sim.run(transpile(qc, sim), shots=shots).result().get_counts()
    tally = Counter()
    for bitstring, c in counts.items():
        r = period_from_phase(int(bitstring, 2), n_count, N, a)
        if r:
            tally[r] += c
    if not tally:
        return {"a": a, "period": None, "factors": None, "counts": counts}
    r = tally.most_common(1)[0][0]
    factors = None
    if r % 2 == 0 and pow(a, r // 2, N) != N - 1:
        f = sorted({math.gcd(pow(a, r // 2) - 1, N), math.gcd(pow(a, r // 2) + 1, N)})
        f = [x for x in f if x not in (1, N)]
        if f:
            factors = (f[0], N // f[0])
    return {"a": a, "period": r, "factors": factors, "counts": counts, "qubits": qc.num_qubits}


def classical_period(a: int, N: int) -> int:
    r, v = 1, a % N
    while v != 1:
        v = (v * a) % N
        r += 1
    return r


def demo_shor(N: int = 15, seed: int = 15) -> AttackResult:
    res = AttackResult(
        "ECC/RSA family (PSLAP, PSRS-D2D, IEEE 1609.2)",
        f"Shor's algorithm factors N = {N} on Qiskit Aer",
        "classical public-key security against a quantum adversary",
        "quantum computer (simulated); period finding via phase estimation + inverse QFT",
    )
    with Timer() as t:
        runs = [shor(N, a, seed=seed) for a in range(2, N) if math.gcd(a, N) == 1]
    res.elapsed_s = t.elapsed
    found = {r["factors"] for r in runs if r["factors"]}
    p = min(d for d in range(2, N) if N % d == 0)
    res.recovered["factors"] = str(sorted(found)[0]) if found else "none"
    res.expected["factors"] = str((p, N // p))
    for r in runs:
        res.recovered[f"period of a={r['a']}"] = str(r["period"])
        res.expected[f"period of a={r['a']}"] = str(classical_period(r["a"], N))
    n_ok = sum(1 for r in runs if r["factors"])
    res.notes.append(
        f"{runs[0]['qubits']} qubits per circuit; {n_ok}/{len(runs)} bases gave the factors "
        "(the others have odd period or a^(r/2) = -1 mod N, as theory predicts)"
    )
    return res


def run_all(seed: int = 0) -> list[AttackResult]:
    return [demo_shor(15, seed + 15), demo_shor(21, seed + 21)]


if __name__ == "__main__":
    for r in run_all():
        print(r.report(), end="\n\n")
