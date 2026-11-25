# QSV2V

A simulation framework for quantum-safe authentication and key exchange in
vehicle-to-vehicle (V2V) networks: BB84 quantum key distribution and
post-quantum cryptography (ML-KEM / ML-DSA). The project plan is in
[`Quantum-Safe V2V Communication — Project Plan.md`](Quantum-Safe%20V2V%20Communication%20—%20Project%20Plan.md).

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Repo setup, BB84 core (Qiskit Aer + NumPy backends) | Done |
| 2 | Channel noise, photon loss, intercept-resend Eve | Not started |
| 3 | Cascade, privacy amplification | Not started |
| 4 | Attacks on the three base papers | Not started |
| 5 | PQ-V2V-AKE protocol | Not started |
| 6 | V2V network simulation | Not started |
| 7 | Experiments E1–E10 | Not started |
| 8 | Dashboard (optional) | Not started |
| 9 | Report | Not started |

## Setup

Python 3.11+.

```bash
python -m venv .venv            # or: uv venv --python 3.12 .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

## Layout

```
qsv2v/
├── qkd/            BB84 simulator
│   ├── states.py       QubitBatch: bits + bases (+ detection mask) in flight
│   ├── channel.py      QuantumChannel (ideal in Phase 1; noise/loss/Eve hook)
│   ├── bb84.py         prepare -> transmit -> measure -> sift; BB84Result
│   └── backends/       numpy_backend.py, qiskit_backend.py
├── attacks/  pqc/  sim/   later phases
experiments/  verification/  dashboard/  results/  docs/
tests/              pytest suite, one file per module
```

## BB84 quickstart

```python
from qsv2v.qkd import run_bb84, get_backend

res = run_bb84(10_000, backend=get_backend("qiskit"), seed=42)
print(res.sifted_length, res.sift_ratio, res.qber)
assert (res.alice_key == res.bob_key).all()
```

### Backends

- **`qiskit`**: every qubit is a real circuit on Qiskit Aer: `X` for bit 1,
  `H` for the diagonal basis, `H` again if Bob measures diagonally, then a
  measurement. Qubits are batched (500 per circuit by default) and simulated
  with Aer's stabilizer method, which handles that width because all gates are
  Clifford. Use it to check correctness and for small demos.
- **`numpy`**: samples the same Born-rule statistics directly (same basis gives
  the encoded bit; the other basis gives a fair coin). Use it for large runs.

Both draw all randomness from one `numpy.random.Generator`, so a seed fixes
the whole run. The Aer simulator seed is derived from that generator.

### Phase 1 results (measured, seed 42)

| Backend | Photons | Sifted | Sift ratio | Errors | Time |
| --- | --- | --- | --- | --- | --- |
| numpy | 1,000,000 | 500,034 | 0.5000 | 0 | 0.06 s |
| qiskit | 20,000 | 10,014 | 0.5007 | 0 | 1.08 s |

The test suite checks the Phase 1 "done when" criteria on both backends: on an
ideal channel the sifted keys match 100%, and the sift ratio is within 4σ of
0.5. It also checks that each of the four BB84 states reads back correctly,
that measuring in the other basis gives uniform outcomes, that the two
backends agree statistically, and that runs repeat exactly under a fixed seed.
