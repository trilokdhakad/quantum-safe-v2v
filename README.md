# QSV2V

A simulation framework for quantum-safe authentication and key exchange in
vehicle-to-vehicle (V2V) networks: BB84 quantum key distribution and
post-quantum cryptography (ML-KEM / ML-DSA). The project plan is in
[`Quantum-Safe V2V Communication — Project Plan.md`](Quantum-Safe%20V2V%20Communication%20—%20Project%20Plan.md).

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Repo setup, BB84 core (Qiskit Aer + NumPy backends) | Done |
| 2 | Channel noise, photon loss, intercept-resend Eve | Done |
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
│   ├── channel.py      QuantumChannel: Eve -> loss + dark counts -> Pauli noise
│   ├── noise.py        PauliNoise (bit-flip, phase-flip, depolarising, general)
│   ├── eve.py          InterceptResendEve (attacks a chosen fraction of photons)
│   ├── estimation.py   QBER on a disclosed random sample; abort rule
│   ├── theory.py       closed-form expected QBER, binary entropy, key rate
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

## Channel realism and the eavesdropper (Phase 2)

```python
from qsv2v.qkd import (
    QuantumChannel,
    PauliNoise,
    InterceptResendEve,
    run_bb84,
    estimate_qber,
    should_abort,
    expected_qber,
)
import numpy as np

ch = QuantumChannel(
    noise=PauliNoise.from_qber(0.03),  # or bit_flip(p), phase_flip(p), depolarizing(p)
    distance_km=20,
    attenuation_db_per_km=0.2,
    detector_efficiency=0.8,
    dark_count_prob=1e-5,
    eve=InterceptResendEve(fraction=0.5),
)
res = run_bb84(100_000, channel=ch, seed=1)
est = estimate_qber(res.alice_key, res.bob_key, np.random.default_rng(2), sample_fraction=0.1)
print(est.qber, should_abort(est), expected_qber(ch.noise, 0.5, ch.eta, 1e-5))
```

Channel model, in order along the link:

1. **Eve** (optional) sits at Alice's output. She attacks each photon with
   probability `fraction`: she measures it in a random basis on the same
   backend Bob uses (a real circuit on Qiskit) and resends her result in her
   basis.
2. **Loss**: the photon survives with η = 10^(−α·d/10) × detector efficiency.
3. **Dark counts**: a lost photon still gives a click with probability
   `dark_count_prob`, and that click's outcome is random.
4. **Noise**: a Pauli channel. On Qiskit it is an Aer `pauli_error` inside the
   circuit; NumPy samples the same Paulis. X and Y flip rectilinear states; Z
   and Y flip diagonal ones.

**Expected QBER.** With noise error e (per basis) and Eve fraction f, the error
rate on sifted bits is

  Q = e + f/4 − f·e/2

The plan's "noise + 0.25 × f" is the first-order form. The −f·e/2 cross term
is real: when Eve guesses the wrong basis, Bob's result is already random, so
noise cannot add errors to those bits. At e = 8% and f = 1 the linear form
overestimates by 4 points, about 30σ at 100k sifted bits. The tests check that
the simulator follows the exact form and not the linear one. Dark counts add
random-outcome clicks:
Q = [η·Q_sig + (1−η)·p_d/2] / [η + (1−η)·p_d].

**Abort rule.** Alice and Bob disclose a random sample of the sifted key (10%
by default) and abort if the sampled QBER exceeds 11%, where the Shor–Preskill
key rate reaches zero. A pure intercept-resend attack is caught when it
touches more than about 44% of photons (0.11 / 0.25).

### Phase 2 results (measured, NumPy, 200,000 photons, seed 20261125)

Depolarising noise e × Eve fraction f. z = (measured − exact) / σ.

| e | f | Measured QBER | Exact Q | Linear e + f/4 | z |
| --- | --- | --- | --- | --- | --- |
| 0.00 | 0.00 | 0.0000 | 0.0000 | 0.0000 | — |
| 0.00 | 0.25 | 0.0612 | 0.0625 | 0.0625 | −1.66 |
| 0.00 | 0.50 | 0.1253 | 0.1250 | 0.1250 | +0.25 |
| 0.00 | 0.75 | 0.1868 | 0.1875 | 0.1875 | −0.56 |
| 0.00 | 1.00 | 0.2495 | 0.2500 | 0.2500 | −0.37 |
| 0.02 | 0.00 | 0.0198 | 0.0200 | 0.0200 | −0.36 |
| 0.02 | 0.25 | 0.0793 | 0.0800 | 0.0825 | −0.83 |
| 0.02 | 0.50 | 0.1394 | 0.1400 | 0.1450 | −0.54 |
| 0.02 | 0.75 | 0.1997 | 0.2000 | 0.2075 | −0.25 |
| 0.02 | 1.00 | 0.2604 | 0.2600 | 0.2700 | +0.28 |
| 0.05 | 0.00 | 0.0492 | 0.0500 | 0.0500 | −1.09 |
| 0.05 | 0.25 | 0.1049 | 0.1062 | 0.1125 | −1.37 |
| 0.05 | 0.50 | 0.1620 | 0.1625 | 0.1750 | −0.45 |
| 0.05 | 0.75 | 0.2184 | 0.2188 | 0.2375 | −0.30 |
| 0.05 | 1.00 | 0.2750 | 0.2750 | 0.3000 | −0.03 |
| 0.08 | 0.00 | 0.0780 | 0.0800 | 0.0800 | −2.31 |
| 0.08 | 0.25 | 0.1314 | 0.1325 | 0.1425 | −1.02 |
| 0.08 | 0.50 | 0.1842 | 0.1850 | 0.2050 | −0.64 |
| 0.08 | 0.75 | 0.2375 | 0.2375 | 0.2675 | +0.00 |
| 0.08 | 1.00 | 0.2899 | 0.2900 | 0.3300 | −0.04 |

All rows use one seed, so their errors are correlated, which is why most z
values share a sign. Over 30 independent seeds the mean z is −0.30 to +0.15
(standard error 0.18) and the spread of z is 0.87–1.06. That is no detectable
bias.

The test suite checks the Phase 2 "done when" criterion over **32 settings**:
26 on NumPy (these 20, plus bit-flip noise and lossy links with dark counts at
50 and 100 km) and 6 on Qiskit Aer with in-circuit noise. Each must fall
within 4σ of the exact formula. Further tests cover detection rate vs η, Eve's
statistics, and abort / no-abort on either side of the ~44% interception
threshold.
