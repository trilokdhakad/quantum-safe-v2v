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
| 3 | Cascade, privacy amplification | Done |
| 4 | Attacks on the three base papers | Done |
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
pip install -e ".[dev,oqs]"   # drop ",oqs" if liboqs will not build (needs CMake + C compiler)
pytest -q                      # liboqs tests skip automatically when it is unavailable
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
│   ├── cascade.py      Cascade reconciliation with leak accounting
│   ├── privacy_amp.py  Toeplitz hashing over GF(2) (FFT), verification tags
│   ├── postprocess.py  estimate -> Cascade -> verify -> privacy amplification; run_qkd
│   ├── bb84.py         prepare -> transmit -> measure -> sift; BB84Result
│   └── backends/       numpy_backend.py, qiskit_backend.py
├── crypto/         seeded DRBG, P-256 arithmetic (ecdsa), SHA-256, AES-GCM
├── pqc/kem.py      ML-KEM-768: liboqs or kyber-py (deterministic), interoperable
├── attacks/        the three base papers as printed + attacks + Shor demo
│   ├── psrs_d2d/       protocol.py, attacks.py
│   ├── pslap/          protocol.py, attacks.py
│   ├── p2as_ioav/      protocol.py, attacks.py
│   └── shor_demo.py
├── sim/            later phases
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

## Post-processing to a final key (Phase 3)

```python
from qsv2v.qkd import run_qkd, QuantumChannel, PauliNoise, PostProcessingConfig

r = run_qkd(100_000, channel=QuantumChannel(noise=PauliNoise.from_qber(0.04)), seed=7)
print(r.aborted, r.final_length, r.keys_match, r.ec_efficiency, r.secret_key_rate)

# Conservative finite-key variant:
r = run_qkd(
    100_000,
    channel=QuantumChannel(noise=PauliNoise.from_qber(0.04)),
    config=PostProcessingConfig(finite_key=True),
    seed=7,
)
```

Pipeline (`postprocess.py`). All classical messages are assumed authenticated
(Phase 5 provides that with PQC).

1. **Parameter estimation**: disclose 10% of the sifted key and abort if the
   QBER is above 11%.
2. **Cascade** (`cascade.py`): 4 passes. The first block size is
   k₁ = ⌈0.73/Q⌉ (with Q floored at 1%) and doubles each pass. Passes 2–4 use
   fresh public random shuffles. A correction in a later pass re-opens the
   affected blocks of earlier passes (the "cascade"). **Every** parity Alice
   discloses counts as leaked, including repeats, so the leak figure is an
   upper bound.
3. **Verification**: Alice and Bob compare a 64-bit Toeplitz tag of their
   corrected keys and abort on a mismatch (collision probability 2⁻⁶⁴). The 64
   bits count as leaked.
4. **Privacy amplification** (`privacy_amp.py`): Toeplitz hashing over GF(2)
   with a public random seed, computed as an FFT convolution in O(n log n). It
   is tested against the explicit matrix product and for 2-universality. Final
   length:

   ℓ = ⌊n·(1 − h(Q))⌋ − leak_EC − 64 − ⌈2·log₂(1/ε_PA)⌉,  with ε_PA = 10⁻¹⁰ (67 bits)

   This is the plan's formula. The n·h(Q) term is Eve's possible phase-error
   information (Shor–Preskill), and the margin comes from the leftover hash
   lemma.

**Choice of Q for privacy amplification. Team decision: the default asymptotic
mode is used for every figure in the report.** The default
uses the *sampled* QBER (`finite_key=False`). That is the asymptotic analysis
that the "theoretical curve" in the plan refers to. Setting `finite_key=True`
adds the Serfling bound μ = √((n+k)(k+1)·ln(1/ε_PE) / (2nk²)), with
ε_PE = 10⁻¹⁰, so the key's true error rate is covered with high probability.
That is the honest choice for short blocks but costs key: at Q = 3%, the key
fraction is 0.27 at 40k photons and 0.47 at 400k, against 0.58 asymptotically.
Quote which mode a figure uses.

### Phase 3 results (measured, NumPy, 100,000 photons, 20 seeds per row)

| QBER | Key fraction | Cascade f | Predicted 1−(1+f)·h(Q)−131/n | Shor–Preskill 1−2h(Q) | Runs with identical key |
| --- | --- | --- | --- | --- | --- |
| 0.00 | 0.9714 | — | 0.9714 | 1.0000 | 20/20 |
| 0.01 | 0.8277 | 1.125 | 0.8254 | 0.8384 | 20/20 |
| 0.02 | 0.6985 | 1.132 | 0.6956 | 0.7171 | 20/20 |
| 0.03 | 0.5816 | 1.147 | 0.5798 | 0.6112 | 20/20 |
| 0.04 | 0.4766 | 1.158 | 0.4741 | 0.5154 | 20/20 |
| 0.05 | 0.3799 | 1.161 | 0.3783 | 0.4272 | 20/20 |
| 0.06 | 0.2859 | 1.178 | 0.2838 | 0.3451 | 20/20 |
| 0.07 | 0.1981 | 1.189 | 0.1961 | 0.2682 | 20/20 |
| 0.08 | 0.1177 | 1.191 | 0.1157 | 0.1956 | 20/20 |
| 0.09 | 0.0433 | 1.194 | 0.0395 | 0.1271 | 20/20 |
| 0.10 | 0 | 1.198 | 0 | 0.0620 | 0/20 (no secret key) |
| 0.12 | 0 | — | 0 | 0 | 0/20 (QBER abort) |

Key fraction is final bits per sifted bit left after sampling. At Q = 0 the
cost is just the Cascade parity checks plus the 131 bits of tag and margin.

What this shows:

- **Correctness**: no run in the test suite or in these probes produced
  mismatched final keys (well over 1,000 runs, covering small frames, Eve,
  near-threshold QBER and the Qiskit backend). Below 9% QBER, 100% of runs at
  40k–100k photons end with identical non-empty keys. Verification works: with
  4,000-photon frames, Cascade left residual errors in 2 of 200 runs and the
  tag check aborted both. With a deliberately weak 1-pass Cascade it aborted
  40 of 40.
- **Curve shape**: the measured key fraction tracks 1 − (1+f)·h(Q) within
  0.004, and sits below the Shor–Preskill curve with the same shape
  (correlation > 0.99).
- **Where the key runs out**: real Cascade leaks f ≈ 1.13–1.20 times the
  Shannon limit (E4's hypothesis of 1.1–1.2× holds), so the key reaches zero
  at Q ≈ 9.7%, not 11%. Between those two values runs end with "no secret key"
  rather than a wrong key. Small frames lose more: the fixed 131-bit overhead
  matters, so at 4,000 photons and Q = 8% only 131 of 200 runs yield a key.

## Attacks on the three base papers (Phase 4)

```bash
python -m qsv2v.attacks              # all 8 attacks; Shor on N = 15
python -m qsv2v.attacks --kem oqs    # P2AS-IoAV on liboqs instead of kyber-py
python -m qsv2v.attacks --n21        # also Shor on N = 21 (about 2.5 minutes)
python -m qsv2v.attacks.psrs_d2d.attacks   # one paper at a time
```

Each protocol is implemented from the paper's own figures and equations
(`protocol.py` quotes them in its docstring). Real P-256 arithmetic comes from
`ecdsa`, and real ML-KEM-768 from liboqs or `kyber-py`. Each attack is given
only what its threat model allows. The victim's true values are used only to
score the result. Every run is seeded and prints identical output on every
run.

### Results (all measured, `python -m qsv2v.attacks`: 8/8 succeed)

| Paper | Attack | Attacker needs | Recovers | Claim refuted |
| --- | --- | --- | --- | --- |
| PSRS-D2D | Passive session-key recovery | Transcript + public key directory | Both drone IDs and the session key | Prop. 2 anonymity, Prop. 5 session-key security |
| PSRS-D2D | Forward secrecy break | Capture one drone, later | Every past session key of that drone (both roles) | Prop. 4 forward secrecy, Prop. 11 capture resistance |
| PSRS-D2D | Master-key extraction | Capture two drones | Pr_TA and MK_TA, then impersonates a never-captured drone and shares its session key | Prop. 11, Prop. 10 impersonation |
| PSLAP | Session linking | §4.3 text version: eavesdropper. Fig. 3 version: the drones | Exact grouping of all sessions per vehicle | Prop. 2 anonymity / untraceability |
| PSLAP | Offline password guessing | OBU ⟨β, γ, δ⟩ + public ID_AV | Password, a₁, α, PID_AV | Prop. 8 AV capture |
| P²AS-IoAV | Forged message 1 | Drone's public key + a registered vehicle ID | Drone accepts and stores a session with the victim vehicle | Prop. 1 mutual authentication, Prop. 8 impersonation |
| P²AS-IoAV | Past-session decryption | Transcripts; later pr_DR and pr_AV (or the TA's copies) | Past session keys and the data sent under them | Prop. 9 perfect forward secrecy |
| ECC/RSA | Shor's algorithm on Qiskit Aer | Quantum computer (simulated) | Factors of 15 (and 21) and all periods | Classical public-key security against quantum adversaries |

Why each attack works, from the papers' own equations:

- **PSRS-D2D.** ADC = a + Cert, and Cert·G = Pub_TA + MP_TA + h(Pub‖ID_TA‖ID‖Pub_TA)·Pub_TA
  is public. So anyone computes X = ADC·G − Cert·G. Trying each directory
  entry until IDbar ⊕ X = ID also reveals who is talking. The session key has
  no Diffie–Hellman term. Cert = (Pr_TA + MK_TA) + h·Pr_TA is affine in the two
  TA secrets, so two certificates give two linear equations mod q.
- **PSLAP.** PID_AV = h(ID‖a₁) never changes. δ = h(PID‖PWD‖α‖β) lets anyone
  holding the OBU test a password guess offline, and identities are public in
  the paper's own adversary model (§3.2).
- **P²AS-IoAV.** Everything the drone checks in msg1 comes from k_i, which the
  sender creates with Encaps on the drone's public key, or from (s_i, ID_AV),
  which are read out of the message itself. The KEM keys are static and the TA
  generates them all, so nothing protects past sessions once those keys leak.

**Where the papers don't support the plan's wording (stated honestly):**

- **PSLAP linking.** The text of §4.3 and the cost analysis in §6.3 send
  msg1 = ⟨Y, m1, m2, **PID_AV**, T1⟩: the static pseudo-identity in clear, which
  any eavesdropper can link. Fig. 3 and Prop. 2 send TID = h(X) ⊕ PID instead.
  Against that version a *passive outsider* cannot link sessions (tested: 30
  sessions give 30 separate groups). The *drones* can: every drone recovers the
  static PID in every session, and the paper's adversary model treats drones as
  untrusted.
- **P²AS-IoAV forward secrecy.** One leaked key is not enough. The drone's key
  alone recovers past vehicles' IDs and s_i (de-anonymisation) but not the
  session key, because r_j stays sealed to the vehicle's key (tested). Both
  static keys are needed, or the TA's copies. That still breaks the paper's
  PFS claim, which explicitly covers compromise of long-term keys.
- **P²AS-IoAV forged message 1.** The drone accepts the forged vehicle, but the
  forger does not learn that session's key.

**Printing errors found in the papers.** The code reproduces each one behind a
flag, and the tests confirm they break honest runs. The attacks use the only
consistent reading.

| Paper | Location | As printed | Effect |
| --- | --- | --- | --- |
| PSRS-D2D | Fig. 2 / §V-C step 2 | D_j checks Cert_i with h(Pub_j‖ID_TA‖ID_j‖Pub_TA), its own values | Honest handshakes always fail |
| PSLAP | Fig. 2 vs Fig. 3 | δ is built with β at registration and recomputed with γ at login | Honest logins always fail |
| PSLAP | §4.3 vs Fig. 3 | msg1 carries PID_AV in one, TID_AV in the other | Two different privacy properties |
| P²AS-IoAV | §V-C.1 step 2 | V₁′ = h(r_j‖k_j‖sk₁‖s_i‖TS₁) | Uses values the drone lacks; Fig. 2 is consistent |

**Implementation choices where the papers are silent** (none affects any
attack): P-256, SHA-256, 160-bit identities (PSRS-D2D §VII-B), and "X ⊕ ID"
taken as the ID XORed with the first 20 bytes of X's x-coordinate. P²AS-IoAV's
Enc/Dec is AES-256-GCM. Peers get public keys from a TA-published directory,
which the papers use without describing.

**Shor demo scope.** Real phase estimation and inverse QFT on Aer: 12 qubits
for N = 15, 15 for N = 21. The modular-multiplication oracle is a classically
computed permutation matrix, which is fine at this size but not scalable.
Breaking P-256 would need about 2,330 logical qubits (Roetteler et al. 2017).
That is why "harvest now, decrypt later" is the practical threat.
