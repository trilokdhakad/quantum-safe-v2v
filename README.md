# QSV2V

A simulation framework for quantum-safe authentication and key exchange in
vehicle-to-vehicle (V2V) networks: BB84 quantum key distribution and
post-quantum cryptography (ML-KEM / ML-DSA).

**Project page (results, charts and a live replay of the simulation): https://trilokdhakad.github.io/quantum-safe-v2v/**

The project plan is in
[`Quantum-Safe V2V Communication — Project Plan.md`](Quantum-Safe%20V2V%20Communication%20—%20Project%20Plan.md).

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Repo setup, BB84 core (Qiskit Aer + NumPy backends) | Done |
| 2 | Channel noise, photon loss, intercept-resend Eve | Done |
| 3 | Cascade, privacy amplification | Done |
| 4 | Attacks on the three base papers | Done |
| 5 | PQ-V2V-AKE protocol | Done |
| 6 | V2V network simulation | Done |
| 7 | Experiments E1–E10 | Done |
| 8 | Dashboard (optional): live BB84 lab on the project page | Done |
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
├── pqc/            post-quantum layer
│   ├── kem.py          ML-KEM-768: liboqs or kyber-py (deterministic), interoperable
│   ├── sig.py          ML-DSA-44 (liboqs / dilithium-py), Falcon-512, ECDSA P-256 baseline
│   ├── certs.py        pseudonym certificate authority, enrollment, revocation (CRL)
│   ├── pq_v2v_ake.py   PQ-V2V-AKE handshake (+ hybrid X25519 mode)
│   ├── broadcast.py    signed safety messages, certificate digests, size table (E8)
│   └── attack_suite.py every Phase 4 attack class re-run against PQ-V2V-AKE (E5)
├── attacks/        the three base papers as printed + attacks + Shor demo
│   ├── psrs_d2d/       protocol.py, attacks.py
│   ├── pslap/          protocol.py, attacks.py
│   ├── p2as_ioav/      protocol.py, attacks.py
│   └── shor_demo.py
├── sim/            V2V network simulation (SimPy)
│   ├── mobility.py     2 km ring highway, 3 lanes each way
│   ├── radio.py        802.11p airtime, CSMA/CA + EDCA, collisions, retries, fragmentation
│   ├── vehicle.py      radio queue, crypto processor, model / real crypto back-ends
│   ├── network.py      safety messages, handshakes, metrics, replay traces
│   ├── profiles.py     measured sizes and timings per protocol
│   └── __main__.py     python -m qsv2v.sim -> results/sim/*.csv
├── experiments/    E1-E10, one script each; python -m qsv2v.experiments runs them all
│   ├── common.py       mean + 95% CI, Wilson intervals, CSV / Markdown / figure output
│   └── e01_eve_detection.py ... e10_qkd_vs_pqc.py
verification/       Scyther model of PQ-V2V-AKE
scripts/            build_showcase_data.py (page datasets), build_site.py (-> docs/data),
                    record_traces.py (replay recordings), run_steady_sweep.py
dashboard/          (optional Phase 8)
results/            generated CSVs and figures (git-ignored; regenerate with the commands)
docs/               the public project page (GitHub Pages): index.html, assets/, data/
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

The three base papers are PSRS-D2D [1], PSLAP [2] and P²AS-IoAV [3] (full
references at the end of this README). Each protocol is implemented from the
paper's own figures and equations
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

## PQ-V2V-AKE: our post-quantum protocol (Phase 5)

```bash
python -m qsv2v.attacks --pq        # attacks on the papers, then the same classes against ours
python -m qsv2v.pqc.attack_suite    # just the attacks against PQ-V2V-AKE
```

```python
from qsv2v.pqc.pq_v2v_ake import setup_network, handshake

net = setup_network(2, seed=1)  # authority + 2 enrolled vehicles (hybrid=True adds X25519)
tr = handshake(*net.vehicles, net.clock)
assert tr.initiator.key == tr.responder.key
print(tr.sizes)  # bytes of m1, m2, m3
```

Three messages:

    m1  I -> R : ek_e, Cert_I, N_I, T_I, Sign_I(m1)
    m2  R -> I : ct = Encaps(ek_e), Cert_R, N_R, T_R, Sign_R(transcript), MAC_R
    m3  I -> R : MAC_I

The session key is HKDF over the ephemeral ML-KEM-768 secret and the whole
transcript. ek_e is fresh for every session and its decapsulation key is
erased after use. Certificates are ML-DSA-44 signatures from a pseudonym
authority over keys the vehicles generated themselves. Each vehicle rotates
through a batch of short-lived pseudonyms (300 s by default). Revocation
works through a signed CRL that covers every pseudonym of a vehicle.

**Each design rule answers a Phase 4 failure** (written into the plan):
the session key comes only from ephemeral secrets (PSRS-D2D, P²AS-IoAV);
there is no key escrow (P²AS-IoAV); certificates are signatures rather than
algebra (PSRS-D2D); the initiator is authenticated before any key work, with
a replay cache (P²AS-IoAV); and there are no static identifiers or password
verifiers (PSLAP).

### Every Phase 4 attack class against PQ-V2V-AKE (measured: 8/8 blocked)

| Attack (analogue of) | What the attacker tried | Outcome |
| --- | --- | --- |
| Passive key recovery (PSRS-D2D 1) | Key schedule on all 32 public values | 0 matches |
| Forward secrecy (PSRS-D2D 2, P²AS 2) | Both vehicles' signing keys + authority key as decapsulation keys | 0 matches. Control: with the ephemeral key it *would* succeed |
| Capture two vehicles, forge (PSRS-D2D 3) | Self-signed certificate, grafted certificate, victim's certificate with own signature | All rejected |
| Forged / replayed message 1 (P²AS 1) | Observed certificate + own signature, swapped key, replay in window, replay after 60 s, revoked vehicle | All rejected |
| MITM swaps the KEM ciphertext | Re-encapsulate to the initiator's ephemeral key | Rejected (responder signature) |
| Linking sessions (PSLAP 1) | Byte windows shared by one vehicle's two pseudonyms but absent from another vehicle's | 0. Control: under one pseudonym, 3,773 found |
| Password guessing (PSLAP 2) | Read the vehicle's stored state | No password verifier exists |
| Quantum attacker in hybrid mode (Shor) | Given the X25519 secret | Key still needs the ML-KEM secret: 0 matches |

**Honest limit:** two sessions under the *same* pseudonym are linkable, which
is true of IEEE 1609.2 pseudonyms as well. The rotation interval is the
privacy setting.

### Measured costs

- **Handshake:** 3.6 ms total compute on liboqs (about 115 ms in pure Python).
  m1 ≈ 7.5 KB, m2 ≈ 7.4 KB, m3 = 38 B. The first two messages each span about
  6 radio frames, because each carries a full ML-DSA certificate (3.8 KB).
  Phase 6 measures what that costs on the channel.
- **Broadcast safety messages (E8)**, 200-byte payload, real signatures,
  certificate attached once per second, digest otherwise:

| Configuration | Certificate | With certificate | With digest | Fits 1,400 B? |
| --- | --- | --- | --- | --- |
| ECDSA P-256 (today) | 221 B | 523 B | 310 B | yes / yes |
| Falcon-512, Falcon-512 authority | 1,643 B | 2,535 B | 899 B | no / **yes** |
| Falcon-512, ML-DSA-44 authority | 3,410 B | 4,301 B | 904 B | no / yes |
| ML-DSA-44, ML-DSA-44 authority | 3,824 B | 6,481 B | 2,665 B | no / **no** |

This confirms E8's hypothesis: ML-DSA-44 alone overflows a frame even with a
digest, and Falcon-512 with a digest fits. Messages that carry a full
post-quantum certificate need fragmenting or separate distribution.

### Formal verification (Scyther)

```bash
set SCYTHER=C:\path\to\scyther-w32.exe       # Scyther v1.3.0, official Windows build
python verification/run_scyther.py            # writes verification/results.txt
```

`verification/pq_v2v_ake.spdl` models the handshake in Scyther's Dolev–Yao
setting. It makes the same claim set the base papers report, for both roles.

| Claim | Initiator | Responder |
| --- | --- | --- |
| Secret: KEM shared secret ss | Ok | Ok |
| Secret: session key | Ok | Ok |
| Alive | Ok | Ok |
| Weakagree | Ok | Ok |
| Niagree | Ok | Ok |
| Nisynch | Ok | Ok |

All 12 claims: **no attack found** at the default bound (5 runs), at 7 runs,
and with `--unbounded`. Scyther still labels every result "within bounds", not
"proof of correctness", so the report should say *no attack found within
bounds*, not *proved*. The likely reason is the responder's untyped `Ticket`
variable for the received key.

Checks that the model means something (`verification/sanity/`, all run by the
script and the test suite):

- **Negative control.** The same protocol with the responder's signature
  removed: Scyther finds attacks on all 6 initiator claims (a man in the middle
  encapsulates to the initiator's key itself). So the model does detect a
  broken protocol, and the code-level test of the same attack agrees.
- **A modelling pitfall, found and documented.** The first model declared the
  ephemeral KEM key pair with `inversekeys(pkE, skE)`. Scyther v1.3.0 treats a
  user-declared pair like that as *symmetric*: its adversary decrypted
  {m}pkE(x) with pkE(x). That made 8 claims fail spuriously. Minimal models
  show the broken behaviour and show that the built-in pk(·)/sk(·) pair works
  correctly: authenticated key Ok, unauthenticated key Fail. The model
  therefore uses pk(ne)/sk(ne).
- **Outside the symbolic model.** Forward secrecy, timestamps, revocation and
  replay caches are not modelled in Scyther; they are tested in code
  (`qsv2v.pqc.attack_suite`).

## V2V network simulation (Phase 6)

```bash
python -m qsv2v.sim                                   # sweep: 10-200 vehicles x 3 handshake types
python -m qsv2v.sim --vehicles 50 --policy same_direction --seeds 0 1 2
python -m qsv2v.sim --crypto real --vehicles 10       # real PQ-V2V-AKE and real signatures inside the sim
python -m qsv2v.pqc.bench                             # E6: ms per crypto operation on this machine
```

Writes `results/sim/summary.csv` (one row per run), `handshakes.csv` (one row
per handshake) and `bsm_pdr.csv` (safety-message delivery by distance), plus
`crypto_profile.json` (the measured sizes and timings the runs used).

**What is simulated** (`qsv2v/sim/`, SimPy discrete-event):

- **Mobility** (`mobility.py`): a 2 km ring highway with 3 lanes each way at
  90/108/126 km/h. Opposite-direction traffic closes at about 220 km/h, so
  neighbours keep arriving and leaving.
- **Radio** (`radio.py`): 802.11p at 6 Mbit/s, with real airtime per frame.
  Carrier sensing and backoff use two EDCA classes: safety messages AC_VO,
  handshakes AC_BE. Collisions include hidden terminals. Distance-dependent
  decoding is 50% at the 300 m range edge. Unicast frames are retried up to 4
  times. Messages over 1,400 B are fragmented, and lost if any fragment is.
- **Vehicles** (`vehicle.py`, `network.py`): every vehicle signs and
  broadcasts a safety message 10 times a second (Falcon-512, certificate once
  a second, digest otherwise). Every receiver verifies on a single crypto
  processor queue. When two vehicles within 200 m have verified each other's
  certificate, the lower-numbered one starts a handshake. The policy is
  either every neighbour or same direction only (platooning-style).
- **Crypto costs** (`profiles.py`): real message sizes and real compute times,
  measured by running the actual protocol code (liboqs). In `--crypto real`
  mode the simulator runs PQ-V2V-AKE itself and signs and verifies every
  safety message for real.

**Validation**: in real-crypto mode the simulator's handshakes derive matching
keys on both sides. Model mode and real mode agree: median handshake latency
30.3 vs 30.7 ms (ML-DSA) and 3.5 vs 3.8 ms (classical), with identical frame
counts (13 and 3) and bytes on air within 2%. Tests also cover hidden-terminal
collisions, carrier sensing, retry exhaustion, determinism under a seed, and
the latency floor on an empty channel (sum of frame airtimes).

### Results (measured; `results/sim/`)

> Superseded for the report by E9 in Phase 7 (5 seeds per point, 95% CIs):
> with more seeds, PQ-ML-DSA's every-neighbour limit moved from 25 to 50
> vehicles (its median at 50 is 95 ± 33 ms, right at the budget). The tables
> below are the original 2-seed Phase 6 runs.

Density is quoted as vehicles on the 2 km, 6-lane road: 50 vehicles is
4.2 vehicles per km per lane, 100 is 8.3, 200 is 16.7.

**1. Handshakes in steady state** (`scripts/run_steady_sweep.py`: 12 s runs,
first 6 s discarded, 2 seeds per point, Falcon-512 safety messages
throughout). The handshake runs with every neighbour that comes within 200 m:

| Vehicles | Handshake | Success | Median latency | Within 100 ms | Channel busy |
| --- | --- | --- | --- | --- | --- |
| 10 | Classical / PQ-Falcon / PQ-ML-DSA | 100% / 100% / 100% | 4 / 18 / 32 ms | 100% / 100% / 100% | 7–8% |
| 25 | Classical / PQ-Falcon / PQ-ML-DSA | 100% / 98% / 92% | 4 / 19 / 39 ms | 100% / 98% / 91% | 16–23% |
| 50 | Classical / PQ-Falcon / PQ-ML-DSA | 95% / 93% / 71% | 11 / 35 / 109 ms | 93% / 86% / 35% | 37–57% |
| 100 | Classical / PQ-Falcon / PQ-ML-DSA | 90% / 23% / 5% | 60 / 257 / 315 ms | 60% / 3% / 0% | 72–97% |
| 200 | Classical / PQ-Falcon / PQ-ML-DSA | 25% / 1% / 0% | 259 / 288 / 299 ms | 3% / 0% / 0% | 96–98% |

With handshakes only between vehicles travelling the same way
(platooning-style), there are 5–8 times fewer handshakes at 50–100 vehicles,
and every protocol lasts longer. At 50 vehicles: classical 97%, PQ-Falcon 91% and PQ-ML-DSA 89% of
handshakes succeed, with median latencies of 8, 26 and 52 ms. At 100 vehicles:
84%, 58% and 26%.

**E9 hypothesis** ("latency stays under the 100 ms budget up to a measurable
density"): the median stays under 100 ms up to 100 vehicles for classical,
50 for PQ-Falcon and 25 for PQ-ML-DSA when every neighbour pair needs a
session. With same-direction sessions only, that rises to 150, 100 and 50.

**2. Safety messages alone** (no handshakes, 4 s runs, 2 seeds; delivery means
received *and* verified within 300 m):

| Vehicles | ECDSA (today) | Falcon-512 | ML-DSA-44 |
| --- | --- | --- | --- |
| 50 | 87% delivered, 14% busy | 70%, 39% busy | 35%, 79% busy |
| 100 | 81%, 28% busy | 43%, 63% busy | 8%, 98% busy |
| 200 | 71%, 45% busy | 19%, 95% busy | 3%, 99% busy |

**What this means:**

- **The bigger bottleneck is the post-quantum signature on every safety
  message, not the handshake.** Ten signed messages a second per vehicle with
  Falcon-512 (900 B) saturate the channel from about 100 vehicles, and with
  ML-DSA-44 (2,665 B) from about 50, with no handshakes at all. Making V2V
  broadcast quantum-safe needs more than a signature swap. It needs a lower
  signing rate, signing only some messages, smaller certificates, or
  congestion control (as ETSI DCC already does for today's messages).
- **The handshake itself is fast**: 4 ms classical, 18 ms Falcon and 32 ms
  ML-DSA on an empty channel, against a 100 ms budget. Its cost is the bytes
  it puts on a shared channel: 13 frames per ML-DSA handshake against 3 for
  classical. That matters once the channel is busy.
- **Falcon beats ML-DSA throughout**, because its signatures and certificates
  are smaller. That supports the plan's choice of Falcon for broadcast, and
  suggests Falcon certificates for the handshake too.

**Method notes (state these in the report):**

- **Short runs include a start-up burst.** The first sweep (4 s runs, still in
  `results/sim/summary.csv`) includes the burst in which every vehicle
  discovers all its neighbours at once. That overstates congestion: at 50
  vehicles PQ-ML-DSA succeeded 26% of the time versus 72% in steady state.
  The tables above use steady state; the safety-message-only runs have no
  handshakes and are not affected.
- **Payload size is an assumption.** Safety-message payloads are 200 bytes.
- **Fragmentation is hypothetical.** Messages over 1,400 B are fragmented,
  which real 802.11p/WSMP cannot do; it prices oversized post-quantum
  messages rather than describing deployed behaviour.
- **Compute times are from this laptop** (`cpu_slowdown` = 1). An embedded
  on-board unit would be slower, but compute is not the bottleneck here: the
  busiest crypto processor in any steady-state run was 1.5% busy.
- **No SUMO traces.** The plan's stretch goal of SUMO mobility traces was not
  attempted; the built-in highway model was used, as the risk table allowed.

## Experiments E1–E10 (Phase 7)

```bash
python -m qsv2v.experiments                 # all ten; ~6 min, plus ~1.5 h the first time for E9's sweep
python -m qsv2v.experiments --only e03 e07  # a subset
python -m qsv2v.experiments --quick         # smoke-test settings (numbers not report quality)
python -m qsv2v.experiments --fresh         # also re-simulate E9's cached runs
```

One command regenerates every report figure and table. Each experiment
writes `results/experiments/eNN_name/` with `data.csv` (every run),
`summary.csv` (means with 95% CIs), `table.md`, `result.json` (finding and
verdict) and `figure.png/pdf`. All figures are also copied to
`results/experiments/figures/`, and `results/experiments/SUMMARY.md` lists
every hypothesis with its verdict. Seeds are fixed throughout. Repeated runs
give means with t-based 95% CIs, and proportions use Wilson intervals. E9
caches each simulation run under `runs/`, so a rerun only redraws.

### Verdicts (measured)

| # | Hypothesis | Verdict | Finding |
| --- | --- | --- | --- |
| E1 | QBER ~linear to ~25%; abort beyond ~44% interception | Supported | QBER 24.9% at full interception; half the runs abort at 43% (theory 44%). 2% noise moves the abort point to 38%. 10 seeds × 21 fractions × 2 noise levels, full pipeline. |
| E2 | Key reaches zero near 9.7% QBER (11% for a perfect code) | Supported | Zero at **10.0%** QBER (0.5% grid, Cascade f = 1.19). 0 of 310 runs ended with mismatched keys. |
| E3 | Key rate decays exponentially with distance | Supported | 0.20 dB/km, the same as the fibre loss, up to 120 km. Dark counts end the key at 190 km (20% detectors, 10⁻⁵ dark counts). |
| E4 | Cascade leaks ~1.1–1.2× the Shannon limit | Supported | 1.14–1.19× at QBER 2–10% with k1 = 0.73/Q. k1 = 1.0/Q leaked slightly less (mean 1.14 vs 1.16). No residual errors for any block size. |
| E5 | Every attack succeeds on the papers, fails on PQ-V2V-AKE | Supported | 40/40 attack runs on the papers succeeded (8 attacks × 5 seeds, all in under 4 s). 0/40 against PQ-V2V-AKE. |
| E6 | PQC within the same order as ECC; signing is the slowest step | **Partly** | PQ sign/verify is 3–4× ECDSA. Signing is slower than verifying for ML-DSA and Falcon but not for ECDSA (OpenSSL). The slowest operation is Falcon key generation (~10–14 ms, once per pseudonym). |
| E7 | Ours costs more bytes, adds forward secrecy and revocation | Supported | 14,958 B in 3 messages vs 304–1,864 B in 2 for the papers [1–3] (P²AS-IoAV with its own Kyber-512; 2,504 B with ML-KEM-768). Compute 2–5 ms (liboqs; varies with CPU speed between runs); the papers' EC steps would take 0.4–1.3 ms in OpenSSL. Only PQ-V2V-AKE has forward secrecy, revocation and quantum resistance together. |
| E8 | ML-DSA overflows a safety message; Falcon + digest fits | Supported | ML-DSA-44: 2,665 B (2 frames). Falcon-512 + digest: about 900 B, at most 998 B with the longest possible signature. |
| E9 | Latency under 100 ms up to a measurable density | Supported | See below. |
| E10 | PQC deployable now; QKD strongest in theory, needs optics | Comparison | See below. |

**E9, network scale** (12 s runs, first 6 s discarded, 5 seeds per point,
315 runs). Largest density whose mean median handshake latency is ≤ 100 ms:

| Sessions | Classical | PQ-Falcon | PQ-ML-DSA |
| --- | --- | --- | --- |
| Every neighbour | 100 | 50 | 50 (95 ± 33 ms; 25 if the upper CI must be under 100) |
| Same direction only | 150 (97 ± 23 ms; 50 by the upper CI) | 100 (95 ± 41 ms; 50 by the upper CI) | 50 |

Safety messages only (no handshakes), share received and verified within
300 m: 87 / 84 / 73% for ECDSA at 50 / 100 / 200 vehicles, 74 / 54 / 27% for
Falcon-512 and 40 / 10 / 3% for ML-DSA-44, with the channel 83–99% busy
under ML-DSA. Speed at 50 vehicles (middle lane 54 → 162 km/h): classical
handshake success stays at 95–97%, Falcon falls from 97% to 88%, ML-DSA from
79% to 60% (wide CIs). Faster traffic gives larger handshakes less time in
range.

**E10, QKD vs PQC**: a table built from E1, E3, E7, E8 and E9
(`e10_qkd_vs_pqc/table.md`). In the optimistic fibre-like model of E3 with a
100 MHz ideal single-photon source, QKD gives about 8 Mbit/s of key at 0 km
and 0.8 Mbit/s at 50 km. PQ-V2V-AKE gives about 50–125 kbit/s per CPU core (depending on the CPU speed during the run) and
works in software on today's hardware. QKD needs line-of-sight optics that
track a car closing at up to 70 m/s. The QKD numbers are an upper bound for
V2V, since free-space loss to a moving vehicle is larger and varies.

### Corrections made while running the experiments

- **Phase 5 linking test: false positives.** E5 reran the defence tests with
  new seeds, and the linking test reported 2 of 40 runs as "linked". The
  shared byte windows were not identifiers. They were chance matches: ML-DSA's
  zero-padded hint counters, and single random bytes next to fixed format
  fields, each about a 1-in-256 coincidence. The rule now counts a window only
  if it looks random (at least 8 distinct byte values) and differs in at
  least 8 bytes from every window of another vehicle's message. It passes 100
  of 100 seeds, and the positive control still finds about 3,700 identifying
  windows under one pseudonym. Regression tests cover the failing seeds and
  check that a planted 16-byte identifier is still caught.
- **E9 limits.** At 10 vehicles with same-direction sessions, every
  handshake finishes during warm-up, so the window holds no latency data. The
  budget rule now skips such points instead of stopping at them.
- **Phase 6 limits revised.** The 5-seed results move PQ-ML-DSA's
  every-neighbour limit from 25 to 50 vehicles. Several limits sit right at
  100 ms, so the report should quote the CIs.
- **Laptop timings vary.** Laptop timings (E6, E7) vary by up to 2× between
  full runs (CPU frequency scaling), more than the within-run CIs show. The
  verdicts do not change; quote compute times as ranges or orders of magnitude.
- **Raspberry Pi.** E6 on a Raspberry Pi was not done (no device).
- **Flaky real-crypto test fixed.** The test comparing the simulator's real-
  crypto mode with its model mode failed about 1 run in 25 under CPU load. It
  compared a timing profile cached hours earlier with wall-clock timings taken
  during the run, and its median rested on a single handshake. Now real mode
  records the cost of every operation and warms up first, as the profile
  measurement does. The model runs with the costs real mode actually observed,
  over all 13 handshakes. It passed 40 of 40 runs under 8-way parallel load.

## Live BB84 lab on the project page (Phase 8)

The plan's optional dashboard is part of the public project page
(https://trilokdhakad.github.io/quantum-safe-v2v/#lab) rather than a separate
Streamlit app, so anyone can use it without installing anything:

- **Run BB84 yourself.** Set how many photons Eve intercepts and how noisy
  the channel is, then send 20,000 photons. The first 16 appear one per
  column, with Alice's bit and basis, Eve's guess, Bob's basis and bit, and
  whether the photon survives sifting. Below them are both sifted keys with
  errors highlighted, the QBER estimated from a 10% sample against the
  formula, the 11% abort decision and the estimated secret key length.
- **The V2V simulation** is replayed from recorded steady-state runs
  (`scripts/record_traces.py`) rather than run live, because a 60-vehicle run
  takes seconds of real crypto timing in Python.

The lab's physics is a small script (`docs/assets/bb84.js`, the same model
as the NumPy backend). `tests/test_web_bb84.py` runs it under Node and checks
it against the Python theory: QBER within 4 standard errors at six
noise/Eve settings, a 50% sift ratio, repeatable seeds, the abort rule, and
the key reaching zero just above 10% QBER. The lab's key length is an
estimate, n(1 − (1 + f)h(Q)) − 131 with f = 1.16 measured in E4. The Python
pipeline runs real Cascade and privacy amplification.

## References

1. M. Shariq, N. Jamil, G. S. Rawat, S. A. Chaudhry, M. Masud and A. K. Das, "Provably Secure and Reliable Privacy-Preserving Authentication Scheme for Drone-to-Drone Communications in Internet of Autonomous Things" (PSRS-D2D), *IEEE Transactions on Mobile Computing*, vol. 25, no. 1, pp. 1445–1456, Jan. 2026. doi:10.1109/TMC.2025.3601369
2. M. Shariq, I. T. Ahmed, M. Masud, A. D. E. Berini and N. Jamil, "Design of a provable secure lightweight privacy-preserving authentication protocol for autonomous vehicles in IoT systems" (PSLAP), *Computer Networks*, vol. 261, Art. no. 111155, 2025. doi:10.1016/j.comnet.2025.111155
3. M. Shariq, N. Jamil, G. S. Rawat, A. K. Das, S. Yigezu, M. Masud and A. H. Abd Ghafar, "Anonymous and Privacy-Preserving Post-Quantum Key Encapsulation-Based Authentication Scheme for UAV-Assisted Internet of Autonomous Vehicles" (P²AS-IoAV), *IEEE Transactions on Vehicular Technology*, vol. 75, no. 10, pp. 24698–24711, Oct. 2026. doi:10.1109/TVT.2026.3698192

P²AS-IoAV evaluates its costs with Kyber-512 (its Sec. VII-B). Our attacks use
ML-KEM-768; the attacks do not depend on the parameter set. E7 measures P²AS-IoAV
with both: 1,864 B per handshake with ML-KEM-512, against the paper's own
14,144 bits (1,768 B) for its vehicle–drone exchange.
