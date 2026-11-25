# Quantum-Safe V2V Communication — Project Plan

Nov 25, 2026 · @TT49139

## Overview

We will build an open-source simulation framework that shows how vehicle-to-vehicle (V2V) links can stay secure once quantum computers exist, using both quantum key distribution (BB84) and post-quantum cryptography (ML-KEM / ML-DSA).

**Working title:** *QSV2V — A Simulation Framework for Quantum-Safe Authentication and Key Exchange in Vehicle-to-Vehicle Networks.*

**In one line:** we take three recent published protocols for autonomous vehicles and drones, show where they fail (quantum attacks, broken anonymity, no forward secrecy), and build and evaluate a working quantum-safe alternative in code.

**What comes out:** a tested Python codebase, a set of attack demonstrations, a new post-quantum V2V protocol, a V2V network simulation with experiments and plots, and a full project report.

## Why: the problem and the research gap

The three base papers each secure vehicle or drone links, but none of them is both quantum-safe and correct for V2V — that gap is the project.

**The quantum threat.** Today's V2V security (IEEE 1609.2) and most research protocols use elliptic-curve cryptography (ECC). Shor's algorithm on a large quantum computer breaks ECC and RSA. An attacker can also record traffic now and decrypt it later ("harvest now, decrypt later"). NIST standardised replacements in August 2024: ML-KEM (FIPS 203) for key exchange and ML-DSA (FIPS 204) for signatures.

**Shortcomings found in the base papers:**

| Paper | Setting | Main shortcomings |
| --- | --- | --- |
| PSLAP — Shariq et al., *Computer Networks* 261, 2025 | Car ↔ drone, ECC | Not quantum-safe. Sends a static pseudo-identity every session, so vehicles can be tracked. Values stored in the onboard unit allow offline password guessing. |
| PSRS-D2D — Shariq et al., *IEEE TMC* 25(1), 2026 | Drone ↔ drone, ECC | Not quantum-safe. Session key has no Diffie–Hellman secret: anyone who knows the drone IDs can recompute it. Capturing one drone opens every past session (no forward secrecy). Certificates are linear in the authority's secrets: two captured drones reveal the master keys. |
| P²AS-IoAV — Shariq et al., *IEEE TVT* 75(10), 2026 | Car ↔ drone ↔ cloud, Kyber | Quantum-safe KEM, but only static keys: no perfect forward secrecy. Drone cannot verify the vehicle in message 1. Every party must store every other party's public key; no revocation. Benchmarks mix hardware. |

**The common gap.** All three are one-to-one handshakes with drones. Real V2V is broadcast (each car sends safety messages about 10 times a second), and post-quantum signatures are much larger than ECC ones. None of the papers evaluates that, and none compares QKD with PQC for vehicles.

**Why this is a good project:** it has a clear problem drawn from current literature, original analysis (the attacks), an engineering contribution (the new protocol and simulator), and measurable results.

## Objectives and deliverables

The project has five objectives, each with a concrete deliverable that can be shown and tested.

| # | Objective | Deliverable |
| --- | --- | --- |
| O1 | Simulate BB84 quantum key distribution between two vehicles, with noise, photon loss and an eavesdropper | `qkd/` module on Qiskit + full post-processing (sifting, error correction, privacy amplification) |
| O2 | Demonstrate the shortcomings of the three base papers | `attacks/` scripts that recover session keys, link sessions and extract master keys from toy implementations |
| O3 | Design a post-quantum V2V authentication protocol that fixes those shortcomings | Protocol specification + `pqc/` implementation using ML-KEM-768 and ML-DSA-44 |
| O4 | Evaluate both approaches in a V2V setting | `sim/` network simulation, benchmarks, plots and comparison tables |
| O5 | Document the work | Project report, README, test suite; optional web dashboard |

**Out of scope:** real quantum hardware and real vehicles. The attacks exploit protocol design flaws, not ECC math, so they run on a real curve (secp256r1); the quantum threat to ECC is shown with a small Shor's-algorithm demo on Qiskit.

## Background primer

Four ideas carry the whole project; each team member should be able to explain all four.

**1. Authentication and key exchange.** Two parties exchange a few messages over an open channel. Each proves its identity, and both end up with the same secret session key that nobody else can compute. Desired properties: mutual authentication, anonymity (real IDs hidden), unlinkability (sessions can't be tied together), forward secrecy (stealing a long-term key later doesn't open old sessions), and resistance to replay, impersonation and man-in-the-middle attacks.

**2. BB84 quantum key distribution.** Alice sends single photons, each encoding a bit in one of two randomly chosen bases (rectilinear + or diagonal ×). Bob measures each in a random basis. They publicly compare bases and keep only matching positions (sifting, about 50% survive). Because measuring a quantum state disturbs it, an eavesdropper who intercepts and resends introduces about 25% errors on the bits she touched. Alice and Bob estimate the quantum bit error rate (QBER) on a sample; above about 11% they abort. Otherwise they fix remaining errors (Cascade) and shrink the key to remove anything Eve might know (privacy amplification). Security comes from physics, but BB84 still needs an *authenticated* classical channel — which is where PQC comes back in.

**3. Post-quantum cryptography.** Ordinary software built on math problems quantum computers are not known to solve, mainly lattices (Module-LWE).

| Primitive | Standard | Use | Public key | Ciphertext / signature |
| --- | --- | --- | --- | --- |
| ML-KEM-768 | FIPS 203 | Key exchange | 1184 B | 1088 B |
| ML-DSA-44 | FIPS 204 | Signatures | 1312 B | 2420 B |
| Falcon-512 | FN-DSA (draft) | Compact signatures | 897 B | \~666 B |
| ECDH / ECDSA P-256 (today) | — | Classical baseline | 64 B | 64 B |

The size jump in that last column is the central V2V challenge.

**4. V2V communication.** Vehicles talk directly over DSRC (IEEE 802.11p) or C-V2X at 5.9 GHz. Safety messages (BSM in the US, CAM in Europe) are broadcast about 10 times a second and signed under IEEE 1609.2 using pseudonym certificates that change regularly to protect privacy. Latency budgets are around 100 ms.

**Threat model.** We use the Dolev–Yao attacker (controls the radio channel: read, drop, change, replay messages) extended with Canetti–Krawczyk powers (can steal long-term keys or session state, can physically capture a drone or vehicle), plus a quantum-capable attacker who can solve ECC discrete logs.

## System architecture

The codebase is one Python package with independent modules; QKD and PQC are separate paths that both plug into the V2V simulation.

&#91;embedded content: system architecture · 7 modules\]

The attacks on the base papers motivate the PQ-V2V-AKE design; both security paths feed the network simulation, and every result flows through `experiments/` into the report.

**Repository layout:**

```
qsv2v/
├── qkd/          # bb84.py, channel.py, eve.py, cascade.py, privacy_amp.py, backends/
├── attacks/      # pslap/, psrs_d2d/, p2as_ioav/, shor_demo.py
├── pqc/          # kem.py, sig.py, certs.py, pq_v2v_ake.py, broadcast.py
├── sim/          # mobility.py, radio.py, vehicle.py, network.py
├── experiments/  # e01_eve_detection.py … e10_qkd_vs_pqc.py
├── verification/ # Scyther / Tamarin models
├── dashboard/    # optional Streamlit app
├── tests/        # pytest suite, one file per module
├── results/      # generated figures and CSV
└── docs/         # report sources
```

**Tech stack:**

| Need | Tool | Why |
| --- | --- | --- |
| Language | Python 3.11+ | Every library below is Python-first |
| Quantum simulation | Qiskit + Qiskit Aer | Industry-standard, real circuits and noise models |
| Post-quantum crypto | liboqs-python (Open Quantum Safe) | NIST algorithms, C speed |
| Classical crypto | `cryptography`, `ecdsa` | ECC, AES-GCM, HKDF baselines |
| Network simulation | SimPy (optional SUMO traces) | Simple discrete-event model |
| Analysis | NumPy, pandas, Matplotlib | Numbers and figures |
| Formal verification | Scyther or Tamarin | Same claims format as the base papers |
| Quality | pytest, ruff, GitHub Actions, Docker | Reproducible on every machine |

## Phase-by-phase plan

Nine phases, each ending with working, tested code before the next starts; Phases 1–7 are the core, 8 is optional, 9 is the report.

### Phase 1 — Project setup and BB84 core

- **What:** repo skeleton, packaging, CI; encode bits as qubits and measure them on Qiskit's Aer simulator; a `QuantumChannel` that carries Alice's states to Bob.
- **Why:** every later QKD result depends on this being correct.
- **How:** `|0⟩`/`|1⟩` for the + basis, apply a Hadamard for the × basis; Bob applies H before measuring when he picks ×. Batch many qubits per circuit for speed. Also a fast NumPy backend that gives the same statistics, for large runs.
- **Done when:** with no noise and no Eve, the sifted keys match 100%; about 50% of bits survive sifting; unit tests pass on both backends.
- **Outcome (done, commit 3374eab):** sifted keys match 100% on both backends; sift ratio 0.5000 (NumPy, 10⁶ photons) and 0.5007 (Qiskit Aer, 2·10⁴).

### Phase 2 — Channel realism and the eavesdropper

- **What:** depolarising / bit-flip noise, photon loss as a function of distance, an intercept-resend Eve who attacks a chosen fraction of photons; QBER estimation on a random sample; abort above the threshold.
- **Why:** without noise and attacks, QKD has nothing to show; detecting Eve is the headline result.
- **How:** Qiskit noise models (or random flips in NumPy); transmittance η = 10^(−α·d/10) for loss; Eve measures in a random basis and resends what she saw.
- **Done when:** measured QBER ≈ noise + 0.25 × (Eve's fraction), within statistical error, across 20+ settings.
- **Outcome (done, commit 22c889e):** met over 32 settings on both backends. Correction: the exact relation is Q = e + f/4 − f·e/2; "noise + 0.25 × f" is its first-order form and overestimates by up to 4 points at high noise. Use the exact form in the report.

### Phase 3 — Post-processing to a final key

- **What:** sifting, Cascade error correction, privacy amplification with Toeplitz hashing, final key verification.
- **Why:** a raw sifted key with errors is useless; this turns it into a usable secret.
- **How:** Cascade with 4 passes, block size ≈ 0.73/QBER doubling each pass, random shuffles between passes, counting every leaked parity bit. Final length ≈ n·(1 − h(Q)) − leaked − security margin, where h is binary entropy. Toeplitz matrix over GF(2) from a shared random seed.
- **Done when:** Alice's and Bob's final keys are identical in ≥ 99% of runs below threshold; secret key rate vs QBER matches the theoretical curve shape.
- **Outcome (done, commit 20e4314):** no run ever produced mismatched keys; 100% identical keys below 9% QBER; key fraction within 0.004 of 1 − (1+f)·h(Q). Cascade leaks f ≈ 1.13–1.20 × the Shannon limit, so the key reaches zero near **9.7%** QBER, not 11% (11% is the Shor–Preskill limit for a perfect code). Team decision: report figures use the asymptotic privacy-amplification mode.

### Phase 4 — Attacks on the three base papers

- **What:** faithful toy implementations of PSLAP, PSRS-D2D and P²AS-IoAV as printed, plus one script per attack.
- **Why:** this is the project's original contribution and the justification for Phase 5.
- **How:** real elliptic-curve math via the `cryptography` / `ecdsa` library; Kyber via `liboqs-python`. Attacks: PSRS-D2D session-key recovery from known IDs; PSRS-D2D forward-secrecy break after one drone capture; PSRS-D2D master-key extraction from two captured certificates (solve two linear equations mod q); PSLAP session linking from the static pseudo-identity; PSLAP offline password guessing from onboard-unit data; P²AS-IoAV past-session decryption after long-term key leak, and acceptance of a forged message 1. Plus a small Shor's-algorithm circuit (factoring 15) to show the quantum threat to the ECC/RSA family.
- **Done when:** each attack script runs end-to-end and prints the recovered secret matching the victim's.
- **Outcome (done, commit 6c6906b):** all 8 succeed (`python -m qsv2v.attacks`), implemented from the papers' own figures. Precisions the report must keep: (a) PSLAP linking works for any eavesdropper against the version in §4.3/§6.3 (PID_AV sent in clear); against Fig. 3 (TID = h(X) ⊕ PID) only the drones can link, a passive outsider cannot. (b) P²AS-IoAV past-session decryption needs both parties' static keys (or the TA's copies, since the TA generates all private keys); the drone key alone only de-anonymises. (c) The P²AS forged message 1 is accepted, but the forger does not learn that session key. (d) The PSRS-D2D master-key attack extends to impersonating a never-captured drone. Printing errors found: PSRS-D2D step 2 certificate check, PSLAP δ (β vs γ) and msg1 contents, P²AS V₁′ equation. Shor demo factors 15 and 21.

### Phase 5 — Our post-quantum V2V protocol

- **What:** a new authenticated key exchange for vehicles. Working name: **PQ-V2V-AKE**.
- **Why:** fixes every shortcoming from Phase 4 while staying practical.
- **How:** three messages. (1) Initiator sends a fresh ephemeral ML-KEM-768 public key + a short-lived pseudonym certificate signed by the trusted authority (ML-DSA-44) + its own signature over the transcript. (2) Responder verifies, encapsulates to the ephemeral key, returns ciphertext + its pseudonym cert + signature + a key-confirmation MAC. (3) Initiator returns its key-confirmation MAC. Session key = HKDF over the shared secret and full transcript. Optional hybrid mode adds X25519 (as TLS does today). Pseudonym rotation and a revocation list handled by the authority. For broadcast safety messages: sign with Falcon-512 and attach only a certificate digest after the first message.
- **Design rules from Phase 4 (added after the attacks):**
  - Session key only from the ephemeral ML-KEM secret plus transcript, never from identities or long-term values (PSRS-D2D key computable from public data; P²AS keys protected only by static keys).
  - Each vehicle generates its own long-term ML-DSA key; the authority only signs certificates and never holds private keys (P²AS-IoAV key escrow).
  - Certificates are ML-DSA signatures, not algebraic combinations of authority secrets, so capturing any number of vehicles reveals nothing about the authority key (PSRS-D2D linear certificates).
  - The responder verifies the initiator's certificate and transcript signature before doing any key work (P²AS forged message 1); freshness by timestamp plus a nonce cache against replay.
  - No static identifier on the air: the short-lived pseudonym certificate is the only identifier and rotates; no password-derived verifier stored on the vehicle (PSLAP).
  - Messages carry full ML-DSA certificates (≈ 3.8 KB) and exceed one 802.11p frame; Phase 6 measures the fragmentation cost.
- **Done when:** handshake completes between two simulated vehicles; tests show every Phase 4 attack fails against it; protocol modelled and verified in Scyther or Tamarin (secrecy, aliveness, agreement claims).
  - Concretely, one test per attack class: passive eavesdropper cannot derive the key from the transcript and public data; past session keys stay secret after both long-term keys and the authority key leak; captured certificates give no way to forge a new one; a forged or replayed message 1 is rejected; two sessions under different pseudonyms share no linkable field; there is no stored password verifier to guess.
- **Outcome (done):** handshake works in PQ-only and hybrid modes (3.6 ms compute on liboqs; m1 ≈ 7.5 KB, m2 ≈ 7.4 KB because each carries an ML-DSA certificate). All 8 Phase 4 attack classes blocked, with positive controls (`python -m qsv2v.attacks --pq`). E8 sizes measured: ML-DSA-44 overflows a 1,400 B frame even with a digest (2,665 B); Falcon-512 + digest fits (899 B). Scyther: all 12 claims, no attack found within bounds (5, 7 runs and --unbounded; Scyther does not report an unbounded proof). A negative control without the responder signature fails as expected. A Scyther pitfall was found: user-declared inversekeys pairs behave symmetrically in v1.3.0, so the model uses the built-in pk/sk pair.

### Phase 6 — V2V network simulation

- **What:** vehicles moving on a road; neighbours in radio range run handshakes and exchange signed safety messages.
- **Why:** shows behaviour at scale, not just between two cars.
- **How:** discrete-event simulation in Python (SimPy) with a simple highway mobility model; configurable vehicle density, speed, packet loss and message rate; measure handshake latency, bandwidth, message size vs the \~1400-byte packet limit. Stretch: mobility traces from SUMO.
- **Done when:** runs with 10–200 vehicles and logs metrics to CSV.

### Phase 7 — Experiments and analysis

- **What:** run the experiment matrix (next section), produce plots and comparison tables.
- **Why:** results are what the report is graded on.
- **How:** one script per experiment, fixed random seeds, repeated runs with mean and 95% confidence intervals, Matplotlib figures saved to `results/`.
- **Done when:** every figure in the report can be regenerated with one command.

### Phase 8 — Dashboard (optional)

- **What:** a web UI to run BB84 and the V2V simulation live and see photons, QBER and keys.
- **How:** Streamlit or a FastAPI backend with a small React front end.

### Phase 9 — Report

- **What:** the final project report (structure below), README and slides.
- **How:** written section by section as phases finish, so the last phase is editing, not writing from zero.

## Experiments and evaluation

Ten experiments make up the results chapter; each produces one figure or table.

| # | Experiment | Varies | Measures | Hypothesis (to test) |
| --- | --- | --- | --- | --- |
| E1 | Eavesdropper detection | Eve's intercept fraction 0–100% | QBER, abort rate | QBER rises \~linearly to \~25%; abort beyond \~44% interception |
| E2 | Channel noise | Noise 0–15% | QBER, final key length | Key length falls to zero near 9.7% QBER with Cascade (11% with a perfect code); measured in Phase 3 |
| E3 | Distance / loss | Link distance | Detection rate, secret key rate | Key rate decays exponentially with distance |
| E4 | Error-correction efficiency | QBER, block size | Bits leaked vs Shannon limit | Cascade leaks \~1.1–1.2× the limit |
| E5 | Attack success | Each base paper | Secret recovered? time taken | Every listed attack succeeds on the paper, fails on PQ-V2V-AKE |
| E6 | Crypto timing | ECDH, ECDSA, ML-KEM, ML-DSA, Falcon | ms per operation (laptop; Raspberry Pi if available) | PQC is within the same order as ECC; signing is the slowest step |
| E7 | Handshake cost | PSLAP, PSRS-D2D, P²AS-IoAV, PQ-V2V-AKE (+ hybrid) | Total compute (ms), bytes on air, round trips | Ours costs more bytes, adds forward secrecy and revocation |
| E8 | Message size vs packet limit | Signature scheme | Bytes per safety message | ML-DSA alone overflows a BSM; Falcon + certificate digest fits |
| E9 | Network scale | 10–200 vehicles, speed, density | Handshake latency, channel load, success rate | Latency stays under the 100 ms budget up to a measurable density |
| E10 | QKD vs PQC | Both approaches in V2V | Security basis, key rate, hardware needs, practicality | PQC is deployable now; QKD is strongest in theory but needs line-of-sight optics |

**Security evaluation** (not experiments, but part of the results): formal verification output from Scyther/Tamarin, and a feature comparison table of all four protocols (mutual authentication, anonymity, unlinkability, forward secrecy, quantum resistance, revocation, capture resistance).

## Report structure

The report follows the standard major-project format; adjust to the department's template when we have it.

1. Front matter — title page, certificate, declaration, acknowledgement, abstract, contents, list of figures/tables, abbreviations
2. Introduction — V2V and autonomous vehicles, the quantum threat, problem statement, objectives, contributions, report outline
3. Literature review — classical V2V authentication, PQC-based schemes, QKD for vehicles; detailed review of the three base papers; research gap table
4. Background — BB84, Cascade, privacy amplification, lattice cryptography (ML-KEM, ML-DSA, Falcon), Shor's algorithm, threat model
5. Cryptanalysis of the base papers — each attack: assumptions, steps, proof sketch, code output (Phase 4)
6. Proposed system — architecture, BB84 simulator design, PQ-V2V-AKE protocol specification, security analysis and formal verification (Phases 1–3, 5)
7. Implementation — tech stack, module design, key algorithms with pseudocode, testing strategy (all phases)
8. Results and discussion — E1–E10 figures and tables, comparison with base papers, QKD vs PQC discussion (Phases 6–7)
9. Conclusion and future work — summary, limitations (simulation only, no real hardware), extensions (hardware testbed, decoy-state QKD, SUMO/Veins integration)
10. References (IEEE style) and appendices — code listings, Scyther/Tamarin models, user manual

## Timeline, team split and risks

The deadline is 5 days, so phases run back to back and the dashboard is dropped unless time is left on Day 5.

**Schedule (weeks):**

1. Day 1 — Phases 1–3: repo, BB84 on Qiskit + NumPy, noise, loss, Eve, Cascade, privacy amplification, tests **(done; Phase 4 also finished on Day 1)**
2.  Day 2 — Phase 4: reference implementations of the three papers as baselines + attack scripts + Shor demo (kept to one day: it is evidence, not the contribution) **(done early; Day 2 now starts Phase 5)**
3.  Day 3 — Phase 5: PQ-V2V-AKE protocol, broadcast signing, Scyther model **(done on Day 1)**
4.  Day 4 — Phases 6–7: V2V network simulation, run E1–E10, figures
5.  Day 5 — Phase 9: report, README, slides; Phase 8 dashboard only if time allows

**Team split (suggested):**

| Member | Owns | Report chapters |
| --- | --- | --- |
| A | QKD simulator (Phases 1–3) | Background, QKD results |
| B | Cryptanalysis (Phase 4) | Literature review, cryptanalysis |
| C | PQ-V2V-AKE + formal verification (Phase 5) | Proposed system |
| D | Network simulation, experiments, dashboard (Phases 6–8) | Implementation, results |

**Risks and fallbacks:**

| Risk | Fallback |
| --- | --- |
| Qiskit too slow for large qubit counts | NumPy backend for big runs; Qiskit for correctness and small demos |
| `liboqs-python` fails to install on someone's machine | Docker image for the whole project; pure-Python `kyber-py` / `dilithium-py` as backup (implemented: liboqs is an optional extra, code and tests fall back automatically) |
| Tamarin learning curve too steep | Use Scyther (same tool as the base papers) |
| Scyther or Tamarin will not run on Windows | Scyther's Windows command-line build; else WSL or Docker; the model files are written either way |
| SUMO integration takes too long | Keep the built-in highway mobility model |
| A claimed attack does not reproduce | Report it honestly as a finding; the remaining attacks still stand |

**Open questions:** semester length and deadlines; team size; department report template and page limit; whether a Raspberry Pi is available for embedded benchmarks.

## References

1. M. Shariq et al., "Design of a provable secure lightweight privacy-preserving authentication protocol for autonomous vehicles in IoT systems," *Computer Networks*, vol. 261, 111155, 2025.
2. M. Shariq et al., "Provably Secure and Reliable Privacy-Preserving Authentication Scheme for Drone-to-Drone Communications in Internet of Autonomous Things," *IEEE Trans. Mobile Computing*, vol. 25, no. 1, pp. 1445–1454, 2026.
3. M. Shariq et al., "Anonymous and Privacy-Preserving Post-Quantum Key Encapsulation-Based Authentication Scheme for UAV-Assisted Internet of Autonomous Vehicles," *IEEE Trans. Vehicular Technology*, vol. 75, no. 10, pp. 24698–24710, 2026.
4. C. H. Bennett and G. Brassard, "Quantum cryptography: Public key distribution and coin tossing," 1984.
5. G. Brassard and L. Salvail, "Secret-key reconciliation by public discussion" (Cascade), EUROCRYPT 1993.
6. NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), August 2024.
7. P. W. Shor, "Algorithms for quantum computation: discrete logarithms and factoring," FOCS 1994.
8. IEEE Std 1609.2 — Security services for applications and management messages in vehicular environments.
