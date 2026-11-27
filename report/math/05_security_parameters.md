# 5. Classical and quantum security parameters

This chapter lists the security parameters of every cryptographic component
in the project, in two senses:

* **(a) Numbers.** How many bits of security each primitive gives against a
  classical and against a quantum attacker, the parameter sets behind those
  numbers, and the parameters of our own protocols.
* **(b) Properties.** Which security properties each of the four protocols
  meets against a classical and against a quantum attacker, with each entry
  pointing to the attack, theorem or test that settles it.

Values quoted from standards and specifications were read from the documents
themselves (see the references in [README.md](README.md)). Computed values come
from [`qsv2v/formulas.py`](../../qsv2v/formulas.py) §5 and are tested.

## 5.1 How security is measured

**Bit security.** A primitive has $\lambda$-bit security if the best known
attack needs about $2^\lambda$ operations.

* For classical attackers, the generic attacks are exhaustive key search
  ($2^k$ for a $k$-bit key), birthday collision search ($\approx 2^{n/2}$ for
  an $n$-bit hash), and Pollard rho for discrete logarithms
  ($\approx \sqrt{\pi n/4}$ for a group of order $n$ [[R14]](README.md#R14)).
* **For quantum attackers, three algorithms change the picture:**
  * **Shor** [[R9]](README.md#R9) solves factoring and discrete logarithms,
    including on elliptic curves, in polynomial time. ECC and RSA therefore
    have *no* quantum security.
  * **Grover** [[R11]](README.md#R11) searches $2^k$ keys in
    $\approx \frac\pi4 2^{k/2}$ sequential quantum iterations. Key search
    costs at most the square root of its classical cost, so a $k$-bit key
    gives at most $k/2$ bits. In practice Grover parallelises badly; the NIST
    accounting below uses a depth limit.
  * **Brassard–Høyer–Tapp** [[R12]](README.md#R12) finds hash collisions in
    $O(2^{n/3})$ queries, but needs $O(2^{n/3})$ quantum memory. Bernstein
    [[R13]](README.md#R13) argues that, counting hardware cost, this does
    not beat parallel classical collision search. So SHA-256 collision
    resistance is usually taken to stay near 128 bits.

**NIST security categories** [[R15]](README.md#R15) (§4.A.5 of the 2016 call)
define post-quantum strength by comparison with a reference attack. The call
gives these gate counts (p. 17), where MAXDEPTH is the longest serial quantum
computation considered plausible (between $2^{40}$ and $2^{96}$ gates):

| Category | Reference attack | Quantum cost | Classical cost |
|---|---|---|---|
| 1 | key search on AES-128 | $2^{170}/\text{MAXDEPTH}$ gates | $2^{143}$ gates |
| 2 | collision on SHA-256 / SHA3-256 | — | $2^{146}$ gates |
| 3 | key search on AES-192 | $2^{233}/\text{MAXDEPTH}$ gates | $2^{207}$ gates |
| 5 | key search on AES-256 | $2^{298}/\text{MAXDEPTH}$ gates | $2^{272}$ gates |

**Core-SVP** is the lattice community's conservative cost of the best known
lattice attack: the cost of one SVP call in the required BKZ block size. It
is $2^{0.292\beta}$ classically and $2^{0.265\beta}$ quantumly for block size
$\beta$. The algorithm specifications report it in bits.

Generic attack costs, computed:

<!-- BEGIN GENERATED: generic_costs -->
| Attack | Formula | log2 cost |
|---|---|---|
| Pollard rho on P-256 (classical) | √(π n / 4), n = group order | 127.8 |
| Grover on a 128-bit key (quantum iterations) | (π/4) 2^(k/2) | 63.7 |
| Grover on a 256-bit key (quantum iterations) | (π/4) 2^(k/2) | 127.7 |
| Birthday collision on SHA-256 (classical) | √(π 2^n / 2) | 128.3 |
| Shor on P-256: logical qubits | 9n + 2⌈log2 n⌉ + 10, n = 256 | 2330 qubits (not a log) |
<!-- END GENERATED: generic_costs -->

## 5.2 (a) Security level of every primitive used

| Primitive | Where it is used | Classical security | Quantum security | Basis and source |
|---|---|---|---|---|
| **ECDH / ECDSA on P-256** | PSLAP, PSRS-D2D; today's IEEE 1609.2; classical baseline | ≈ 128 bits (Pollard rho: $2^{127.8}$ group operations) | **none**: Shor, ≈ 2330 logical qubits and ≈ $1.26\cdot10^{11}$ Toffoli gates | ECDLP; [[R14]](README.md#R14), [[R10]](README.md#R10) |
| **X25519** | hybrid mode of PQ-V2V-AKE; classical baseline | "slightly under the standard 128-bit level" (RFC 7748 §7); Pollard rho on the $\approx 2^{252}$ subgroup ≈ $2^{125.8}$ | **none** (Shor) | ECDLP on Curve25519; [[R34]](README.md#R34) |
| **ML-KEM-768** | PQ-V2V-AKE key exchange | NIST category 3; core-SVP 183 bits | category 3; core-SVP 166 bits | Module-LWE; [[R16]](README.md#R16) §8, [[R18]](README.md#R18) Table 4 |
| **ML-KEM-512** (Kyber-512) | P²AS-IoAV (the paper's cost evaluation) | category 1; core-SVP 118 bits | category 1; core-SVP 107 bits | [[R18]](README.md#R18) Table 4 |
| **ML-DSA-44** | PQ-V2V-AKE signatures, pseudonym certificates, safety messages | category 2; core-SVP 123 bits (LWE and SIS) | category 2; core-SVP 112 bits | Module-LWE / Module-SIS; [[R17]](README.md#R17) Table 1, [[R19]](README.md#R19) Table 1 |
| **Falcon-512** | compact signatures (E8) | category 1; core-SVP 120 bits (forgery), 133 (key recovery) | category 1; core-SVP 108 (forgery), 121 (key recovery) | NTRU lattices; [[R20]](README.md#R20) Table 3.3 |
| **SHA-256** | transcript hashes, certificate digests | collisions $2^{128.3}$ (birthday); preimages $2^{256}$ | collisions ≈ 128 bits ([[R13]](README.md#R13)); preimages $2^{128}$ (Grover) | [[R35]](README.md#R35), [[R12]](README.md#R12) |
| **HMAC-SHA-256 / HKDF** with 256-bit keys | key derivation, key confirmation | 256-bit key search; tag guessing $2^{-256}$ | 128 bits (Grover on the key) | PRF / swap-PRF: [[R27]](README.md#R27) |
| **AES-256-GCM** | P²AS-IoAV's Enc/Dec; data under a session key | 256 bits | 128 bits; category-5 reference | [[R36]](README.md#R36), [[R15]](README.md#R15) |
| **BB84 + Cascade + Toeplitz PA** | QKD path | information-theoretic: ε ≤ $10^{-10} + 2^{-64} + 10^{-10}$ | **same**: no computational assumption on the quantum part | §1.6; [[R2]](README.md#R2), [[R7]](README.md#R7) |

**Reading the table.**

* The two elliptic-curve rows are the only ones whose quantum security is zero.
  That is the "harvest now, decrypt later" threat: traffic recorded today
  under P-256 or X25519 can be opened once a large quantum computer exists.
* The lattice rows keep most of their strength against quantum attackers. The
  gap between their classical and quantum core-SVP is 11–17 bits, not half.
* Symmetric primitives with 256-bit keys keep 128-bit quantum security.
* BB84's guarantee does not depend on the attacker's computing power at all.
  It does, however, assume an authenticated classical channel, which in
  practice means post-quantum signatures again (E10).

**The weakest link of PQ-V2V-AKE** is ML-DSA-44 (category 2). With Falcon-512
signatures it is category 1. The key exchange itself (ML-KEM-768) is
category 3. Theorem 2 reduces the protocol's security to these primitives,
with a polynomial loss (§3.6).

### Internal parameter sets

**ML-KEM-768** (FIPS 203, Table 2; sizes Table 3; failure rate Table 1):

| $n$ | $q$ | $k$ | $\eta_1$ | $\eta_2$ | $d_u$ | $d_v$ | RBG strength | $\lvert\mathit{ek}\rvert$ | $\lvert\mathit{dk}\rvert$ | $\lvert\mathit{ct}\rvert$ | $\lvert\mathit{ss}\rvert$ | decapsulation failure |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 256 | 3329 | 3 | 2 | 2 | 10 | 4 | 192 bits | 1184 B | 2400 B | 1088 B | 32 B | $2^{-164.8}$ |

**ML-DSA-44** (FIPS 204, Table 1; sizes Table 2):

| $q$ | $d$ | $\tau$ | $\lambda$ | $\gamma_1$ | $\gamma_2$ | $(k, \ell)$ | $\eta$ | $\beta = \tau\eta$ | $\omega$ | pk | sk | signature |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 8380417 | 13 | 39 | 128 | $2^{17}$ | $(q-1)/88$ | (4, 4) | 2 | 78 | 80 | 1312 B | 2560 B | 2420 B |

**Falcon-512** (specification v1.2, Table 3.3):

| $n$ | $q$ | $\sigma$ | $\sigma_\text{min}$ | $\sigma_\text{max}$ | max. signature norm² | pk | signature |
|---|---|---|---|---|---|---|---|
| 512 | 12289 | 165.7366 | 1.2778 | 1.8205 | 34,034,726 | 897 B | 666 B (spec); ≤ 752 B in liboqs |

Chapter 4 derives every size in these tables from the parameters, and the
tests check them against liboqs.

### Parameters of PQ-V2V-AKE

| Parameter | Value | Security role | Where |
|---|---|---|---|
| Nonces $N_I, N_R$ | 256 bits | session uniqueness: collision ≤ $n_S^2/2^{256}$ (Lemma 3.3) | `NONCE_LEN` |
| Freshness window $\Delta$ | 5 s (GNSS-synchronised clocks) | bounds replays; with the nonce cache, none are accepted (Lemma 3.4) | `MAX_SKEW` |
| Replay cache horizon | $2\Delta$ = 10 s | must exceed $\Delta$ for Lemma 3.4 | `check_fresh` |
| Session key $K$, confirmation keys $K_R, K_I$ | 256 bits each | Theorem 2; 128-bit quantum security against key search | `_keys` |
| MAC tags $\tau_R, \tau_I$ | 256 bits | guessing a tag: $2^{-256}$ (Theorem 1) | `mac` |
| Protocol label | `PQ-V2V-AKE-v1` | domain separation of signatures and keys (Lemma 3.2) | `LABEL` |
| Pseudonym | 16 random bytes | anonymity (§3.8) | `PSEUDONYM_LEN` |
| Pseudonym lifetime $L$ | 300 s (default); windows on the global grid $[kL, (k+1)L)$ | unlinkability across windows: validity fields reveal nothing about the holder (§3.8) | `Authority.enroll` |
| Certificate digest | 64 bits (as IEEE 1609.2 HashedId8) | lookup only, among certificates already verified. A digest collision causes a verification failure, not a forgery, and among $N$ cached certificates has probability ≤ $N^2/2^{65}$ | `PseudonymCert.digest` |
| Revocation | signed CRL of pseudonyms | revoked pseudonyms rejected | `verify_cert` |

### Parameters of the BB84 pipeline

| Parameter | Value | Security role | Where |
|---|---|---|---|
| QBER sample | 10% of sifted bits | estimate of Eve's disturbance, $\sigma = \sqrt{Q(1-Q)/m}$ (§1.4) | `sample_fraction` |
| Abort threshold | 11% | Shor–Preskill limit, $1 - 2h(Q) = 0$ (§1.6) | `QBER_THRESHOLD` |
| Cascade | 4 passes, $k_1 = \lceil 0.73/Q\rceil$, doubling | leakage $f_\text{EC}\,n\,h(Q)$, $f_\text{EC}$ = 1.14–1.19 (E4) | `cascade` |
| Verification tag | 64-bit Toeplitz hash | $\varepsilon_\text{ver} = 2^{-64}$ (Lemma 2) | `tag_bits` |
| Privacy amplification | $\varepsilon_\text{PA} = 10^{-10}$, margin $\lceil 2\log_2 10^{10}\rceil = 67$ bits | leftover hash lemma (§1.6) | `eps_pa` |
| Finite-key option | $\varepsilon_\text{PE} = 10^{-10}$, Serfling correction | covers the true QBER with probability $1 - \varepsilon_\text{PE}$ | `finite_key`, `eps_pe` |

## 5.3 (b) Security properties against classical and quantum attackers

**The attackers.**

* **Classical:** Dolev–Yao control of the radio channel, plus
  Canetti–Krawczyk key leaks and physical capture (the plan's threat model).
* **Quantum:** the same powers, plus Shor and Grover. It may record traffic
  today and attack it later (harvest now, decrypt later).

Each cell reads **C** (classical) / **Q** (quantum). "No attack found" means
we did not break the property, not that it is proved.

| Property | PSLAP | PSRS-D2D | P²AS-IoAV | PQ-V2V-AKE |
|---|---|---|---|---|
| **Session-key secrecy** against an eavesdropper | C: no attack found. Q: **no**, ECDH falls to Shor | C: **no**, the key is computable from public data (§2.1.1). Q: **no** | C: no attack found. Q: no attack found (Kyber) | C, Q: **yes**, Theorem 2 |
| **Mutual authentication** | C: no attack found. Q: **no**, ECC keys recoverable by Shor | C: **no**, impersonation after two captures (§2.1.3). Q: **no** | C: **no**, a forged message 1 is accepted (§2.3.1). Q: **no** | C, Q: **yes**, Theorem 1 |
| **Perfect forward secrecy** | C: yes, the key uses ephemeral ECDH. Q: **no**, recorded ephemerals fall to Shor | C, Q: **no**, one capture opens all past sessions (§2.1.2) | C, Q: **no**, static keys only (§2.3.2) | C, Q: **yes**, Theorem 2 (dk erased) |
| **Anonymity** (real identity hidden) | C: text version **no** (PID in clear); figure version yes against outsiders, **no** against drones. Q: **no** | C, Q: **no**, identity unmasked (§2.1.1) | C: partial, ID only under $k_i$, open to drone-key holders and to the escrowing TA. Q: same | C, Q: **yes**, random pseudonyms only (§3.8) |
| **Unlinkability** | C, Q: **no**, static PID (§2.2.1) | C, Q: **no** | C, Q: partial (as above) | C, Q: **yes** across pseudonyms; validity windows on a global grid (§3.8) |
| **Resistance to vehicle or drone capture** | C, Q: partial, the OBU allows offline password guessing (§2.2.2) | C, Q: **no**, two captures give the master keys (§2.1.3) | C, Q: **no**, TA key escrow and static keys | C, Q: **yes**, capture yields only that vehicle's current pseudonym keys: no past sessions, no CA key, no other vehicle (Theorem 2; E5) |
| **Password guessing resistance** | C, Q: **no** (§2.2.2) | not applicable | not applicable | not applicable: nothing password-derived is stored (E5) |
| **Replay resistance** | timestamps (not analysed here) | timestamps (not analysed here) | timestamps (not analysed here) | C, Q: **yes**, timestamp and nonce cache (Lemma 3.4) |
| **Revocation** | no mechanism | no mechanism | no mechanism | **yes**, signed CRL (E7) |
| **No key escrow** | not analysed | not analysed | **no**, the TA generates every private key | **yes**, vehicles generate their own keys |
| **Quantum resistance** of the key exchange | **no** (ECC) | **no** (ECC) | yes (Kyber) | **yes** (ML-KEM-768; hybrid adds X25519) |

**Summary of (b).**

* The two ECC papers lose every property against a quantum attacker, because
  every secret they derive passes through an elliptic-curve discrete
  logarithm.
* P²AS-IoAV keeps its key exchange quantum-safe, but fails authentication and
  forward secrecy for design reasons, against classical attackers as well.
* PQ-V2V-AKE meets every row against both attackers. The cost is size
  (Chapter 4): 14,958 B per handshake with ML-DSA-44 (7,064 B with
  Falcon-512), against 304–2,504 B for the base papers (E7).
