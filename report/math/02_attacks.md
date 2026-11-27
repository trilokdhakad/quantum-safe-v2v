# 2. Attacks on the base papers: the mathematics

This chapter writes each of the seven attacks on the three base papers
[[R32]](README.md#R32) as algebra. For each one it gives what the attacker
knows, the equations they solve, and why the solution is the victim's secret.
The symbols follow the papers. The code is in
[`qsv2v/attacks/`](../../qsv2v/attacks/), and every attack is run end to end in
E5.

Common notation: $G$ is the generator of P-256 and $q$ its prime order. Lower-case
letters are scalars in $\mathbb Z_q$, upper-case letters are points.
$h(\cdot)$ is SHA-256, reduced mod $q$ where a scalar is needed. $\oplus$ is
XOR, and $[x]$ denotes the 160-bit slice of a point's $x$-coordinate that the
papers XOR with identities.

## 2.1 PSRS-D2D (drone ↔ drone)

**The scheme as printed.** The authority holds $\mathit{MK}$ and $\mathit{Pr}$, and
publishes $\mathit{MP} = \mathit{MK}\cdot G$ and $\mathit{Pub} = \mathit{Pr}\cdot G$.
Drone $\alpha$ has a key pair $(\mathit{Pr}_\alpha, \mathit{Pub}_\alpha)$ and the
certificate

$$
\mathit{Cert}_\alpha = \mathit{Pr} + \mathit{MK} + h_\alpha\,\mathit{Pr} \pmod q,
\qquad h_\alpha = h(\mathit{Pub}_\alpha \lVert \mathit{ID}_\text{TA} \lVert \mathit{ID}_\alpha \lVert \mathit{Pub}).
$$

In a session, drone $i$ picks $a_i$ and sends
$X_i = a_iG$ (hidden), $Y_i = a_i\mathit{Pub}_j$, $\mathit{ADC}_i = a_i + \mathit{Cert}_i$,
$\overline{\mathit{ID}}_i = [X_i] \oplus \mathit{ID}_i$. Drone $j$ answers in kind,
and the session key is

$$
\mathit{SK} = h(X_i \lVert X_j \lVert \mathit{ID}_i \lVert \mathit{ID}_j \lVert T_i \lVert T_j).
$$

### 2.1.1 Passive session-key recovery

*Attacker:* an eavesdropper who knows the public parameters and the public
directory $\{(\mathit{ID}, \mathit{Pub}_\mathit{ID})\}$.

1. Multiply the certificate equation by $G$:
   $\mathit{Cert}_\alpha G = \mathit{Pub} + \mathit{MP} + h_\alpha \mathit{Pub}$. Every
   term on the right is public, so anyone can compute $C_\alpha := \mathit{Cert}_\alpha G$
   for every registered drone.
2. From the transcript, $\mathit{ADC}_i G = a_iG + \mathit{Cert}_iG = X_i + C_i$.
   So for each candidate $\alpha$ in the directory, compute
   $X^{(\alpha)} = \mathit{ADC}_i G - C_\alpha$.
3. The right candidate satisfies
   $\overline{\mathit{ID}}_i \oplus [X^{(\alpha)}] = \mathit{ID}_\alpha$. A wrong one
   matches only if a 160-bit value collides, with probability $2^{-160}$. This
   reveals $\mathit{ID}_i$ (anonymity is broken) and $X_i$.
4. Repeat for message 2 to get $\mathit{ID}_j$ and $X_j$. Every input to
   $\mathit{SK}$ is now known, including the clear timestamps.
5. The public verifier $\mathit{SKV} = h(\mathit{SK} \lVert X_i \lVert X_j \lVert T_j)$
   lets the attacker confirm the result.

*Cost:* at most $2|\mathcal D|$ scalar multiplications for a directory of size
$|\mathcal D|$. *Root cause:* $\mathit{SK}$ contains no Diffie–Hellman secret
$a_ia_jG$, so nothing in it needs a private key.

### 2.1.2 Forward secrecy broken by one capture

*Attacker:* has recorded past transcripts, then captures drone $j$'s memory
$\{\mathit{Pr}_j, \mathit{Cert}_j, \mathit{ID}_j, \dots\}$.

1. $j$'s own ephemeral: $a_j = \mathit{ADC}_j - \mathit{Cert}_j \bmod q$, so $X_j = a_jG$.
2. The peer's ephemeral: $Y_i = a_i \mathit{Pub}_j = a_i\mathit{Pr}_jG = \mathit{Pr}_j X_i$,
   so $X_i = \mathit{Pr}_j^{-1} Y_i$.
3. $\mathit{ID}_i = \overline{\mathit{ID}}_i \oplus [X_i]$. Every input to $\mathit{SK}$ is
   known, for **every** past session $j$ took part in (either role; the code
   handles both).

### 2.1.3 Master keys from two captured certificates

*Attacker:* captures two drones, which gives two certificates $c_1, c_2$ and
their public $h_1, h_2$.

Write $x = \mathit{Pr}$ and $y = \mathit{MK}$. Each certificate is one linear
equation in the two unknowns:

$$
\begin{pmatrix} 1+h_1 & 1 \\ 1+h_2 & 1 \end{pmatrix}
\begin{pmatrix} x \\ y \end{pmatrix}
=
\begin{pmatrix} c_1 \\ c_2 \end{pmatrix}
\pmod q .
$$

The determinant is $(1+h_1) - (1+h_2) = h_1 - h_2$. It is invertible mod the
prime $q$ unless $h_1 \equiv h_2$, which happens with probability about $1/q$
for distinct registrations. Subtracting the two rows:

$$
x = (c_1 - c_2)(h_1 - h_2)^{-1} \bmod q, \qquad y = c_1 - (1+h_1)\,x \bmod q .
$$

The attacker checks the result against the public keys: $xG = \mathit{Pub}$ and
$yG = \mathit{MP}$. With $(x, y)$ the attacker issues a valid certificate for
any drone and impersonates one it never captured (E5 completes such a
handshake with an honest drone). *Root cause:* certificates are affine in the
authority's secrets with public coefficients, so $k$ captures give $k$
equations and two suffice. `formulas.solve_master_keys` is this computation;
the tests check it on fresh random instances mod the P-256 order.

## 2.2 PSLAP (car ↔ drone)

**The scheme as printed.** At registration the vehicle picks $a_1$ and fixes the
pseudo-identity $\mathit{PID} = h(\mathit{ID} \lVert a_1)$ for its lifetime. Its
on-board unit (OBU) stores

$$
\beta = h(\mathit{PWD}) \oplus a_1, \quad
\gamma = \alpha \oplus h(a_1), \quad
\delta = h(\mathit{PID} \lVert \mathit{PWD} \lVert \alpha \lVert \beta).
$$

### 2.2.1 Session linking

Unlinkability asks that an adversary cannot tell whether two sessions belong
to the same vehicle with probability noticeably better than guessing. The
attack wins with probability 1.

* **Text version** (§4.3 and §6.3 of the paper): message 1 carries
  $\mathit{PID}$ in clear. The linking function is the identity map: group
  sessions by $\mathit{PID}$.
* **Figure version** (Fig. 3): message 1 carries
  $\mathit{TID} = h(X) \oplus \mathit{PID}$ with $X = a_2\mathit{Pu}_D$. The drone
  computes $X = \mathit{Pr}_D\,Y$ (since $Y = a_2G$), and so
  $\mathit{PID} = \mathit{TID} \oplus h(X)$. The same $\mathit{PID}$ comes back in
  every session, so every drone, and any set of colluding drones, links all of
  a vehicle's sessions. The paper's own adversary model treats drones as
  untrusted. A passive outsider cannot unmask $\mathit{TID}$, and the demo
  checks that too.

E5 recovers the exact partition of 30 shuffled sessions into 6 vehicles in
both settings.

### 2.2.2 Offline password guessing

*Attacker:* reads $(\beta, \gamma, \delta)$ from the OBU (the paper's capture
model) and knows the public $\mathit{ID}$ (also allowed by its model).

For each guess $w$:

$$
a_1(w) = \beta \oplus h(w),\quad
\alpha(w) = \gamma \oplus h(a_1(w)),\quad
\mathit{PID}(w) = h(\mathit{ID} \lVert a_1(w)),\quad
\text{test } \delta \stackrel{?}{=} h(\mathit{PID}(w) \lVert w \lVert \alpha(w) \lVert \beta).
$$

* **Completeness.** For $w = \mathit{PWD}$ every line reproduces the
  registration values, so the test passes.
* **Soundness.** For $w \ne \mathit{PWD}$, $\delta$ is compared with a hash of a
  different input. Modelling SHA-256 as a random function, a false match has
  probability $2^{-256}$.

The test is perfect and needs no interaction with anyone. With the password
drawn uniformly from a dictionary of size $D$, the expected number of guesses
is $(D+1)/2$, at four hash evaluations each. For E5's $D = 20{,}000$ that is
about 10,000 guesses, a fraction of a second. A guess also recovers
$a_1$, $\alpha$ and $\mathit{PID}$, which are the vehicle's long-term secrets.

## 2.3 P²AS-IoAV (car ↔ drone ↔ cloud, Kyber)

**The scheme as printed.** Every party has a static Kyber key pair generated by
the authority. Message 1 is

$$
(c_i, k_i) \leftarrow \mathrm{Encaps}(\mathit{pu}_\mathit{DR}),\
\mathit{sk}_1^* = \mathrm{Enc}_{k_i}(s_i \lVert \mathit{ID}_\mathit{AV}),\
V_1 = h(r_i \lVert k_i \lVert s_i \lVert \mathit{TS}_1),\
r_i^* = r_i \oplus h(k_i \lVert V_1 \lVert \mathit{ID}_\mathit{AV} \lVert \mathit{TS}_1),
$$

and the session key is
$\mathit{SK} = h(r_i \lVert r_j \lVert s_i \lVert s_j \lVert \mathit{ID}_\mathit{AV} \lVert \mathit{ID}_\mathit{DR} \lVert \mathit{TS}_1 \lVert \mathit{TS}_2)$.

### 2.3.1 A forged message 1 is accepted

The drone's checks on message 1 are:

1. $k_i = \mathrm{Decaps}(\mathit{pr}_\mathit{DR}, c_i)$;
2. $(s_i, \mathit{ID}) = \mathrm{Dec}_{k_i}(\mathit{sk}_1^*)$;
3. $r_i = r_i^* \oplus h(k_i \lVert V_1 \lVert \mathit{ID} \lVert \mathit{TS}_1)$;
4. $V_1 \stackrel{?}{=} h(r_i \lVert k_i \lVert s_i \lVert \mathit{TS}_1)$.

Every value in them is a function of $(k_i, s_i, \mathit{ID}, r_i, \mathit{TS}_1)$.
An attacker with no credentials runs $\mathrm{Encaps}(\mathit{pu}_\mathit{DR})$
itself, which takes only the public key, and so knows $k_i$. It then picks any
$s_i, r_i$ and a registered $\mathit{ID}$, and computes $V_1, r_i^*, \mathit{sk}_1^*$
exactly as an honest vehicle would. KEM correctness gives
$\mathrm{Decaps}(\mathit{pr}_\mathit{DR}, c_i) = k_i$ (except with the failure
probability $2^{-164.8}$ for ML-KEM-768 [[R16]](README.md#R16)), so step 4 holds
identically.

The drone never compares $s_i$ with anything it stores, so it accepts with
probability $\approx 1$. The paper's Proposition 8 assumes the attacker
"cannot recompute $k_i$", but the attacker *chooses* $c_i$. The forger does not
learn the drone's $\mathit{SK}$, because that needs $k_j$, encapsulated to the
real vehicle. This is an authentication failure, not key recovery.

### 2.3.2 No forward secrecy

$\mathit{SK}$ is a deterministic function of the transcript and the two static
private keys:

$$
\mathit{SK} = \Phi(\mathit{pr}_\mathit{DR}, \mathit{pr}_\mathit{AV}, \text{transcript}),
$$

because $(s_i, \mathit{ID}_\mathit{AV}, r_i)$ come from $\mathrm{Decaps}(\mathit{pr}_\mathit{DR}, c_i)$
and $(s_j, \mathit{ID}_\mathit{DR}, r_j)$ from $\mathrm{Decaps}(\mathit{pr}_\mathit{AV}, c_j)$
(steps 1–3 above, applied to both messages). So anyone who later obtains both
static keys evaluates $\Phi$ on every recorded transcript. That includes the
authority, which generated them (key escrow). Forward secrecy demands exactly
the opposite. One leaked key alone still de-anonymises: the drone's key gives
$(\mathit{ID}_\mathit{AV}, s_i)$ for every past session.

*The contrast with PQ-V2V-AKE* (Chapter 3): there the key depends on an
ephemeral decapsulation key that is erased, so no function $\Phi$ of the
long-term keys exists.

## 2.4 Shor's algorithm: why ECC falls

**Period finding.** For $\gcd(a, N) = 1$, $f(x) = a^x \bmod N$ is periodic with
the order $r$ of $a$. Phase estimation over $2n$ counting qubits
($n = \lceil\log_2 N\rceil$) followed by an inverse QFT returns
$y \approx 2^{2n}\,s/r$ for a uniformly random $s \in \{0,\dots,r-1\}$.
Continued fractions recover $s/r$ in lowest terms, which gives $r$ or a divisor
of it. The code then tries small multiples until $a^r \equiv 1$.

**From the period to the factors.** If $r$ is even and
$a^{r/2} \not\equiv -1 \pmod N$, then $N \mid (a^{r/2}-1)(a^{r/2}+1)$ but
divides neither factor. So $\gcd(a^{r/2} \pm 1, N)$ are non-trivial factors.

*Worked example* ($N = 15$, $a = 7$, 8 counting qubits):

* The powers are $7^1 = 7$, $7^2 \equiv 4$, $7^3 \equiv 13$, $7^4 \equiv 1$,
  so $r = 4$.
* Peaks fall at $y = 256s/4 \in \{0, 64, 128, 192\}$, each with probability
  1/4. The peaks $y = 64$ and $y = 192$ give $s/r = 1/4, 3/4$, hence $r = 4$.
  The peak $y = 128$ gives $1/2$, a divisor; doubling it gives 4. The peak
  $y = 0$ gives nothing.
* $7^2 = 49 \equiv 4$, and $\gcd(3, 15) = 3$, $\gcd(5, 15) = 5$.

**Elliptic curves.** Shor's discrete-log algorithm [[R9]](README.md#R9) finds $k$
in $Q = kP$ by two-dimensional period finding on $f(u, v) = uP + vQ$. Its period
lattice contains $(k, -1)$. For P-256, Roetteler et al.
[[R10]](README.md#R10) estimate $9n + 2\lceil\log_2 n\rceil + 10 = 2330$ logical
qubits and about $1.26\times 10^{11}$ Toffoli gates. So ECDH and ECDSA, and
with them PSLAP, PSRS-D2D and IEEE 1609.2, fall to a large quantum computer.
Recorded traffic can be decrypted later ("harvest now, decrypt later").

## 2.5 Results (E5)

<!-- BEGIN GENERATED: attacks -->
| Target | Attack | Succeeded | Mean time per run |
|---|---|---|---|
| PSRS-D2D | Passive session-key recovery and de-anonymisation | 5/5 | 0.0594 s |
| PSRS-D2D | Forward secrecy broken by one drone capture | 5/5 | 0.0339 s |
| PSRS-D2D | Master-key extraction from two captured drones, then impersonation | 5/5 | 0.0427 s |
| PSLAP | Session linking via the static pseudo-identity PID_AV | 5/5 | 1.5 s |
| PSLAP | Offline password guessing from OBU contents | 5/5 | 0.215 s |
| P2AS-IoAV | Forged message 1 accepted by the drone (vehicle impersonation) | 5/5 | 0.0344 s |
| P2AS-IoAV | Past-session decryption after long-term key leak (no forward secrecy) | 5/5 | 0.0945 s |
| ECC/RSA family | Shor's algorithm factors N = 15 on Qiskit Aer | 5/5 | 3.85 s |
| PQ-V2V-AKE (ours) | Passive session-key recovery | 0/5 | 1.36 s |
| PQ-V2V-AKE (ours) | Past sessions after every long-term key leaks | 0/5 | 1.36 s |
| PQ-V2V-AKE (ours) | Capture two vehicles, then forge a certificate | 0/5 | 2.14 s |
| PQ-V2V-AKE (ours) | Forged or replayed message 1 | 0/5 | 2.21 s |
| PQ-V2V-AKE (ours) | Man in the middle swaps the KEM ciphertext | 0/5 | 1.42 s |
| PQ-V2V-AKE (ours) | Linking a vehicle's sessions | 0/5 | 4.06 s |
| PQ-V2V-AKE (ours) | Offline password guessing from vehicle storage | 0/5 | 4.12e-05 s |
| PQ-V2V-AKE (ours) | Quantum attacker breaks X25519 in hybrid mode | 0/5 | 1.19 s |
<!-- END GENERATED: attacks -->

Each attack counts as a success only if the recovered secret equals the
victim's, byte for byte (`AttackResult.success`). The rows for PQ-V2V-AKE are
the same attack classes re-run against our protocol. Chapter 3 proves why they
fail.
