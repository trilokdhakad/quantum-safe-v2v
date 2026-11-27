# 4. Network and performance

This chapter derives the costs measured in E7–E10 from first principles:

* the size of every message, from the cryptographic parameter sets and the
  wire format;
* the time each message spends on the 802.11p channel;
* the handshake latency on an idle channel;
* the channel load created by signed safety messages;
* the two key rates compared in E10.

Code: [`qsv2v/sim/radio.py`](../../qsv2v/sim/radio.py),
[`qsv2v/pqc/`](../../qsv2v/pqc/). Closed forms:
[`qsv2v/formulas.py`](../../qsv2v/formulas.py) §3–4.

## 4.1 Sizes of the cryptographic objects

From FIPS 203 [[R16]](README.md#R16), with ML-KEM-768 parameters $k = 3$,
$d_u = 10$, $d_v = 4$:

* The encapsulation key is $k$ polynomials of 256 coefficients at 12 bits,
  plus a 32-byte seed: $\mathit{ek} = 384k + 32 = 1184$ B.
* The decapsulation key is $\mathit{dk} = 768k + 96 = 2400$ B.
* The ciphertext is $k$ polynomials compressed to $d_u$ bits plus one
  compressed to $d_v$ bits:
  $\mathit{ct} = 32(d_u k + d_v) = 32\cdot 34 = 1088$ B.

From FIPS 204 [[R17]](README.md#R17) Algorithms 22 and 26, with ML-DSA-44
parameters $q = 8380417$, $d = 13$, $(k, \ell) = (4, 4)$, $\gamma_1 = 2^{17}$,
$\omega = 80$, $\lambda = 128$:

* The public key packs $t_1$ with $\mathrm{bitlen}(q-1) - d = 23 - 13 = 10$
  bits per coefficient: $\mathit{pk} = 32 + 32k\cdot 10 = 1312$ B.
* The signature is
  $\lambda/4 + 32\ell(1 + \mathrm{bitlen}(\gamma_1 - 1)) + \omega + k = 32 + 32\cdot4\cdot18 + 80 + 4 = 2420$ B.

For Falcon-512 [[R20]](README.md#R20), $q = 12289$ needs 14 bits per
coefficient: $\mathit{pk} = 1 + 14\cdot 512/8 = 897$ B. Falcon signatures are
variable-length. The specification gives 666 B, and liboqs allows up to 752 B.

## 4.2 Message sizes from the wire format

Every field is length-prefixed, $\mathrm{lp}(x) = 4 + \lvert x\rvert$ bytes
(Lemma 3.1).

**Certificate.**

$$
\lvert\mathit{cert}\rvert = \underbrace{23}_\text{domain} + \mathrm{lp}(16) + \mathrm{lp}(\lvert\mathit{alg}\rvert) + \mathrm{lp}(\mathit{pk}) + \underbrace{8 + 8}_\text{validity} + \mathrm{lp}(8) + \mathrm{lp}(\sigma_\text{CA})
= 83 + \lvert\mathit{alg}\rvert + \mathit{pk} + \sigma_\text{CA}.
$$

For ML-DSA-44 throughout this gives $83 + 9 + 1312 + 2420 = 3824$ B.

**Handshake messages** (field order of §3.2):

$$
\begin{aligned}
\lvert m_1\rvert &= 2 + \mathrm{lp}(\mathit{ek}) + \mathrm{lp}(x) + \mathrm{lp}(\mathit{cert}) + \mathrm{lp}(32) + 8 + \mathrm{lp}(\sigma) = 62 + \mathit{ek} + x + \lvert\mathit{cert}\rvert + \sigma,\\
\lvert m_2\rvert &= 2 + \mathrm{lp}(\mathit{ct}) + \mathrm{lp}(x) + \mathrm{lp}(\mathit{cert}) + \mathrm{lp}(32) + 8 + \mathrm{lp}(\sigma) + \mathrm{lp}(32) = 98 + \mathit{ct} + x + \lvert\mathit{cert}\rvert + \sigma,\\
\lvert m_3\rvert &= 2 + \mathrm{lp}(32) = 38,
\end{aligned}
$$

where $x$ is 32 in hybrid mode and 0 otherwise. With ML-KEM-768 and ML-DSA-44,
$\lvert m_1\rvert = 62 + 1184 + 3824 + 2420 = 7490$ B. The three messages total
14,958 B, which is E7's figure.

**Safety message** (`BSM` tag, algorithm name, 8-byte time, 1-byte signer type,
signer, payload, signature):

$$
\lvert \mathrm{BSM}\rvert = 3 + \mathrm{lp}(\lvert\mathit{alg}\rvert) + 8 + 1 + \mathrm{lp}(\mathit{signer}) + \mathrm{lp}(\mathit{payload}) + \mathrm{lp}(\sigma),
$$

where the signer is an 8-byte certificate digest, or the whole certificate
once per second. With a digest this is $36 + \lvert\mathit{alg}\rvert + \mathit{payload} + \sigma$.

<!-- BEGIN GENERATED: sizes -->
| Object (bytes) | Formula | Formula gives | Measured | Equal |
|---|---|---|---|---|
| ML-KEM-768 encapsulation key | 384k + 32 | 1184 | 1184 | yes |
| ML-KEM-768 decapsulation key | 768k + 96 | 2400 | 2400 | yes |
| ML-KEM-768 ciphertext | 32(d_u k + d_v) | 1088 | 1088 | yes |
| ML-DSA-44 public key | 32 + 32k(bitlen(q−1) − d) | 1312 | 1312 | yes |
| ML-DSA-44 signature | λ/4 + 32ℓ(1 + bitlen(γ₁−1)) + ω + k | 2420 | 2420 | yes |
| Falcon-512 public key | 1 + 14n/8 | 897 | 897 | yes |
| Pseudonym certificate, ML-DSA-44 / ML-DSA-44 CA | 83 + len(alg) + pk + σ_CA | 3824 | 3824 | yes |
| Pseudonym certificate, ECDSA / ECDSA CA | 83 + len(alg) + pk + σ_CA | 221 | 221 | yes |
| Handshake m1 (ML-KEM-768 + ML-DSA-44) | 62 + ek + x + cert + σ | 7490 | 7490 | yes |
| Handshake m2 (ML-KEM-768 + ML-DSA-44) | 98 + ct + x + cert + σ | 7430 | 7430 | yes |
| Handshake m3 | 2 + lp(32) | 38 | 38 | yes |
| Handshake m1 / m2, hybrid (+ X25519) | x = 32 | 7522 / 7462 | 7522 / 7462 | yes |
| Handshake m1 / m2, classical (X25519 + ECDSA) | ek = ct = 32, σ = 64 | 379 / 415 | 379 / 415 | yes |
| Safety message + digest, ML-DSA-44 | 36 + len(alg) + payload + σ | 2665 | 2665 | yes |
| Safety message + certificate, ML-DSA-44 | … + (cert − 8) | 6481 | 6481 | yes |
| Safety message + digest, ECDSA | 36 + len(alg) + payload + σ | 310 | 310 | yes |
| Safety message + digest, Falcon-512, longest signature | σ = 752 (liboqs maximum) | 998 | 998 | yes |
<!-- END GENERATED: sizes -->

**Consequence (E8).** A safety message fits one 1,400-byte frame only if
$36 + \lvert\mathit{alg}\rvert + 200 + \sigma \le 1400$, i.e.
$\sigma \le 1155$ B for a 9–10-character algorithm name.

* ML-DSA-44 ($\sigma = 2420$) cannot fit, whatever is done with the
  certificate.
* Falcon-512 fits even with its longest signature (998 B).
* Messages that carry the full certificate fit for no post-quantum option.

## 4.3 Time on the channel (802.11p)

The radio model follows the 802.11p OCB parameters ([`radio.py`](../../qsv2v/sim/radio.py),
[[R31]](README.md#R31)): data rate $R = 6$ Mbit/s, PHY preamble and header
$T_\text{PHY} = 40\ \mu$s, MAC/LLC overhead $h = 44$ B, slot $13\ \mu$s,
SIFS $32\ \mu$s. Then:

$$
T_\text{air}(n) = T_\text{PHY} + \frac{8(n + h)}{R}, \qquad
T_\text{ack} = \text{SIFS} + T_\text{PHY} + \frac{8\cdot 14}{R} = 90.7\ \mu\text{s},
$$

so a full 1,400-byte frame takes $40 + 8\cdot1444/6 = 1965.3\ \mu$s on air.

**Channel access.** Before each frame the sender waits AIFS and then a backoff
drawn uniformly from $\{0, \dots, \mathit{CW}\}$ slots. Its mean is
$\mathit{CW}/2$ slots.

* Handshake frames use AC_BE: $\text{AIFS} = 32 + 6\cdot13 = 110\ \mu$s and
  $\mathit{CW} = 15$, so the mean backoff is $97.5\ \mu$s.
* Safety messages use AC_VO: $\text{AIFS} = 58\ \mu$s, $\mathit{CW} = 3$.

On an idle channel, the expected time of one unicast frame is therefore

$$
t_\text{frame}(n) = \text{AIFS} + \frac{\mathit{CW}}{2}\,\text{slot} + T_\text{air}(n) + T_\text{ack},
$$

and a message of $S$ bytes is sent as $F(S) = \lceil S/1400\rceil$ frames.

## 4.4 Handshake latency on an idle channel

The three messages go strictly one after another, and each side computes
before it sends. So on an idle channel with no frame loss,

$$
L_0 = t_\text{init} + \sum_{f \in m_1} t_\text{frame}(f) + t_\text{resp} + \sum_{f \in m_2} t_\text{frame}(f) + t_\text{fin} + \sum_{f\in m_3} t_\text{frame}(f) + t_\text{conf}.
$$

Here the four compute times are the medians measured with liboqs
(`results/sim/crypto_profile.json`). For ML-KEM-768 + ML-DSA-44 the messages
take $6 + 6 + 1 = 13$ frames.

**Exact check.** `tests/test_formulation.py` places two vehicles 10 m apart on
an otherwise empty road, with no safety messages, and runs the simulator's own
handshake process over many seeds. The mean latency equals $L_0$ within the
backoff's statistical error, and every run lies between the minimum (all
backoffs 0) and maximum (all backoffs $\mathit{CW}$) that the formula allows.

**Against E9.** E9's smallest network (10 vehicles) also carries safety
messages from every vehicle, so handshake frames sometimes wait for a busy
channel. $L_0$ is therefore a lower bound, and the gap measures contention.

<!-- BEGIN GENERATED: latency -->
| Handshake | Frames | Compute (ms) | Predicted L0, idle channel (ms) | Measured median, 10 vehicles (ms, ± 95% CI) | Measured / L0 |
|---|---|---|---|---|---|
| classical | 3 | 1.25 | 3.55 | 3.6 ± 0.1 | 1.01 |
| pq-falcon | 7 | 1.34 | 13.55 | 15.9 ± 3.5 | 1.17 |
| pq-mldsa | 13 | 2.02 | 27.13 | 31.2 ± 1.8 | 1.15 |
<!-- END GENERATED: latency -->

For the classical handshake (3 frames) the measurement equals the idle
prediction. For the post-quantum ones (7 and 13 frames) the median is 15–17%
higher: each extra frame is another chance to find the channel busy. This is
the mechanism behind E9's main finding. Latency grows with
(frames per handshake) × (channel busy ratio), so the 13-frame ML-DSA
handshake leaves the 100 ms budget at the lowest density.

## 4.5 Channel busy ratio from safety messages

Each vehicle broadcasts $r = 10$ messages per second. Every tenth carries the
full certificate. The mean airtime per message is

$$
\bar T = \frac{T(\text{cert msg}) + 9\,T(\text{digest msg})}{10}, \qquad T(S) = \sum_{f \in \text{frags}(S)} T_\text{air}(f).
$$

A vehicle senses every transmission from within the carrier-sense range
$d_\text{cs} = 450$ m along the ring road of length $L = 2000$ m. The road is
only tens of metres wide, so the lateral offset is negligible. The vehicle
therefore hears a share $2d_\text{cs}/L = 0.45$ of all $N$ vehicles, itself
included. CSMA/CA keeps sensed transmissions from overlapping, so their busy
times add up:

$$
\rho(N) = \frac{2 d_\text{cs}}{L}\, N\, r\, \bar T .
$$

This holds while $\rho$ is well below 1. Near saturation, deferrals, hidden
terminals and collisions take over, and the measured ratio levels off below 1.

<!-- BEGIN GENERATED: cbr -->
| Signature | Vehicles | Predicted busy ratio ρ | Measured (± 95% CI) | ρ inside CI |
|---|---|---|---|---|
| ecdsa | 10 | 0.024 | 0.021 ± 0.026 | yes |
| ecdsa | 25 | 0.061 | 0.053 ± 0.025 | yes |
| ecdsa | 50 | 0.122 | 0.133 ± 0.026 | yes |
| ecdsa | 100 | 0.243 | 0.262 ± 0.055 | yes |
| ecdsa | 150 | 0.365 | 0.381 ± 0.060 | yes |
| ecdsa | 200 | 0.486 | 0.434 ± 0.102 | yes |
| falcon | 10 | 0.069 | 0.071 ± 0.029 | yes |
| falcon | 25 | 0.172 | 0.163 ± 0.012 | yes |
| falcon | 50 | 0.344 | 0.356 ± 0.037 | yes |
| falcon | 100 | 0.688 | 0.631 ± 0.047 | saturating |
| falcon | 150 | 1.031 | 0.839 ± 0.005 | saturating |
| falcon | 200 | 1.375 | 0.961 ± 0.005 | saturating |
| mldsa | 10 | 0.193 | 0.212 ± 0.027 | yes |
| mldsa | 25 | 0.483 | 0.444 ± 0.064 | yes |
| mldsa | 50 | 0.965 | 0.826 ± 0.024 | saturating |
| mldsa | 100 | 1.930 | 0.980 ± 0.003 | saturating |
| mldsa | 150 | 2.895 | 0.989 ± 0.001 | saturating |
| mldsa | 200 | 3.860 | 0.990 ± 0.001 | saturating |
<!-- END GENERATED: cbr -->

Below saturation ($\rho < 0.5$), every prediction lies inside the measured 95%
confidence interval. Saturation sets in at $N \approx 0.45^{-1}/(r\bar T)$
vehicles. That is about 145 vehicles for Falcon-512 and about 52 for
ML-DSA-44 (and about 410 for ECDSA). This is consistent with where E9's
safety-message delivery collapses for each scheme.

**Delivery of fragmented messages.** A message of $F$ fragments is received
only if every fragment is. If each fragment independently survives with
probability $p$, delivery is $p^F$. A two-fragment ML-DSA message is
therefore hit twice, once per fragment. On top of that, longer frames overlap
more transmissions, which lowers $p$ itself. This explains the ordering
ECDSA > Falcon > ML-DSA in E9's delivery ratios
([`SUMMARY.md`](../../results/experiments/SUMMARY.md)). We do not claim a
closed form for $p$ under contention.

## 4.6 Key rates compared in E10

* **PQC.** Each handshake yields one 256-bit key for its compute time, so
  $R_\text{PQC} = 256 / t_\text{handshake}$ bit/s per core.
* **QKD.** The key rate per pulse $R(d)$ comes from §1.7. At a source rate of
  $10^8$ pulses/s, $R_\text{QKD}(d) = 10^8 R(d)$.

<!-- BEGIN GENERATED: e10 -->
| Quantity | Formula | Formula gives | E10 reports |
|---|---|---|---|
| PQC key rate per core | 256 bit / t_handshake | 124,757 bit/s | 124,757 bit/s |
| QKD key rate at 0 km | R(0) × 10^8 pulses/s | 8,252,392 bit/s | 8,252,065 bit/s |
| QKD key rate at 50 km | R(50) × 10^8 pulses/s | 822,462 bit/s | 822,820 bit/s |
<!-- END GENERATED: e10 -->

The QKD rows differ in the fourth significant figure. E10 uses the *measured*
detection rate and QBER of E3, while the formula uses their expected values.
