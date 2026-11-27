# 1. BB84 quantum key distribution

This chapter derives every quantity the BB84 simulator reports, step by step,
from the physics of single qubits to the length of the final secret key. Each
result ends with the simulator's measurement next to it.

Code: [`qsv2v/qkd/`](../../qsv2v/qkd/). Closed forms:
[`qsv2v/formulas.py`](../../qsv2v/formulas.py) §1 and
[`qsv2v/qkd/theory.py`](../../qsv2v/qkd/theory.py).

## 1.1 Model and notation

Alice sends $N$ photons. For photon $i$ she picks a bit $a_i \in \{0,1\}$ and a
basis $\alpha_i \in \{+, \times\}$, each uniformly at random. She prepares

$$
|0\rangle_+ = |0\rangle,\quad |1\rangle_+ = |1\rangle,\quad
|0\rangle_\times = |{+}\rangle = \tfrac{1}{\sqrt2}(|0\rangle + |1\rangle),\quad
|1\rangle_\times = |{-}\rangle = \tfrac{1}{\sqrt2}(|0\rangle - |1\rangle),
$$

that is, $|a\rangle_\times = H|a\rangle$ with $H$ the Hadamard gate. Bob picks a
basis $\beta_i$ uniformly and measures. A $\times$ measurement is $H$ followed by
a computational-basis measurement.

The channel between them has four effects, in this order (as in
[`channel.py`](../../qsv2v/qkd/channel.py)):

| Effect | Parameter | Meaning |
|---|---|---|
| Intercept-resend eavesdropper | $f \in [0,1]$ | Eve attacks each photon independently with probability $f$ |
| Loss | $\eta = \eta_\text{det}\,10^{-\alpha d/10}$ | probability the photon reaches and triggers Bob's detector |
| Dark counts | $p_d$ | probability of a click when no photon arrived |
| Pauli noise | $(p_x, p_y, p_z)$ | the channel applies $X$, $Y$ or $Z$ with these probabilities |

## 1.2 Sifting keeps half the bits

**Claim.** With no noise and no Eve, $P(\beta_i = \alpha_i) = 1/2$. When the
bases match, Bob's bit equals Alice's with probability 1. When they differ,
Bob's bit is a fair coin.

*Derivation.*

1. Same basis. If $\alpha = \beta = +$, Bob measures $|a\rangle$ in the
   computational basis and gets $a$ with probability $|\langle a|a\rangle|^2 = 1$.
   If $\alpha=\beta=\times$, Bob applies $H$ to $H|a\rangle$. Since $H^2 = I$,
   he measures $|a\rangle$ and again gets $a$ with certainty.
2. Different basis. If Alice sent $|a\rangle_\times$ and Bob measures in $+$,
   then $P(b) = |\langle b|H|a\rangle|^2 = |(-1)^{ab}/\sqrt2|^2 = 1/2$ for both
   values of $b$. The case $\alpha = +$, $\beta = \times$ is symmetric.
3. Bases are independent and uniform:
   $P(\alpha = \beta) = P(+,+) + P(\times,\times) = \tfrac14 + \tfrac14 = \tfrac12$.

Alice and Bob publish the bases and keep only the positions where they match.
The expected sifted length is $N\,p_\text{click}/2$, with
$p_\text{click} = \eta + (1-\eta)p_d$ (§1.7).

<!-- BEGIN GENERATED: sift -->
| Quantity | Theory | Measured (NumPy backend, 10^6 photons, seed 20261125) |
|---|---|---|
| Sift ratio | 1/2 | 0.50039 (+0.79 σ, σ = 0.00050) |
| QBER, no noise and no Eve | 0 | 0.0000 (0 errors in 500,394 sifted bits) |
<!-- END GENERATED: sift -->

The standard deviation is that of a Binomial$(N, 1/2)$ proportion,
$\sigma = \sqrt{1/(4N)}$. The Qiskit Aer backend gives the same statistics; this
is tested in `tests/test_backends.py`.

## 1.3 QBER with channel noise and an eavesdropper

### Lemma 1 (Pauli errors keep BB84 states in their basis)

$X|a\rangle = |1-a\rangle$ and $Z|a\rangle = (-1)^a|a\rangle$. So in the $+$ basis,
$X$ flips the bit and $Z$ only adds a global phase. In the $\times$ basis,
$Z|{\pm}\rangle = |{\mp}\rangle$ and $X|{\pm}\rangle = \pm|{\pm}\rangle$, so $Z$
flips the bit and $X$ does not. $Y = iXZ$ flips in both bases. Therefore each
Pauli maps a BB84 state to a BB84 state of the *same* basis, and

$$
e_+ = p_x + p_y, \qquad e_\times = p_z + p_y
$$

are the bit-flip probabilities in each basis. Depolarising noise of strength
$p$ has $p_x = p_y = p_z = p/4$, so $e_+ = e_\times = p/2$
([`noise.py`](../../qsv2v/qkd/noise.py)).

### Theorem 1.1 (QBER with noise and intercept-resend)

On a sifted bit in basis $b$, with noise error $e_b$ and intercept fraction
$f$:

$$
Q_b = e_b + \frac{f}{4} - \frac{f\,e_b}{2},
\qquad
Q = \tfrac12 (Q_+ + Q_\times).
$$

*Derivation.* Fix the sifted basis $b$ (Alice's and Bob's) and follow the
three branches of what happens to the photon:

1. **Eve does not attack** (probability $1-f$). The state reaches the channel
   unchanged. Bob errs exactly when the noise flips it: probability $e_b$.
2. **Eve attacks in basis $b$** (probability $f/2$). By §1.2 she reads $a$
   exactly and resends $|a\rangle_b$. Bob again errs with probability $e_b$.
3. **Eve attacks in the other basis $\bar b$** (probability $f/2$). By §1.2 her
   outcome $c$ is a fair coin. She resends $|c\rangle_{\bar b}$. By Lemma 1 the
   noise keeps this state in basis $\bar b$ (it may flip $c$, which does not
   matter). Bob measures a $\bar b$ state in basis $b$, so by §1.2 his bit is a
   fair coin: error probability $1/2$, whatever the noise did.

Adding the branches:

$$
Q_b = (1-f)\,e_b + \frac f2\,e_b + \frac f2\cdot\frac12
     = e_b - f e_b + \frac{f e_b}{2} + \frac f4
     = e_b + \frac f4 - \frac{f e_b}{2}. \qquad\blacksquare
$$

With $e = 0$ and $f = 1$ this is the textbook 25%. The plan's first-order
form $e + f/4$ drops the cross term $-fe/2$. That term is real: branch 3
"uses up" the noise, because a noise flip on a random bit leaves it random.
The overestimate is $fe/2$, which is 1 point at $e = 2\%$, $f = 1$.

**Check by enumeration.** `formulas.qber_by_enumeration` walks every leaf of
the event tree (Alice's basis, interception, Eve's basis, Eve's outcome, the
Pauli flip) in exact rational arithmetic. It never uses the closed form, and
the tests check that the two agree *exactly* on a grid of $(e_+, e_\times, f)$.

<!-- BEGIN GENERATED: qber -->
| Noise e | Eve f | Exact Q (enumeration) | First-order e + f/4 at e = 0 | Measured (10 runs, ± 95% CI) | Exact Q inside CI |
|---|---|---|---|---|---|
| 0% | 0.0 | 0.0000 (= 0) | 0.0000 | 0.0000 ± 0.0000 | yes |
| 0% | 0.2 | 0.0500 (= 1/20) | 0.0500 | 0.0505 ± 0.0019 | yes |
| 0% | 0.4 | 0.1000 (= 1/10) | 0.1000 | 0.1001 ± 0.0047 | yes |
| 0% | 0.6 | 0.1500 (= 3/20) | 0.1500 | 0.1486 ± 0.0052 | yes |
| 0% | 0.8 | 0.2000 (= 1/5) | 0.2000 | 0.1982 ± 0.0071 | yes |
| 0% | 1.0 | 0.2500 (= 1/4) | 0.2500 | 0.2485 ± 0.0075 | yes |
| 2% | 0.0 | 0.0200 (= 1/50) | 0.0000 | 0.0197 ± 0.0021 | yes |
| 2% | 0.2 | 0.0680 (= 17/250) | 0.0500 | 0.0682 ± 0.0041 | yes |
| 2% | 0.4 | 0.1160 (= 29/250) | 0.1000 | 0.1131 ± 0.0042 | yes |
| 2% | 0.6 | 0.1640 (= 41/250) | 0.1500 | 0.1659 ± 0.0040 | yes |
| 2% | 0.8 | 0.2120 (= 53/250) | 0.2000 | 0.2102 ± 0.0029 | yes |
| 2% | 1.0 | 0.2600 (= 13/50) | 0.2500 | 0.2576 ± 0.0070 | yes |
<!-- END GENERATED: qber -->

(The column "e + f/4 at e = 0" is the first-order form evaluated with the
noise term omitted, i.e. Eve's contribution alone. On the 2% rows the exact
value differs from $e + f/4$ by exactly $fe/2$.)

### Dark counts

A click comes either from a photon (probability $\eta$, error $Q_\text{sig}$
from Theorem 1.1) or from a dark count with no photon (probability
$(1-\eta)p_d$). A dark click is modelled as a random BB84 state, so it is a
fair coin and has error $1/2$. Conditioning on a click:

$$
Q = \frac{\eta\,Q_\text{sig} + (1-\eta)\,p_d/2}{\eta + (1-\eta)\,p_d}.
$$

As $\eta \to 0$ (long distance), the dark term dominates and $Q \to 1/2$. That
limit sets the range of QKD (§1.7).

## 1.4 Detecting Eve: the abort point

Alice and Bob disclose a random 10% sample of the sifted key, $m$ bits, and
estimate $\hat Q$ = errors / $m$. They abort if $\hat Q > Q_\text{th} = 11\%$
(the reason for 11% is in §1.6).

**Abort point.** Set the expected QBER equal to the threshold and solve
Theorem 1.1 for $f$:

$$
e + \frac f4 - \frac{fe}{2} = Q_\text{th}
\;\Longrightarrow\;
f\left(\frac14 - \frac e2\right) = Q_\text{th} - e
\;\Longrightarrow\;
f^* = \frac{Q_\text{th} - e}{\tfrac14 - \tfrac e2}.
$$

On a clean channel $f^* = 0.11/0.25 = 0.44$. With $e = 2\%$,
$f^* = 0.09/0.24 = 0.375$: noise hides part of Eve's signature, so less
interception is needed to trigger the abort.

**Abort probability.** The number of errors in the sample is
Binomial$(m, Q)$. So $\hat Q$ has mean $Q$ and standard deviation
$\sigma_m = \sqrt{Q(1-Q)/m}$. With the normal approximation,

$$
P(\text{abort}) = P(\hat Q > Q_\text{th}) \approx 1 - \Phi\!\left(\frac{Q_\text{th} - Q}{\sigma_m}\right).
$$

In E1, $N = 50{,}000$ photons give about 25,000 sifted bits, so $m \approx 2{,}500$.

<!-- BEGIN GENERATED: abort -->
| Noise e | Predicted abort point f* | Measured 50%-abort point |
|---|---|---|
| 0% | 0.4400 | 0.4286 |
| 2% | 0.3750 | 0.3800 |

| Noise e | Eve f | Expected Q | Predicted P(abort), m = 2,500 | Measured abort rate |
|---|---|---|---|---|
| 0% | 0.35 | 0.0875 | 0.00 | 0.0 (10 runs) |
| 0% | 0.40 | 0.1000 | 0.05 | 0.1 (10 runs) |
| 0% | 0.45 | 0.1125 | 0.65 | 0.8 (10 runs) |
| 0% | 0.50 | 0.1250 | 0.99 | 1.0 (10 runs) |
| 2% | 0.30 | 0.0920 | 0.00 | 0.0 (10 runs) |
| 2% | 0.35 | 0.1040 | 0.16 | 0.2 (10 runs) |
| 2% | 0.40 | 0.1160 | 0.83 | 0.7 (10 runs) |
| 2% | 0.45 | 0.1280 | 1.00 | 1.0 (10 runs) |
<!-- END GENERATED: abort -->

With only 10 runs per point, a measured rate has a standard error of up to
$\sqrt{0.25/10} = 0.16$. Every measured rate is within that of the prediction.

## 1.5 Error correction: what Cascade must reveal

**Lower bound.** Bob's sifted key $Y$ differs from Alice's $X$ by i.i.d. errors
with probability $Q$. To correct it, Alice must disclose at least
$H(X \mid Y) = n\,h(Q)$ bits; this is the Slepian–Wolf / Shannon limit. A real
code discloses $\text{leak}_\text{EC} = f_\text{EC}\, n\, h(Q)$ with efficiency
$f_\text{EC} \ge 1$.

**Cascade's first pass** [[R3]](README.md#R3) splits the key into blocks of
$k_1 = \lceil 0.73/Q \rceil$ bits. Each block then holds on average
$k_1 Q \approx 0.73$ errors.

*Probability that a block has odd parity.* The errors in a block are
Binomial$(k, Q)$. The odd terms of $(a+b)^k$ are $\frac12[(a+b)^k - (b-a)^k]$,
so with $a = Q$, $b = 1-Q$:

$$
P_\text{odd}(k) = \sum_{j\ \text{odd}} \binom kj Q^j (1-Q)^{k-j}
= \frac{1 - (1-2Q)^k}{2}.
$$

Only odd blocks are visible to a parity check. Each one costs a BINARY search
that halves the block $\lceil\log_2 k\rceil$ times, disclosing one parity per
halving, and locates one error. The pass therefore discloses
$n/k_1$ block parities plus about $(n/k_1)\,P_\text{odd}\lceil\log_2 k_1\rceil$
search parities. Later passes (doubled blocks, random permutations, and the
"cascade" back to earlier passes) find the even-numbered errors left behind.
They have no simple closed form, which is why $f_\text{EC}$ is measured (E4).

<!-- BEGIN GENERATED: cascade -->
| Q | k1 = ⌈0.73/Q⌉ | Blocks | Predicted odd blocks | Counted odd blocks (n = 10^5) | Parities per BINARY search |
|---|---|---|---|---|---|
| 0.01 | 73 | 1370 | 528 | 521 | 7 |
| 0.03 | 25 | 4000 | 1574 | 1574 | 5 |
| 0.05 | 15 | 6667 | 2647 | 2699 | 4 |
| 0.08 | 10 | 10000 | 4125 | 4098 | 4 |
<!-- END GENERATED: cascade -->

(The count of odd blocks is itself Binomial, so its standard deviation is
about $\sqrt{\text{blocks}\cdot P_\text{odd}(1-P_\text{odd})}$, i.e. 18–49
here. All four counts are within 2 standard deviations.) E4 measured
$f_\text{EC} = 1.14$–$1.19$ for $Q$ = 2–10% with the standard $k_1$, with zero
residual errors.

### Lemma 2 (Toeplitz verification tag)

After Cascade, both sides compare a $t$-bit Toeplitz hash of their keys
($t = 64$). The $m\times n$ Toeplitz matrix $T_{ij} = s_{i-j+n-1}$ is fixed by
$n+m-1$ public random bits $s$.

**Claim.** For any two different keys $x \ne y$,
$P_s[Tx = Ty] = 2^{-m}$.

*Proof.* Let $z = x \oplus y \ne 0$ and let $j^*$ be the smallest index with
$z_{j^*} = 1$. Row $i$ of $Tz$ is $\bigoplus_{j: z_j=1} s_{i-j+n-1}$. Its
largest seed index is $i - j^* + n - 1$, which grows with $i$. So the seed bit
$s_{i-j^*+n-1}$ appears in row $i$ but in no earlier row. Conditioned on rows
$0,\dots,i-1$, row $i$ is therefore XORed with a fresh uniform bit, which makes
it uniform. By induction $Tz$ is uniform on $\{0,1\}^m$, and
$P[Tz = 0] = 2^{-m}$. $\blacksquare$

So a residual error escapes the 64-bit check with probability $2^{-64}$.
Toeplitz hashing for authentication is analysed in [[R6]](README.md#R6). The
same 2-universality [[R5]](README.md#R5) is what privacy amplification needs
below.

## 1.6 Privacy amplification and the final key length

**Leftover hash lemma** [[R7]](README.md#R7), [[R4]](README.md#R4). If Eve's
min-entropy about the $n$-bit key is $H_\infty$, hashing it with a random member
of a 2-universal family down to

$$
\ell \le H_\infty - 2\log_2(1/\varepsilon_\text{PA})
$$

bits gives a key that is $\varepsilon_\text{PA}$-close to uniform from Eve's
point of view.

**What Eve knows.** In BB84 the phase-error rate equals the bit-error rate by
the symmetry between the two bases. Shor and Preskill [[R2]](README.md#R2) show
that, asymptotically, privacy amplification must remove $n\,h(Q)$ bits for the
quantum phase. The classical discussion revealed
$\text{leak}_\text{EC} + t$ more. So the pipeline
([`postprocess.py`](../../qsv2v/qkd/postprocess.py)) keeps

$$
\ell = \lfloor n(1 - h(Q))\rfloor - \text{leak}_\text{EC} - t - \lceil 2\log_2(1/\varepsilon_\text{PA})\rceil,
\qquad t = 64,\ \varepsilon_\text{PA} = 10^{-10}\ (\text{margin } 67\text{ bits}).
$$

Dividing by $n$ and writing $\text{leak}_\text{EC} = f_\text{EC}\,n\,h(Q)$:

$$
r(Q) = \frac{\ell}{n} = 1 - (1 + f_\text{EC})\,h(Q) - \frac{131}{n}.
$$

**Thresholds.** As $n\to\infty$ the key vanishes where $(1+f_\text{EC})h(Q) = 1$:

* a perfect code ($f_\text{EC} = 1$) gives $h(Q) = 1/2$, i.e.
  $Q = 11.00\%$, the Shor–Preskill limit and the abort threshold of §1.4;
* Cascade with the measured $f_\text{EC} \approx 1.19$ gives
  $h(Q) = 1/2.19$, i.e. $Q \approx 9.6\%$.

**Why the measured key fraction runs slightly high.** The pipeline runs in
asymptotic mode, so it puts the *sampled* QBER $\hat Q$ into $h(\cdot)$, while
the table's $x$-axis is the key's true QBER. $\hat Q$ has standard deviation
$\sigma_m$ (§1.4) with $m = n/9$ (10% of the sifted bits are disclosed). To
first order the key fraction therefore varies from run to run by

$$
\sigma_r = h'(Q)\,\sigma_m = \log_2\!\frac{1-Q}{Q}\,\sqrt{\frac{Q(1-Q)}{m}},
$$

which is about 0.013 at $Q = 5$–$10\%$. The noise has mean zero. E2 reuses the
same 10 seeds at every noise level, so a seed whose sample happened to
under-estimate $Q$ does so at every level. The measured per-seed deviations
are positively correlated across noise levels: the correlation between the 3%
and 7% rows is 0.52. That is why all rows below lean the same way, each within
about 2σ of a 10-run mean.

<!-- BEGIN GENERATED: keyfraction -->
| Measured QBER | Measured Cascade f | 1 − 2h(Q) | Predicted μ = 1 − (1+f)h(Q) − 131/n | Measured key fraction (± 95% CI) | σ of a 10-run mean (QBER sampling) | (measured − μ) / σ |
|---|---|---|---|---|---|---|
| 0.0098 | 1.123 | 0.8409 | 0.8282 | 0.8305 ± 0.0037 | 0.0029 | +0.8 |
| 0.0300 | 1.146 | 0.6114 | 0.5802 | 0.5858 ± 0.0107 | 0.0038 | +1.5 |
| 0.0499 | 1.158 | 0.4278 | 0.3796 | 0.3862 ± 0.0141 | 0.0041 | +1.6 |
| 0.0699 | 1.186 | 0.2692 | 0.1984 | 0.2068 ± 0.0147 | 0.0043 | +2.0 |
| 0.0899 | 1.193 | 0.1280 | 0.0407 | 0.0474 ± 0.0122 | 0.0043 | +1.5 |

| Measured QBER | μ | Predicted mean of max(0, ·) | Measured mean | Predicted runs with a key | Measured runs with a key |
|---|---|---|---|---|---|
| 0.0899 | +0.0407 | 0.0407 | 0.0474 | 10.0 | 10/10 |
| 0.0950 | +0.0025 | 0.0067 | 0.0147 | 5.7 | 8/10 |
| 0.1001 | -0.0344 | 0.0000 | 0.0000 | 0.1 | 0/10 |
| 0.1052 | -0.0671 | 0.0000 | 0.0000 | 0.0 | 0/10 |

| Zero-key point | Predicted QBER | Measured (E2) |
|---|---|---|
| Perfect code, f = 1 (Shor–Preskill) | 11.00% | — |
| Cascade, measured mean f = 1.189 | 9.62% | — |
| … plus the fixed 131-bit overhead (n ≈ 44,911) | 9.58% | between 9.50% (last grid point with key) and 10.01% (first with none) |
<!-- END GENERATED: keyfraction -->

**Near the threshold** the pipeline floors $\ell$ at 0. With
$r \sim \mathcal N(\mu, \sigma_r^2)$, the mean of the floored values is

$$
\mathbb E[\max(0, r)] = \mu\,\Phi(\mu/\sigma_r) + \sigma_r\,\varphi(\mu/\sigma_r),
$$

and a run yields a key with probability $\Phi(\mu/\sigma_r)$. This is what the
middle table compares. E2 reports the zero-key point as 10.0%. That is the
first point on its 0.5% grid where all 10 runs ended without a key. The
prediction, 9.58%, falls between that point and the last grid point that still
produced a key.

**Finite-key option.** With `finite_key=True` the pipeline replaces $\hat Q$ by
$\hat Q + \mu$, where
$\mu = \sqrt{\frac{(n+k)(k+1)\ln(1/\varepsilon_\text{PE})}{2nk^2}}$ (Serfling
bound, [[R8]](README.md#R8); $k$ = sample size). The true error rate of the key
is then covered with probability $1-\varepsilon_\text{PE}$. The composable
security of the whole protocol is
$\varepsilon \le \varepsilon_\text{PE} + \varepsilon_\text{ver} + \varepsilon_\text{PA}
= 10^{-10} + 2^{-64} + 10^{-10}$.

## 1.7 Loss, dark counts and distance

**Transmittance.** Fibre-like attenuation $\alpha$ dB/km over $d$ km multiplies
the power by $10^{-\alpha d/10}$, and the detector catches a fraction
$\eta_\text{det}$:

$$
\eta(d) = \eta_\text{det}\,10^{-\alpha d/10}, \qquad
p_\text{click}(d) = \eta(d) + (1-\eta(d))\,p_d.
$$

**Secret key rate per pulse.** Half the clicks survive sifting, and each
sifted bit is worth $r(Q)$ (§1.6, asymptotic):

$$
R(d) = \frac{p_\text{click}(d)}{2}\,\max\{0,\ 1 - (1+f_\text{EC})\,h(Q(d))\},
$$

with $Q(d)$ from the dark-count formula of §1.3.

**Slope.** While $\eta \gg p_d$, $Q(d)$ stays at the intrinsic error and

$$
\log_{10} R(d) = \text{const} - \frac{\alpha}{10}\,d,
$$

so the key rate falls exactly as fast as the light: $\alpha$ dB per km.

**Cut-off.** Once $\eta(d)$ approaches $p_d$, $Q(d) \to 1/2$. The key rate
reaches zero where $(1+f_\text{EC})\,h(Q(d)) = 1$, found by bisection
(`LinkModel.cutoff_km`). The parameters are E3's: $\alpha = 0.2$ dB/km,
$\eta_\text{det} = 0.2$, $p_d = 10^{-5}$, intrinsic error 1%,
$f_\text{EC} = 1.16$.

<!-- BEGIN GENERATED: distance -->
| km | η(d) | Q(d) theory | Q measured | R(d) theory (bits/pulse) | R measured (± 95% CI) |
|---|---|---|---|---|---|
| 0 | 2.000e-01 | 0.0100 | 0.0102 | 8.252e-02 | 8.252e-02 ± 1.2e-03 |
| 50 | 2.000e-02 | 0.0102 | 0.0106 | 8.225e-03 | 8.228e-03 ± 1.3e-04 |
| 100 | 2.000e-03 | 0.0124 | 0.0120 | 7.955e-04 | 8.064e-04 ± 2.9e-05 |
| 150 | 2.000e-04 | 0.0333 | 0.0376 | 5.719e-05 | 5.084e-05 ± 3.4e-06 |
| 200 | 2.000e-05 | 0.1733 | 0.2082 | 0.000e+00 | 0.000e+00 ± 0.0e+00 |

| Quantity | Theory | Measured (E3) |
|---|---|---|
| Loss slope of the key rate | 0.20 dB/km | 0.203 dB/km (fit, 0–120 km) |
| Distance where the key rate reaches zero | 182.1 km | between 180 and 190 km (10 km grid) |
<!-- END GENERATED: distance -->

E10's statement "no key beyond 183 km" is the first whole kilometre at which
$R(d) = 0$, so it agrees with the 182.1 km found here. At 150–200 km only a
few hundred clicks are left per run. The measured QBER there is noisier than
the prediction and sits slightly above it, so the measured rate sits slightly
below.
