# 3. PQ-V2V-AKE: formal model and security proofs

This chapter specifies PQ-V2V-AKE as equations, taken line by line from
[`qsv2v/pqc/pq_v2v_ake.py`](../../qsv2v/pqc/pq_v2v_ake.py). It then defines a
security model and proves three theorems:

* **Theorem 1 (mutual authentication):** each side ends with a partner that
  holds the same transcript.
* **Theorem 2 (session-key secrecy with perfect forward secrecy):** a session
  key is indistinguishable from random, even after every long-term key leaks.
* **Theorem 3 (hybrid mode):** with X25519 mixed in, the key stays secret
  against classical attackers if *either* ML-KEM or X25519 is secure.

The proofs are game-based, in the style of Bellare–Rogaway
[[R21]](README.md#R21) and Canetti–Krawczyk [[R22]](README.md#R22), with
Real-or-Random session keys [[R23]](README.md#R23). The base papers use the
same model. The proof technique follows the analyses of SIGMA
[[R24]](README.md#R24) and TLS 1.3 [[R29]](README.md#R29), whose structure
(sign the transcript, MAC under a derived key) PQ-V2V-AKE shares. The proofs
are written by hand and are not machine-checked. The machine-checked part is
the Scyther model ([`verification/`](../../verification/)), which verifies
secrecy, aliveness and agreement symbolically (§3.9).

## 3.1 Primitives

| Primitive | Instantiation | Property used | Advantage term |
|---|---|---|---|
| KEM $(\mathrm{KGen}, \mathrm{Encaps}, \mathrm{Decaps})$ | ML-KEM-768 [[R16]](README.md#R16) | IND-CCA | $\mathrm{Adv}^\text{ind-cca}_\text{KEM}$ |
| Signature $(\mathrm{SKGen}, \mathrm{Sign}, \mathrm{Vrfy})$ for pseudonyms | ML-DSA-44 [[R17]](README.md#R17) (or Falcon-512) | EUF-CMA | $\mathrm{Adv}^\text{euf-cma}_\text{SIG}$ |
| Signature for the authority | same scheme | EUF-CMA | $\mathrm{Adv}^\text{euf-cma}_\text{CA}$ |
| Hash $H$ | SHA-256 [[R35]](README.md#R35) | collision resistance | $\mathrm{Adv}^\text{cr}_H$ |
| $\mathrm{Ext}(s, k) = \mathrm{HMAC}(s, k)$ | HKDF-Extract [[R33]](README.md#R33), [[R25]](README.md#R25) | **swap-PRF**: a PRF when keyed through its *message* input $k$ | $\mathrm{Adv}^\text{swap}_\text{HMAC}$ |
| $\mathrm{Exp}(k, \ell)$, $\mathrm{HMAC}(k, \cdot)$ | HKDF-Expand, HMAC | PRF (keyed normally) | $\mathrm{Adv}^\text{prf}_\text{HMAC}$ |

**Why these assumptions hold for the parameters used.**

* *Swap-PRF.* In PQ mode, $\mathrm{Ext}$ is keyed through its message input by
  the 32-byte ML-KEM shared secret. Backendal, Bellare, Günther and Scarlata
  [[R27]](README.md#R27) prove that HMAC restricted to keys from a set
  $\mathcal S$ is swap-PRF secure *if and only if* $\mathcal S$ is "feasible",
  meaning either $\mathcal S = \{0,1\}^\ell$ for some $\ell \le b$ (the block
  length) or $\mathcal S$ contains no strings of length $\le b$. Their proof is
  in the standard model and assumes only properties of the compression
  function. For SHA-256, $b = 512$ bits. The ML-KEM secret is always exactly
  256 bits, so $\mathcal S = \{0,1\}^{256}$ is feasible and the result applies.
* *Conventional PRF.* The same paper proves PRF security of HMAC for keys of
  any length. This covers the 256-bit keys used in $\mathrm{Exp}$ and the MACs,
  which are shorter than the block. Earlier proofs [[R26]](README.md#R26)
  covered only full-block keys.
* *Quantum attackers.* All four assumptions are believed to hold against
  quantum adversaries for these parameters (Chapter 5).

**No random oracle.** The proofs never model a hash as a random oracle. Every
reduction below is straight-line and black-box, and the adversary talks to the
protocol through classical messages only. So the reductions apply unchanged to
a quantum polynomial-time adversary, given that the assumptions hold against
such adversaries. This avoids the quantum-random-oracle complications a
ROM-based proof would bring. ML-KEM's own IND-CCA security is argued by its
designers through the Fujisaki–Okamoto transform. We take it as an assumption,
as FIPS 203 does.

## 3.2 The protocol as equations

**Setup.**

* The authority CA holds a signing key pair $(\mathit{pk}_\text{CA}, \mathit{sk}_\text{CA})$.
* A vehicle generates its own pseudonym key pairs $(\mathit{pk}_P, \mathit{sk}_P)$.
  The CA never sees a private key.
* For each pseudonym the CA issues
  $\mathit{cert}_P = (\mathit{tbs}_P, \mathrm{Sign}(\mathit{sk}_\text{CA}, \mathit{tbs}_P))$
  with $\mathit{tbs}_P = \texttt{CERT\_DOMAIN} \lVert \mathrm{lp}(\mathit{pn}_P) \lVert \mathrm{lp}(\mathit{alg}) \lVert \mathrm{lp}(\mathit{pk}_P) \lVert t_\text{nb} \lVert t_\text{na} \lVert \mathrm{lp}(\mathit{issuer})$.
  Here $\mathit{pn}_P$ is a uniformly random 16-byte pseudonym.

**The handshake.** $\mathsf L$ = `"PQ-V2V-AKE-v1"`; $\Delta = 5$ s.

| Step | Initiator $I$ | | Responder $R$ |
|---|---|---|---|
| 1 | $(\mathit{ek}, \mathit{dk}) \leftarrow \mathrm{KGen}()$; $N_I \leftarrow \{0,1\}^{256}$ | | |
| | $b_1 = \texttt{m1} \lVert \mathrm{lp}(\mathit{ek}) \lVert \mathrm{lp}(\varepsilon) \lVert \mathrm{lp}(\mathit{cert}_I) \lVert \mathrm{lp}(N_I) \lVert T_I$ | | |
| | $\sigma_I = \mathrm{Sign}(\mathit{sk}_I, \mathsf L \lVert b_1)$; $m_1 = b_1 \lVert \mathrm{lp}(\sigma_I)$ | $\xrightarrow{\ m_1\ }$ | |
| 2 | | | verify $\mathit{cert}_I$ (CA signature, validity, CRL); $\mathrm{Vrfy}(\mathit{pk}_I, \mathsf L \lVert b_1, \sigma_I)$; $\lvert t - T_I\rvert \le \Delta$; $N_I$ not in cache |
| | | | $(\mathit{ct}, \mathit{ss}) \leftarrow \mathrm{Encaps}(\mathit{ek})$; $N_R \leftarrow \{0,1\}^{256}$ |
| | | | $\mathit{th}_1 = H(\mathsf L \lVert m_1)$; $b_2 = \texttt{m2} \lVert \mathrm{lp}(\mathit{ct}) \lVert \mathrm{lp}(\varepsilon) \lVert \mathrm{lp}(\mathit{cert}_R) \lVert \mathrm{lp}(N_R) \lVert T_R$ |
| | | | $\mathit{th}_2 = H(\mathit{th}_1 \lVert b_2)$; $\sigma_R = \mathrm{Sign}(\mathit{sk}_R, \mathsf L \lVert \mathit{th}_2)$; $\mathit{th}_3 = H(\mathit{th}_2 \lVert \sigma_R)$ |
| | | | $\mathit{prk} = \mathrm{Ext}(\mathit{th}_2, \mathit{ss})$; $K = \mathrm{Exp}(\mathit{prk}, \mathsf L\lVert\text{" session key"})$ |
| | | | $K_R = \mathrm{Exp}(\mathit{prk}, \mathsf L\lVert\text{" responder confirm"})$, $K_I = \mathrm{Exp}(\mathit{prk}, \mathsf L\lVert\text{" initiator confirm"})$ |
| | | $\xleftarrow{\ m_2\ }$ | $\tau_R = \mathrm{HMAC}(K_R, \mathit{th}_3)$; $m_2 = b_2 \lVert \mathrm{lp}(\sigma_R) \lVert \mathrm{lp}(\tau_R)$ |
| 3 | verify $\mathit{cert}_R$; $\lvert t - T_R\rvert \le \Delta$; recompute $\mathit{th}_2$; $\mathrm{Vrfy}(\mathit{pk}_R, \mathsf L \lVert \mathit{th}_2, \sigma_R)$ | | |
| | $\mathit{ss} = \mathrm{Decaps}(\mathit{dk}, \mathit{ct})$; **erase $\mathit{dk}$**; derive $K, K_R, K_I$ | | |
| | check $\tau_R$; **accept $K$**; $\tau_I = \mathrm{HMAC}(K_I, \mathit{th}_3 \lVert \tau_R)$ | $\xrightarrow{\ m_3\ }$ | check $\tau_I$; **accept $K$** |

In hybrid mode, $\mathrm{lp}(\varepsilon)$ carries an ephemeral X25519 share
$x_I G$ (resp. $x_R G$). The input keying material becomes
$\mathit{ss} \lVert \mathrm{X25519}(x_I, x_R G)$, and $x_I$ is erased with $\mathit{dk}$.

### Lemma 3.1 (injective encoding)

Every message, certificate and signed string is a fixed tag followed by
fixed-width integers and length-prefixed fields. The decoders reject trailing
bytes. Two different field tuples therefore never encode to the same bytes.
Consequently, equal hashes of encodings imply equal field tuples, unless $H$
has a collision.

### Lemma 3.2 (domain separation of signatures)

A pseudonym key signs exactly four kinds of string:

1. $\mathsf L \lVert b_1$, which starts with $\mathsf L \lVert \texttt{m1}$ and is
   longer than 1,000 bytes for ML-KEM;
2. $\mathsf L \lVert \mathit{th}_2$, exactly $13 + 32 = 45$ bytes;
3. safety messages, which start with `BSM` ([`broadcast.py`](../../qsv2v/pqc/broadcast.py));
4. the enrollment proof of possession, which starts with `QSV2V-POP`.

The CA key signs only strings starting with the certificate or CRL domain tags.
These sets are pairwise disjoint (by prefix, or for 1 vs 2 by length). So a
signature produced in one context is never a valid signature for a string of
another context. The proofs below can therefore treat "honest party signed
$\mathsf L \lVert x$" as an event about the handshake alone.

## 3.3 Security model

**Parties.** Each pseudonym is a party $P$ with a certified key pair.
$n_P$ = number of pseudonyms, $n_S$ = maximum number of sessions (handshake
instances) the adversary starts.

**Sessions.** Instance $\pi$ of party $P$ has:

* a role $\in \{I, R\}$;
* a status $\in \{\text{running}, \text{accepted}, \text{rejected}\}$;
* on acceptance, a key $\pi.K$, a peer $\pi.\mathit{pid}$ (the pseudonym in the
  certificate it received, so peers are *post-specified* as in SIGMA
  [[R24]](README.md#R24)), and a session identifier $\pi.\mathit{sid} = \mathit{th}_2$.

$\mathit{th}_2$ is a hash of $m_1$ and $b_2$. By Lemma 3.1 and collision
resistance, it fixes both pseudonyms, both nonces, $\mathit{ek}$, $\mathit{ct}$
and $\sigma_I$.

**Partners.** $\pi$ and $\pi'$ are partners if they have opposite roles and
$\pi.\mathit{sid} = \pi'.\mathit{sid}$. Using $\mathit{th}_2$, rather than the
full transcript including $\sigma_R$ and the MACs, means we never need
*strong* unforgeability. A re-randomised $\sigma_R$ changes $\mathit{th}_3$,
and the MAC check then fails (Theorem 1, step I-3).

**The adversary** $\mathcal A$ is a quantum polynomial-time algorithm. It
controls the network completely (Dolev–Yao) and may make these classical
queries:

| Query | Effect |
|---|---|
| $\mathsf{Send}(\pi, m)$ | deliver $m$ to $\pi$ (or start $\pi$ as initiator) and return its reply |
| $\mathsf{Reveal}(\pi)$ | return $\pi.K$ if $\pi$ accepted |
| $\mathsf{Corrupt}(P)$ | return $\mathit{sk}_P$: the vehicle is captured. Its *erased* ephemeral keys are gone |
| $\mathsf{CorruptCA}$ | return $\mathit{sk}_\text{CA}$ |
| $\mathsf{Test}(\pi)$ | flip $b \leftarrow \{0,1\}$ once; return $\pi.K$ if $b = 1$, a uniform 32-byte string if $b = 0$ |

**Freshness.** A session $\pi$ with peer $Q$ is *fresh* if all of the
following hold:

1. $\pi$ accepted;
2. there was no $\mathsf{Reveal}$ of $\pi$ or of its partner;
3. there was no $\mathsf{Corrupt}(Q)$ **before $\pi$ accepted**;
4. there was no $\mathsf{CorruptCA}$ **before $\pi$ accepted**.

Corruptions *after* acceptance are allowed: that is exactly forward secrecy.
Corrupting $\pi$'s *own* party at any time is allowed: that is resistance to
key-compromise impersonation. We exclude revealing the ephemeral $\mathit{dk}$
of the tested session while it is running, as the CK model does for session
state.

**Advantage.** $\mathcal A$ makes one $\mathsf{Test}$ query on a fresh session
and outputs $b'$:

$$
\mathrm{Adv}^\text{ror}_\Pi(\mathcal A) = \lvert 2\Pr[b' = b] - 1 \rvert .
$$

With $q_T$ Test queries on independent sessions, the advantage grows by at
most a factor $q_T$ (standard hybrid argument).

**Authentication.** Let $\mathsf{BadAuth}$ be the event that some session
$\pi$ accepts with peer $Q$, while $Q$ and the CA were uncorrupted when $\pi$
accepted, and either no session of $Q$ is a partner of $\pi$, or two sessions
are.

## 3.4 Two preliminary bounds

**Lemma 3.3 (no collisions among honest values).** Honest sessions draw 256-bit
nonces, and ML-KEM encapsulation keys contain a fresh 256-bit seed $\rho$
[[R16]](README.md#R16). The probability that two honest sessions repeat a
nonce or an $\mathit{ek}$ is at most
$2\binom{n_S}{2}2^{-256} \le n_S^2/2^{256}$.

**Lemma 3.4 (freshness and replay).** Responder $R$ accepts $m_1$ only if
$\lvert t - T_I\rvert \le \Delta$ and $N_I$ is not in its cache. The cache keeps
every nonce whose timestamp satisfies $t - T \le 2\Delta$
([`check_fresh`](../../qsv2v/pqc/pq_v2v_ake.py)).

*Claim:* $R$ never accepts the same $m_1$ twice.

*Proof.* Suppose $R$ accepted $m_1$ at time $t_1$ and receives it again at
$t_2 \ge t_1$. If $t_2 - T_I > \Delta$, the timestamp check rejects it.
Otherwise $t_2 - T_I \le \Delta < 2\Delta$, so the nonce stored at $t_1$ is
still in the cache and the replay is rejected. $\blacksquare$

A replay of $m_1$ to a *different* responder may be accepted. That is
harmless: the replayer cannot decapsulate (Theorem 2), and the initiator
accepts at most one $m_2$, because $\mathit{dk}$ is erased after the first.

## 3.5 Theorem 1: mutual authentication

**Theorem 1.** For every adversary $\mathcal A$ there are adversaries
$\mathcal B_1, \dots, \mathcal B_6$, running in about the time of $\mathcal A$,
such that

$$
\Pr[\mathsf{BadAuth}] \le \frac{n_S^2}{2^{256}}
+ \mathrm{Adv}^\text{cr}_H(\mathcal B_1)
+ \mathrm{Adv}^\text{euf-cma}_\text{CA}(\mathcal B_2)
+ n_P\,\mathrm{Adv}^\text{euf-cma}_\text{SIG}(\mathcal B_3)
+ n_S^2\Big(\mathrm{Adv}^\text{ind-cca}_\text{KEM}(\mathcal B_4)
+ \mathrm{Adv}^\text{swap}_\text{HMAC}(\mathcal B_5)
+ 2\,\mathrm{Adv}^\text{prf}_\text{HMAC}(\mathcal B_6) + 2^{-256}\Big).
$$

*Proof.* Rule out four bad events first.

* **E1:** two honest sessions repeat a nonce or $\mathit{ek}$. Lemma 3.3
  bounds it by $n_S^2/2^{256}$.
* **E2:** some value hashed by an honest party collides with another.
  $\mathcal B_1$ runs the whole experiment itself and outputs the collision,
  so E2 costs $\mathrm{Adv}^\text{cr}_H$.
* **E3:** an honest party accepts a certificate that the CA never issued,
  while the CA is uncorrupted. $\mathcal B_2$ embeds its challenge key as
  $\mathit{pk}_\text{CA}$, uses its signing oracle to issue certificates, and
  outputs the accepted certificate's signature as a forgery. Cost:
  $\mathrm{Adv}^\text{euf-cma}_\text{CA}$.
* **E4:** an honest party accepts a valid signature under pseudonym $Q$'s
  key, while $Q$ is uncorrupted, on a string $Q$ never signed. $\mathcal B_3$
  guesses $Q$ (factor $n_P$), embeds its challenge key as $\mathit{pk}_Q$,
  signs for $Q$ with its oracle, and aborts if $Q$ is corrupted (allowed only
  after the event). Cost: $n_P\,\mathrm{Adv}^\text{euf-cma}_\text{SIG}$.

From now on assume none of E1–E4 occurs.

*Initiator side.* Let $\pi_I$ accept with peer $Q$, with $Q$ and the CA
uncorrupted at that time.

1. $\mathit{cert}_Q$ verified, and not E3. So the CA issued it, and $\mathit{pk}_Q$
   is the genuine key that vehicle $Q$ generated.
2. $\sigma_R$ verified on $\mathsf L \lVert \mathit{th}_2$, and not E4. By
   Lemma 3.2, some session $\pi_Q$ of $Q$ signed $\mathsf L \lVert \mathit{th}_2$
   in step 2 of the handshake. It computed $\mathit{th}_2 = H(H(\mathsf L \lVert m_1') \lVert b_2')$
   from the $m_1'$ it received and the $b_2'$ it sent. By not-E2 and
   Lemma 3.1, $m_1' = m_1$ (exactly what $\pi_I$ sent) and $b_2' = b_2$ (exactly
   what $\pi_I$ received). So $\pi_Q.\mathit{sid} = \pi_I.\mathit{sid}$, and both
   agree on both certificates, both nonces, $\mathit{ek}$ and $\mathit{ct}$.
3. $\pi_Q$ is unique. It signed a $\mathit{th}_2$ containing its own fresh
   $N_R$, and by not-E1 no other session uses that nonce. (If $\mathcal A$
   replaces $\sigma_R$ by another valid signature on the same string, then
   $\pi_I$'s $\mathit{th}_3$ differs from $\pi_Q$'s and $\tau_R$ fails. If it
   does not fail, $\mathcal A$ has forged an HMAC tag, which is bounded in the
   responder case below.)

*Responder side.* Let $\pi_R$ accept with peer $Q$, with $Q$ and the CA
uncorrupted at that time.

1. As above, $\sigma_I$ on $\mathsf L \lVert b_1$ means an initiator session
   $\pi_Q$ of $Q$ created $b_1$, including its fresh $\mathit{ek}$.
2. $\pi_R$ checked $\tau_I = \mathrm{HMAC}(K_I, \mathit{th}_3 \lVert \tau_R)$,
   where $K_I$ comes from $\mathit{ss}$, which $\pi_R$ encapsulated to
   $\pi_Q$'s $\mathit{ek}$, and the salt $\mathit{th}_2^R$. Guess $\pi_Q$ and
   $\pi_R$ (factor $n_S^2$) and run three game hops:
   * **H1.** Replace $\mathit{ss}$ by a uniform value. $\mathcal B_4$ embeds
     its IND-CCA challenge key as $\pi_Q$'s $\mathit{ek}$ and its challenge
     ciphertext as $\pi_R$'s $\mathit{ct}$. Any *other* ciphertext later
     delivered to $\pi_Q$ goes to $\mathcal B_4$'s decapsulation oracle. Every
     other session is simulated with known keys. Cost:
     $\mathrm{Adv}^\text{ind-cca}_\text{KEM}$.
   * **H2.** Replace $\mathit{prk} = \mathrm{Ext}(\cdot, \mathit{ss})$ by a
     random function of the salt. Its key $\mathit{ss}$ is now uniform in
     $\{0,1\}^{256}$, a feasible set, so this costs
     $\mathrm{Adv}^\text{swap}_\text{HMAC}$.
   * **H3.** Replace $K_I$ and $K_R$ derived from $\mathit{prk}(\mathit{th}_2^R)$
     by uniform keys. This costs $\mathrm{Adv}^\text{prf}_\text{HMAC}$, since
     $\mathrm{Exp}$ is HMAC keyed by the uniform $\mathit{prk}$ on distinct
     labels.
3. After H3, $K_I$ is a uniform key that only sessions holding salt
   $\mathit{th}_2^R$ and secret $\mathit{ss}$ could compute. If $\pi_Q$ used a
   different salt $\mathit{th}_2' \ne \mathit{th}_2^R$, its $\mathrm{prk}$ is an
   independent random value. So a valid $\tau_I$ means either $\pi_Q$ computed
   it with $\mathit{th}_2' = \mathit{th}_2^R$, which makes it a partner, or
   $\mathcal A$ produced a valid HMAC tag under a uniform key it never saw.
   HMAC with a uniform key is a PRF, so the second case costs at most
   $\mathrm{Adv}^\text{prf}_\text{HMAC} + 2^{-256}$.
4. Uniqueness again follows from not-E1. $\blacksquare$

Theorem 1 gives **explicit** mutual authentication with key confirmation:

* the initiator knows a unique responder signed the same transcript;
* the responder knows the initiator derived the same keys from the same
  transcript;
* both agree on each other's pseudonym.

## 3.6 Theorem 2: session-key secrecy and perfect forward secrecy

**Theorem 2.** For every adversary $\mathcal A$ there are adversaries
$\mathcal B_1, \dots, \mathcal B_6$, running in about the time of $\mathcal A$,
such that

$$
\mathrm{Adv}^\text{ror}_\Pi(\mathcal A) \le 2\Big[\frac{n_S^2}{2^{256}}
+ \mathrm{Adv}^\text{cr}_H(\mathcal B_1)
+ \mathrm{Adv}^\text{euf-cma}_\text{CA}(\mathcal B_2)
+ n_P\,\mathrm{Adv}^\text{euf-cma}_\text{SIG}(\mathcal B_3)
+ n_S^2\big(\mathrm{Adv}^\text{ind-cca}_\text{KEM}(\mathcal B_4)
+ \mathrm{Adv}^\text{swap}_\text{HMAC}(\mathcal B_5)
+ \mathrm{Adv}^\text{prf}_\text{HMAC}(\mathcal B_6)\big)\Big],
$$

and the bound holds even when $\mathcal A$ corrupts every pseudonym and the CA
after the tested session accepts.

*Proof.* Let $\mathsf{Succ}_i$ be the event $b' = b$ in game $G_i$, and let
$\mathrm{Adv}_i = \lvert 2\Pr[\mathsf{Succ}_i] - 1\rvert$.

**$G_0$.** The real experiment, so $\mathrm{Adv}_0 = \mathrm{Adv}^\text{ror}_\Pi(\mathcal A)$.

**$G_1$.** Abort on E1 or E2 (as in Theorem 1). By the difference lemma,
$\mathrm{Adv}_0 \le \mathrm{Adv}_1 + 2(n_S^2/2^{256} + \mathrm{Adv}^\text{cr}_H)$.

**$G_2$.** Abort on E3 or E4, but only for acceptances that happen while the
peer and the CA are uncorrupted. This is all freshness requires.
$\mathrm{Adv}_1 \le \mathrm{Adv}_2 + 2(\mathrm{Adv}^\text{euf-cma}_\text{CA} + n_P\,\mathrm{Adv}^\text{euf-cma}_\text{SIG})$.

*Consequence of $G_2$.* Let $\pi^*$ be the tested (fresh) session. By the
argument of Theorem 1, there is a unique honest initiator session $\pi_I^*$ and
a unique honest responder session $\pi_R^*$ such that:

* $\pi_I^*$ generated $(\mathit{ek}^*, \mathit{dk}^*)$;
* $\pi_R^*$ produced $(\mathit{ct}^*, \mathit{ss}^*) = \mathrm{Encaps}(\mathit{ek}^*)$
  and signed $\mathit{th}_2^*$;
* $\pi^*$ is one of these two;
* $\pi^*.K = \mathrm{Exp}(\mathrm{Ext}(\mathit{th}_2^*, \mathit{ss}^*), \text{session label})$.

The adversary's later corruptions reveal $\mathit{sk}$ values, never
$\mathit{dk}^*$. That key was erased the moment $\pi_I^*$ decapsulated, and
$\pi_R^*$ never held it.

**$G_3$.** The challenger guesses the pair $(\pi_I^*, \pi_R^*)$ among at most
$n_S^2$ pairs and aborts (outputting a random bit) if the guess is wrong.
Then $\mathrm{Adv}_2 = n_S^2\,\mathrm{Adv}_3$.

**$G_4$.** Replace $\mathit{ss}^*$ by a uniform 32-byte string in both
sessions. Reduction $\mathcal B_4$ against IND-CCA of ML-KEM:

* It receives $\mathit{ek}^\circ$ and a challenge $(\mathit{ct}^\circ, k_\beta)$.
* It uses $\mathit{ek}^\circ$ as $\pi_I^*$'s ephemeral key, and uses
  $\mathit{ct}^\circ$ and $k_\beta$ when $\pi_R^*$ encapsulates.
* If $\pi_I^*$ receives a different ciphertext (possible only in runs where
  $\pi^*$ is not fresh, or the guess is wrong), $\mathcal B_4$ asks its
  decapsulation oracle.
* Every other session runs with keys $\mathcal B_4$ chose itself, so it
  answers Reveal and Corrupt for them, at any time, including Corrupt of every
  party after acceptance. $\mathcal B_4$ also holds the CA key, so it answers
  CorruptCA.

$\beta = 1$ simulates $G_3$ and $\beta = 0$ simulates $G_4$, so
$\mathrm{Adv}_3 \le \mathrm{Adv}_4 + 2\,\mathrm{Adv}^\text{ind-cca}_\text{KEM}$.

**$G_5$.** Replace $\mathit{prk}^* = \mathrm{Ext}(\mathit{th}_2^*, \mathit{ss}^*)$
by a uniform value. In $G_4$, $\mathit{ss}^*$ is uniform on
$\{0,1\}^{256}$ and is used only as the message-side key of $\mathrm{Ext}$.
Both $\pi_I^*$ and $\pi_R^*$ evaluate it at the single salt $\mathit{th}_2^*$
($\pi_I^*$ decapsulates $\mathit{ct}^*$ only after verifying $\sigma_R$ on a
$\mathit{th}_2$ that contains $\mathit{ct}^*$, and by $G_2$ that is
$\mathit{th}_2^*$). Reduction $\mathcal B_5$ obtains $\mathit{prk}^*$ from its
swap-PRF oracle. $\mathrm{Adv}_4 \le \mathrm{Adv}_5 + 2\,\mathrm{Adv}^\text{swap}_\text{HMAC}$.

**$G_6$.** Replace $(K^*, K_R^*, K_I^*) = \mathrm{Exp}(\mathit{prk}^*, \cdot)$ on
the three distinct labels by independent uniform strings. Reduction
$\mathcal B_6$ queries its PRF oracle (HMAC keyed by the uniform
$\mathit{prk}^*$) on the three labels.
$\mathrm{Adv}_5 \le \mathrm{Adv}_6 + 2\,\mathrm{Adv}^\text{prf}_\text{HMAC}$.

**In $G_6$** the tested key $K^*$ is uniform and independent of everything
else $\mathcal A$ sees. The MAC tags use the independent $K_R^*$ and $K_I^*$,
and $\mathit{th}_3$ is public anyway. So $\Pr[\mathsf{Succ}_6] = 1/2$ and
$\mathrm{Adv}_6 = 0$. Chaining the inequalities gives the theorem.
$\blacksquare$

**Perfect forward secrecy.** Nothing in $G_3$–$G_6$ uses a long-term secret.
$G_2$ needs unforgeability only *up to acceptance*. So corrupting every
pseudonym, the CA, or the CA's copies (it has none: vehicles generate their
own keys) after the test session accepts leaves the bound unchanged. This is
full forward secrecy, not only "weak" forward secrecy, because the ephemerals
of the tested session are authenticated by signatures that were unforgeable
when they were checked.

*Implementation note.* The proof assumes $\mathit{dk}$ is actually erased.
The code drops its only reference (`st.dk = None`) after decapsulation.
Python cannot guarantee that the bytes are overwritten in memory; an embedded
implementation should zeroise the buffer explicitly.

### What the bound means

The loss factors $n_P$ and $n_S^2$ come from guessing. They are common in AKE
proofs and are not believed to reflect real attacks. Take $n_S = 2^{30}$
handshakes and $n_P = 2^{20}$ pseudonyms. The collision term is then
$2^{60-256} = 2^{-196}$, and the reduction loses at most 60 bits relative to
the primitives' security. So the security of PQ-V2V-AKE is reduced to
ML-KEM-768 (NIST category 3), ML-DSA-44 (category 2) and HMAC-SHA-256
(Chapter 5), with a polynomial loss. Tighter proofs exist for similar
protocols, at the cost of stronger assumptions or more complex arguments; we
do not attempt one.

**Experimental counterpart.** E5 re-runs eight attack classes against
PQ-V2V-AKE ([`attack_suite.py`](../../qsv2v/pqc/attack_suite.py)). Five are
concrete instances of events this proof rules out: passive key recovery, past
sessions after every key leaks, a forged certificate, a forged or replayed
$m_1$, and swapping the ciphertext. Of the other three, linking is covered in
§3.8, password guessing has nothing to attack, and the hybrid case is §3.7.
None of the 40 runs succeeded. Where a test has a positive control (the same
attack succeeding when the defence is removed), passing the control is part
of the test.

## 3.7 Theorem 3: hybrid mode

In hybrid mode, $\mathit{prk} = \mathrm{Ext}(\mathit{th}_2, \mathit{ss} \lVert z)$
with $z = \mathrm{X25519}(x_I, x_R G)$ [[R34]](README.md#R34). Both shares are
inside the signed $\mathit{th}_2$.

**Assumption $\mathsf A_\text{hyb}$ (concatenation combiner).**
$s \mapsto \mathrm{HMAC}(s, k_1 \lVert k_2)$ is a PRF whenever one of $k_1$,
$k_2$ is uniform and secret, even if the other is known to, or chosen by, the
adversary.

This is the assumption behind concatenating shared secrets into HKDF-Extract.
That is how hybrid key exchange for TLS 1.3 is built, and the "dual-PRF
combiner" of Bindel et al. [[R28]](README.md#R28) (§3.2) models it. Note that
it is **stronger** than what [[R27]](README.md#R27) proves: their swap-PRF
theorem covers a key drawn uniformly from a feasible set, not a 512-bit key
half of which is known. We therefore state $\mathsf A_\text{hyb}$ as an
explicit assumption.

**Theorem 3 (sketch).** Under $\mathsf A_\text{hyb}$, Theorem 2 holds for the
hybrid mode with $\mathrm{Adv}^\text{ind-cca}_\text{KEM}$ replaced by
$\min\{\mathrm{Adv}^\text{ind-cca}_\text{KEM},\ \mathrm{Adv}^\text{ddh}_\text{X25519}\}$
for a *classical* adversary. For a quantum adversary, DDH on Curve25519 fails
(Shor), so the bound is the KEM term alone, exactly as in Theorem 2.

*Sketch.* Repeat $G_0$–$G_3$ unchanged. In $G_4$, replace either $\mathit{ss}^*$
(IND-CCA, as before) or $z^*$ by an independent value. For $z^*$: the two
shares are honest and signed, so under DDH, $z^*$ is indistinguishable from
the X25519 output of a random point. In $G_5$, use $\mathsf A_\text{hyb}$ with
the replaced component as the secret half. $G_6$ is unchanged. Bindel et al.
note that the combined key must also bind both ciphertexts, or one KEM could
be mauled. Here both ciphertexts are inside the salt $\mathit{th}_2$, which
both sides sign or check. $\square$

E5's last defence row checks this behaviour: even an attacker who knows the
X25519 secret (a quantum attacker) does not get the hybrid key.

## 3.8 Anonymity and unlinkability

**Anonymity.** The only identifier on the air is the pseudonym certificate: a
uniform random 16-byte pseudonym, a public key that is fresh per pseudonym,
and a validity window. The real identity is known only to the CA. No field is
a function of the real identity (compare PSLAP's
$\mathit{PID} = h(\mathit{ID} \lVert a_1)$ and PSRS-D2D's
$\overline{\mathit{ID}} = [X] \oplus \mathit{ID}$, both inverted in Chapter 2).

**Unlinkability across pseudonyms.** Game: the adversary sees two handshakes
under pseudonyms $P_0$ and $P_1$ and must decide whether they belong to the
same vehicle. Field by field:

* $\mathit{ek}$, $N$, $\mathit{ct}$ and $\sigma$ are fresh per session.
* $\mathit{pn}_P$ and $\mathit{pk}_P$ are generated independently for each
  pseudonym, even for one vehicle.
* The only fields that could correlate are the validity windows
  $[t_\text{nb}, t_\text{na})$ and the algorithm name.

The algorithm name is the same for every vehicle. A vehicle's pseudonyms have
consecutive windows of length $L = 300$ s.

**Finding, and the fix applied.** In the first version, the windows started
at the vehicle's enrollment time $t_0$, so $t_\text{nb} \equiv t_0 \pmod L$
for all of a vehicle's pseudonyms. Vehicles that enrol at different times
then differ in $t_0 \bmod L$, and that residue links all of a vehicle's
pseudonyms. Our simulation enrolled every vehicle at the same instant, which
hid the problem: E5's linking test could not see it.

The authority now puts every window on one global grid,
$[kL, (k+1)L)$ for integer $k$, with the first window being the one that
contains the enrollment time (`Authority.enroll`). IEEE 1609.2 pseudonym
schedules follow the same idea. Every vehicle's certificate for window $k$
then carries the same validity fields, $(kL, (k+1)L)$, so they reveal nothing
about who holds the certificate or when it enrolled.
`tests/test_certs.py::test_validity_windows_do_not_reveal_enrollment_time`
checks this with two vehicles enrolling at different times. That test fails
on the first version.

Within one pseudonym's window, sessions are linkable by design. This is the
same trade-off IEEE 1609.2 makes.

The same certificate signs safety messages and handshakes, so within a window
the two kinds of traffic are linkable to each other. Across windows, nothing
in either kind of traffic links pseudonyms.

## 3.9 Relation to the Scyther verification

The Scyther model ([`verification/pq_v2v_ake.spdl`](../../verification/pq_v2v_ake.spdl),
[[R30]](README.md#R30)) treats the primitives as perfect: symbolic encryption,
signatures and hashes. Within the bounds it explores, it verifies all 12
claims for both roles: secrecy of $\mathit{ss}$ and $K$, aliveness, weak
agreement, non-injective agreement and synchronisation. A negative control,
with the responder signature removed, fails as it should. This complements the
theorems above:

* Scyther searches every interleaving of messages for logical attacks, but
  assumes the cryptography is perfect.
* Theorems 1–3 account for the cryptography's real, computational security,
  but are argued by hand.

Forward secrecy is outside Scyther's default adversary. It is covered by
Theorem 2 and tested in code.
