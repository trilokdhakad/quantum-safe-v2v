# Mathematical formulation

This part of the report gives the mathematics behind every simulated result in
QSV2V. Each chapter states its model, derives each result step by step, and
then puts the prediction next to what the code measured.

| Chapter | What is derived | Checked against |
|---|---|---|
| [1. BB84 quantum key distribution](01_qkd.md) | sifting rate; QBER with noise, loss, dark counts and an intercept-resend eavesdropper; abort point; Cascade parity statistics; Toeplitz collision bound; final key length and the 11% / 9.6% thresholds; key rate vs distance | E1–E4, E10 |
| [2. Attacks on the base papers](02_attacks.md) | the algebra of all seven attacks on PSLAP, PSRS-D2D and P²AS-IoAV; Shor's period finding | E5 |
| [3. PQ-V2V-AKE: model and proofs](03_pq_v2v_ake_proofs.md) | the protocol as equations; a Real-or-Random security model with key leaks and capture; Theorem 1 (mutual authentication), Theorem 2 (session-key secrecy with perfect forward secrecy), Theorem 3 (hybrid mode); replay, anonymity and unlinkability | E5 defences, Scyther |
| [4. Network and performance](04_network.md) | every message size from the parameter sets; 802.11p airtime; handshake latency on an idle channel; channel busy ratio; key rates for E10 | E7–E10 |
| [5. Security parameters](05_security_parameters.md) | (a) classical and quantum bit security of every primitive, with the internal parameter sets; (b) the security properties each protocol meets against a classical and a quantum attacker | FIPS 203/204, NIST, E5 |

## How the numbers are kept honest

* **Formulas as code.** Every closed-form result is also a function in
  [`qsv2v/formulas.py`](../../qsv2v/formulas.py). Its docstring names the
  section that derives it.
* **Tests.** [`tests/test_formulation.py`](../../tests/test_formulation.py)
  checks each formula against independent evidence:
  * an exact enumeration of the BB84 event tree, in rational arithmetic;
  * the cryptographic libraries' own key and ciphertext sizes;
  * the real protocol encodings;
  * the simulator itself (for example, a two-vehicle handshake on an idle
    channel must take exactly the predicted time);
  * the attack algebra, on fresh random instances.
* **Generated tables.** Every "theory vs measured" table sits between
  `<!-- BEGIN GENERATED -->` markers. It is written by
  [`scripts/build_math_tables.py`](../../scripts/build_math_tables.py) from
  `results/` (produced by `python -m qsv2v.experiments`) and from
  `qsv2v/formulas.py`, so no measured number in these tables is typed by
  hand. The test suite runs the script in `--check` mode, so it fails if a
  table no longer matches the recorded results.
* **Where theory and measurement differ, we say by how much and why.**
  Two places need explaining, and both chapters do it:
  * the final key fraction (§1.6), where the sampled QBER adds run-to-run
    spread;
  * the handshake latency (§4.4), where the idle-channel model is a lower
    bound.

## Notation used throughout

| Symbol | Meaning |
|---|---|
| $\lVert$ | concatenation of byte strings; every field on the wire is length-prefixed, $\mathrm{lp}(x) = \mathrm{len}(x)_{32\text{-bit}} \lVert x$ |
| $h(p)$ | binary entropy, $-p\log_2 p - (1-p)\log_2(1-p)$ |
| $H$ | SHA-256 |
| $\mathrm{HMAC}(k, m)$ | HMAC-SHA-256 with key $k$ and message $m$ |
| $\mathrm{Ext}(s, k) = \mathrm{HMAC}(s, k)$, $\mathrm{Exp}(k, \ell)$ | HKDF-Extract (salt $s$, input keying material $k$) and HKDF-Expand (label $\ell$), RFC 5869 [[R33]](#R33) |
| $G$, $q$ | generator and order of the P-256 group (Chapter 2) |
| $\mathbb{Z}_q$ | integers mod $q$ |
| $\mathrm{Adv}^{\text{x}}_{S}(\mathcal{B})$ | advantage of adversary $\mathcal{B}$ against property x of scheme $S$ |
| $\lambda$ | security parameter, in bits |

## References

Every DOI below was resolved through doi.org (handle API) and checked against
its title, authors and pages with Crossref. The specification numbers quoted
in Chapter 5 were read from the PDFs themselves (URLs given).

<a id="R1"></a>[R1] C. H. Bennett and G. Brassard, "Quantum cryptography: Public key distribution and coin tossing," *Proc. IEEE Int. Conf. Computers, Systems and Signal Processing*, 1984; reprinted in *Theoretical Computer Science* 560, pp. 7–11, 2014. [doi:10.1016/j.tcs.2014.05.025](https://doi.org/10.1016/j.tcs.2014.05.025)

<a id="R2"></a>[R2] P. W. Shor and J. Preskill, "Simple proof of security of the BB84 quantum key distribution protocol," *Physical Review Letters* 85, pp. 441–444, 2000. [doi:10.1103/PhysRevLett.85.441](https://doi.org/10.1103/PhysRevLett.85.441)

<a id="R3"></a>[R3] G. Brassard and L. Salvail, "Secret-key reconciliation by public discussion" (Cascade), *EUROCRYPT '93*, LNCS 765, pp. 410–423, 1994. [doi:10.1007/3-540-48285-7_35](https://doi.org/10.1007/3-540-48285-7_35)

<a id="R4"></a>[R4] C. H. Bennett, G. Brassard, C. Crépeau and U. M. Maurer, "Generalized privacy amplification," *IEEE Trans. Information Theory* 41(6), pp. 1915–1923, 1995. [doi:10.1109/18.476316](https://doi.org/10.1109/18.476316)

<a id="R5"></a>[R5] J. L. Carter and M. N. Wegman, "Universal classes of hash functions," *Journal of Computer and System Sciences* 18, pp. 143–154, 1979. [doi:10.1016/0022-0000(79)90044-8](https://doi.org/10.1016/0022-0000(79)90044-8)

<a id="R6"></a>[R6] H. Krawczyk, "LFSR-based hashing and authentication," *CRYPTO '94*, LNCS 839, pp. 129–139, 1994. [doi:10.1007/3-540-48658-5_15](https://doi.org/10.1007/3-540-48658-5_15)

<a id="R7"></a>[R7] J. Håstad, R. Impagliazzo, L. Levin and M. Luby, "A pseudorandom generator from any one-way function" (leftover hash lemma), *SIAM Journal on Computing* 28, pp. 1364–1396, 1999. [doi:10.1137/S0097539793244708](https://doi.org/10.1137/S0097539793244708)

<a id="R8"></a>[R8] M. Tomamichel, C. C. W. Lim, N. Gisin and R. Renner, "Tight finite-key analysis for quantum cryptography," *Nature Communications* 3, 634, 2012. [doi:10.1038/ncomms1631](https://doi.org/10.1038/ncomms1631)

<a id="R9"></a>[R9] P. W. Shor, "Algorithms for quantum computation: discrete logarithms and factoring," *Proc. 35th FOCS*, pp. 124–134, 1994. [doi:10.1109/SFCS.1994.365700](https://doi.org/10.1109/SFCS.1994.365700)

<a id="R10"></a>[R10] M. Roetteler, M. Naehrig, K. M. Svore and K. Lauter, "Quantum resource estimates for computing elliptic curve discrete logarithms," *ASIACRYPT 2017*, LNCS 10625, pp. 241–270, 2017. [doi:10.1007/978-3-319-70697-9_9](https://doi.org/10.1007/978-3-319-70697-9_9) (P-256: 2330 logical qubits, about 1.26·10¹¹ Toffoli gates; read from [arXiv:1706.06752](https://arxiv.org/abs/1706.06752), §1)

<a id="R11"></a>[R11] L. K. Grover, "A fast quantum mechanical algorithm for database search," *Proc. 28th STOC*, pp. 212–219, 1996. [doi:10.1145/237814.237866](https://doi.org/10.1145/237814.237866)

<a id="R12"></a>[R12] G. Brassard, P. Høyer and A. Tapp, "Quantum cryptanalysis of hash and claw-free functions," *LATIN '98*, LNCS 1380, pp. 163–169, 1998. [doi:10.1007/BFb0054319](https://doi.org/10.1007/BFb0054319)

<a id="R13"></a>[R13] D. J. Bernstein, "Cost analysis of hash collisions: Will quantum computers make SHARCS obsolete?," *SHARCS 2009*, Lausanne, 2009. [cr.yp.to/papers.html#collisioncost](https://cr.yp.to/papers.html#collisioncost)

<a id="R14"></a>[R14] J. M. Pollard, "Monte Carlo methods for index computation (mod p)," *Mathematics of Computation* 32(143), pp. 918–924, 1978. [doi:10.1090/S0025-5718-1978-0491431-9](https://doi.org/10.1090/S0025-5718-1978-0491431-9)

<a id="R15"></a>[R15] NIST, *Submission Requirements and Evaluation Criteria for the Post-Quantum Cryptography Standardization Process*, Dec. 2016, §4.A.5 (security categories 1–5). [csrc.nist.gov PDF](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/call-for-proposals-final-dec-2016.pdf)

<a id="R16"></a>[R16] NIST, FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, Aug. 2024 (Tables 1–3). [doi:10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)

<a id="R17"></a>[R17] NIST, FIPS 204, *Module-Lattice-Based Digital Signature Standard*, Aug. 2024 (Tables 1–2, Algorithms 22 and 26). [doi:10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)

<a id="R18"></a>[R18] R. Avanzi, J. Bos, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, J. M. Schanck, P. Schwabe, G. Seiler and D. Stehlé, *CRYSTALS-Kyber Algorithm Specifications and Supporting Documentation*, version 3.02, Aug. 2021 (Table 4). [pq-crystals.org PDF](https://www.pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf)

<a id="R19"></a>[R19] S. Bai, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, P. Schwabe, G. Seiler and D. Stehlé, *CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation*, version 3.1, Feb. 2021 (Table 1). [pq-crystals.org PDF](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)

<a id="R20"></a>[R20] P.-A. Fouque, J. Hoffstein, P. Kirchner, V. Lyubashevsky, T. Pornin, T. Prest, T. Ricosset, G. Seiler, W. Whyte and Z. Zhang, *Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU*, specification v1.2, Oct. 2020 (Table 3.3). [falcon-sign.info PDF](https://falcon-sign.info/falcon.pdf)

<a id="R21"></a>[R21] M. Bellare and P. Rogaway, "Entity authentication and key distribution," *CRYPTO '93*, LNCS 773, pp. 232–249, 1994. [doi:10.1007/3-540-48329-2_21](https://doi.org/10.1007/3-540-48329-2_21)

<a id="R22"></a>[R22] R. Canetti and H. Krawczyk, "Analysis of key-exchange protocols and their use for building secure channels," *EUROCRYPT 2001*, LNCS 2045, pp. 453–474, 2001. [doi:10.1007/3-540-44987-6_28](https://doi.org/10.1007/3-540-44987-6_28)

<a id="R23"></a>[R23] M. Abdalla, P.-A. Fouque and D. Pointcheval, "Password-based authenticated key exchange in the three-party setting" (the Real-or-Random model), *PKC 2005*, LNCS 3386, pp. 65–84, 2005. [doi:10.1007/978-3-540-30580-4_6](https://doi.org/10.1007/978-3-540-30580-4_6)

<a id="R24"></a>[R24] H. Krawczyk, "SIGMA: The 'SIGn-and-MAc' approach to authenticated Diffie-Hellman and its use in the IKE protocols," *CRYPTO 2003*, LNCS 2729, pp. 400–425, 2003. [doi:10.1007/978-3-540-45146-4_24](https://doi.org/10.1007/978-3-540-45146-4_24)

<a id="R25"></a>[R25] H. Krawczyk, "Cryptographic extraction and key derivation: The HKDF scheme," *CRYPTO 2010*, LNCS 6223, pp. 631–648, 2010. [doi:10.1007/978-3-642-14623-7_34](https://doi.org/10.1007/978-3-642-14623-7_34)

<a id="R26"></a>[R26] M. Bellare, "New proofs for NMAC and HMAC: Security without collision-resistance," *CRYPTO 2006*, LNCS 4117, pp. 602–619, 2006. [doi:10.1007/11818175_36](https://doi.org/10.1007/11818175_36)

<a id="R27"></a>[R27] M. Backendal, M. Bellare, F. Günther and M. Scarlata, "When messages are keys: Is HMAC a dual-PRF?," *CRYPTO 2023*, LNCS 14083, pp. 661–693, 2023. [doi:10.1007/978-3-031-38548-3_22](https://doi.org/10.1007/978-3-031-38548-3_22) (full version, read for this report: [NSF PAR copy](https://par.nsf.gov/servlets/purl/10493803))

<a id="R28"></a>[R28] N. Bindel, J. Brendel, M. Fischlin, B. Goncalves and D. Stebila, "Hybrid key encapsulation mechanisms and authenticated key exchange," *PQCrypto 2019*, LNCS 11505, pp. 206–226, 2019. [doi:10.1007/978-3-030-25510-7_12](https://doi.org/10.1007/978-3-030-25510-7_12) (ePrint 2018/903, §3.2, read for this report)

<a id="R29"></a>[R29] B. Dowling, M. Fischlin, F. Günther and D. Stebila, "A cryptographic analysis of the TLS 1.3 handshake protocol," *Journal of Cryptology* 34, article 37, 2021. [doi:10.1007/s00145-021-09384-1](https://doi.org/10.1007/s00145-021-09384-1)

<a id="R30"></a>[R30] C. J. F. Cremers, "The Scyther tool: Verification, falsification, and analysis of security protocols," *CAV 2008*, LNCS 5123, pp. 414–418, 2008. [doi:10.1007/978-3-540-70545-1_38](https://doi.org/10.1007/978-3-540-70545-1_38)

<a id="R31"></a>[R31] IEEE Std 802.11p-2010, *Amendment 6: Wireless Access in Vehicular Environments*. [doi:10.1109/IEEESTD.2010.5514475](https://doi.org/10.1109/IEEESTD.2010.5514475)

<a id="R32"></a>[R32] The three base papers, as cited in the project plan:
PSLAP, *Computer Networks* 261, 111155, 2025, [doi:10.1016/j.comnet.2025.111155](https://doi.org/10.1016/j.comnet.2025.111155);
PSRS-D2D, *IEEE Trans. Mobile Computing* 25(1), pp. 1445–1456, 2026, [doi:10.1109/TMC.2025.3601369](https://doi.org/10.1109/TMC.2025.3601369);
P²AS-IoAV, *IEEE Trans. Vehicular Technology* 75(10), pp. 24698–24711, 2026, [doi:10.1109/TVT.2026.3698192](https://doi.org/10.1109/TVT.2026.3698192).

<a id="R33"></a>[R33] H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," RFC 5869, 2010. [doi:10.17487/RFC5869](https://doi.org/10.17487/RFC5869)

<a id="R34"></a>[R34] A. Langley, M. Hamburg and S. Turner, "Elliptic Curves for Security" (X25519), RFC 7748, 2016. [doi:10.17487/RFC7748](https://doi.org/10.17487/RFC7748)

<a id="R35"></a>[R35] NIST, FIPS 180-4, *Secure Hash Standard (SHS)*, 2015. [doi:10.6028/NIST.FIPS.180-4](https://doi.org/10.6028/NIST.FIPS.180-4)

<a id="R36"></a>[R36] NIST, FIPS 197, *Advanced Encryption Standard (AES)*, updated 2023. [doi:10.6028/NIST.FIPS.197-upd1](https://doi.org/10.6028/NIST.FIPS.197-upd1)
