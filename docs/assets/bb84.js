// BB84 in the browser: the same physics as qsv2v.qkd (NumPy backend), small enough to read.
// Used by the page's "Run BB84 yourself" lab and checked against the Python theory in
// tests/test_web_bb84.py (run with Node).
(function (root) {
  'use strict';

  // Seeded PRNG (mulberry32) so a run can be repeated exactly.
  function rng(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // Measuring a qubit prepared as (bit, basis) in basis b: the bit if bases match, else a coin flip.
  function measure(bit, basis, b, r) { return basis === b ? bit : (r() < 0.5 ? 1 : 0); }

  /**
   * Send n photons. eve = fraction intercepted (intercept-resend), noise = channel error rate e
   * (in both bases, as PauliNoise.from_qber(e)). Returns one record per photon.
   */
  function send(n, eve, noise, seed) {
    const r = rng(seed);
    const out = new Array(n);
    for (let i = 0; i < n; i++) {
      const aBit = r() < 0.5 ? 1 : 0, aBasis = r() < 0.5 ? 1 : 0; // basis 0 = +, 1 = ×
      let bit = aBit, basis = aBasis, eBasis = null, eBit = null;
      const intercepted = r() < eve;
      if (intercepted) { // Eve measures in a random basis and resends what she saw
        eBasis = r() < 0.5 ? 1 : 0;
        eBit = measure(bit, basis, eBasis, r);
        bit = eBit; basis = eBasis;
      }
      const bBasis = r() < 0.5 ? 1 : 0;
      let bBit = measure(bit, basis, bBasis, r);
      if (r() < noise) bBit ^= 1; // channel noise flips the outcome
      const sifted = aBasis === bBasis;
      out[i] = { aBit, aBasis, intercepted, eBasis, eBit, bBasis, bBit, sifted, error: sifted && aBit !== bBit };
    }
    return out;
  }

  const h = (p) => (p <= 0 || p >= 1 ? 0 : -p * Math.log2(p) - (1 - p) * Math.log2(1 - p));
  const theoryQber = (eve, noise) => noise + eve / 4 - (eve * noise) / 2;

  /**
   * Sift, estimate QBER on a random 10% sample, abort above 11%, and estimate the final
   * key with the asymptotic formula n(1 - (1+f)h(Q)) - 131, f = 1.16 (Cascade, measured in E4).
   * The Python pipeline runs real Cascade and privacy amplification; this is the estimate.
   */
  function analyse(photons, seed) {
    const r = rng((seed ^ 0x9e3779b9) >>> 0);
    const sifted = photons.filter((p) => p.sifted);
    const sample = [], keep = [];
    sifted.forEach((p) => (r() < 0.1 ? sample : keep).push(p));
    const sErr = sample.filter((p) => p.error).length;
    const qEst = sample.length ? sErr / sample.length : 0;
    const qTrue = sifted.length ? sifted.filter((p) => p.error).length / sifted.length : 0;
    const abort = qEst > 0.11;
    const F_EC = 1.16, OVERHEAD = 131;
    const keyBits = abort ? 0 : Math.max(0, Math.floor(keep.length * (1 - (1 + F_EC) * h(qEst)) - OVERHEAD));
    return { n: photons.length, sifted: sifted.length, sample: sample.length, qEst, qTrue, abort, keyBits, keep: keep.length };
  }

  const api = { rng, send, analyse, theoryQber, h };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.BB84 = api;
})(typeof window !== 'undefined' ? window : globalThis);
