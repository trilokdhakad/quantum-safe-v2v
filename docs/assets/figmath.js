// Numbers the page's chart annotations show ("caught at 44%", "no key above 11%", "10x less key
// every 49 km"), computed from the data files. Kept free of the DOM so tests/test_web_figures.py can
// check them under Node against qsv2v.formulas and the experiment results.
(function (root) {
  'use strict';

  // Where a series falls to zero. Extends the line through its last two positive points and keeps
  // the answer inside the bracket [last positive x, first zero x]. (Interpolating from a tiny last
  // value straight to the zero point would overshoot when the curve meets zero between grid points.)
  // Returns null if the series never reaches zero.
  function zeroAt(rows, xKey, yKey) {
    const pts = rows.filter((r) => r[yKey] != null).map((r) => [+r[xKey], +r[yKey]]).sort((a, b) => a[0] - b[0]);
    let i = -1;
    pts.forEach((p, k) => { if (p[1] > 0) i = k; });
    if (i < 0 || i === pts.length - 1) return null;
    const [x0, y0] = pts[i], x1 = pts[i + 1][0];
    if (i === 0) return x1;
    const [xa, ya] = pts[i - 1];
    const slope = (y0 - ya) / (x0 - xa);
    return slope < 0 ? Math.min(x1, x0 - y0 / slope) : x1;
  }

  // For each noise level of the E1 grid: the share of photons Eve must intercept for the theory QBER
  // to reach the abort threshold. The formula is linear in that share, so interpolating between grid
  // points is exact.
  function eveCrossings(grid, threshold) {
    return [...new Set(grid.map((r) => r.noise))].map((name) => {
      const rows = grid.filter((r) => r.noise === name).sort((a, b) => a.eve_fraction - b.eve_fraction);
      let f = null;
      for (let i = 1; i < rows.length && f == null; i++) {
        const a = rows[i - 1], b = rows[i];
        if (+a.qber_theory <= threshold && +b.qber_theory >= threshold) {
          f = +a.eve_fraction + ((threshold - a.qber_theory) * (b.eve_fraction - a.eve_fraction)) / (b.qber_theory - a.qber_theory);
        }
      }
      return { name, rows, f };
    });
  }

  // Decay of the E3 key rate in dB per km: least-squares fit of log10(rate) against distance up to
  // 120 km, before dark counts matter (the same fit as qsv2v/experiments/e03_distance_loss.py).
  function e3Slope(rows) {
    const pts = rows.filter((r) => +r.skr_asymptotic > 0 && +r.distance_km <= 120).map((r) => [+r.distance_km, Math.log10(+r.skr_asymptotic)]);
    const n = pts.length;
    const mx = pts.reduce((s, p) => s + p[0], 0) / n, my = pts.reduce((s, p) => s + p[1], 0) / n;
    const sxy = pts.reduce((s, p) => s + (p[0] - mx) * (p[1] - my), 0), sxx = pts.reduce((s, p) => s + (p[0] - mx) ** 2, 0);
    return (-10 * sxy) / sxx;
  }

  // A power of ten as "1 in N": 1e-3 -> "1 in 1k", 1e-7 -> "1 in 10M".
  const SI = { 0: '', 3: 'k', 6: 'M', 9: 'G' };
  function inWords(v) {
    const e = Math.round(-Math.log10(v)), k = Math.floor(e / 3) * 3;
    return `1 in ${10 ** (e - k)}${SI[k]}`;
  }

  const api = { zeroAt, eveCrossings, e3Slope, inWords };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.FigMath = api;
})(typeof window !== 'undefined' ? window : globalThis);
