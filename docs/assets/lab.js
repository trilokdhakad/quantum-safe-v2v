// "Run BB84 yourself": live photons, keys, QBER and the abort decision (physics in bb84.js).
(function () {
  'use strict';
  const el = document.getElementById('lab');
  if (!el || !window.BB84) return;
  const B = window.BB84;
  const N = 20000, SHOW = 16, KEYSHOW = 48;
  const pct = (v, d = 1) => (100 * v).toFixed(d) + '%';
  const sym = (b) => (b ? '×' : '+');
  let seed = 20261125, timer = null;

  el.innerHTML = `
    <div class="lab-controls">
      <label><span>Eve intercepts <b id="lab-eve-v">0%</b> of photons</span>
        <input id="lab-eve" type="range" min="0" max="100" step="5" value="0" aria-label="Fraction of photons Eve intercepts"></label>
      <label><span>Channel noise <b id="lab-noise-v">1.0%</b></span>
        <input id="lab-noise" type="range" min="0" max="10" step="0.5" value="1" aria-label="Channel error rate"></label>
      <button id="lab-go" type="button" class="go">Send ${N.toLocaleString()} photons</button>
    </div>
    <div class="lab-strip-wrap"><table class="lab-strip" aria-label="The first photons, one per column"><tbody id="lab-strip"></tbody></table></div>
    <div class="lab-keys">
      <div><span class="k">Alice's sifted key</span><code id="lab-ka"></code></div>
      <div><span class="k">Bob's sifted key</span><code id="lab-kb"></code></div>
    </div>
    <div class="lab-out">
      <div class="lab-gauge"><div class="lab-gauge-bar"><div id="lab-fill"></div><i class="thr" style="left:${(11 / 30) * 100}%"></i></div>
        <div class="lab-gauge-scale"><span>0%</span><span style="left:${(11 / 30) * 100}%">11% abort</span><span style="right:0">30%</span></div></div>
      <div class="lab-nums" id="lab-nums"></div>
      <div class="lab-verdict" id="lab-verdict" role="status" aria-live="polite"></div>
    </div>`;
  const $ = (id) => document.getElementById(id);
  const eve = $('lab-eve'), noise = $('lab-noise');
  const label = () => { $('lab-eve-v').textContent = eve.value + '%'; $('lab-noise-v').textContent = (+noise.value).toFixed(1) + '%'; };
  eve.oninput = noise.oninput = label;

  function strip(ph) {
    const rows = [
      ['Alice bit', (p) => p.aBit],
      ['Alice basis', (p) => sym(p.aBasis)],
      ['Eve', (p) => (p.intercepted ? `${sym(p.eBasis)}${p.eBit}` : '·')],
      ['Bob basis', (p) => sym(p.bBasis)],
      ['Bob bit', (p) => p.bBit],
      ['Kept?', (p) => (p.sifted ? (p.error ? '✗' : '✓') : '')],
    ];
    const tb = $('lab-strip'); tb.replaceChildren();
    rows.forEach(([name, f], ri) => {
      const tr = tb.insertRow(); const th = document.createElement('th'); th.textContent = name; tr.appendChild(th);
      ph.slice(0, SHOW).forEach((p, i) => {
        const c = tr.insertCell(); c.textContent = f(p); c.style.animationDelay = i * 70 + 'ms'; c.className = 'pop';
        if (!p.sifted) c.classList.add('dim');
        if (ri === 2 && p.intercepted) c.classList.add('eve');
        if (ri === 5 && p.sifted) c.classList.add(p.error ? 'err' : 'okc');
        if (ri === 4 && p.error) c.classList.add('err');
      });
    });
  }
  function keys(ph) {
    const s = ph.filter((p) => p.sifted).slice(0, KEYSHOW);
    const ka = $('lab-ka'), kb = $('lab-kb'); ka.replaceChildren(); kb.replaceChildren();
    s.forEach((p) => {
      const a = document.createElement('span'); a.textContent = p.aBit; ka.appendChild(a);
      const b = document.createElement('span'); b.textContent = p.bBit; if (p.error) b.className = 'err'; kb.appendChild(b);
    });
  }
  function results(a, f, e) {
    const th = B.theoryQber(f, e);
    $('lab-fill').style.width = Math.min(100, (a.qEst / 0.3) * 100) + '%';
    $('lab-fill').className = a.abort ? 'bad' : 'good';
    const items = [
      ['Photons sent', a.n.toLocaleString()],
      ['Kept after sifting', `${a.sifted.toLocaleString()} (${pct(a.sifted / a.n, 0)})`],
      ['QBER from the sample', `${pct(a.qEst, 2)} of ${a.sample.toLocaleString()} bits`],
      ['Theory, Q = e + f/4 − fe/2', pct(th, 2)],
    ];
    const box = $('lab-nums'); box.replaceChildren();
    items.forEach(([k, v]) => { const d = document.createElement('div'); const s = document.createElement('span'); s.textContent = k; const b = document.createElement('b'); b.textContent = v; d.append(s, b); box.appendChild(d); });
    const v = $('lab-verdict');
    v.className = 'lab-verdict ' + (a.abort ? 'bad' : 'good');
    v.textContent = a.abort
      ? `Abort: QBER ${pct(a.qEst, 1)} is above 11%, so an eavesdropper may be present. Alice and Bob discard the key.`
      : a.keyBits > 0
        ? `Key accepted: after error correction and privacy amplification about ${a.keyBits.toLocaleString()} secret bits remain (estimate${f > 0 ? '; whatever Eve learned is removed by privacy amplification' : ''}).`
        : `No abort, but the error rate is too high to leave any secret key after error correction.`;
  }
  function go() {
    clearTimeout(timer);
    const f = eve.value / 100, e = noise.value / 100;
    seed += 1;
    const ph = B.send(N, f, e, seed);
    strip(ph); keys(ph);
    timer = setTimeout(() => results(B.analyse(ph, seed), f, e), SHOW * 70 + 150);
  }
  $('lab-go').onclick = go;
  label(); go();
})();
