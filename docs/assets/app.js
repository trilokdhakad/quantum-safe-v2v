// QSV2V public page: loads docs/data/*.json and draws every number, chart and table.
(function () {
  'use strict';
  const $ = (sel) => document.querySelector(sel);
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const C = () => [css('--c0'), css('--c1'), css('--c2'), css('--c3')];
  const fmtInt = d3.format(',');
  const DATA = {};
  const REFS = { 'PSRS-D2D': '[1]', PSLAP: '[2]', 'P2AS-IoAV': '[3]', 'P²AS-IoAV': '[3]' };

  async function load(name) {
    const r = await fetch(`data/${name}.json`);
    if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
    const obj = await r.json();
    return obj && obj.rows ? obj.rows : obj;
  }

  // ---------- small helpers ----------
  function bind(key, value) {
    document.querySelectorAll(`[data-bind="${key}"]`).forEach((el) => { el.textContent = value; });
  }
  function td(tr, text, cls) { const c = tr.insertCell(); c.textContent = text == null ? '—' : text; if (cls) c.className = cls; return c; }
  function pill(tr, text, kind) {
    const c = tr.insertCell(); const s = document.createElement('span');
    s.className = 'pill ' + kind; s.textContent = text; c.appendChild(s); return c;
  }
  function fail(el, msg) { el.replaceChildren(); const p = document.createElement('p'); p.className = 'fail'; p.textContent = msg || 'This could not be loaded.'; el.appendChild(p); }
  function legend(el, items) {
    el.replaceChildren();
    items.forEach((it) => {
      const s = document.createElement('span'); const i = document.createElement('i');
      i.style.background = it.dashed ? `repeating-linear-gradient(90deg, ${it.color} 0 5px, transparent 5px 8px)` : it.color;
      s.append(i, document.createTextNode(it.name)); el.appendChild(s);
    });
  }
  const sup = { '-': '⁻', 0: '⁰', 1: '¹', 2: '²', 3: '³', 4: '⁴', 5: '⁵', 6: '⁶', 7: '⁷', 8: '⁸', 9: '⁹' };
  const pow10 = (v) => '10' + String(Math.round(Math.log10(v))).split('').map((c) => sup[c]).join('');

  // ---------- line chart: one y-axis, thin lines, dots, reference line, nearest-x tooltip ----------
  function lineChart(el, opt) {
    el.replaceChildren();
    const W = el.clientWidth || 640, H = Math.max(260, Math.min(380, W * 0.55));
    const narrow = W < 520;
    const m = { top: 14, right: 18, bottom: 42, left: 54 };
    const x = d3.scaleLinear().domain(opt.xDomain).range([m.left, W - m.right]);
    const y = opt.yLog
      ? d3.scaleLog().domain(opt.yDomain).range([H - m.bottom, m.top]).clamp(true)
      : d3.scaleLinear().domain(opt.yDomain).nice().range([H - m.bottom, m.top]);
    const ok = (p) => p.y != null && !Number.isNaN(p.y) && (!opt.yLog || p.y > 0);
    const svg = d3.select(el).append('svg').attr('viewBox', `0 0 ${W} ${H}`).attr('height', H)
      .attr('role', 'img').attr('aria-label', opt.aria || '');
    svg.append('g').attr('transform', `translate(0,${H - m.bottom})`)
      .call(d3.axisBottom(x).ticks(narrow ? 4 : 7).tickFormat(opt.xFmt).tickSizeOuter(0));
    svg.append('g').attr('transform', `translate(${m.left},0)`)
      .call(d3.axisLeft(y).ticks(5).tickValues(opt.yTicks || null).tickFormat(opt.yFmt).tickSize(-(W - m.left - m.right)))
      .call((g) => g.select('.domain').remove());
    svg.append('text').attr('class', 'axis-label').attr('x', (m.left + W - m.right) / 2).attr('y', H - 6)
      .attr('text-anchor', 'middle').text(opt.xLabel);
    svg.append('text').attr('class', 'axis-label').attr('transform', `translate(13,${(H - m.bottom + m.top) / 2}) rotate(-90)`)
      .attr('text-anchor', 'middle').text(opt.yLabel);
    if (opt.refY != null) {
      svg.append('line').attr('x1', m.left).attr('x2', W - m.right).attr('y1', y(opt.refY)).attr('y2', y(opt.refY))
        .style('stroke', css('--ref')).attr('stroke-dasharray', '4 4').attr('stroke-width', 1.5);
      svg.append('text').attr('class', 'axis-label').attr('x', W - m.right - 4).attr('y', y(opt.refY) - 6)
        .attr('text-anchor', 'end').text(opt.refLabel);
    }
    const clipId = 'clip' + Math.random().toString(36).slice(2);
    svg.append('clipPath').attr('id', clipId).append('rect').attr('x', m.left).attr('y', m.top - 6)
      .attr('width', W - m.left - m.right + 6).attr('height', H - m.top - m.bottom + 12);
    const plot = svg.append('g').attr('clip-path', `url(#${clipId})`);
    const line = d3.line().x((p) => x(p.x)).y((p) => y(p.y)).defined(ok);
    opt.series.forEach((s) => {
      if (s.band) {
        const area = d3.area().x((p) => x(p.x)).y0((p) => y(Math.max(p.lo, opt.yLog ? opt.yDomain[0] : -Infinity)))
          .y1((p) => y(p.hi)).defined((p) => p.lo != null && p.hi != null && (!opt.yLog || p.hi > 0));
        plot.append('path').attr('d', area(s.band)).style('fill', s.color).style('opacity', 0.16);
      }
      if (s.line) plot.append('path').attr('d', line(s.points)).attr('fill', 'none').style('stroke', s.color)
        .attr('stroke-width', 2).attr('stroke-dasharray', s.dashed ? '6 4' : null);
      if (s.dots) plot.append('g').selectAll('circle').data(s.points.filter(ok)).join('circle')
        .attr('cx', (p) => x(p.x)).attr('cy', (p) => y(p.y)).attr('r', 4).style('fill', s.color)
        .style('stroke', css('--panel')).attr('stroke-width', 2);
    });
    // Tooltip at the nearest x value.
    const tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true; el.appendChild(tip);
    const guide = svg.append('line').attr('y1', m.top).attr('y2', H - m.bottom).style('stroke', css('--line')).style('opacity', 0);
    const xs = [...new Set(opt.series.flatMap((s) => s.points.filter(ok).map((p) => p.x)))].sort((a, b) => a - b);
    const show = (ev) => {
      const [px] = d3.pointer(ev, svg.node());
      const sx = px * (W / svg.node().getBoundingClientRect().width);
      const xv = x.invert(sx);
      const near = xs.reduce((a, b) => (Math.abs(b - xv) < Math.abs(a - xv) ? b : a), xs[0]);
      guide.attr('x1', x(near)).attr('x2', x(near)).style('opacity', 1);
      tip.replaceChildren();
      const h = document.createElement('div'); h.className = 't'; h.textContent = opt.tipTitle(near); tip.appendChild(h);
      opt.series.forEach((s) => {
        const p = s.points.find((q) => q.x === near);
        if (!p || !ok(p) || s.noTip) return;
        const row = document.createElement('div');
        const sw = document.createElement('span');
        sw.style.cssText = `display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:${s.color}`;
        row.append(sw, document.createTextNode(`${s.name}: ${opt.yFmtTip(p.y)}${p.ci ? ' ± ' + opt.yFmtTip(p.ci) : ''}`));
        tip.appendChild(row);
      });
      tip.hidden = false;
      const bw = el.clientWidth, tw = tip.offsetWidth, left = (x(near) / W) * bw;
      tip.style.left = Math.max(0, Math.min(bw - tw, left + 14 > bw - tw ? left - tw - 14 : left + 14)) + 'px';
      tip.style.top = '6px';
    };
    svg.append('rect').attr('x', m.left).attr('y', m.top).attr('width', W - m.left - m.right).attr('height', H - m.top - m.bottom)
      .attr('fill', 'transparent').on('pointermove', show).on('pointerleave', () => { tip.hidden = true; guide.style('opacity', 0); });
  }

  // ---------- headline numbers ----------
  function headline() {
    const { attacks, defenses, scyther, experiments, tests, qber_grid: grid, key_rate: kr, e3_distance: e3 } = DATA;
    if (attacks) {
      // The three papers' attacks only; the Shor demonstration targets the ECC/RSA family, not a paper.
      const onPapers = attacks.filter((r) => REFS[r.paper]);
      bind('attacks_ok', onPapers.filter((r) => +r.success).length); bind('attacks_total', onPapers.length);
      bind('paper_attacks', onPapers.length);
    }
    if (defenses) { bind('def_ok', defenses.filter((r) => +r.blocked).length); bind('def_total', defenses.length); }
    if (scyther) { bind('scy_total', scyther.length); bind('scy_ok', scyther.filter((r) => r.verdict === 'Ok').length); }
    if (experiments) {
      bind('exp_supported', experiments.filter((r) => +r.supported === 1).length);
      bind('exp_tested', experiments.filter((r) => +r.tested === 1).length);
      bind('exp_partly', experiments.filter((r) => r.verdict === 'Partly supported').length);
    }
    if (tests) {
      bind('tests_passed', fmtInt(d3.sum(tests, (r) => +r.passed)));
      bind('tests_total', fmtInt(d3.sum(tests, (r) => +r.tests)));
    }
    if (grid) { bind('max_z', d3.format('.1f')(d3.max(grid, (r) => Math.abs(+r.z)))); bind('qber_points', grid.length); }
    if (kr) {
      const fs = kr.filter((r) => r.cascade_f != null && +r.qber > 0).map((r) => +r.cascade_f);
      bind('cascade_f', d3.format('.2f')(d3.mean(fs)));
      bind('qkd_runs', fmtInt(d3.sum(kr, (r) => +r.runs)));
      bind('wrong_keys', d3.sum(kr, (r) => +r.runs_with_wrong_key));
    }
    if (e3) {
      const pts = e3.filter((r) => +r.skr_asymptotic > 0 && +r.distance_km <= 120).map((r) => [+r.distance_km, Math.log10(+r.skr_asymptotic)]);
      const mx = d3.mean(pts, (p) => p[0]), my = d3.mean(pts, (p) => p[1]);
      const slope = d3.sum(pts, (p) => (p[0] - mx) * (p[1] - my)) / d3.sum(pts, (p) => (p[0] - mx) ** 2);
      bind('e3_db', d3.format('.2f')(-10 * slope));
      const none = e3.find((r) => +r.skr_asymptotic <= 0);
      bind('e3_cut', none ? fmtInt(+none.distance_km) : '—');
    }
  }

  // ---------- Part 1 charts ----------
  function eveChart() {
    const d = DATA.qber_grid, el = $('#eve-chart');
    if (!d) return fail(el);
    const names = [...new Set(d.map((r) => r.noise))], col = C();
    legend($('#eve-legend'), names.map((n, i) => ({ name: `${n} (line: theory, dots: simulated)`, color: col[i] })));
    const series = names.flatMap((n, i) => {
      const rows = d.filter((r) => r.noise === n);
      return [
        { name: n + ' theory', color: col[i], line: true, points: rows.map((r) => ({ x: +r.eve_fraction, y: +r.qber_theory })) },
        { name: n + ' simulated', color: col[i], dots: true, points: rows.map((r) => ({ x: +r.eve_fraction, y: +r.qber_measured })) },
      ];
    });
    lineChart(el, {
      series, xDomain: [0, 1], yDomain: [0, 0.32], xFmt: d3.format('.0%'), yFmt: d3.format('.0%'),
      xLabel: 'Fraction of photons Eve intercepts', yLabel: 'Error rate (QBER)', refY: 0.11, refLabel: 'abort above 11%',
      aria: 'QBER rises linearly with the fraction of photons intercepted, matching theory for 0, 2, 5 and 8 percent noise.',
      tipTitle: (v) => `Eve intercepts ${d3.format('.0%')(v)}`, yFmtTip: d3.format('.2%'),
    });
  }
  function krChart() {
    const d = DATA.key_rate, el = $('#kr-chart');
    if (!d) return fail(el);
    const col = C(), pts = (f) => d.map((r) => ({ x: +r.qber, y: r[f] == null ? null : +r[f] }));
    const series = [
      { name: 'Measured', color: col[0], line: true, dots: true, points: pts('key_fraction') },
      { name: 'Predicted from Cascade leakage', color: col[1], line: true, dashed: true, points: pts('predicted') },
      { name: 'Shor–Preskill bound (perfect code)', color: css('--ref'), line: true, points: pts('shor_preskill') },
    ];
    legend($('#kr-legend'), series.map((s) => ({ name: s.name, color: s.color, dashed: s.dashed })));
    lineChart(el, {
      series, xDomain: [0, 0.12], yDomain: [0, 1], xFmt: d3.format('.0%'), yFmt: d3.format('.0%'),
      xLabel: 'Channel error rate (QBER)', yLabel: 'Secret key per sifted bit',
      aria: 'The secret key fraction falls from 97 percent at zero error to zero near 10 percent; measured values follow the prediction, below the Shor-Preskill bound.',
      tipTitle: (v) => `QBER ${d3.format('.1%')(v)}`, yFmtTip: d3.format('.1%'),
    });
  }
  function e3Chart() {
    const d = DATA.e3_distance, el = $('#e3-chart');
    if (!d) return fail(el);
    const col = C(), pts = (f) => d.map((r) => ({ x: +r.distance_km, y: r[f] != null && +r[f] > 0 ? +r[f] : null }));
    const series = [
      { name: 'Simulated (from measured detections and errors)', color: col[0], line: true, dots: true, points: pts('skr_asymptotic') },
      { name: 'Simulated, end-to-end final key', color: col[1], dots: true, points: pts('skr_end_to_end') },
      { name: 'Theory', color: css('--ref'), line: true, dashed: true, points: pts('skr_theory') },
    ];
    legend($('#e3-legend'), series.map((s) => ({ name: s.name, color: s.color, dashed: s.dashed })));
    lineChart(el, {
      series, xDomain: [0, 200], yDomain: [1e-7, 0.2], yLog: true, yTicks: [1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1],
      xFmt: (v) => v + ' km', yFmt: pow10, xLabel: 'Link distance', yLabel: 'Secret key bits per pulse (log)',
      aria: 'On a log scale the key rate falls in a straight line with distance and stops shortly before 190 km.',
      tipTitle: (v) => `${v} km`, yFmtTip: d3.format('.2e'),
    });
  }

  // ---------- Part 2 and 3 tables ----------
  function tables() {
    const fill = (id, rows, cols, row) => {
      const tb = $(id); if (!tb) return; tb.replaceChildren();
      if (!rows) { const tr = tb.insertRow(); const c = tr.insertCell(); c.colSpan = cols; c.className = 'fail'; c.textContent = 'Could not load.'; return; }
      rows.forEach((r) => row(tb.insertRow(), r));
    };
    fill('#attack-rows', DATA.attacks, 5, (tr, r) => {
      const ref = REFS[r.paper];
      td(tr, ref ? `${r.paper.replace('P2AS', 'P²AS')} ${ref}` : 'Shor demo (ECC/RSA family)');
      td(tr, r.attack); td(tr, r.attacker, 'small'); td(tr, r.claim_refuted, 'small');
      const label = !ref ? `Demo: factors found (${r.fields_matched})`
        : +r.success ? `Succeeds (${r.fields_matched} checks match)` : '✗ ' + r.result;
      const c = pill(tr, label, !ref ? 'muted' : +r.success ? 'bad' : 'ok');
      c.title = `Recovered: ${r.recovered}\nVictim's:  ${r.victim}`;
    });
    fill('#error-rows', DATA.paper_errors, 4, (tr, r) => { td(tr, `${r.paper.replace('P2AS', 'P²AS')} ${REFS[r.paper] || ''}`); td(tr, r.where); td(tr, r.as_printed, 'small'); td(tr, r.effect); });
    fill('#defense-rows', DATA.defenses, 4, (tr, r) => {
      td(tr, r.attack); td(tr, r.analogue_of, 'small'); td(tr, r.control || '—', 'small');
      pill(tr, +r.blocked ? '✓ Blocked' : '✗ ' + r.result, +r.blocked ? 'ok' : 'bad');
    });
    const yes = (v) => /^yes/.test(v || '');
    fill('#cost-rows', DATA.e7_cost, 9, (tr, r) => {
      td(tr, REFS[r.protocol] ? `${r.protocol} ${REFS[r.protocol]}` : r.protocol); td(tr, r.variant, 'small');
      td(tr, d3.format('.1f')(r.compute_ms), 'r');
      td(tr, r.ec_at_c_speed_ms != null ? d3.format('.2f')(r.ec_at_c_speed_ms) : '—', 'r');
      td(tr, fmtInt(r.bytes_total), 'r'); td(tr, String(r.messages), 'r');
      [r.forward_secrecy, r.quantum_resistant, r.revocation].forEach((v) => {
        const na = !v || v === '—';
        pill(tr, na ? 'not rated' : v, na ? 'muted' : yes(v) ? 'ok' : 'bad');
      });
    });
    fill('#exp-rows', DATA.experiments, 5, (tr, r) => {
      td(tr, r.key); td(tr, r.title); td(tr, r.hypothesis, 'small');
      const kind = { Supported: 'ok', 'Partly supported': 'part', 'Not supported': 'bad' }[r.verdict] || 'muted';
      pill(tr, (r.verdict === 'Supported' ? '✓ ' : '') + r.verdict, kind); td(tr, r.finding, 'small');
    });
    fill('#theory-rows', DATA.theory, 6, (tr, r) => {
      td(tr, r.area); td(tr, r.quantity); td(tr, r.formula, 'small');
      td(tr, r.theory, 'r'); td(tr, r.measured, 'r');
      pill(tr, r.agreement === 'lower bound' ? 'lower bound' : '✓ ' + r.agreement, r.agreement === 'lower bound' ? 'part' : 'ok');
    });
    fill('#seclevel-rows', DATA.security_levels, 5, (tr, r) => {
      td(tr, r.primitive); td(tr, r.used_in, 'small'); td(tr, r.classical, 'small');
      if (/^none/.test(r.quantum)) pill(tr, r.quantum, 'bad'); else td(tr, r.quantum, 'small');
      td(tr, r.source, 'small');
    });
  }

  // ---------- message size bars ----------
  function bsmChart() {
    const rows = DATA.bsm_sizes, el = $('#bsm-chart');
    if (!rows) return fail(el);
    el.replaceChildren();
    const col = C();
    const series = [
      { key: 'msg_with_digest_bytes', name: 'With certificate digest (9 of every 10 messages)', color: col[0] },
      { key: 'msg_with_cert_bytes', name: 'With full certificate (once a second)', color: col[1] },
    ];
    legend($('#bsm-legend'), [...series, { name: '1,400-byte radio frame', color: css('--ref'), dashed: true }]);
    const W = el.clientWidth || 640, barH = 13, gap = 3, labelH = 20, groupGap = 14;
    const groupH = labelH + series.length * barH + gap + groupGap, m = { top: 4, right: 60, bottom: 30, left: 4 };
    const H = m.top + rows.length * groupH + m.bottom, limit = +rows[0].frame_limit || 1400;
    const x = d3.scaleLinear().domain([0, d3.max(rows, (r) => d3.max(series, (s) => +r[s.key]))]).nice().range([m.left, W - m.right]);
    const svg = d3.select(el).append('svg').attr('viewBox', `0 0 ${W} ${H}`).attr('height', H).attr('role', 'img')
      .attr('aria-label', 'Safety-message size by signature scheme against the 1,400-byte frame: ECDSA fits, Falcon-512 fits with a digest, ML-DSA-44 overflows.');
    svg.append('g').attr('transform', `translate(0,${H - m.bottom})`)
      .call(d3.axisBottom(x).ticks(W < 520 ? 4 : 7).tickFormat((v) => fmtInt(v) + ' B').tickSize(-(H - m.top - m.bottom)))
      .call((g) => g.select('.domain').remove());
    rows.forEach((r, gi) => {
      const y0 = m.top + gi * groupH;
      svg.append('text').attr('class', 'direct').attr('x', m.left).attr('y', y0 + 13).text(r.config);
      series.forEach((s, si) => {
        const v = +r[s.key], y = y0 + labelH + si * (barH + gap);
        svg.append('rect').attr('x', x(0)).attr('y', y).attr('width', Math.max(1, x(v) - x(0))).attr('height', barH).attr('rx', 3).style('fill', s.color)
          .append('title').text(`${s.name}: ${fmtInt(v)} bytes (${v <= limit ? 'fits one frame' : Math.ceil(v / limit) + ' frames'})`);
        svg.append('text').attr('class', 'axis-label').attr('x', x(v) + 5).attr('y', y + barH - 2).text(fmtInt(v));
      });
    });
    svg.append('line').attr('x1', x(limit)).attr('x2', x(limit)).attr('y1', m.top).attr('y2', H - m.bottom)
      .style('stroke', css('--ref')).attr('stroke-dasharray', '4 4').attr('stroke-width', 1.5);
  }

  // ---------- network charts with pickers ----------
  const PROFILES = [['classical', 'Classical (X25519 + ECDSA)'], ['pq-falcon', 'Post-quantum, Falcon-512'], ['pq-mldsa', 'Post-quantum, ML-DSA-44']];
  const SIGS = [['ecdsa', 'ECDSA P-256 (today)'], ['falcon', 'Falcon-512'], ['mldsa', 'ML-DSA-44']];
  const SCALE_METRICS = [
    { key: 'hs_latency_ms_p50', short: 'Latency', label: 'Median handshake latency (ms)', fmt: ',.0f', ref: 100, refLabel: '100 ms budget' },
    { key: 'hs_success_rate', short: 'Success rate', label: 'Handshakes that succeed', fmt: '.0%', domain: [0, 1] },
    { key: 'cbr_mean', short: 'Channel load', label: 'Share of time the channel is busy', fmt: '.0%', domain: [0, 1] },
  ];
  const BSM_METRICS = [
    { key: 'bsm_pdr_in_range', short: 'Delivered', label: 'Safety messages delivered and verified (≤ 300 m)', fmt: '.0%', domain: [0, 1] },
    { key: 'cbr_mean', short: 'Channel load', label: 'Share of time the channel is busy', fmt: '.0%', domain: [0, 1] },
  ];
  const state = { scaleMetric: SCALE_METRICS[0].key, policy: 'all', bsmMetric: BSM_METRICS[0].key };
  // Segmented toggle for 2-4 options: one click, the choice always visible. Exposes .value.
  function segmented(label, options, value, onChange) {
    const g = document.createElement('div'); g.className = 'seg'; g.setAttribute('role', 'radiogroup'); g.setAttribute('aria-label', label);
    let current = value;
    const btns = options.map(([v, t]) => {
      const b = document.createElement('button'); b.type = 'button'; b.textContent = t; b.setAttribute('role', 'radio');
      b.onclick = () => { if (v === current) return; current = v; sync(); onChange(v); };
      b.onkeydown = (e) => {
        const k = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
        if (!k) return; e.preventDefault();
        const i = (options.findIndex(([x]) => x === current) + k + options.length) % options.length;
        btns[i].click(); btns[i].focus();
      };
      g.appendChild(b); return b;
    });
    const sync = () => btns.forEach((b, i) => {
      const on = options[i][0] === current;
      b.setAttribute('aria-checked', String(on)); b.tabIndex = on ? 0 : -1;
    });
    Object.defineProperty(g, 'value', { get: () => current });
    sync(); return g;
  }
  function select(label, options, value, onChange) {
    const s = document.createElement('select'); s.setAttribute('aria-label', label);
    options.forEach(([v, t]) => s.appendChild(new Option(t, v))); s.value = value;
    s.onchange = () => onChange(s.value); return s;
  }
  function meanCi(vals) {
    const v = vals.filter((x) => x != null && !Number.isNaN(+x)).map(Number);
    if (!v.length) return [null, null];
    const mu = d3.mean(v);
    const t = { 2: 12.71, 3: 4.30, 4: 3.18, 5: 2.78, 6: 2.57 }[v.length] || 2.0;
    return [mu, v.length > 1 ? (t * d3.deviation(v)) / Math.sqrt(v.length) : null];
  }
  function netChart(holder, rows, key, defs, metric, aria) {
    const col = C(), xs = [...new Set(rows.map((r) => +r.n_vehicles))].sort((a, b) => a - b);
    const series = defs.map(([k, name], i) => {
      const pts = xs.map((x) => {
        const [mu, ci] = meanCi(rows.filter((r) => r[key] === k && +r.n_vehicles === x).map((r) => r[metric.key]));
        return { x, y: mu, ci };
      });
      return { name, color: col[i], line: true, dots: true, points: pts,
        band: pts.map((p) => ({ x: p.x, lo: p.y != null && p.ci != null ? p.y - p.ci : null, hi: p.y != null && p.ci != null ? p.y + p.ci : null })) };
    });
    const ys = series.flatMap((s) => s.points.map((p) => p.y)).filter((y) => y != null);
    lineChart(holder, {
      series, xDomain: [0, d3.max(xs)], yDomain: metric.domain || [0, Math.min(Math.max(metric.ref || 0, ...ys) * 1.15, 500)],
      xFmt: d3.format(',.0f'), yFmt: d3.format(metric.fmt), xLabel: 'Vehicles on the 2 km, 6-lane highway', yLabel: metric.label,
      refY: metric.ref ?? null, refLabel: metric.refLabel, aria: aria + ' Showing: ' + metric.label + '.',
      tipTitle: (x) => `${x} vehicles (mean ± 95% CI over seeds)`, yFmtTip: d3.format(metric.fmt),
    });
  }
  function scaleChart() {
    const el = $('#scale-chart'), d = DATA.sim_steady;
    if (!d) return fail(el);
    if (!el.dataset.ready) {
      const bar = document.createElement('div'); bar.className = 'controls';
      bar.append(
        segmented('Measure', SCALE_METRICS.map((m) => [m.key, m.short]), state.scaleMetric, (v) => { state.scaleMetric = v; scaleChart(); }),
        segmented('Who runs handshakes', [['all', 'Every neighbour'], ['same_direction', 'Same direction only']], state.policy, (v) => { state.policy = v; scaleChart(); }),
      );
      const holder = document.createElement('div'); holder.className = 'chart';
      el.append(bar, holder); el.dataset.ready = '1';
      legend($('#scale-legend'), PROFILES.map(([, n], i) => ({ name: n, color: C()[i] })));
    }
    const metric = SCALE_METRICS.find((m) => m.key === state.scaleMetric);
    netChart(el.querySelector('.chart'), d.filter((r) => r.hs_policy === state.policy), 'handshake_profile', PROFILES, metric,
      'Handshake performance against the number of vehicles for classical, Falcon and ML-DSA handshakes.');
  }
  function bsmNetChart() {
    const el = $('#bsmnet-chart'), d = DATA.sim_broadcast;
    if (!d) return fail(el);
    if (!el.dataset.ready) {
      const bar = document.createElement('div'); bar.className = 'controls';
      bar.append(segmented('Measure', BSM_METRICS.map((m) => [m.key, m.short]), state.bsmMetric, (v) => { state.bsmMetric = v; bsmNetChart(); }));
      const holder = document.createElement('div'); holder.className = 'chart';
      el.append(bar, holder); el.dataset.ready = '1';
      legend($('#bsmnet-legend'), SIGS.map(([, n], i) => ({ name: n, color: C()[i] })));
    }
    netChart(el.querySelector('.chart'), d, 'bsm_profile', SIGS, BSM_METRICS.find((m) => m.key === state.bsmMetric),
      'Safety-message delivery and channel load against the number of vehicles for ECDSA, Falcon-512 and ML-DSA-44.');
  }

  // ---------- animated replay ----------
  function replay() {
    const el = $('#replay');
    const TR = { mldsa: DATA.trace_pq_mldsa, classical: DATA.trace_classical };
    const LABEL = { mldsa: 'Post-quantum handshake (ML-KEM + ML-DSA)', classical: 'Classical handshake (X25519 + ECDSA)' };
    if (!TR.mldsa || !TR.classical) return fail(el, 'The recorded runs could not be loaded.');
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const bar = document.createElement('div'); bar.className = 'controls';
    const START = 0; // the recording already starts after a 6 s warm-up (scripts/record_traces.py)
    const st = { key: 'mldsa', t: START, playing: !reduce, last: null, visible: true };
    const prep = (tr) => {
      const hs = new Map();
      tr.events.forEach((e) => {
        const k = e.a + '-' + e.b;
        if (e.type === 'hs_start') hs.set(k, { a: e.a, b: e.b, t0: e.t, t1: null, ok: null });
        if (e.type === 'hs_ok' || e.type === 'hs_fail') { const h = hs.get(k); if (h && h.t1 == null) { h.t1 = e.t; h.ok = e.type === 'hs_ok'; } }
      });
      return { tr, hs: [...hs.values()], bsm: tr.events.filter((e) => e.type === 'bsm'), duration: tr.period * (tr.x.length - 1) };
    };
    const P = { mldsa: prep(TR.mldsa), classical: prep(TR.classical) };
    const SHORT = { mldsa: 'Post-quantum (ML-DSA)', classical: 'Classical (ECDSA)' };
    const sel = segmented('Which run', Object.keys(LABEL).map((k) => [k, SHORT[k]]), st.key, (v) => { st.key = v; st.t = START; });
    const play = document.createElement('button'); play.type = 'button'; play.className = 'icon-btn';
    const setPlay = () => {
      play.innerHTML = st.playing
        ? '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><rect x="3" y="2" width="3.5" height="12" rx="1"/><rect x="9.5" y="2" width="3.5" height="12" rx="1"/></svg>'
        : '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M4 2.5v11a1 1 0 0 0 1.5.86l9-5.5a1 1 0 0 0 0-1.72l-9-5.5A1 1 0 0 0 4 2.5z"/></svg>';
      play.setAttribute('aria-label', st.playing ? 'Pause' : 'Play'); play.setAttribute('aria-pressed', String(st.playing));
    };
    play.onclick = () => { st.playing = !st.playing; st.last = null; setPlay(); }; setPlay();
    const speed = segmented('Speed', [['0.25', '¼×'], ['0.5', '½×'], ['1', '1×']], '0.25', () => {});
    const slider = document.createElement('input'); slider.type = 'range'; slider.min = 0; slider.max = 1000; slider.value = 0; slider.className = 'slider';
    slider.setAttribute('aria-label', 'Replay time');
    slider.oninput = () => { st.t = (+slider.value / 1000) * P[st.key].duration; st.last = null; };
    bar.classList.add('replay-bar'); bar.append(sel, play, slider, speed);
    const canvas = document.createElement('canvas'); canvas.className = 'road'; canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'Animated replay of 60 vehicles on a 2 km highway with handshakes drawn as lines between vehicles.');
    const stats = document.createElement('div'); stats.className = 'replay-stats';
    el.append(bar, canvas, stats);
    if ('IntersectionObserver' in window) new IntersectionObserver((es) => { st.visible = es[0].isIntersecting; }).observe(el);

    function render() {
      const p = P[st.key], tr = p.tr;
      const W = Math.max(280, el.clientWidth), lanes = tr.lanes, laneH = W < 520 ? 8 : 12, median = laneH;
      const top = 20, H = 2 * lanes * laneH + median + top + 22, dpr = window.devicePixelRatio || 1;
      if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) {
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); canvas.style.height = H + 'px';
      }
      const g = canvas.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, W, H);
      const L = tr.road_length, sx = W / L, muted = css('--muted'), col = C();
      const okC = css('--ok'), badC = css('--bad'), warnC = css('--warn');
      g.fillStyle = css('--line'); g.globalAlpha = 0.55; g.fillRect(0, top, W, 2 * lanes * laneH + median); g.globalAlpha = 1;
      g.strokeStyle = muted; g.setLineDash([6, 8]); g.lineWidth = 1;
      for (let k = 1; k < 2 * lanes; k++) { if (k === lanes) continue; const y = top + k * laneH + (k > lanes ? median : 0); g.beginPath(); g.moveTo(0, y); g.lineTo(W, y); g.stroke(); }
      g.setLineDash([]);
      const yOf = (v) => (v.dir > 0 ? top + (lanes - 1 - v.lane) * laneH + laneH / 2 : top + lanes * laneH + median + v.lane * laneH + laneH / 2);
      const fi = Math.min(tr.x.length - 1, Math.max(0, st.t / tr.period)), i0 = Math.floor(fi), i1 = Math.min(tr.x.length - 1, i0 + 1), fr = fi - i0;
      const pos = tr.vehicles.map((v, i) => {
        const a = tr.x[i0][i]; let b = tr.x[i1][i];
        if (Math.abs(b - a) > L / 2) b += a > b ? L : -L;
        return [((((a + (b - a) * fr) % L) + L) % L) * sx, yOf(v)];
      });
      const t = st.t;
      p.bsm.forEach((e) => {
        const age = t - e.t; if (age < 0 || age > 0.12) return;
        const [x, y] = pos[e.a]; g.strokeStyle = e.cert ? warnC : muted; g.globalAlpha = 0.55 * (1 - age / 0.12);
        g.beginPath(); g.arc(x, y, 3 + (age / 0.12) * 16, 0, 2 * Math.PI); g.stroke();
      });
      g.globalAlpha = 1;
      let active = 0, ok = 0, bad = 0;
      p.hs.forEach((h) => {
        if (h.t0 > t) return;
        if (h.t1 != null && h.t1 <= t) { if (h.ok) ok++; else bad++; }
        let color = null, alpha = 1;
        if (h.t1 == null || t < h.t1) { color = warnC; active++; alpha = 0.9; } else if (t - h.t1 < 0.6) { color = h.ok ? okC : badC; alpha = 1 - (t - h.t1) / 0.6; }
        if (!color) return;
        const [xa, ya] = pos[h.a], [xb, yb] = pos[h.b];
        if (Math.abs(xa - xb) > W / 2) return;
        g.strokeStyle = color; g.globalAlpha = alpha; g.lineWidth = 2.2; g.beginPath(); g.moveTo(xa, ya); g.lineTo(xb, yb); g.stroke();
      });
      g.globalAlpha = 1;
      tr.vehicles.forEach((v, i) => { const [x, y] = pos[i]; g.fillStyle = v.dir > 0 ? col[0] : col[1]; g.fillRect(x - 4, y - 3, 8, 6); });
      g.fillStyle = muted; g.font = '12px ' + css('--sans');
      g.fillText('→ eastbound', 4, 14); g.textAlign = 'right'; g.fillText('westbound ←', W - 4, H - 6); g.textAlign = 'left';
      const scale = 500 * sx; g.strokeStyle = muted; g.beginPath(); g.moveTo(4, H - 10); g.lineTo(4 + scale, H - 10); g.stroke(); g.fillText('500 m', 8 + scale, H - 6);
      const s = tr.summary || {};
      stats.textContent = `t = ${t.toFixed(2)} s · handshakes so far: ${ok} done, ${bad} failed, ${active} running · whole run: ${Math.round((s.hs_success_rate || 0) * 100)}% succeed, median ${d3.format('.0f')(s.hs_latency_ms_p50 || 0)} ms, channel ${Math.round((s.cbr_mean || 0) * 100)}% busy`;
      slider.value = String(Math.round((t / p.duration) * 1000));
      slider.style.setProperty('--fill', (100 * t) / p.duration + '%');
    }
    const loop = (now) => {
      const p = P[st.key];
      if (st.playing && st.visible) {
        if (st.last != null) st.t += ((now - st.last) / 1000) * +speed.value;
        if (st.t > p.duration) st.t = START;
      }
      st.last = now;
      if (st.visible || !st.drawn) { render(); st.drawn = true; }
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  // ---------- boot ----------
  const NAMES = ['tests', 'qber_grid', 'key_rate', 'e3_distance', 'attacks', 'paper_errors', 'defenses', 'scyther',
    'bsm_sizes', 'e7_cost', 'sim_steady', 'sim_broadcast', 'experiments', 'trace_classical', 'trace_pq_mldsa',
    'theory', 'security_levels'];
  const charts = [eveChart, krChart, e3Chart, bsmChart, scaleChart, bsmNetChart];
  Promise.all(NAMES.map((n) => load(n).then((v) => { DATA[n] = v; }).catch((e) => console.error(e)))).then(() => {
    headline(); tables(); charts.forEach((f) => f()); replay();
    let w = window.innerWidth, timer;
    window.addEventListener('resize', () => {
      if (Math.abs(window.innerWidth - w) < 30) return;
      w = window.innerWidth; clearTimeout(timer); timer = setTimeout(() => charts.forEach((f) => f()), 150);
    });
    if (window.matchMedia) window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => charts.forEach((f) => f()));
  });
})();
