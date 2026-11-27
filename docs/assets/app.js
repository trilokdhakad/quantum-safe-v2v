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
  // Legend entries: a line swatch by default; kind 'dot' (simulated points), 'box' (solid bar) or 'pale' (pale bar).
  function legend(el, items) {
    el.replaceChildren();
    items.forEach((it) => {
      const s = document.createElement('span'); const i = document.createElement('i');
      if (it.kind === 'dot') i.className = 'dot';
      if (it.kind === 'box' || it.kind === 'pale') i.className = 'box';
      if (it.kind === 'pale') { i.style.background = `color-mix(in srgb, ${it.color} 32%, transparent)`; i.style.border = `1.5px solid ${it.color}`; } else {
        i.style.background = it.dashed ? `repeating-linear-gradient(90deg, ${it.color} 0 5px, transparent 5px 8px)` : it.color;
      }
      s.append(i, document.createTextNode(it.name)); el.appendChild(s);
    });
  }
  const pct0 = d3.format('.0%');
  // SVG text with "\n" line breaks.
  function label(g, cls, x0, y0, str, anchor) {
    const t = g.append('text').attr('class', cls).attr('x', x0).attr('y', y0).attr('text-anchor', anchor || 'start');
    String(str).split('\n').forEach((line, i) => t.append('tspan').attr('x', x0).attr('dy', i ? '1.25em' : 0).text(line));
    return t;
  }
  // Annotation numbers (zero points, abort crossings, dB/km fit, "1 in N" ticks): assets/figmath.js,
  // tested under Node in tests/test_web_figures.py.
  const { zeroAt, e3Slope, inWords } = window.FigMath;

  // ---------- line chart: one y-axis, thin lines, dots, reference line, nearest-x tooltip ----------
  // Annotations, all in data units so each label sits on the data it explains:
  //   zones  [{y0, y1?, label, below?}]  red-tinted band from y0 up to y1 (default: top); label at its
  //                                      top-left, optional quiet `below` label at the bottom-right.
  //   vlines [{x, at, label}]            dashed guide from the x-axis up to y = at, label to its left.
  //   notes  [{x, y, label, dx?, dy?, anchor?}]  text at a data point ("\n" breaks lines).
  //   rings  [{x, y}]                    ring markers at points of interest.
  //   better 'up' | 'down'               which direction is better, shown above the plot.
  //   series[i].endLabel                 direct label at the series' last point (nudged apart).
  //   series[i].hollow(p)                draw that point hollow, and the line into it dashed.
  //   point.note                         extra text for that point in the tooltip.
  function lineChart(el, opt) {
    el.replaceChildren();
    const W = el.clientWidth || 640, H = Math.max(280, Math.min(400, W * 0.55));
    const narrow = W < 520;
    const ends = !narrow && opt.series.some((s) => s.endLabel);
    const m = { top: opt.better ? 28 : 14, right: ends ? (opt.endWidth || 96) : 18, bottom: 42, left: opt.left || 58 };
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
    if (opt.better) svg.append('text').attr('class', 'hint').attr('x', m.left).attr('y', 13)
      .text(opt.better === 'up' ? '↑ higher is better' : '↓ lower is better');
    const [yBot, yTop] = y.domain();
    (opt.zones || []).forEach((z) => {
      const a = y(Math.min(z.y1 ?? yTop, yTop)), b = y(Math.max(z.y0, yBot));
      svg.append('rect').attr('x', m.left).attr('width', W - m.left - m.right).attr('y', a).attr('height', Math.max(0, b - a))
        .style('fill', css('--bad')).style('opacity', 0.07);
      if (z.label) label(svg, 'zone-label', m.left + 8, a + 17, z.label);
      if (z.below) label(svg, 'zone-label quiet', W - m.right - 6, H - m.bottom - 10, z.below, 'end');
    });
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
        plot.append('path').attr('d', area(s.band)).style('fill', s.color).style('opacity', 0.11);
      }
      const hol = (p) => !!(s.hollow && s.hollow(p));
      if (s.line && s.hollow) {
        // Dashed underneath everywhere; solid only between trustworthy points, so the dashed part
        // shows exactly the stretch that leads into hollow points.
        plot.append('path').attr('d', line(s.points)).attr('fill', 'none').style('stroke', s.color)
          .attr('stroke-width', 1.5).attr('stroke-dasharray', '3 4').style('opacity', 0.85);
        plot.append('path').attr('d', d3.line().x((p) => x(p.x)).y((p) => y(p.y)).defined((p) => ok(p) && !hol(p))(s.points))
          .attr('fill', 'none').style('stroke', s.color).attr('stroke-width', 2);
      } else if (s.line) {
        plot.append('path').attr('d', line(s.points)).attr('fill', 'none').style('stroke', s.color)
          .attr('stroke-width', 2).attr('stroke-dasharray', s.dashed ? '6 4' : null);
      }
      if (s.dots) plot.append('g').selectAll('circle').data(s.points.filter(ok)).join('circle')
        .attr('cx', (p) => x(p.x)).attr('cy', (p) => y(p.y)).attr('r', 4)
        .style('fill', (p) => (hol(p) ? css('--panel') : s.color))
        .style('stroke', (p) => (hol(p) ? s.color : css('--panel'))).attr('stroke-width', 2);
    });
    // Direct labels at line ends, pushed apart so they never overlap.
    if (ends) {
      const labs = opt.series.filter((s) => s.endLabel).map((s) => {
        const pts = s.points.filter(ok); const p = pts[pts.length - 1];
        return p && { text: s.endLabel, px: x(p.x), py: y(p.y) };
      }).filter(Boolean).sort((a, b) => a.py - b.py);
      for (let i = 1; i < labs.length; i++) if (labs[i].py - labs[i - 1].py < 14) labs[i].py = labs[i - 1].py + 14;
      labs.forEach((l) => svg.append('text').attr('class', 'end-label').attr('x', l.px + 9).attr('y', l.py + 4).text(l.text));
    }
    (opt.vlines || []).forEach((v) => {
      const xv = x(v.x), top = y(v.at);
      svg.append('line').attr('x1', xv).attr('x2', xv).attr('y1', H - m.bottom).attr('y2', top - 4)
        .style('stroke', css('--muted')).attr('stroke-dasharray', '3 3').attr('stroke-width', 1.2);
      label(svg, 'note-label', xv - 6, top + 4, v.label, 'end');
    });
    (opt.rings || []).forEach((r) => svg.append('circle').attr('cx', x(r.x)).attr('cy', y(r.y)).attr('r', 7)
      .attr('fill', 'none').style('stroke', css('--fg')).attr('stroke-width', 1.5));
    (opt.notes || []).forEach((n) => label(svg, 'note-label', x(n.x) + (n.dx || 0), y(n.y) + (n.dy || 0), n.label, n.anchor));
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
        row.append(sw, document.createTextNode(`${s.name}: ${opt.yFmtTip(p.y)}${p.ci ? ' ± ' + opt.yFmtTip(p.ci) : ''}${p.note ? ' (' + p.note + ')' : ''}`));
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
      const db = e3Slope(e3);
      bind('e3_db', d3.format('.3f')(db));
      bind('e3_decade', d3.format('.0f')(10 / db)); // km for a tenfold drop: 10 dB at db dB/km
      const none = e3.find((r) => +r.skr_asymptotic <= 0);
      bind('e3_cut', none ? fmtInt(+none.distance_km) : '—');
      const noneE2e = e3.find((r) => +r.skr_end_to_end <= 0);
      bind('e3_e2e_cut', noneE2e ? fmtInt(+noneE2e.distance_km) : '—');
    }
    if (kr) bind('kr_zero', pct0(zeroAt(kr, 'qber', 'key_fraction')));
    if (grid) {
      const cr = eveCrossings(grid);
      bind('eve_cross_clean', pct0(cr[0].f)); bind('eve_cross_noisy', pct0(cr[cr.length - 1].f));
      bind('eve_noisy_name', cr[cr.length - 1].name.replace(' noise', ''));
    }
    const { trace_classical: tc, trace_pq_mldsa: tp, sim_steady: ss } = DATA;
    if (tc && tp) {
      const a = tc.summary || {}, b = tp.summary || {};
      bind('rp_cls_ok', pct0(a.hs_success_rate)); bind('rp_pq_ok', pct0(b.hs_success_rate));
      bind('rp_cls_ms', d3.format('.0f')(a.hs_latency_ms_p50)); bind('rp_pq_ms', d3.format('.0f')(b.hs_latency_ms_p50));
      bind('rp_cls_cbr', pct0(a.cbr_mean)); bind('rp_pq_cbr', pct0(b.cbr_mean));
    }
    if (ss) {
      const at100 = (k) => pct0(d3.mean(ss.filter((r) => r.hs_policy === 'all' && r.handshake_profile === k && +r.n_vehicles === 100), (r) => +r.hs_success_rate));
      bind('s100_cls', at100('classical')); bind('s100_fal', at100('pq-falcon')); bind('s100_mld', at100('pq-mldsa'));
    }
    if (DATA.sim_broadcast) {
      bind('b100_fal', pct0(d3.mean(DATA.sim_broadcast.filter((r) => r.bsm_profile === 'falcon' && +r.n_vehicles === 100), (r) => +r.bsm_pdr_in_range)));
    }
  }
  // Eve fraction at which each noise level's theory line reaches the 11% abort threshold.
  const ABORT = 0.11;
  const eveCrossings = (grid) => window.FigMath.eveCrossings(grid, ABORT);

  // ---------- Part 1 charts ----------
  function eveChart() {
    const d = DATA.qber_grid, el = $('#eve-chart');
    if (!d) return fail(el);
    // Channel noise is an ordered quantity, so it gets ordered steps of one hue: darker = noisier.
    const cr = eveCrossings(d), ramp = ['--q0', '--q1', '--q2', '--q3'].map(css), ink = css('--muted');
    legend($('#eve-legend'), [
      { name: 'dots: simulated', color: ink, kind: 'dot' }, { name: 'lines: formula', color: ink },
      ...cr.map((c, i) => ({ name: c.name, color: ramp[i] })),
    ]);
    const series = cr.flatMap((c, i) => [
      { name: c.name + ', formula', color: ramp[i], line: true, endLabel: c.name, points: c.rows.map((r) => ({ x: +r.eve_fraction, y: +r.qber_theory })) },
      { name: c.name + ', simulated', color: ramp[i], dots: true, points: c.rows.map((r) => ({ x: +r.eve_fraction, y: +r.qber_measured })) },
    ]);
    const clean = cr[0], narrow = (el.clientWidth || 640) < 520;
    lineChart(el, {
      series, xDomain: [0, 1], yDomain: [0, 0.32], xFmt: pct0, yFmt: pct0,
      xLabel: 'Share of photons Eve intercepts', yLabel: 'Error rate in Bob\'s bits (QBER)',
      refY: ABORT, refLabel: '11% threshold',
      zones: [{ y0: ABORT, label: 'Above 11%: Alice and Bob abort. Eve is detected.', below: 'Below 11%: the key is accepted' }],
      rings: cr.filter((c) => c.f != null).map((c) => ({ x: c.f, y: ABORT })),
      notes: clean.f != null ? [{ x: clean.f, y: ABORT, dx: 12, dy: 24,
        label: narrow ? `Clean channel:\ncaught at ${pct0(clean.f)}` : `Clean channel: Eve is caught once\nshe intercepts ${pct0(clean.f)} of the photons` }] : [],
      aria: `The error rate rises in a straight line with the share of photons Eve intercepts, matching the formula at every noise level. On a clean channel it crosses the 11% abort line at ${pct0(clean.f)}.`,
      tipTitle: (v) => `Eve intercepts ${pct0(v)}`, yFmtTip: d3.format('.2%'),
    });
  }
  function krChart() {
    const d = DATA.key_rate, el = $('#kr-chart');
    if (!d) return fail(el);
    const col = C(), pts = (f) => d.map((r) => ({ x: +r.qber, y: r[f] == null ? null : +r[f] }));
    const series = [
      { name: 'Measured: our full pipeline', color: col[0], line: true, dots: true, points: pts('key_fraction') },
      { name: 'Predicted from what error correction revealed', color: col[1], line: true, dashed: true, points: pts('predicted') },
      { name: 'Best possible: a perfect error-correcting code (Shor–Preskill)', color: css('--ref'), line: true, points: pts('shor_preskill') },
    ];
    legend($('#kr-legend'), series.map((s) => ({ name: s.name, color: s.color, dashed: s.dashed })));
    const zMeas = zeroAt(d, 'qber', 'key_fraction'), zBest = zeroAt(d, 'qber', 'shor_preskill'), narrow = (el.clientWidth || 640) < 520;
    lineChart(el, {
      series, xDomain: [0, 0.12], yDomain: [0, 1], xFmt: pct0, yFmt: pct0, better: 'up',
      xLabel: 'Error rate in the kept bits (QBER)', yLabel: 'Share of kept bits that become secret key',
      vlines: [
        zMeas != null && { x: zMeas, at: 0.8, label: `${narrow ? 'Cascade' : 'Our error correction (Cascade)'}: no key above ${pct0(zMeas)}` },
        zBest != null && { x: zBest, at: 0.93, label: `${narrow ? 'Perfect code' : 'A perfect code'}: no key above ${pct0(zBest)}` },
      ].filter(Boolean),
      rings: [zMeas != null && { x: zMeas, y: 0 }, zBest != null && { x: zBest, y: 0 }].filter(Boolean),
      aria: `The share of bits that become secret key falls from 97 percent at zero error to zero at ${pct0(zMeas)}; measured values follow the prediction, just below the perfect-code bound, which reaches zero at ${pct0(zBest)}.`,
      tipTitle: (v) => `QBER ${d3.format('.1%')(v)}`, yFmtTip: d3.format('.1%'),
    });
  }
  function e3Chart() {
    const d = DATA.e3_distance, el = $('#e3-chart');
    if (!d) return fail(el);
    const col = C(), pts = (f) => d.map((r) => ({ x: +r.distance_km, y: r[f] != null && +r[f] > 0 ? +r[f] : null }));
    const series = [
      { name: 'Simulated: long-run rate from the measured detections and errors', color: col[0], line: true, dots: true, points: pts('skr_asymptotic') },
      { name: 'Simulated: final key that full runs actually produced', color: col[1], dots: true, points: pts('skr_end_to_end') },
      { name: 'Theory', color: css('--ref'), line: true, dashed: true, points: pts('skr_theory') },
    ];
    legend($('#e3-legend'), series.map((s, i) => ({ name: s.name, color: s.color, dashed: s.dashed, kind: i === 1 ? 'dot' : undefined })));
    // Log axis in words: 1e-3 reads "1 in 1k" (one secret bit per thousand photons sent).
    const cut = d.find((r) => +r.skr_asymptotic <= 0), db = e3Slope(d), at = (km) => +(d.find((r) => +r.distance_km === km) || {}).skr_theory;
    const narrow = (el.clientWidth || 640) < 520, noteKm = narrow ? 20 : 60;
    lineChart(el, {
      series, xDomain: [0, 200], yDomain: [1e-7, 0.2], yLog: true, yTicks: [1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1],
      xFmt: (v) => v + ' km', yFmt: inWords, xLabel: 'Length of the fibre link', yLabel: 'Secret bits per photon sent (log scale)',
      left: 74, better: 'up',
      vlines: cut ? [{ x: +cut.distance_km, at: 0.02, label: `No key at${narrow ? '\n' : ' '}${fmtInt(+cut.distance_km)} km and beyond` }] : [],
      notes: at(noteKm) > 0 ? [{ x: noteKm, y: at(noteKm), dy: -26, label: `10× less key every ${d3.format('.0f')(10 / db)} km` }] : [],
      aria: `On a log scale the key rate falls in a straight line, ten times lower every ${d3.format('.0f')(10 / db)} km, and there is no key from ${cut ? cut.distance_km : '?'} km.`,
      tipTitle: (v) => `${v} km`, yFmtTip: (v) => `1 secret bit per ${fmtInt(Math.round(1 / v))} photons`,
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
    // Colour = the vehicle's signature algorithm, the same colours as the network charts below.
    // Solid bar = the usual message (certificate digest); pale bar = the message with the full certificate.
    const col = C(), ink = css('--muted');
    const ALG = { 'ECDSA-P256': col[0], 'Falcon-512': col[1], 'ML-DSA-44': col[2] };
    const series = [
      { key: 'msg_with_digest_bytes', name: 'with the 8-byte certificate digest (9 of every 10 messages)', pale: false },
      { key: 'msg_with_cert_bytes', name: 'with the full certificate (1 of every 10)', pale: true },
    ];
    legend($('#bsm-legend'), [
      { name: 'Solid: usual message, 8-byte certificate digest (9 of every 10)', color: ink, kind: 'box' },
      { name: 'Pale: message with the full certificate (1 of every 10)', color: ink, kind: 'pale' },
      { name: 'One radio frame: 1,400 bytes', color: css('--ref'), dashed: true },
    ]);
    const W = el.clientWidth || 640, narrow = W < 520, barH = 14, gap = 4, labelH = 20, groupGap = 16;
    const groupH = labelH + series.length * barH + gap + groupGap, m = { top: 22, right: narrow ? 100 : 150, bottom: 30, left: 4 };
    const H = m.top + rows.length * groupH + m.bottom, limit = +rows[0].frame_limit || 1400;
    const x = d3.scaleLinear().domain([0, d3.max(rows, (r) => d3.max(series, (s) => +r[s.key]))]).nice().range([m.left, W - m.right]);
    const svg = d3.select(el).append('svg').attr('viewBox', `0 0 ${W} ${H}`).attr('height', H).attr('role', 'img')
      .attr('aria-label', 'Safety-message size by signature scheme against the 1,400-byte frame: ECDSA fits, Falcon-512 fits with a digest, ML-DSA-44 overflows.');
    svg.append('g').attr('transform', `translate(0,${H - m.bottom})`)
      .call(d3.axisBottom(x).ticks(narrow ? 4 : 7).tickFormat((v) => fmtInt(v) + ' B').tickSize(-(H - m.top - m.bottom)))
      .call((g) => g.select('.domain').remove());
    // Frame limit first, so the row labels (with a halo) sit on top of it.
    svg.append('line').attr('x1', x(limit)).attr('x2', x(limit)).attr('y1', m.top - 4).attr('y2', H - m.bottom)
      .style('stroke', css('--ref')).attr('stroke-dasharray', '4 4').attr('stroke-width', 1.5);
    svg.append('text').attr('class', 'note-label').attr('x', x(limit) + 6).attr('y', m.top - 8).text('1 radio frame = 1,400 B');
    rows.forEach((r, gi) => {
      const y0 = m.top + gi * groupH, c = ALG[r.vehicle_alg] || ink;
      svg.append('text').attr('class', 'direct').attr('x', m.left).attr('y', y0 + 13).text(r.config);
      series.forEach((s, si) => {
        const v = +r[s.key], y = y0 + labelH + si * (barH + gap), frames = Math.ceil(v / limit);
        const verdict = v <= limit ? '✓ fits one frame' : `✗ needs ${frames} frames`;
        const bar = svg.append('rect').attr('x', x(0)).attr('y', y).attr('width', Math.max(1, x(v) - x(0))).attr('height', barH).attr('rx', 3).style('fill', c);
        if (s.pale) bar.style('fill-opacity', 0.32).style('stroke', c).attr('stroke-width', 1.5);
        bar.append('title').text(`${r.config}, message ${s.name}: ${fmtInt(v)} bytes (${verdict.slice(2)})`);
        svg.append('text').attr('class', 'axis-label bar-label').attr('x', x(v) + 6).attr('y', y + barH - 3)
          .text(narrow ? `${fmtInt(v)} ${v <= limit ? '✓' : '✗'}` : `${fmtInt(v)} B  ${verdict}`);
      });
    });
  }

  // ---------- network charts with pickers ----------
  // [key, legend name, short end-of-line label]. Colours follow the algorithm: ECDSA / classical blue,
  // Falcon-512 orange, ML-DSA-44 green, here and in the message-size bars above.
  const PROFILES = [['classical', 'Classical (X25519 + ECDSA)', 'Classical'], ['pq-falcon', 'Post-quantum, Falcon-512', 'PQ, Falcon'], ['pq-mldsa', 'Post-quantum, ML-DSA-44', 'PQ, ML-DSA']];
  const SIGS = [['ecdsa', 'ECDSA P-256 (today)', 'ECDSA'], ['falcon', 'Falcon-512', 'Falcon-512'], ['mldsa', 'ML-DSA-44', 'ML-DSA-44']];
  const CHANNEL = { key: 'cbr_mean', short: 'Channel load', label: 'Share of time the channel is busy', fmt: '.0%', domain: [0, 1], better: 'down',
    note: 'Share of time the radio channel is busy (channel busy ratio). Lower is better: near 100% the channel is saturated, so messages wait, collide and are lost.' };
  const SCALE_METRICS = [
    { key: 'hs_latency_ms_p50', short: 'Latency', label: 'Median handshake latency (ms)', fmt: ',.0f', ref: 100, refLabel: '100 ms', better: 'down',
      zone: { y0: 100, label: 'Over the 100 ms budget' },
      note: 'Median time from the first handshake message to a shared key, over the handshakes that finished. Lower is better; V2V safety applications budget about 100 ms. Hollow dots and dashed lines: most handshakes failed, so the median comes from the few that finished (see Success rate).' },
    { key: 'hs_success_rate', short: 'Success rate', label: 'Handshakes that succeed', fmt: '.0%', domain: [0, 1], better: 'up',
      note: 'Share of started handshakes that end with both cars holding the same session key. Higher is better.' },
    CHANNEL,
  ];
  const BSM_METRICS = [
    { key: 'bsm_pdr_in_range', short: 'Delivered', label: 'Safety messages delivered and verified (≤ 300 m)', fmt: '.0%', domain: [0, 1], better: 'up',
      note: 'Share of safety messages that cars within 300 m receive and verify. Higher is better: each missed message is a position and speed update from a nearby car that never arrived.' },
    CHANNEL,
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
    // A latency median is only meaningful if most handshakes finished: otherwise mark the point hollow.
    const latency = metric.key === 'hs_latency_ms_p50';
    const series = defs.map(([k, name, short], i) => {
      const pts = xs.map((x) => {
        const sel = rows.filter((r) => r[key] === k && +r.n_vehicles === x);
        const [mu, ci] = meanCi(sel.map((r) => r[metric.key]));
        const p = { x, y: mu, ci };
        if (latency && mu != null) {
          const ok = d3.mean(sel, (r) => +r.hs_success_rate);
          if (ok < 0.5) { p.weak = true; p.note = `only ${pct0(ok)} of handshakes finished`; }
        }
        return p;
      });
      return { name, color: col[i], line: true, dots: true, points: pts, endLabel: short, hollow: latency ? (p) => p.weak : null,
        // No band where the median is not meaningful (hollow points): it would only add clutter.
        band: pts.map((p) => { const b = p.y != null && p.ci != null && !p.weak; return { x: p.x, lo: b ? p.y - p.ci : null, hi: b ? p.y + p.ci : null }; }) };
    });
    const ys = series.flatMap((s) => s.points.map((p) => p.y)).filter((y) => y != null);
    lineChart(holder, {
      series, xDomain: [0, d3.max(xs)], yDomain: metric.domain || [0, Math.min(Math.max(metric.ref || 0, ...ys) * 1.15, 500)],
      xFmt: d3.format(',.0f'), yFmt: d3.format(metric.fmt), xLabel: 'Vehicles on the 2 km, 6-lane highway', yLabel: metric.label,
      refY: metric.ref ?? null, refLabel: metric.refLabel, better: metric.better, zones: metric.zone ? [metric.zone] : [], endWidth: 84,
      aria: aria + ' Showing: ' + metric.label + '.',
      tipTitle: (x) => `${x} vehicles (mean ± 95% CI over seeds)`, yFmtTip: d3.format(metric.fmt),
    });
  }
  // The explanation under a chart's buttons, which follows the chosen measure.
  function metricNote(el, metric) {
    let p = el.querySelector('.metric-note');
    if (!p) { p = document.createElement('p'); p.className = 'metric-note'; p.setAttribute('aria-live', 'polite'); el.querySelector('.controls').after(p); }
    p.textContent = metric.note;
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
    metricNote(el, metric);
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
    const metric = BSM_METRICS.find((m) => m.key === state.bsmMetric);
    metricNote(el, metric);
    netChart(el.querySelector('.chart'), d, 'bsm_profile', SIGS, metric,
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
    // Whole-run results of both recordings, side by side; the one playing is highlighted.
    const runs = document.createElement('div'); runs.className = 'runs';
    ['classical', 'mldsa'].forEach((k) => {
      const s = TR[k].summary || {}, card = document.createElement('div'); card.className = 'run'; card.dataset.k = k;
      const name = document.createElement('div'); name.className = 'name'; name.textContent = LABEL[k] + ', whole run';
      const nums = document.createElement('div'); nums.className = 'nums';
      [[pct0(s.hs_success_rate || 0), 'handshakes succeed'], [d3.format('.0f')(s.hs_latency_ms_p50 || 0) + ' ms', 'median handshake'],
        [pct0(s.cbr_mean || 0), 'channel busy']].forEach(([v, l]) => {
        const c = document.createElement('div'); const b = document.createElement('b'); b.textContent = v; c.append(b, document.createTextNode(l)); nums.appendChild(c);
      });
      card.append(name, nums); runs.appendChild(card);
    });
    const mark = () => runs.querySelectorAll('.run').forEach((c) => c.classList.toggle('on', c.dataset.k === st.key));
    const sel = segmented('Which run', Object.keys(LABEL).map((k) => [k, SHORT[k]]), st.key, (v) => { st.key = v; st.t = START; mark(); });
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
    el.append(runs, bar, canvas, stats); mark();
    if ('IntersectionObserver' in window) new IntersectionObserver((es) => { st.visible = es[0].isIntersecting; }).observe(el);

    function render() {
      const p = P[st.key], tr = p.tr;
      const W = Math.max(280, el.clientWidth), lanes = tr.lanes, laneH = W < 520 ? 8 : 12, median = laneH;
      const top = 20, H = 2 * lanes * laneH + median + top + 22, dpr = window.devicePixelRatio || 1;
      if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) {
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); canvas.style.height = H + 'px';
      }
      const g = canvas.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, W, H);
      const L = tr.road_length, sx = W / L, muted = css('--muted');
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
      // Cars are neutral: colour on this canvas means only handshake state (amber / green / red).
      g.fillStyle = css('--fg'); g.globalAlpha = 0.78;
      tr.vehicles.forEach((v, i) => { const [x, y] = pos[i]; g.fillRect(x - 4, y - 3, 8, 6); });
      g.globalAlpha = 1;
      g.fillStyle = muted; g.font = '12px ' + css('--sans');
      g.fillText('→ eastbound', 4, 14); g.textAlign = 'right'; g.fillText('westbound ←', W - 4, H - 6); g.textAlign = 'left';
      const scale = 500 * sx; g.strokeStyle = muted; g.beginPath(); g.moveTo(4, H - 10); g.lineTo(4 + scale, H - 10); g.stroke(); g.fillText('500 m', 8 + scale, H - 6);
      stats.textContent = `${SHORT[st.key]} · t = ${t.toFixed(2)} s of ${p.duration.toFixed(0)} s · handshakes so far: ${ok} done, ${bad} failed, ${active} running`;
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
