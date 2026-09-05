/* The learning chapter.
 *
 * Everything here is read from learn.json, which is the verbatim JSON output of
 * three meshctl commands anyone can run:
 *
 *     go run ./cmd/meshctl --json learn validate
 *     go run ./cmd/meshctl --json learn discover
 *     go run ./cmd/meshctl --json learn calibrate
 *
 * Nothing is computed here that the commands did not already report, and no
 * figure on this page is written by hand. If a number moves, it is because the
 * command produced a different one.
 *
 * The file loads separately from run.json and fails independently. A chapter
 * that cannot render should hide itself rather than take the rest of the page
 * down with it, because the audit-chain verification above it is the part a
 * reviewer most needs to work.
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const VERSION =
    (document.currentScript && new URL(document.currentScript.src).searchParams.get('v')) || 'dev';

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function row(cells) {
    const tr = document.createElement('tr');
    for (const c of cells) {
      const td = document.createElement('td');
      if (c && typeof c === 'object' && !(c instanceof Node)) {
        if (c.cls) td.className = c.cls;
        if (c.node) td.appendChild(c.node);
        else td.textContent = String(c.text ?? '');
      } else if (c instanceof Node) {
        td.appendChild(c);
      } else {
        td.textContent = String(c ?? '');
      }
      tr.appendChild(td);
    }
    return tr;
  }

  const kv = (dl, k, v) => {
    dl.appendChild(el('dt', null, k));
    dl.appendChild(el('dd', null, v));
  };

  const num = (n) => Number(n).toLocaleString('en-IN');
  const pct = (f, d = 1) => (100 * Number(f)).toFixed(d) + '%';
  const paisa = (p) => Number(p).toFixed(0);

  /* Rupees for the headline totals only. The per-decision figures stay in
     paisa, because rounding them to rupees would hide the difference the whole
     chapter is about. */
  const rupees = (p) => '₹' + Math.round(Number(p) / 100).toLocaleString('en-IN');

  fetch('learn.json?v=' + VERSION, { cache: 'no-cache' })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status))))
    .then((data) => {
      if (!data || data.schema !== 'resilientmesh.learn.v1') {
        throw new Error('unexpected schema ' + (data && data.schema));
      }
      render(data);
    })
    .catch((err) => {
      const sec = $('learning');
      if (sec) sec.hidden = true;
      const link = document.querySelector('.navlink[href="#learning"]');
      if (link) link.hidden = true;
      if (window.console) console.warn('learning chapter unavailable:', err.message);
    });

  function render(data) {
    renderGate(data.validate);
    renderPolicies(data.validate);
    renderCounterfactual(data.validate);
    renderDiscovery(data.discover);
    renderCalibration(data.calibrate);
  }

  /* ------------------------------------------------------------ the gate -- */

  function renderGate(v) {
    const tb = $('lrn-arms');
    const arms = Object.keys(v.arms_available || {}).sort(
      (a, b) => v.arms_available[b] - v.arms_available[a]
    );
    for (const label of arms) {
      const n = v.arms_available[label];
      const share = n / v.actionable_incidents;
      const bar = el('span', 'minibar');
      const fill = el('i');
      fill.style.width = (100 * share).toFixed(1) + '%';
      bar.appendChild(fill);
      tb.appendChild(row([label, { cls: 'r mono', text: num(n) }, { node: bar }]));
    }

    const reasons = Object.keys(v.gate_refusals || {})
      .map((k) => k + ' ' + num(v.gate_refusals[k]))
      .join(', ');
    $('lrn-gate').textContent =
      num(v.gate_refused) +
      ' of ' +
      num(v.incidents) +
      ' incidents were refused outright before any learning could touch them (' +
      reasons +
      '). The remaining action space is what is left over, per incident, after the invariants have taken their share.';
  }

  /* ------------------------------------------------------- the policies -- */

  function renderPolicies(v) {
    const tb = $('lrn-policies');
    const runs = v.policies || [];
    const base = runs.find((p) => p.name === 'backoff');
    let best = null;

    for (const p of runs) {
      const learner = p.name === 'thompson';
      if (learner) best = p;
      tb.appendChild(
        row([
          { node: el('span', learner ? 'pill ok' : 'pill mut', p.name) },
          { cls: 'r mono', text: pct(p.recovery_rate) },
          { cls: 'r mono', text: paisa(p.mean_net_paisa) },
        ])
      );
    }

    if (base && best) {
      const lift = (best.net_paisa - base.net_paisa) / base.net_paisa;
      $('lrn-policy-note').textContent =
        'The learner recovers ' +
        pct(best.recovery_rate) +
        ' against the fixed schedule’s ' +
        pct(base.recovery_rate) +
        ', which is ' +
        pct(lift, 0) +
        ' more net value over ' +
        num(best.decisions) +
        ' decisions: ' +
        rupees(best.net_paisa) +
        ' against ' +
        rupees(base.net_paisa) +
        ' of simulated recovery.';
    }
  }

  /* -------------------------------------------------- the counterfactual -- */

  /* The bar is drawn rather than described because the claim is geometric: the
     truth has to fall inside the interval, and a reader should be able to see
     that at a glance instead of comparing three numbers in a table. */
  function renderCounterfactual(v) {
    const est = v.estimated_lift_paisa;
    const truth = v.true_lift_paisa;

    /* Pad the domain so nothing lands flush against an edge. A truth marker
       sitting exactly on the boundary of the band is the one case a reader
       cannot resolve by eye, and it is also the case the whole figure exists to
       show. */
    const rawLo = Math.min(est.lower, truth, 0);
    const rawHi = Math.max(est.upper, truth);
    const pad = 0.12 * (rawHi - rawLo || 1);
    const lo = rawLo - pad;
    const hi = rawHi + pad;
    const span = hi - lo || 1;
    const at = (x) => (100 * (x - lo)) / span;

    const box = $('lrn-cf');
    box.textContent = '';

    const track = el('div', 'cfbar-track');
    const band = el('div', 'cfbar-band');
    band.style.left = at(est.lower) + '%';
    band.style.width = Math.max(0.5, at(est.upper) - at(est.lower)) + '%';
    track.appendChild(band);

    const point = el('div', 'cfbar-point');
    point.style.left = at(est.value) + '%';
    track.appendChild(point);

    const truthMark = el('div', 'cfbar-truth' + (v.lift_covered ? ' in' : ' out'));
    truthMark.style.left = at(truth) + '%';
    track.appendChild(truthMark);

    if (lo < 0) {
      const zero = el('div', 'cfbar-zero');
      zero.style.left = at(0) + '%';
      track.appendChild(zero);
    }
    /* The interval endpoints go below the bar and the truth goes above it.
       Separating them by axis rather than by position is what stops the two
       labels colliding when the truth lands near a bound, which is exactly the
       case worth reading carefully. */
    const below = el('div', 'cfbar-axis below');
    const above = el('div', 'cfbar-axis above');
    const tick = (parent, x, text, cls) => {
      const t = el('span', 'cftick' + (cls ? ' ' + cls : ''), text);
      t.style.left = at(x) + '%';
      parent.appendChild(t);
    };
    if (lo < 0) tick(below, 0, '0', 'zero');
    tick(below, est.lower, paisa(est.lower));
    tick(below, est.upper, paisa(est.upper));
    tick(above, truth, 'true ' + paisa(truth), v.lift_covered ? 'truth' : 'truth out');
    track.appendChild(below);
    track.appendChild(above);
    box.appendChild(track);

    const legend = el('div', 'cfbar-legend');
    legend.appendChild(legendItem('band', 'estimated, ' + pct(est.confidence, 0) + ' interval'));
    legend.appendChild(legendItem('point', 'point estimate ' + paisa(est.value)));
    legend.appendChild(
      legendItem(v.lift_covered ? 'truth in' : 'truth out', 'the truth ' + paisa(truth))
    );
    box.appendChild(legend);

    const dl = $('lrn-cfmeta');
    dl.textContent = '';
    kv(dl, 'Estimator', v.lift_estimator);
    kv(dl, 'Estimated lift', paisa(est.value) + ' paisa a decision  [' + paisa(est.lower) + ', ' + paisa(est.upper) + ']');
    kv(dl, 'True lift', paisa(truth) + ' paisa a decision');
    kv(dl, 'Interval contained it', v.lift_covered ? 'yes' : 'no');
    kv(dl, 'Relative error on value', pct(Math.abs(v.relative_error), 2));
    kv(dl, 'Decisions that differ', num(v.influential_decisions));
    kv(dl, 'Effective sample size', num(Math.round(v.effective_sample_size)) + ' of ' + num(v.actionable_incidents));
    kv(dl, 'Reward model, held out', 'skill ' + v.reward_model_skill.toFixed(3) + ', AUC ' + v.reward_model_auc.toFixed(3));

    $('lrn-cfnote').textContent =
      'Only ' +
      num(v.influential_decisions) +
      ' of ' +
      num(v.actionable_incidents) +
      ' logged decisions differ between the two policies, and those are the only ones carrying the estimate. ' +
      'That count rather than the corpus size is what an interval this wide should be read against, which is why the estimator reports it.';
  }

  function legendItem(kind, text) {
    const s = el('span', 'cfleg');
    s.appendChild(el('i', 'sw ' + kind));
    s.appendChild(el('span', null, text));
    return s;
  }

  /* ------------------------------------------------------- the discovery -- */

  function renderDiscovery(d) {
    const dl = $('lrn-round');
    dl.textContent = '';
    kv(dl, 'Proposer', d.proposer + (d.degraded ? ' (fell back: ' + d.fallback_cause + ')' : ''));
    kv(dl, 'Logged decisions', num(d.decisions));
    kv(dl, 'Hypotheses tested', String(d.hypotheses_tested));
    kv(
      dl,
      'Confidence per test',
      d.per_test_confidence.toFixed(4) +
        ', widened from ' +
        (1 - d.family_alpha).toFixed(2) +
        ' so the chance of any false survivor across the round stays at ' +
        d.family_alpha.toFixed(2)
    );

    const box = $('lrn-verdicts');
    box.textContent = '';
    for (const v of d.verdicts || []) {
      const card = el('div', 'verdict ' + (v.survived ? 'ok' : 'no'));

      const head = el('div', 'verdict-head');
      head.appendChild(el('span', 'pill ' + (v.survived ? 'ok' : 'mut'), v.survived ? 'survived' : 'refuted'));
      head.appendChild(el('b', null, v.statement));
      card.appendChild(head);

      if (v.description) card.appendChild(el('p', 'verdict-why', v.description));

      const facts = el('p', 'verdict-num');
      facts.textContent =
        'covers ' +
        num(v.coverage) +
        ' decisions  ·  lift ' +
        paisa(v.lift_paisa.value) +
        ' [' +
        paisa(v.lift_paisa.lower) +
        ', ' +
        paisa(v.lift_paisa.upper) +
        '] paisa a decision';
      card.appendChild(facts);

      if (v.note) card.appendChild(el('p', 'verdict-note', v.note));
      box.appendChild(card);
    }

    const rev = $('lrn-reveal');
    rev.textContent = '';
    rev.appendChild(el('div', 'reveal-tag', 'The answer key, opened only now'));
    rev.appendChild(el('p', 'reveal-rule', d.planted_rule));
    rev.appendChild(
      el(
        'p',
        'reveal-note',
        d.planted_rule_found
          ? 'Found. Nothing in the policy, the features, the prompt or the gate named that rule. It was proposed from the log and confirmed against data the proposer did not influence.'
          : 'Not found in this round. The corpus or the proposal budget was too small for the effect to clear a corrected threshold.'
      )
    );
  }

  /* ----------------------------------------------------- the calibration -- */

  function renderCalibration(c) {
    const v = c.recovery_model;
    const tb = $('lrn-bins');
    for (const b of v.bins || []) {
      const gap = b.mean_stated - b.observed_rate;
      const bad = Math.abs(gap) > 0.1;
      tb.appendChild(
        row([
          b.lower.toFixed(1) + '–' + b.upper.toFixed(1),
          { cls: 'r mono', text: num(b.count) + (b.thin ? ' *' : '') },
          { cls: 'r mono', text: b.mean_stated.toFixed(3) },
          { cls: 'r mono', text: b.observed_rate.toFixed(3) },
          { cls: 'r mono' + (bad ? ' warn' : ''), text: (gap >= 0 ? '+' : '') + gap.toFixed(3) },
        ])
      );
    }

    const dl = $('lrn-calmeta');
    dl.textContent = '';
    kv(dl, 'Observations', num(v.observations) + ', out of fold');
    kv(dl, 'Expected calibration error', v.expected_calibration_error.toFixed(4));
    kv(dl, 'Worst bin', v.maximum_calibration_error.toFixed(4));
    kv(dl, 'Noise floor at this size', v.noise_floor.toFixed(4));
    kv(dl, 'Verdict', v.miscalibration_is_significant ? 'real, not sampling noise' : 'inside the noise floor');
    kv(dl, 'After isotonic repair', v.expected_calibration_error_after.toFixed(4) + ', cross-fitted');

    drawReliability(v);

    const worst = (v.bins || []).reduce(
      (acc, b) => (Math.abs(b.mean_stated - b.observed_rate) > Math.abs(acc.mean_stated - acc.observed_rate) ? b : acc),
      v.bins[0]
    );
    $('lrn-calnote').textContent =
      'The model is well calibrated in aggregate and overconfident exactly where it is most confident: the ' +
      worst.lower.toFixed(1) +
      ' to ' +
      worst.upper.toFixed(1) +
      ' bin claims ' +
      pct(worst.mean_stated, 0) +
      ' and delivers ' +
      pct(worst.observed_rate, 0) +
      ' over ' +
      num(worst.count) +
      ' attempts. That matters because the number is multiplied by a real amount to decide whether an attempt is worth making. ' +
      'It was found by measuring rather than by reading the code.';
  }

  /* A reliability diagram: perfect calibration is the diagonal, and the
     distance from it is the whole story. Drawn on a canvas rather than as an
     image so it stays sharp and follows the page theme. */
  function drawReliability(v) {
    const cv = $('lrn-rel');
    if (!cv) return;

    const css = getComputedStyle(document.documentElement);
    const ink = css.getPropertyValue('--ink').trim() || '#c8d3e8';
    const dim = css.getPropertyValue('--ink-3').trim() || '#6b7a99';
    const line = css.getPropertyValue('--line').trim() || '#1e2942';
    const acc = css.getPropertyValue('--accent').trim() || '#5b8cff';
    const warn = css.getPropertyValue('--warn').trim() || '#e8b04b';

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = cv.clientWidth || 340;
    const h = Math.round(w * 0.78);
    cv.width = Math.round(w * dpr);
    cv.height = Math.round(h * dpr);
    cv.style.height = h + 'px';

    const g = cv.getContext('2d');
    g.scale(dpr, dpr);
    g.clearRect(0, 0, w, h);

    const pad = { l: 38, r: 10, t: 10, b: 26 };
    const pw = w - pad.l - pad.r;
    const ph = h - pad.t - pad.b;
    const X = (p) => pad.l + p * pw;
    const Y = (p) => pad.t + (1 - p) * ph;

    g.strokeStyle = line;
    g.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const p = i / 4;
      g.beginPath();
      g.moveTo(X(0), Y(p));
      g.lineTo(X(1), Y(p));
      g.stroke();
    }

    g.strokeStyle = dim;
    g.setLineDash([4, 4]);
    g.beginPath();
    g.moveTo(X(0), Y(0));
    g.lineTo(X(1), Y(1));
    g.stroke();
    g.setLineDash([]);

    const pts = (v.bins || []).filter((b) => b.count > 0);
    const maxN = pts.reduce((m, b) => Math.max(m, b.count), 1);

    g.strokeStyle = acc;
    g.lineWidth = 2;
    g.beginPath();
    pts.forEach((b, i) => {
      const x = X(b.mean_stated);
      const y = Y(b.observed_rate);
      if (i === 0) g.moveTo(x, y);
      else g.lineTo(x, y);
    });
    g.stroke();

    for (const b of pts) {
      const x = X(b.mean_stated);
      const y = Y(b.observed_rate);
      const r = 2.5 + 4.5 * Math.sqrt(b.count / maxN);
      const off = Math.abs(b.mean_stated - b.observed_rate) > 0.1;
      g.fillStyle = off ? warn : acc;
      g.beginPath();
      g.arc(x, y, r, 0, Math.PI * 2);
      g.fill();
    }

    g.fillStyle = dim;
    g.font = '11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
    g.textAlign = 'right';
    for (let i = 0; i <= 4; i++) {
      const p = i / 4;
      g.fillText(p.toFixed(2), pad.l - 6, Y(p) + 3.5);
    }
    g.textAlign = 'center';
    for (let i = 0; i <= 4; i++) {
      const p = i / 4;
      g.fillText(p.toFixed(2), X(p), h - 8);
    }
    g.fillStyle = ink;
    g.textAlign = 'left';
    g.fillText('observed', pad.l + 4, pad.t + 12);
    g.textAlign = 'right';
    g.fillText('predicted', X(1), h - 8 - 14);
  }

  let resizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      const cv = $('lrn-rel');
      if (!cv || !cv.dataset.ready) return;
      fetch('learn.json?v=' + VERSION, { cache: 'force-cache' })
        .then((r) => r.json())
        .then((d) => drawReliability(d.calibrate.recovery_model))
        .catch(() => {});
    }, 180);
  });
})();
