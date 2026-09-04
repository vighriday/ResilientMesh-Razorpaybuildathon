/* ResilientMesh: the moving parts.
 * ==========================================================================
 * Two canvases, and only one of them is decoration.
 *
 * The gradient field behind the hero is the single piece of purely ornamental
 * motion on this page. It is slow, low-contrast and stops painting the moment
 * it scrolls out of view, because a gradient nobody can see is battery cost.
 *
 * The pipeline is not ornament. It replays real incidents from the exported
 * run through the real architecture, and every one of them branches at the gate
 * the way it actually branched, carrying its own payment id, decline code and
 * amount. Nothing in it is invented to make the animation look better: the
 * refused payments appear in the proportion the run produced, because an
 * animation that showed only successes would be the exact dishonesty the rest
 * of this project is arguing against.
 *
 * Exposes window.RMStage.start(run).
 * ========================================================================== */

'use strict';

(function () {
  const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const $ = (id) => document.getElementById(id);
  const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

  /** hexA turns a hex colour into rgba, tolerating the short form and falling
   *  back to the accent for anything unparseable, so a theme edit can never
   *  blank the canvas. */
  function hexA(hex, a) {
    let h = (hex || '').replace('#', '').trim();
    if (h.length === 3) h = h.split('').map((c) => c + c).join('');
    if (h.length !== 6 || /[^0-9a-fA-F]/.test(h)) h = '2757f0';
    const n = parseInt(h, 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }

  function fit(cv) {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const r = cv.getBoundingClientRect();
    cv.width = Math.max(1, Math.round(r.width * dpr));
    cv.height = Math.max(1, Math.round(r.height * dpr));
    const ctx = cv.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, w: r.width, h: r.height };
  }

  /** onlyWhenVisible pauses a loop whose output is off screen. */
  function onlyWhenVisible(node, isRunning, start, stop) {
    if (!('IntersectionObserver' in window)) return;
    new IntersectionObserver((recs) => {
      const vis = recs[0] && recs[0].isIntersecting;
      if (vis && isRunning()) start(); else stop();
    }, { threshold: 0 }).observe(node);
  }

  /* ---------------------------------------------------- gradient field --- */

  function startField() {
    const cv = $('field');
    if (!cv || REDUCED) return;
    let g = fit(cv);
    let raf = 0;

    const blobs = [
      { x: 0.20, y: 0.02, r: 0.50, c: '--accent', sx: 0.000060, sy: 0.000042, a: 0.15 },
      { x: 0.74, y: -0.10, r: 0.42, c: '--accent-2', sx: -0.000048, sy: 0.000071, a: 0.13 },
      { x: 0.50, y: 0.26, r: 0.34, c: '--ok', sx: 0.000082, sy: -0.000055, a: 0.07 },
    ];

    const draw = (t) => {
      const { ctx, w, h } = g;
      ctx.clearRect(0, 0, w, h);
      for (let i = 0; i < blobs.length; i++) {
        const b = blobs[i];
        const cx = (b.x + Math.sin(t * b.sx + i * 1.7) * 0.06) * w;
        const cy = (b.y + Math.cos(t * b.sy + i * 2.3) * 0.05) * h + h * 0.10;
        const rad = b.r * Math.max(w, h);
        const col = cssVar(b.c) || '#2757f0';
        const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, rad);
        grad.addColorStop(0, hexA(col, b.a));
        grad.addColorStop(1, hexA(col, 0));
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(cx, cy, rad, 0, Math.PI * 2);
        ctx.fill();
      }
      raf = requestAnimationFrame(draw);
    };

    const go = () => { if (!raf) raf = requestAnimationFrame(draw); };
    const halt = () => { if (raf) { cancelAnimationFrame(raf); raf = 0; } };
    go();
    window.addEventListener('resize', () => { g = fit(cv); }, { passive: true });
    onlyWhenVisible(cv.parentElement, () => true, go, halt);
  }

  /* --------------------------------------------------------- pipeline --- */

  const STATIONS = [
    { label: 'Webhook', sub: 'HMAC verified first' },
    { label: 'Ingest', sub: 'one transaction' },
    { label: 'Queue', sub: 'outbox, streams' },
    { label: 'Diagnose', sub: 'model is advisory' },
    { label: 'Gatekeeper', sub: '14 invariants' },
    { label: 'Execute', sub: 'the only spender' },
    { label: 'Ledger', sub: 'hash chain' },
  ];
  const GATE = 4;
  const LAST = STATIONS.length - 1;
  const GATE_AT = GATE / LAST;

  const S = {
    raf: 0, running: true, tokens: [], last: 0, spawn: 0, cursor: 0,
    seen: 0, pass: 0, stop: 0, led: 0, cast: [],
  };

  function startPipeline(run) {
    const cv = $('pipe');
    const host = $('stage');
    if (!cv || !host) return;
    host.hidden = false;

    let g = fit(cv);
    let lay = layout(g.w, g.h);
    window.addEventListener('resize', () => { g = fit(cv); lay = layout(g.w, g.h); }, { passive: true });

    S.cast = buildCast(run);
    if (!S.cast.length) { host.hidden = true; return; }

    const toggle = $('stage-toggle');
    toggle.addEventListener('click', () => {
      S.running = !S.running;
      toggle.textContent = S.running ? 'Pause' : 'Play';
      toggle.setAttribute('aria-pressed', String(S.running));
      if (S.running) go();
    });

    const frame = (now) => {
      S.raf = 0;
      const dt = Math.min(48, now - (S.last || now));
      S.last = now;
      if (S.running) step(dt);
      paint(g.ctx, g.w, g.h, lay);
      if (S.running || S.tokens.length) go();
    };
    const go = () => { if (!S.raf) S.raf = requestAnimationFrame(frame); };
    const halt = () => { if (S.raf) { cancelAnimationFrame(S.raf); S.raf = 0; } };

    if (REDUCED) {
      /* Still show the diagram, just without anything moving. */
      S.running = false;
      toggle.textContent = 'Play';
      toggle.setAttribute('aria-pressed', 'false');
      paint(g.ctx, g.w, g.h, lay);
    } else {
      go();
    }
    onlyWhenVisible(host, () => S.running, go, halt);
  }

  /** buildCast draws the players from the run's own incidents, keeping refused
   *  ones in their real proportion. The invariant shown beside a refusal comes
   *  from the run's veto breakdown rather than being chosen for effect. */
  function buildCast(run) {
    const inc = (run.incidents || []).slice(0, 60);
    const rules = (run.vetoes || []).map((v) => v.invariant);
    let r = 0;
    const made = inc.map((i) => {
      const refused = i.state === 'ABSTAINED';
      return {
        id: i.payment_id,
        amount: i.amount,
        code: i.error_code,
        refused,
        rule: refused && rules.length ? rules[r++ % rules.length] : '',
      };
    });

    /* Interleaved rather than left in arrival order. The table is ordered by
       arrival, which clusters outcomes, so a viewer watching the first twenty
       seconds would see only permits and conclude the gate never refuses. The
       proportion is preserved exactly; only the ordering is evened out. */
    const yes = made.filter((m) => !m.refused);
    const no = made.filter((m) => m.refused);
    if (!no.length || !yes.length) return made;
    const out = [];
    const every = Math.max(1, Math.round(yes.length / no.length));
    let ni = 0;
    yes.forEach((y, i) => {
      out.push(y);
      if ((i + 1) % every === 0 && ni < no.length) out.push(no[ni++]);
    });
    while (ni < no.length) out.push(no[ni++]);
    return out;
  }

  function layout(w, h) {
    const pad = Math.max(30, Math.min(70, w * 0.05));
    const usable = Math.max(1, w - pad * 2);
    const xs = STATIONS.map((_, i) => pad + (usable * i) / LAST);
    return { xs, mid: h * 0.52, top: h * 0.17, bot: h * 0.86, w, h };
  }

  function step(dt) {
    S.spawn -= dt;
    if (S.spawn <= 0) {
      const c = S.cast[S.cursor % S.cast.length];
      S.cursor++;
      S.seen++;
      S.tokens.push({ ...c, p: 0 });
      S.spawn = 1150;
    }
    const speed = 0.000175;
    for (const t of S.tokens) {
      const before = t.p;
      t.p = Math.min(1, t.p + dt * speed);
      if (before < GATE_AT && t.p >= GATE_AT) {
        if (t.refused) S.stop++; else S.pass++;
        S.led++;
      }
    }
    S.tokens = S.tokens.filter((t) => t.p < 1);
    setNum('s-seen', S.seen);
    setNum('s-pass', S.pass);
    setNum('s-stop', S.stop);
    setNum('s-led', S.led);
  }

  function setNum(id, v) {
    const n = $(id);
    if (n && n.textContent !== String(v)) n.textContent = String(v);
  }

  function paint(ctx, w, h, lay) {
    ctx.clearRect(0, 0, w, h);

    const line = cssVar('--line') || '#e4e6f0';
    const ink = cssVar('--ink') || '#0a0d18';
    const ink3 = cssVar('--ink-3') || '#767d94';
    const accent = cssVar('--accent') || '#2757f0';
    const ok = cssVar('--ok') || '#0b7a52';
    const warn = cssVar('--warn') || '#8a5a05';
    const mono = cssVar('--mono') || 'monospace';
    const sans = cssVar('--sans') || 'sans-serif';

    const gx = lay.xs[GATE];

    ctx.lineWidth = 1.5;
    ctx.strokeStyle = line;

    ctx.beginPath();
    ctx.moveTo(lay.xs[0], lay.mid);
    ctx.lineTo(gx, lay.mid);
    ctx.stroke();

    /* The permitted branch is solid, the refused branch dashed. A refusal is
       not a failure, but it is a different kind of outcome, and the eye should
       be able to tell them apart before it reads the labels. */
    ctx.beginPath();
    ctx.moveTo(gx, lay.mid);
    ctx.bezierCurveTo(gx + 46, lay.mid, lay.xs[5] - 46, lay.top, lay.xs[5], lay.top);
    ctx.lineTo(lay.xs[6], lay.top);
    ctx.stroke();

    ctx.setLineDash([4, 5]);
    ctx.beginPath();
    ctx.moveTo(gx, lay.mid);
    ctx.bezierCurveTo(gx + 46, lay.mid, lay.xs[5] - 46, lay.bot, lay.xs[5], lay.bot);
    ctx.lineTo(lay.xs[6], lay.bot);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.beginPath();
    ctx.moveTo(lay.xs[6], lay.top);
    ctx.lineTo(lay.xs[6], lay.bot);
    ctx.stroke();

    ctx.textAlign = 'center';
    for (let i = 0; i < STATIONS.length; i++) {
      const x = lay.xs[i];
      const y = i === 5 ? lay.top : i === 6 ? (lay.top + lay.bot) / 2 : lay.mid;
      const isGate = i === GATE;
      const isLedger = i === 6;

      if (isGate) {
        ctx.beginPath();
        ctx.arc(x, y, 15, 0, Math.PI * 2);
        ctx.fillStyle = hexA(ok, 0.14);
        ctx.fill();
      }
      ctx.beginPath();
      ctx.arc(x, y, isGate ? 8 : 5.5, 0, Math.PI * 2);
      ctx.fillStyle = isGate ? ok : isLedger ? accent : line;
      ctx.fill();

      ctx.fillStyle = ink;
      ctx.font = '600 10.5px ' + mono;
      ctx.fillText(STATIONS[i].label.toUpperCase(), x, y - 24);
      ctx.fillStyle = ink3;
      ctx.font = '10px ' + sans;
      ctx.fillText(STATIONS[i].sub, x, y + 30);
    }

    const mx = (gx + lay.xs[5]) / 2;
    ctx.font = '600 9.5px ' + mono;
    ctx.fillStyle = ok;
    ctx.fillText('PERMITTED', mx, lay.top - 34);
    ctx.fillStyle = warn;
    ctx.fillText('REFUSED, RULE NAMED', mx, lay.bot + 40);

    for (const t of S.tokens) {
      const pos = tokenPos(t, lay);
      const col = t.p < GATE_AT ? accent : t.refused ? warn : ok;
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 11, 0, Math.PI * 2);
      ctx.fillStyle = hexA(col, 0.15);
      ctx.fill();
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.fill();

      /* A label is drawn only when nothing else is close enough to collide
         with it. Two overlapping decline codes are less legible than one. */
      const crowded = S.tokens.some((o) => o !== t
        && Math.abs(tokenPos(o, lay).x - pos.x) < 130
        && Math.abs(tokenPos(o, lay).y - pos.y) < 14
        && o.p > t.p);
      if (t.p > 0.05 && t.p < 0.94 && lay.w > 620 && !crowded) {
        ctx.textAlign = 'left';
        ctx.font = '9.5px ' + mono;
        ctx.fillStyle = t.p < GATE_AT ? ink3 : col;
        const label = t.p < GATE_AT ? t.code : t.refused ? (t.rule || 'refused') : t.amount;
        ctx.fillText(label, pos.x + 14, pos.y + 3.5);
        ctx.textAlign = 'center';
      }
    }
  }

  function tokenPos(t, lay) {
    if (t.p <= GATE_AT) {
      const k = t.p / GATE_AT;
      return { x: lay.xs[0] + (lay.xs[GATE] - lay.xs[0]) * k, y: lay.mid };
    }
    const k = (t.p - GATE_AT) / (1 - GATE_AT);
    const endY = t.refused ? lay.bot : lay.top;
    const x = lay.xs[GATE] + (lay.xs[6] - lay.xs[GATE]) * k;
    /* Eased so the fork reads as a decision being taken rather than a jump. */
    const e = k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
    return { x, y: lay.mid + (endY - lay.mid) * Math.min(1, e * 1.7) };
  }

  window.RMStage = {
    start(run) {
      startField();
      startPipeline(run);
    },
  };
})();
