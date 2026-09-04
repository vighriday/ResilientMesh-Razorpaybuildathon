/* ResilientMesh evidence page.
 *
 * Two jobs. The first is rendering an exported run, which is ordinary. The
 * second is re-deriving the audit ledger's hash chain from the exported bytes,
 * which is the reason this page exists: a claim about tamper-evidence that you
 * can only check by trusting the claimant is not a claim about anything.
 *
 * Everything below is plain ES2020 with no dependencies. Text reaches the DOM
 * through textContent, never innerHTML, so a value from the exported document
 * cannot become markup.
 */

'use strict';

// ---------------------------------------------------------------- helpers --

const $ = (id) => document.getElementById(id);

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

function pill(text, kind) {
  return el('span', 'pill ' + (kind || 'mute'), text);
}

const STATE_KIND = {
  RECOVERED: 'ok', SCHEDULED: 'accent', EXECUTING: 'accent',
  ABSTAINED: 'warn', FAILED: 'bad', RECEIVED: 'mute',
};

function shortHash(h) {
  return h ? h.slice(0, 12) + '...' : '';
}

// --------------------------------------------------------------- theme ----

(function theme() {
  const btn = $('theme-toggle');
  const stored = (() => { try { return localStorage.getItem('rm-theme'); } catch (_) { return null; } })();
  if (stored === 'dark' || stored === 'light') {
    document.documentElement.setAttribute('data-theme', stored);
  }
  btn.addEventListener('click', () => {
    const now = document.documentElement.getAttribute('data-theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const next = now ? (now === 'dark' ? 'light' : 'dark') : (prefersDark ? 'light' : 'dark');
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('rm-theme', next); } catch (_) { /* private mode */ }
  });
})();

// ------------------------------------------------- the hash chain, in JS --

const enc = new TextEncoder();

/** u64be encodes a value as 8 big-endian bytes.
 *  BigInt throughout: a Unix nanosecond timestamp exceeds 2^53, so doing this
 *  with Numbers would round the preimage and every digest would be wrong. */
function u64be(value) {
  const out = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

/** absorb appends an 8-byte big-endian length followed by the bytes.
 *  This length prefix is the whole point: naive concatenation would let an
 *  attacker who controls two adjacent fields forge a colliding entry by moving
 *  the boundary between them. */
function absorb(parts, bytes) {
  parts.push(u64be(bytes.length), bytes);
}

const absorbStr = (parts, s) => absorb(parts, enc.encode(s ?? ''));
const absorbUint = (parts, v) => absorb(parts, u64be(v));

function concat(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function hex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

function b64bytes(s) {
  const bin = atob(s || '');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** computeHash mirrors AuditEntry.ComputeHash in internal/domain/records.go,
 *  field for field and in the same order. */
async function computeHash(entry, prevHash) {
  const parts = [];
  absorbUint(parts, entry.seq);
  absorbStr(parts, entry.incident_id);
  absorbStr(parts, entry.kind);
  absorbStr(parts, entry.actor);
  absorb(parts, entry._detail);           // decoded once, at load
  absorbUint(parts, entry.at_unix_nano);
  absorbStr(parts, prevHash);
  return hex(await crypto.subtle.digest('SHA-256', concat(parts)));
}

/** verifyChain walks the ledger from the genesis anchor and stops at the first
 *  entry that does not check out, reporting where and why. Localising a break
 *  is what makes the property useful, because a ledger that only says "invalid"
 *  tells an operator nothing about what was touched. */
async function verifyChain(entries, genesis, onProgress) {
  let prev = genesis;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prev_hash !== prev) {
      return { valid: false, index: i, seq: e.seq, cause: 'broken link to the previous entry', head: prev };
    }
    const got = await computeHash(e, prev);
    if (got !== e.hash) {
      return { valid: false, index: i, seq: e.seq, cause: 'hash mismatch', head: prev, expected: e.hash, got };
    }
    prev = e.hash;
    if (onProgress && (i % 40 === 0 || i === entries.length - 1)) {
      onProgress(i + 1, entries.length);
      await new Promise((r) => setTimeout(r, 0)); // let the bar paint
    }
  }
  return { valid: true, head: prev };
}

// ------------------------------------------------------------------ boot --

let RUN = null;

async function boot() {
  let res;
  try {
    res = await fetch('run.json', { cache: 'no-cache' });
  } catch (err) {
    return fail('Could not load run.json: ' + err.message);
  }
  if (!res.ok) return fail('Could not load run.json (HTTP ' + res.status + ').');

  try {
    RUN = await res.json();
  } catch (err) {
    return fail('run.json is not valid JSON: ' + err.message);
  }
  if (!RUN || RUN.schema !== 'resilientmesh.run.v1') {
    return fail('Unexpected export schema: ' + (RUN && RUN.schema));
  }

  // Decode every detail column once. Keeping the decoded bytes beside the entry
  // means the table renders exactly what the verifier hashes; decoding twice is
  // how a page ends up displaying one thing and checking another.
  for (const e of RUN.chain.entries) e._detail = b64bytes(e.detail_b64);

  $('app').hidden = true;
  $('content').hidden = false;
  render();
}

function fail(msg) {
  const box = $('app');
  box.textContent = '';
  const d = el('div', 'loading');
  d.appendChild(el('p', null, msg));
  d.appendChild(el('p', null, 'The run this page describes is still reproducible: go run ./cmd/meshdemo'));
  box.appendChild(d);
}

// ---------------------------------------------------------------- render --

function render() {
  renderClaims();
  renderRunMeta();
  renderTables();
  renderCase();
  renderNarration();
  renderEntries(RUN.chain.entries);
  wireVerify();
  wireScrollSpy();

  const foot = RUN.commit
    ? 'Run exported ' + RUN.generated_at + ' from commit ' + RUN.commit
    : 'Run exported ' + RUN.generated_at;
  $('foot-run').textContent = foot;
}

function renderClaims() {
  const totalIncidents = RUN.state_counts.reduce((a, r) => a + r.count, 0);
  const refusals = RUN.vetoes.reduce((a, r) => a + r.count, 0);
  const recovered = (RUN.state_counts.find((r) => r.name === 'RECOVERED') || {}).count || 0;
  // Labels say "simulated" wherever the figure describes money, because the
  // traffic is generated by the Razorpay simulator rather than by customers.
  // The system, the decisions and the ledger are real; the payments are not,
  // and a headline reading "merchant revenue recovered" would imply otherwise.
  const claims = [
    [String(totalIncidents), 'simulated failures handled'],
    [String(recovered), 'recovered end to end'],
    [RUN.economics.recovered, 'simulated revenue recovered'],
    [RUN.economics.fees, 'simulated gateway fees spent'],
    [String(refusals), 'actions refused by a rule'],
    [String(RUN.chain.count), 'ledger entries, chain intact'],
  ];
  const strip = $('statgrid');
  strip.textContent = '';
  for (const [n, l] of claims) {
    const c = el('div', 'stat');
    c.appendChild(el('div', 'n', n));
    c.appendChild(el('div', 'l', l));
    strip.appendChild(c);
  }
}

function renderRunMeta() {
  const r = RUN.run;
  const pairs = [
    ['Scenario', r.scenario + ', seed ' + r.seed],
    ['Traffic', r.rate + ' scripted failures/second'],
    ['Inference', r.model ? r.provider + ' / ' + r.model : r.inference_tier],
    ['Boot', r.boot_seconds.toFixed(1) + ' s, from an empty database'],
    ['Wall clock', Math.round(r.elapsed_seconds) + ' s'],
    ['Retry ceiling', r.max_attempts + ' attempts per incident'],
    ['Time scale', 'waits compressed ' + r.time_scale + 'x, regulatory delays never compressed'],
  ];
  const dl = $('runmeta');
  dl.textContent = '';
  for (const [k, v] of pairs) {
    dl.appendChild(el('dt', null, k));
    dl.appendChild(el('dd', null, v));
  }

  $('run-blurb').textContent =
    'The transcript below is the real one, replayed. Each act waits for the system to reach '
    + 'the state it is about to describe, then reads the numbers back out of PostgreSQL. '
    + 'Nothing here is printed from a script.';

  $('term-title').textContent =
    'go run ./cmd/meshdemo -rate ' + r.rate + ' -soak 75s';

  $('econ').textContent =
    RUN.economics.recovered + ' of simulated merchant revenue recovered for '
    + RUN.economics.fees + ' in simulated gateway fees. Both are summed from the attempts '
    + 'table of this run, ' + RUN.economics.ratio_note + '.';

  const live = (RUN.tier_mix.find((t) => t.name === 'LIVE') || {}).count || 0;
  $('tier-note').textContent = live > 0
    ? 'A live model answered ' + live + ' of these. The rest were decline codes whose cause the '
      + 'taxonomy already states, where paying a model to restate it would be the worse '
      + 'engineering decision.'
    : 'No model key was configured for this run, so the deterministic tiers answered '
      + 'everything. That is the path every reviewer without a key takes, which is exactly '
      + 'why it has to work.';

  $('verify-blurb').textContent =
    'This page ships all ' + RUN.chain.count + ' ledger entries as the exact bytes the '
    + 'ledger hashed. The button below re-derives every digest with crypto.subtle and walks '
    + 'the chain from its genesis anchor. Then plant a forgery and watch it localise the break '
    + 'to the row you edited, the same attack the demonstration runs against PostgreSQL.';
}

function renderTables() {
  const st = $('states');
  st.textContent = '';
  for (const s of RUN.state_counts) {
    st.appendChild(row([{ node: pill(s.name, STATE_KIND[s.name]) }, { cls: 'num', text: s.count }]));
  }

  const tb = $('tiers');
  tb.textContent = '';
  for (const t of RUN.tier_mix) {
    tb.appendChild(row([{ node: pill(t.name, t.name === 'LIVE' ? 'accent' : 'mute') }, { cls: 'num', text: t.count }]));
  }

  const inc = $('incidents');
  inc.textContent = '';
  for (const i of RUN.incidents) {
    inc.appendChild(row([
      { cls: 'mono', text: i.payment_id },
      i.issuer_key,
      { cls: 'mono', text: i.error_code },
      { cls: 'num', text: i.amount },
      { node: pill(i.state, STATE_KIND[i.state]) },
    ]));
  }

  const inv = $('invariants-body');
  inv.textContent = '';
  for (const v of RUN.invariants) {
    inv.appendChild(row([
      { cls: 'mono', text: v.name },
      { cls: 'num', text: v.fired },
      { cls: 'wrap-cell', text: v.prevents },
    ]));
  }
}

function renderCase() {
  const c = RUN.case;
  const i = c.incident;

  $('case-title').textContent = i.payment_id + ', ' + i.amount + ' on ' + i.issuer_key;

  const facts = [
    ['Payment', i.payment_id],
    ['Amount', i.amount],
    ['Rail', i.method + ' via ' + i.issuer_key],
    ['Declined', i.error_code],
    ['Recurring', i.is_recurring ? 'yes, so RBI mandate rules apply' : 'no'],
    ['Attempts', String(i.attempt_count)],
    ['Final state', i.state],
  ];
  const dl = $('case-facts');
  dl.textContent = '';
  for (const [k, v] of facts) {
    dl.appendChild(el('dt', null, k));
    dl.appendChild(el('dd', null, v));
  }

  const md = $('case-mandate');
  md.textContent = '';
  if (c.mandate) {
    const p = el('p', 'note');
    p.textContent =
      'Mandate ' + c.mandate.subscription_id + ', category ' + c.mandate.category
      + ', ' + c.mandate.attempts_in_cycle + ' attempt(s) this cycle'
      + (c.mandate.halted ? ', HALTED' : '')
      + '. The cooling window, the pre-debit notice and the additional-factor ceiling '
      + 'are all evaluated against this row.';
    md.appendChild(p);
  }

  const at = $('case-attempts');
  at.textContent = '';
  for (const a of c.attempts) {
    at.appendChild(row([
      { cls: 'num', text: a.attempt_number },
      { cls: 'mono', text: a.action },
      { cls: 'mono', text: a.rail || 'none' },
      { node: pill(a.succeeded ? 'succeeded' : (a.error_code || 'failed'), a.succeeded ? 'ok' : 'bad') },
      { cls: 'num', text: a.fee },
    ]));
  }
  $('case-attempts-note').textContent = c.attempts.length
    ? 'Read from the attempts table, which has a unique constraint on (incident, attempt '
      + 'number), so a retried write cannot double-count a gateway fee. That constraint '
      + 'exists because deterministic simulation found it missing.'
    : 'Nothing was executed for this incident, and that is a recorded outcome rather than '
      + 'an absence. The ledger below names the rule that stopped it.';

  const tl = $('case-timeline');
  tl.textContent = '';
  for (const e of c.timeline) {
    const li = document.createElement('li');
    if (e.kind === 'ATTEMPT_RESULT' && /recovered/i.test(e.summary)) li.className = 'good';
    if (e.kind === 'TERMINAL_HALT' || e.kind === 'INCIDENT_CLOSED') li.className = 'good';
    if (/refus|abstain|halt/i.test(e.summary)) li.className = 'stop';

    const h = el('div');
    h.appendChild(el('span', 'st-kind', e.kind));
    h.appendChild(el('span', 'st-seq', '#' + e.seq + ' · ' + e.at));
    li.appendChild(h);
    li.appendChild(el('div', 'st-sum', e.summary));

    const det = document.createElement('details');
    det.appendChild(el('summary', null, 'the bytes that were hashed'));
    const pre = el('pre', null, JSON.stringify(e.detail, null, 2));
    det.appendChild(pre);
    li.appendChild(det);
    tl.appendChild(li);
  }
}

// ------------------------------------------------------------- narration --

let player = { i: 0, timer: null };

function renderNarration() {
  const jump = $('actjump');
  jump.textContent = '';
  for (const a of RUN.acts) {
    const b = el('button', 'chip', a.number === 0 ? 'Start' : 'Act ' + a.number);
    b.title = a.title;
    b.addEventListener('click', () => jumpToAct(a.number));
    jump.appendChild(b);
  }

  $('play').addEventListener('click', togglePlay);
  $('skip').addEventListener('click', () => { stop(); drawUpTo(RUN.narration.length); });

  drawUpTo(RUN.narration.length);
}

function drawUpTo(n) {
  const term = $('term');
  term.textContent = '';
  const frag = document.createDocumentFragment();
  for (let i = 0; i < n && i < RUN.narration.length; i++) {
    const r = RUN.narration[i];
    frag.appendChild(el('span', 'tl ' + r.kind, r.text === '' ? ' ' : r.text));
  }
  term.appendChild(frag);
  player.i = Math.min(n, RUN.narration.length);
  term.scrollTop = term.scrollHeight;
}

function appendLine(i) {
  const r = RUN.narration[i];
  const term = $('term');
  term.appendChild(el('span', 'tl ' + r.kind, r.text === '' ? ' ' : r.text));
  term.scrollTop = term.scrollHeight;
}

function play() {
  if (player.timer) return;
  $('play').textContent = 'Pause';
  if (player.i >= RUN.narration.length) { player.i = 0; drawUpTo(0); }
  player.timer = setInterval(() => {
    if (player.i >= RUN.narration.length) { stop(); return; }
    appendLine(player.i);
    player.i++;
  }, 55);
}

function stop() {
  if (player.timer) clearInterval(player.timer);
  player.timer = null;
  $('play').textContent = 'Replay the run';
}

function togglePlay() { player.timer ? stop() : play(); }

function jumpToAct(n) {
  stop();
  let start = RUN.narration.findIndex((r) => r.act === n);
  if (start < 0) start = 0;
  drawUpTo(start);
  play();
  for (const b of $('actjump').children) b.classList.remove('on');
  const idx = RUN.acts.findIndex((a) => a.number === n);
  if (idx >= 0) $('actjump').children[idx].classList.add('on');
}

// ----------------------------------------------------------- the ledger ---

let TAMPERED = null; // { index, original }, so the edit is reversible

function renderEntries(entries) {
  $('chaincount').textContent = entries.length + ' entries';
  const filter = ($('entryfilter').value || '').trim().toLowerCase();
  const body = $('entries');
  body.textContent = '';

  const matching = entries.filter((e) => !filter
    || e.kind.toLowerCase().includes(filter)
    || (e.incident_id || '').toLowerCase().includes(filter)
    || String(e.seq) === filter);

  const shown = matching.slice(0, 200);
  $('entryshown').textContent = shown.length < matching.length
    ? 'showing 200 of ' + matching.length
    : matching.length + ' shown';

  const frag = document.createDocumentFragment();
  for (const e of shown) {
    const tr = row([
      { cls: 'num', text: e.seq },
      { cls: 'mono', text: e.kind },
      { cls: 'wrap-cell', text: e.summary },
      { cls: 'mono', text: shortHash(e.hash) },
    ]);
    if (TAMPERED && entries[TAMPERED.index] === e) tr.classList.add('tampered');
    frag.appendChild(tr);
  }
  body.appendChild(frag);
}

function wireVerify() {
  $('entryfilter').addEventListener('input', () => renderEntries(RUN.chain.entries));
  $('btn-verify').addEventListener('click', runVerify);
  $('btn-tamper').addEventListener('click', plantForgery);
  $('btn-restore').addEventListener('click', restore);

  $('tamper-note').textContent =
    'When the demonstration ran this attack against the real database it edited entry '
    + RUN.tamper.target_seq + ' and verification localised the break to entry '
    + RUN.tamper.detected_seq + '. That is the exact row that was touched, not merely "the chain is '
    + 'invalid". The row edited is in the middle of the chain rather than at its head, because '
    + 'a ledger that only catches a modified head catches nothing: the head is what an attacker '
    + 'rewrites last.';
}

function setStatus(kind, text, spinning) {
  const box = $('vstatus');
  box.className = 'vstatus' + (kind ? ' ' + kind : '');
  box.textContent = '';
  if (spinning) box.appendChild(el('span', 'spin'));
  box.appendChild(el('span', null, text));
}

async function runVerify() {
  const btns = ['btn-verify', 'btn-tamper', 'btn-restore'].map($);
  for (const b of btns) b.disabled = true;

  setStatus('', 'Re-deriving ' + RUN.chain.entries.length + ' SHA-256 digests in this browser.', true);
  $('hashline').textContent = '';

  const began = performance.now();
  const result = await verifyChain(RUN.chain.entries, RUN.chain.genesis, (done, total) => {
    $('vbar').style.width = ((done / total) * 100).toFixed(1) + '%';
  });
  const ms = Math.round(performance.now() - began);
  $('vbar').style.width = '100%';

  const line = $('hashline');
  line.textContent = '';
  if (result.valid) {
    setStatus('ok',
      'Chain verified. ' + RUN.chain.entries.length + ' entries, every digest re-derived from '
      + 'the published bytes, in ' + ms + ' ms.', false);
    line.appendChild(el('b', null, 'head  '));
    line.appendChild(document.createTextNode(result.head));
    if (result.head === RUN.chain.head) {
      line.appendChild(el('br'));
      line.appendChild(el('b', null, 'matches the head the running system reported.'));
    }
  } else {
    setStatus('bad',
      'Tamper detected at entry ' + result.seq + '. Cause: ' + result.cause
      + '. Every entry before it still verifies.', false);
    if (result.expected) {
      line.appendChild(el('b', null, 'recorded  '));
      line.appendChild(document.createTextNode(result.expected));
      line.appendChild(el('br'));
      line.appendChild(el('b', null, 'recomputed  '));
      line.appendChild(document.createTextNode(result.got));
    }
  }

  for (const b of btns) b.disabled = false;
  $('btn-restore').disabled = !TAMPERED;
  renderEntries(RUN.chain.entries);
}

/** plantForgery edits one entry's detail bytes and leaves its recorded digest
 *  alone, which is exactly what an attacker with database access can do, and
 *  what the demonstration does against PostgreSQL. The middle of the chain is
 *  chosen on purpose. */
function plantForgery() {
  const entries = RUN.chain.entries;
  if (!entries.length) return;
  if (TAMPERED) restore();

  const index = Math.floor(entries.length / 2);
  const e = entries[index];
  const forged = enc.encode(JSON.stringify({
    note: 'this row was edited in your browser, after the ledger hashed it',
    action: 'IN_SESSION_RAIL_MORPH',
  }));
  TAMPERED = { index, original: e._detail, seq: e.seq };
  e._detail = forged;

  setStatus('warn',
    'Entry ' + e.seq + ' has been rewritten in memory. Its recorded digest was left untouched, '
    + 'as an attacker with database access would leave it. Verify the chain again.', false);
  $('vbar').style.width = '0%';
  $('hashline').textContent = '';
  $('btn-restore').disabled = false;
  renderEntries(entries);
}

function restore() {
  if (!TAMPERED) return;
  RUN.chain.entries[TAMPERED.index]._detail = TAMPERED.original;
  const seq = TAMPERED.seq;
  TAMPERED = null;
  $('btn-restore').disabled = true;
  setStatus('', 'Entry ' + seq + ' restored. Verify again and the chain closes.', false);
  $('vbar').style.width = '0%';
  $('hashline').textContent = '';
  renderEntries(RUN.chain.entries);
}

/** wireScrollSpy marks the section currently in view, so the nav reports where
 *  you are rather than only offering somewhere to go. */
function wireScrollSpy() {
  const links = Array.from(document.querySelectorAll('#topnav a'));
  const targets = links
    .map((a) => ({ a, el: document.querySelector(a.getAttribute('href')) }))
    .filter((t) => t.el);
  if (!targets.length || !('IntersectionObserver' in window)) return;

  const seen = new Map();
  const io = new IntersectionObserver((records) => {
    for (const r of records) seen.set(r.target, r.intersectionRatio);
    let best = null, bestRatio = 0;
    for (const t of targets) {
      const ratio = seen.get(t.el) || 0;
      if (ratio > bestRatio) { best = t; bestRatio = ratio; }
    }
    for (const t of targets) t.a.classList.toggle('on', best !== null && t === best);
  }, { rootMargin: '-72px 0px -55% 0px', threshold: [0, .1, .25, .5, .75, 1] });

  for (const t of targets) io.observe(t.el);
}

boot();
