/* ResilientMesh evidence page.
 * ==========================================================================
 * Renders one exported run, and computes three things live in the reader's
 * browser, because a claim you can only check by trusting the claimant is not
 * a claim about anything:
 *
 *   1. The ledger's hash chain, re-derived from the exact bytes it hashed.
 *   2. One payment's Merkle inclusion proof, so a single record can be checked
 *      without the rest of the ledger.
 *   3. The real gatekeeper, compiled to WebAssembly, so the reader can attack
 *      it and can confirm it agrees with the server build on recorded vectors.
 *
 * Plain ES2020, no dependencies, no build step. Text reaches the DOM through
 * textContent rather than innerHTML, so a value from the exported document can
 * never become markup.
 * ========================================================================== */

'use strict';

/* The version this page was deployed at, rewritten by scripts/build-space.sh.
   Every asset URL carries it, because a browser that cached a previous deploy
   would otherwise run last week's JavaScript against this week's data, and the
   symptom of that is a page quietly showing the wrong numbers. */
const PAGE_VERSION = (document.currentScript && new URL(document.currentScript.src).searchParams.get('v')) || 'dev';
const WASM_URL = 'gatekeeper.wasm?v=' + PAGE_VERSION;

/* ------------------------------------------------------------- helpers --- */

const $ = (id) => document.getElementById(id);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function frag(...nodes) {
  const f = document.createDocumentFragment();
  for (const n of nodes) if (n) f.appendChild(n);
  return f;
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

const pill = (t, k) => el('span', 'pill ' + (k || 'mut'), t);

const STATE_KIND = {
  RECOVERED: 'ok', SCHEDULED: 'acc', EXECUTING: 'acc',
  ABSTAINED: 'wa', FAILED: 'bad', RECEIVED: 'mut',
};

const short = (h, n = 12) => (h ? h.slice(0, n) + '...' : '');

const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* --------------------------------------------------------------- theme --- */

(function theme() {
  const stored = (() => { try { return localStorage.getItem('rm-theme'); } catch (_) { return null; } })();
  if (stored === 'dark' || stored === 'light') document.documentElement.setAttribute('data-theme', stored);
  $('theme').addEventListener('click', () => {
    const now = document.documentElement.getAttribute('data-theme');
    const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const next = now ? (now === 'dark' ? 'light' : 'dark') : (dark ? 'light' : 'dark');
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('rm-theme', next); } catch (_) { /* private mode */ }
  });
})();

/* ------------------------------------------------- hashing, in the page --- */

const enc = new TextEncoder();

/** u64be encodes a value as eight big-endian bytes.
 *  BigInt throughout, because a Unix nanosecond timestamp exceeds 2^53 and
 *  doing this with Numbers would round the preimage into a different digest. */
function u64be(value) {
  const out = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

/** absorb appends an eight-byte length and then the bytes. The length prefix is
 *  the whole point: plain concatenation would let an attacker who controls two
 *  adjacent fields forge a collision by moving the boundary between them. */
const absorb = (parts, bytes) => { parts.push(u64be(bytes.length), bytes); };
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

function unhex(s) {
  if (typeof s !== 'string' || s.length !== 64 || /[^0-9a-f]/.test(s)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function b64bytes(s) {
  const bin = atob(s || '');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

/** entryDigest mirrors AuditEntry.ComputeHash in internal/domain/records.go,
 *  field for field and in the same order. */
async function entryDigest(e, prevHash) {
  const parts = [];
  absorbUint(parts, e.seq);
  absorbStr(parts, e.incident_id);
  absorbStr(parts, e.kind);
  absorbStr(parts, e.actor);
  absorb(parts, e._detail);
  absorbUint(parts, e.at_unix_nano);
  absorbStr(parts, prevHash);
  return hex(await sha256(concat(parts)));
}

/** verifyChain walks from the genesis anchor and stops at the first entry that
 *  does not check out, reporting where and why. Localising a break is what
 *  makes the property useful: a ledger that only says "invalid" tells an
 *  operator nothing about what was touched. */
async function verifyChain(entries, genesis, onProgress) {
  let prev = genesis;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prev_hash !== prev) {
      return { valid: false, seq: e.seq, cause: 'broken link to the previous entry' };
    }
    const got = await entryDigest(e, prev);
    if (got !== e.hash) {
      return { valid: false, seq: e.seq, cause: 'hash mismatch', expected: e.hash, got };
    }
    prev = e.hash;
    if (onProgress && (i % 40 === 0 || i === entries.length - 1)) {
      onProgress(i + 1, entries.length);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  return { valid: true, head: prev };
}

/* ------------------------------------------ Merkle inclusion, in the page - */

/* Domain separation, matching internal/attest. Leaves and interior nodes carry
   different tags so no leaf can ever hash to the same value as a node, which is
   the second-preimage defence RFC 6962 uses. */
async function leafHash(entryHash32) {
  const b = new Uint8Array(33);
  b[0] = 0x00; b.set(entryHash32, 1);
  return sha256(b);
}
async function nodeHash(left, right) {
  const b = new Uint8Array(65);
  b[0] = 0x01; b.set(left, 1); b.set(right, 33);
  return sha256(b);
}

/** verifyInclusion recomputes the entry's own digest from its bytes, then folds
 *  the sibling path into the published root. Both halves matter: the first
 *  catches an edited record, the second catches a record that was never in the
 *  ledger at all. */
async function verifyInclusion(entry) {
  const recomputed = await entryDigest(entry, entry.prev_hash);
  if (recomputed !== entry.hash) {
    return { ok: false, why: 'the entry does not hash to its own recorded digest' };
  }
  const raw = unhex(entry.hash);
  if (!raw) return { ok: false, why: 'the recorded digest is not a 32-byte value' };

  const p = entry.inclusion_proof;
  if (!p || p.leaf_index < 0 || p.leaf_index >= p.tree_size) {
    return { ok: false, why: 'the proof does not name a leaf in its own tree' };
  }
  let cur = await leafHash(raw);
  if (hex(cur) !== p.entry_hash) {
    return { ok: false, why: 'the proof commits to a different leaf' };
  }
  for (const step of (p.path || [])) {
    const sib = unhex(step.hash);
    if (!sib) return { ok: false, why: 'a sibling in the path is not a digest' };
    cur = step.right ? await nodeHash(cur, sib) : await nodeHash(sib, cur);
  }
  const got = hex(cur);
  return got === p.root
    ? { ok: true, root: got, steps: (p.path || []).length }
    : { ok: false, why: 'the path does not fold to the published root' };
}

/* ---------------------------------------------------------------- boot --- */

let RUN = null;

async function boot() {
  let res;
  try {
    res = await fetch('run.json?v=' + PAGE_VERSION, { cache: 'no-cache' });
  } catch (err) {
    return bootFail('Could not load run.json: ' + err.message);
  }
  if (!res.ok) return bootFail('Could not load run.json (HTTP ' + res.status + ').');
  try {
    RUN = await res.json();
  } catch (err) {
    return bootFail('run.json is not valid JSON: ' + err.message);
  }
  if (!RUN || RUN.schema !== 'resilientmesh.run.v1') {
    return bootFail('Unexpected export schema: ' + (RUN && RUN.schema));
  }

  /* Decode each detail column once. Keeping the decoded bytes on the entry is
     what guarantees the table renders exactly what the verifier hashes. */
  for (const e of RUN.chain.entries) e._detail = b64bytes(e.detail_b64);
  if (RUN.case && RUN.case.evidence) {
    for (const e of RUN.case.evidence.entries) e._detail = b64bytes(e.detail_b64);
  }

  $('boot').hidden = true;
  $('main').hidden = false;
  render();
}

function bootFail(msg) {
  const box = $('boot');
  box.textContent = '';
  const d = el('div', 'boot');
  d.appendChild(el('p', null, msg));
  d.appendChild(el('p', 'dim', 'The run this page describes is still reproducible with: go run ./cmd/meshdemo'));
  box.appendChild(d);
}

/* -------------------------------------------------------------- render --- */

function render() {
  renderStats();
  renderRun();
  renderRefusals();
  renderTables();
  renderCase();
  renderPack();
  renderBroke();
  renderEntries(RUN.chain.entries);
  wireTabs();
  wireVerify();
  wireWasm();
  wireChrome();
  if (window.RMStage) window.RMStage.start(RUN);

  $('foot-run').textContent = RUN.commit
    ? 'Run exported ' + RUN.generated_at + ' from commit ' + RUN.commit
    : 'Run exported ' + RUN.generated_at;
}

/* The money figures say "simulated" wherever they describe money, because the
   traffic comes from the simulator. The system is real; the rupees are not. */
function renderStats() {
  const total = RUN.state_counts.reduce((a, r) => a + r.count, 0);
  const recovered = (RUN.state_counts.find((r) => r.name === 'RECOVERED') || {}).count || 0;
  const refusals = RUN.vetoes.reduce((a, r) => a + r.count, 0);

  const items = [
    { v: String(total), k: 'simulated failures handled' },
    { v: String(recovered), k: 'recovered end to end', ok: true },
    { v: String(refusals), k: 'actions refused by a rule' },
    { v: String(RUN.vetoes.length), k: 'distinct invariants fired' },
    { v: String(RUN.chain.count), k: 'ledger entries, chain intact' },
    { v: RUN.economics.recovered, k: 'simulated revenue recovered' },
  ];

  const box = $('stats');
  box.textContent = '';
  for (const it of items) {
    const c = el('div', 'stat');
    const v = el('div', 'v' + (it.ok ? ' ok' : ''), it.v);
    c.appendChild(v);
    c.appendChild(el('div', 'k', it.k));
    box.appendChild(c);
    countUp(v, it.v);
  }
}

/** countUp animates a figure into place. Only plain integers, because animating
 *  a currency string would mean re-formatting it mid-flight and briefly showing
 *  an amount that was never true. */
function countUp(node, finalText) {
  if (REDUCED || !/^\d+$/.test(finalText)) return;
  const target = Number(finalText);
  if (target < 5) return;
  const started = performance.now();
  node.textContent = '0';
  const tick = (t) => {
    const p = Math.min(1, (t - started) / 700);
    node.textContent = String(Math.round(target * (1 - Math.pow(1 - p, 3))));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function renderRun() {
  const r = RUN.run;
  $('run-blurb').textContent =
    'Each act waits for the system to reach the state it is about to describe, then reads the '
    + 'numbers back out of PostgreSQL. Nothing in the transcript is printed from a script.';
  $('cmdline').textContent = 'go run ./cmd/meshdemo -rate ' + r.rate + ' -soak 75s';

  const pairs = [
    ['Scenario', r.scenario + ', seed ' + r.seed],
    ['Traffic', r.rate + ' scripted failures per second'],
    ['Inference', r.model ? r.provider + ' / ' + r.model : r.inference_tier],
    ['Boot', r.boot_seconds.toFixed(1) + ' s, from an empty database'],
    ['Wall clock', Math.round(r.elapsed_seconds) + ' s'],
    ['Retry ceiling', r.max_attempts + ' attempts per incident'],
    ['Time scale', 'waits compressed ' + r.time_scale + 'x; regulatory delays never'],
  ];
  const dl = $('runmeta');
  dl.textContent = '';
  for (const [k, v] of pairs) { dl.appendChild(el('dt', null, k)); dl.appendChild(el('dd', null, v)); }

  $('econ').textContent =
    RUN.economics.recovered + ' of simulated merchant revenue recovered for '
    + RUN.economics.fees + ' in simulated gateway fees. Both are summed from the attempts table '
    + 'of this run, ' + RUN.economics.ratio_note + '.';

  $('verify-blurb').textContent =
    'This page ships all ' + RUN.chain.count + ' ledger entries as the exact bytes the ledger '
    + 'hashed, and re-derives every digest here, in your browser. Then plant a forgery and watch '
    + 'verification localise the break to the row you edited.';

  renderNarration();
}

function renderRefusals() {
  const box = $('refusals');
  box.textContent = '';
  for (const inv of RUN.invariants) {
    const r = el('div', 'refusal rise' + (inv.fired === 0 ? ' z' : ''));
    r.appendChild(el('div', 'n', inv.fired));
    const t = el('div');
    t.appendChild(el('div', 'name', inv.name));
    t.appendChild(el('div', 'what', inv.prevents));
    r.appendChild(t);
    box.appendChild(r);
  }
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
    tb.appendChild(row([{ node: pill(t.name, t.name === 'LIVE' ? 'acc' : 'mut') }, { cls: 'num', text: t.count }]));
  }
  const live = (RUN.tier_mix.find((t) => t.name === 'LIVE') || {}).count || 0;
  $('tier-note').textContent = live > 0
    ? 'A live model answered ' + live + ' of these. The rest were decline codes whose cause the '
      + 'taxonomy already states, where paying a model to restate it is the worse engineering decision.'
    : 'No model key was configured, so the deterministic tiers answered everything. That is the '
      + 'path every reviewer without a key takes, which is exactly why it has to work.';

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
}

/* ----------------------------------------------------------- narration --- */

const player = { i: 0, timer: null };

function renderNarration() {
  const chips = $('acts');
  chips.textContent = '';
  for (const a of RUN.acts) {
    const b = el('button', 'chip', a.number === 0 ? 'Start' : 'Act ' + a.number);
    b.type = 'button';
    b.title = a.title;
    b.setAttribute('aria-pressed', 'false');
    b.addEventListener('click', () => jumpToAct(a.number, b));
    chips.appendChild(b);
  }
  $('play').addEventListener('click', () => (player.timer ? stopPlayer() : startPlayer()));
  $('skip').addEventListener('click', () => { stopPlayer(); drawUpTo(RUN.narration.length); });
  drawUpTo(RUN.narration.length);
}

function drawUpTo(n) {
  const term = $('term');
  term.textContent = '';
  const f = document.createDocumentFragment();
  for (let i = 0; i < n && i < RUN.narration.length; i++) {
    const r = RUN.narration[i];
    f.appendChild(el('span', 'tl ' + r.kind, r.text === '' ? ' ' : r.text));
  }
  term.appendChild(f);
  player.i = Math.min(n, RUN.narration.length);
  term.scrollTop = term.scrollHeight;
}

function startPlayer() {
  if (player.timer) return;
  $('play').textContent = 'Pause';
  if (player.i >= RUN.narration.length) { player.i = 0; drawUpTo(0); }
  player.timer = setInterval(() => {
    if (player.i >= RUN.narration.length) { stopPlayer(); return; }
    const r = RUN.narration[player.i];
    const term = $('term');
    term.appendChild(el('span', 'tl ' + r.kind, r.text === '' ? ' ' : r.text));
    term.scrollTop = term.scrollHeight;
    player.i++;
  }, REDUCED ? 4 : 42);
}

function stopPlayer() {
  if (player.timer) clearInterval(player.timer);
  player.timer = null;
  $('play').textContent = 'Replay the run';
}

function jumpToAct(n, btn) {
  stopPlayer();
  let start = RUN.narration.findIndex((r) => r.act === n);
  if (start < 0) start = 0;
  drawUpTo(start);
  startPlayer();
  for (const b of $('acts').children) b.setAttribute('aria-pressed', String(b === btn));
}

/* ----------------------------------------------------------- case file --- */

function renderCase() {
  const c = RUN.case;
  if (!c || !c.incident) return;
  const i = c.incident;
  $('case-title').textContent = i.payment_id + ', ' + i.amount;

  const facts = [
    ['Payment', i.payment_id], ['Amount', i.amount],
    ['Rail', i.method + ' via ' + i.issuer_key], ['Declined', i.error_code],
    ['Recurring', i.is_recurring ? 'yes, so RBI mandate rules apply' : 'no'],
    ['Attempts', String(i.attempt_count)], ['Final state', i.state],
  ];
  const dl = $('case-facts');
  dl.textContent = '';
  for (const [k, v] of facts) { dl.appendChild(el('dt', null, k)); dl.appendChild(el('dd', null, v)); }

  const md = $('case-mandate');
  md.textContent = '';
  if (c.mandate) {
    md.appendChild(el('p', 'aside',
      'Mandate ' + c.mandate.subscription_id + ', category ' + c.mandate.category + ', '
      + c.mandate.attempts_in_cycle + ' attempt(s) this cycle'
      + (c.mandate.halted ? ', HALTED' : '')
      + '. The cooling window, the pre-debit notice and the additional-factor ceiling are all '
      + 'evaluated against this row.'));
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
  $('case-note').textContent = c.attempts.length
    ? 'Read from the attempts table, which carries a unique constraint on (incident, attempt '
      + 'number), so a retried write cannot double-count a gateway fee. That constraint exists '
      + 'because deterministic simulation found it missing.'
    : 'Nothing was executed, and that is a recorded outcome rather than an absence. The trail '
      + 'below names the rule that stopped it.';

  const tl = $('case-timeline');
  tl.textContent = '';
  for (const e of c.timeline) {
    const li = document.createElement('li');
    if (/recovered/i.test(e.summary) || e.kind === 'INCIDENT_CLOSED') li.className = 'good';
    if (/refus|abstain|halt/i.test(e.summary) || e.kind === 'TERMINAL_HALT') li.className = 'stop';

    const h = el('div', 'st-h');
    h.appendChild(el('span', 'st-k', e.kind));
    h.appendChild(el('span', 'st-m', '#' + e.seq + '  ' + e.at));
    li.appendChild(h);
    li.appendChild(el('div', 'st-b', e.summary));

    const d = document.createElement('details');
    d.appendChild(el('summary', null, 'the bytes that were hashed'));
    d.appendChild(el('pre', null, JSON.stringify(e.detail, null, 2)));
    li.appendChild(d);
    tl.appendChild(li);
  }
}

/* ------------------------------------------------------- evidence pack --- */

let PACK_FORGED = null;

function renderPack() {
  const pk = RUN.case && RUN.case.evidence;
  const meta = $('pk-meta');
  meta.textContent = '';
  if (!pk || !pk.entries || !pk.entries.length) {
    setState($('pk-state'), '', 'This run produced no evidence pack.', false);
    ['pk-run', 'pk-forge'].forEach((id) => ($(id).disabled = true));
    return;
  }

  const saving = pk.full_ledger_bytes > 0
    ? Math.round(pk.full_ledger_bytes / Math.max(1, pk.proof_bytes)) : 0;
  const pairs = [
    ['Payment', pk.payment_id],
    ['Entries proved', String(pk.entries.length)],
    ['Ledger it came from', pk.tree_size + ' entries'],
    ['Path length', pk.entries[0].inclusion_proof.path.length + ' sibling hashes per entry'],
    ['Bundle size', humanBytes(pk.proof_bytes)],
    ['Whole ledger', humanBytes(pk.full_ledger_bytes) + (saving ? ', about ' + saving + 'x larger' : '')],
    ['Merkle root', pk.merkle_root],
  ];
  for (const [k, v] of pairs) { meta.appendChild(el('dt', null, k)); meta.appendChild(el('dd', null, v)); }

  $('pk-note').textContent =
    'This is the shape a merchant hands a bank during a chargeback dispute. It proves what was '
    + 'decided for this payment and that the record is genuine, while disclosing nothing about '
    + 'any other payment: the siblings in the path are digests, not records.';

  renderPackRows();
}

function renderPackRows(results) {
  const pk = RUN.case.evidence;
  const body = $('pk-entries');
  body.textContent = '';
  pk.entries.forEach((e, i) => {
    const r = results && results[i];
    const tr = row([
      { cls: 'num', text: e.seq },
      { cls: 'mono', text: e.kind },
      { cls: 'free', text: e.summary },
      { node: r ? pill(r.ok ? 'proved' : 'FAILED', r.ok ? 'ok' : 'bad')
                : pill(e.inclusion_proof.path.length + ' hashes', 'mut') },
    ]);
    if (PACK_FORGED && PACK_FORGED.index === i) tr.classList.add('hit');
    body.appendChild(tr);
  });
}

function humanBytes(n) {
  if (!n) return 'unknown';
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB';
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + ' kB';
  return n + ' bytes';
}

/* ---------------------------------------------------------- what broke --- */

const DEFECTS = [
  { via: 'MODEL CHECKING', title: 'Two gatekeeper defects that 20,000 property cases missed',
    body: 'RBI_AFA_CEILING was specified and never implemented, so a mandate above Rs 15,000 '
      + 'would have been retried without a fresh authentication factor. That is a regulatory '
      + 'breach, not a suboptimal choice. EXECUTABLE_NAMES_A_RAIL failed at 29,952 states: the '
      + 'gate emitted an executable command naming no rail. The property corpus could never '
      + 'generate an instrument refresh, so 20,000 draws of the wrong distribution found '
      + 'nothing. Property testing samples; model checking enumerates. 58,512 violations to 0.' },
  { via: 'CONSUMER REVIEW', title: 'Five fail-open defects in my own frozen contracts',
    body: 'The worst: Validate() accepted NaN as a confidence score. Every ordered comparison '
      + 'against NaN is false, so conf < floor waved it straight through and every downstream '
      + 'check read it as maximum confidence. Also a failure class that defaulted to '
      + 'recoverable, and provenance fields a model could set to forge its own tier.' },
  { via: 'UNICODE', title: 'Case folding admitted non-members into every closed set',
    body: 'strings.ToUpper applies Unicode case mapping, and U+017F, the long s, uppercases to '
      + 'a plain ASCII S, so ParseAction of that spelling of ASYNC_EXPONENTIAL_RETRY returned a '
      + 'valid action. Three of those parsers sit directly on the model boundary. Replaced with '
      + 'ASCII-only folds. You can try this one yourself in chapter 04.' },
  { via: 'BOOTING IT', title: 'The offline path recovered nothing',
    body: 'Every unit test passed and every component was individually correct. Running the '
      + 'whole thing showed twelve incidents diagnosed and one acted on: the deterministic tier '
      + 'had no rule for the soft decline codes, so with no API key, which is every reviewer by '
      + 'design, a recovery system recovered nothing.' },
  { via: 'BOOTING IT', title: 'Deferred recoveries were silently dropped',
    body: 'The worker marked a delayed command SCHEDULED and acknowledged the message. A comment '
      + 'claimed a scheduler would collect it. There was no scheduler. The ledger recorded '
      + 'correct decisions that never happened, and every report looked right. Fixing it exposed '
      + 'a second defect immediately behind it: a swept incident recomputed its backoff and '
      + 'deferred itself forever.' },
  { via: 'SIMULATION', title: 'A retried write that double-counted money',
    body: 'The attempt-commit path is retried on purpose, but the retried block was not '
      + 'idempotent: a fault after RecordAttempt re-ran it and inserted a second row for the same '
      + 'attempt. The table had an index on (incident, attempt) but no uniqueness, so it '
      + 'double-counted a gateway fee and inflated every measurement, in the direction that '
      + 'flatters the system.' },
  { via: 'SIMULATION', title: 'A transient broker outage permanently destroyed events',
    body: 'The relay parked a row on its first publish failure, which made the eight-attempt '
      + 'budget unreachable, and the claim itself charged an attempt, so an outage exhausted '
      + 'every budget in the table. The relay comment stated the correct principle and the code '
      + 'did the opposite. It now probes the queue and hands the batch back uncharged when the '
      + 'broker is down.' },
  { via: 'RUNNING IT TWICE', title: 'The demonstration poisoned its own next run',
    body: 'Act 5 forges a ledger row on purpose and does not repair it, and the data directory '
      + 'was reused on purpose. Each decision is right; together they meant a second run failed '
      + 'at boot with a chain broken before it had written anything. The rejected fix was to '
      + 'repair the row: a system with a repair path for its own audit trail does not have one. '
      + 'The demonstration now owns a database it empties every run, which also makes "the run '
      + 'is a pure function of its seed" true on the second run rather than only the first.' },
  { via: 'RUNNING THE HARNESS TWICE', title: 'A flaky verification gate, which is worse than a failing one',
    body: 'The race-detector gate failed once and passed on a re-run. That is the worst result a '
      + 'gate can give: a reviewer who hits it concludes the project is broken, and one who does '
      + 'not never learns there was anything wrong. The cause was a genuine unsynchronised read '
      + 'in a test helper, which appends each webhook delivery under a mutex and then let the '
      + 'assertions read the slice with no lock. It passed in isolation eight times running, '
      + 'because the deliveries are logically complete by then, but the handler goroutine that '
      + 'appended the last one has not necessarily returned. A test helper is production code for '
      + 'the purposes of concurrency.' },
  { via: 'RECORDED VECTORS', title: 'A vector that made the gate look like it permitted a stolen card',
    body: 'One conformance vector used error_code "card_stolen", which is not in the taxonomy, so '
      + 'it fell through to a generic retry and read as the gate permitting a retry on a stolen '
      + 'card. The real code is card_lost_or_stolen. An unrecognised code is deliberately not '
      + 'treated as terminal, because inventing terminality for unknown strings is how a recovery '
      + 'system silently stops recovering, so the gate was right and the fixture was wrong. It was '
      + 'legible only because the expected answers are recorded from a real run rather than '
      + 'asserted by hand.' },
  { via: 'OPEN, NOT FIXED', open: true, title: 'The reconciler amplifies during an outage',
    body: 'A parked outbox row is not PENDING, so the reconciler treats its incident as stalled '
      + 'and inserts a replacement, which parks too. 20,434 rows from 400 incidents, all of it '
      + 'write amplification aimed at a queue that is already down. Two fixes were attempted and '
      + 'both reverted: one traded a loud failure for a silent one, the other stopped the run '
      + 'draining for reasons I did not fully characterise. A verification harness edited until '
      + 'it agrees with the system is not a harness, and a fix I cannot explain is not a fix. '
      + 'Reproduce it with: go run ./cmd/meshsim --seed 20260904 --incidents 400' },
];

function renderBroke() {
  const box = $('broke');
  box.textContent = '';
  DEFECTS.forEach((d, i) => {
    const det = document.createElement('details');
    if (d.open) det.className = 'open-issue';
    const sum = document.createElement('summary');
    sum.appendChild(el('span', 'idx', String(i + 1).padStart(2, '0')));
    sum.appendChild(el('span', 'ttl', d.title));
    sum.appendChild(el('span', 'via', d.via));
    det.appendChild(sum);
    const body = el('div', 'body');
    body.appendChild(el('p', null, d.body));
    det.appendChild(body);
    box.appendChild(det);
  });
}

/* ------------------------------------------------------------- ledger ---- */

let TAMPERED = null;

function renderEntries(entries) {
  $('chain-n').textContent = entries.length + ' entries';
  const q = ($('filter').value || '').trim().toLowerCase();
  const match = entries.filter((e) => !q
    || e.kind.toLowerCase().includes(q)
    || (e.incident_id || '').toLowerCase().includes(q)
    || String(e.seq) === q);
  const shown = match.slice(0, 200);
  $('shown').textContent = shown.length < match.length
    ? 'showing 200 of ' + match.length : match.length + ' shown';

  const body = $('entries');
  body.textContent = '';
  const f = document.createDocumentFragment();
  for (const e of shown) {
    const tr = row([
      { cls: 'num', text: e.seq },
      { cls: 'mono', text: e.kind },
      { cls: 'free', text: e.summary },
      { cls: 'mono', text: short(e.hash) },
    ]);
    if (TAMPERED && entries[TAMPERED.index] === e) tr.classList.add('hit');
    f.appendChild(tr);
  }
  body.appendChild(f);
}

function setState(node, kind, text, spinning) {
  node.className = 'vstate' + (kind ? ' ' + kind : '');
  node.textContent = '';
  if (spinning) node.appendChild(el('span', 'spin'));
  node.appendChild(el('span', null, text));
}

function wireVerify() {
  $('filter').addEventListener('input', () => renderEntries(RUN.chain.entries));
  $('v-run').addEventListener('click', runChainVerify);
  $('v-tamper').addEventListener('click', plantForgery);
  $('v-restore').addEventListener('click', restoreForgery);
  $('pk-run').addEventListener('click', runPackVerify);
  $('pk-forge').addEventListener('click', forgePack);
  $('pk-restore').addEventListener('click', restorePack);

  $('tamper-note').textContent =
    'When the demonstration ran this attack against the real database it edited entry '
    + RUN.tamper.target_seq + ' and verification localised the break to entry '
    + RUN.tamper.detected_seq + '. That is the exact row that was touched, not merely "the chain '
    + 'is invalid". The row it edits sits in the middle of the chain rather than at its head, '
    + 'because a ledger that only catches a modified head catches nothing: the head is what an '
    + 'attacker rewrites last.';
}

async function runChainVerify() {
  const btns = ['v-run', 'v-tamper', 'v-restore'].map($);
  btns.forEach((b) => (b.disabled = true));
  setState($('vstate'), '', 'Re-deriving ' + RUN.chain.entries.length + ' SHA-256 digests in this browser.', true);
  $('hashes').textContent = '';

  const t0 = performance.now();
  const r = await verifyChain(RUN.chain.entries, RUN.chain.genesis, (d, n) => {
    $('meter').style.width = ((d / n) * 100).toFixed(1) + '%';
  });
  const ms = Math.round(performance.now() - t0);
  $('meter').style.width = '100%';

  const h = $('hashes');
  h.textContent = '';
  if (r.valid) {
    setState($('vstate'), 'ok',
      'Chain verified. All ' + RUN.chain.entries.length + ' entries re-derived from the published '
      + 'bytes in ' + ms + ' ms.', false);
    h.appendChild(frag(el('b', null, 'head  '), document.createTextNode(r.head)));
    if (r.head === RUN.chain.head) {
      h.appendChild(el('br'));
      h.appendChild(el('b', null, 'matches the head the running system reported'));
    }
  } else {
    setState($('vstate'), 'bad',
      'Tamper detected at entry ' + r.seq + '. Cause: ' + r.cause
      + '. Every entry before it still verifies.', false);
    if (r.expected) {
      h.appendChild(frag(el('b', null, 'recorded    '), document.createTextNode(r.expected), el('br'),
                         el('b', null, 'recomputed  '), document.createTextNode(r.got)));
    }
  }
  btns.forEach((b) => (b.disabled = false));
  $('v-restore').disabled = !TAMPERED;
  renderEntries(RUN.chain.entries);
}

/** plantForgery edits one entry's detail bytes and leaves its recorded digest
 *  alone, which is exactly what an attacker with database access can do, and
 *  exactly what the demonstration does against PostgreSQL. */
function plantForgery() {
  const entries = RUN.chain.entries;
  if (!entries.length) return;
  if (TAMPERED) restoreForgery();
  const index = Math.floor(entries.length / 2);
  const e = entries[index];
  TAMPERED = { index, original: e._detail, seq: e.seq };
  e._detail = enc.encode(JSON.stringify({
    note: 'this row was edited in your browser, after the ledger hashed it',
    action: 'IN_SESSION_RAIL_MORPH',
  }));
  setState($('vstate'), 'wa',
    'Entry ' + e.seq + ' has been rewritten in memory. Its recorded digest was left untouched, '
    + 'exactly as an attacker with database access would leave it. Verify the chain again.', false);
  $('meter').style.width = '0%';
  $('hashes').textContent = '';
  $('v-restore').disabled = false;
  renderEntries(entries);
}

function restoreForgery() {
  if (!TAMPERED) return;
  RUN.chain.entries[TAMPERED.index]._detail = TAMPERED.original;
  const seq = TAMPERED.seq;
  TAMPERED = null;
  $('v-restore').disabled = true;
  setState($('vstate'), '', 'Entry ' + seq + ' restored. Verify again and the chain closes.', false);
  $('meter').style.width = '0%';
  $('hashes').textContent = '';
  renderEntries(RUN.chain.entries);
}

async function runPackVerify() {
  const pk = RUN.case && RUN.case.evidence;
  if (!pk) return;
  ['pk-run', 'pk-forge', 'pk-restore'].forEach((id) => ($(id).disabled = true));
  setState($('pk-state'), '', 'Checking ' + pk.entries.length + ' inclusion proofs against the Merkle root.', true);

  const t0 = performance.now();
  const results = [];
  for (const e of pk.entries) results.push(await verifyInclusion(e));
  const ms = Math.round(performance.now() - t0);

  const bad = results.findIndex((r) => !r.ok);
  if (bad === -1) {
    setState($('pk-state'), 'ok',
      'All ' + pk.entries.length + ' entries proved against the published root in ' + ms + ' ms, '
      + 'using ' + results[0].steps + ' sibling hashes each, without reading the other '
      + (pk.tree_size - pk.entries.length) + ' entries in the ledger.', false);
  } else {
    setState($('pk-state'), 'bad',
      'Entry ' + pk.entries[bad].seq + ' failed: ' + results[bad].why + '.', false);
  }
  renderPackRows(results);
  ['pk-run', 'pk-forge'].forEach((id) => ($(id).disabled = false));
  $('pk-restore').disabled = !PACK_FORGED;
}

/** forgePack inserts a record the ledger never committed to. The inclusion
 *  proof is what makes membership, rather than mere self-consistency, the thing
 *  being proved. */
function forgePack() {
  const pk = RUN.case.evidence;
  if (!pk || !pk.entries.length) return;
  if (PACK_FORGED) restorePack();
  const index = Math.min(1, pk.entries.length - 1);
  const e = pk.entries[index];
  PACK_FORGED = { index, original: e._detail, seq: e.seq };
  e._detail = enc.encode(JSON.stringify({
    note: 'a record inserted into the bundle after the ledger committed to it',
    action: 'ASYNC_EXPONENTIAL_RETRY', amount_paisa: 9999900,
  }));
  setState($('pk-state'), 'wa',
    'Entry ' + e.seq + ' in the bundle now says something the ledger never committed to. '
    + 'Verify again: the inclusion proof is what catches it.', false);
  $('pk-restore').disabled = false;
  renderPackRows();
}

function restorePack() {
  if (!PACK_FORGED) return;
  RUN.case.evidence.entries[PACK_FORGED.index]._detail = PACK_FORGED.original;
  PACK_FORGED = null;
  $('pk-restore').disabled = true;
  setState($('pk-state'), '', 'Bundle restored.', false);
  renderPackRows();
}

/* --------------------------------------------------------------- WASM ---- */

let WASM_READY = false;
let ATTACK = null;

const vectorById = (id) => (RUN.gate_vectors || []).find((v) => v.id === id);

function wireWasm() {
  if (!RUN.gate_vectors || !RUN.gate_vectors.length) {
    $('wasm-load').disabled = true;
    $('wasm-state').textContent = 'This run exported no gate vectors.';
    return;
  }
  /* The tab set is generated from the vectors, so a case added in Go appears
     here without this page being edited. */
  const tabs = $('atk-tabs');
  tabs.textContent = '';
  RUN.gate_vectors.forEach((v, i) => {
    const b = el('button', 'tab', v.hostile ? v.title.replace(/^The model /, '') : 'A legitimate one');
    b.type = 'button';
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', String(i === 0));
    b.dataset.atk = v.id;
    b.title = v.title;
    b.addEventListener('click', () => selectAttack(v.id));
    tabs.appendChild(b);
  });

  $('wasm-load').addEventListener('click', loadWasm);
  $('atk-run').addEventListener('click', runAttack);
  $('atk-reset').addEventListener('click', () => selectAttack(ATTACK));
  $('replay-run').addEventListener('click', runReplay);
  selectAttack(RUN.gate_vectors[0].id);
}

async function loadWasm() {
  const btn = $('wasm-load');
  btn.disabled = true;
  $('wasm-state').textContent = 'Fetching gatekeeper.wasm';
  try {
    if (typeof Go !== 'function') throw new Error('the Go WebAssembly loader is not present');
    const go = new Go();
    /* Streaming instantiation is the fast path and it is also the fragile one:
       it refuses anything not served as application/wasm, and the module is
       delivered here through a redirect to a CDN. Falling back to a buffered
       instantiate costs one extra copy and removes a whole class of "it works
       on my host" failure. */
    let mod;
    try {
      mod = await WebAssembly.instantiateStreaming(fetch(WASM_URL), go.importObject);
    } catch (_) {
      const bytes = await (await fetch(WASM_URL)).arrayBuffer();
      mod = await WebAssembly.instantiate(bytes, go.importObject);
    }
    go.run(mod.instance);
    /* go.run resolves only when the module exits, and ours parks forever, so the
       export is read on the next microtask rather than awaited. */
    await new Promise((r) => setTimeout(r, 0));
    if (typeof window.resilientMeshDecide !== 'function') {
      throw new Error('the module started but exported no decide function');
    }
    WASM_READY = true;
    $('wasm-ui').hidden = false;
    $('wasm-state').textContent = 'Loaded. Every decision below runs here, not on a server.';
    $('replay-run').disabled = false;
    setState($('replay-state'), '', 'Ready to re-derive ' + RUN.gate_vectors.length + ' recorded decisions.', false);
    btn.textContent = 'Gatekeeper loaded';
  } catch (err) {
    btn.disabled = false;
    $('wasm-state').textContent = 'Could not load: ' + err.message;
  }
}

function selectAttack(id) {
  ATTACK = id;
  for (const b of $('atk-tabs').children) b.setAttribute('aria-selected', String(b.dataset.atk === id));
  const v = vectorById(id);
  if (!v) return;
  $('atk-story').textContent = v.story;
  $('atk-input').value = JSON.stringify(v.request, null, 2);
  setState($('atk-verdict'), '', 'Nothing sent yet.', false);
  $('atk-out').textContent = '';
  $('atk-why').textContent = '';
}

function runAttack() {
  if (!WASM_READY) return;
  let parsed;
  try { parsed = JSON.parse($('atk-input').value); } catch (err) {
    setState($('atk-verdict'), 'bad', 'That is not valid JSON: ' + err.message, false);
    return;
  }
  const out = JSON.parse(window.resilientMeshDecide(JSON.stringify(parsed)));
  const asked = parsed.proposal || {};
  const body = $('atk-out');
  body.textContent = '';

  if (out.error) {
    setState($('atk-verdict'), 'bad', 'The gate refused to decide: ' + out.error, false);
    $('atk-why').textContent =
      'An error here is a refusal, not a crash. The gate returns no command at all rather than a '
      + 'partially valid one, because a half-formed command is exactly what an executor would act on.';
    return;
  }

  const changed = asked.recommended_action && asked.recommended_action !== out.action;
  setState($('atk-verdict'), out.executable ? (changed ? 'wa' : 'ok') : 'wa',
    out.executable
      ? (changed ? 'Permitted, but not what was asked for. The gate emitted ' + out.action + '.'
                 : 'Permitted: ' + out.action
                   + (out.target_rail && out.target_rail !== 'none' ? ' on ' + out.target_rail : ''))
      : 'Refused. The gate emitted ' + out.action + ', which spends nothing.',
    false);

  const rows = [
    ['Action asked for', asked.recommended_action || 'none', out.action],
    ['Rail asked for', asked.target_rail || 'none', out.target_rail || 'none'],
    ['Amount asked for',
      asked.amount_paisa != null ? formatPaisa(asked.amount_paisa) : 'the type has no such field',
      formatPaisa(out.amount_paisa)],
    ['Confidence claimed', asked.confidence_score != null ? String(asked.confidence_score) : 'none', ''],
    ['Tier claimed', asked.mode || 'none', out.mode || 'stamped in-process'],
    ['Delay asked for', asked.delay_seconds != null ? asked.delay_seconds + 's' : 'none', out.delay_seconds + 's'],
  ];
  /* Asked and got share one cell. Three columns of monospace overflowed the
     card on a laptop, and a table that shears is worse than a denser one. */
  for (const [k, a, b] of rows) {
    const differs = b && String(a) !== String(b);
    const cell = el('div', 'cmp');
    cell.appendChild(el('span', 'mono was' + (differs ? ' struck' : ''), a));
    if (b) {
      cell.appendChild(el('span', 'arrow', '→'));
      cell.appendChild(differs ? pill(b, 'ok') : el('span', 'mono', b));
    }
    body.appendChild(row([{ cls: 'dim', text: k }, { node: cell }]));
  }
  body.appendChild(row([
    { cls: 'dim', text: 'Invariants applied' },
    { cls: 'free', text: (out.applied_invariants || []).join('   ') || 'none' },
  ]));

  $('atk-why').textContent = out.reason
    ? out.reason.split('\n').filter((l) => /^\s+\d+\./.test(l)).join('  ').slice(0, 420)
      || out.reason.split('\n')[1] || ''
    : '';
}

function formatPaisa(p) {
  if (p == null) return 'none';
  const neg = p < 0;
  const abs = Math.abs(p);
  let s = String(Math.trunc(abs / 100));
  const paise = String(abs % 100).padStart(2, '0');
  /* Indian grouping: the last three digits, then pairs. */
  if (s.length > 3) {
    const tail = s.slice(-3);
    let head = s.slice(0, -3);
    const parts = [];
    while (head.length > 2) { parts.unshift(head.slice(-2)); head = head.slice(0, -2); }
    if (head) parts.unshift(head);
    s = parts.join(',') + ',' + tail;
  }
  return (neg ? '-' : '') + '₹' + s + '.' + paise;
}

/** runReplay re-derives every recorded decision through the browser module and
 *  compares it, field by field, with what the server build produced. This is
 *  what makes the playground above trustworthy: it shows two builds of one
 *  package agreeing, rather than asserting that they do. */
async function runReplay() {
  if (!WASM_READY) return;
  $('replay-run').disabled = true;
  setState($('replay-state'), '', 'Re-deriving ' + RUN.gate_vectors.length + ' decisions.', true);

  const mismatches = [];
  const t0 = performance.now();
  for (const v of RUN.gate_vectors) {
    const got = JSON.parse(window.resilientMeshDecide(JSON.stringify(v.request)));
    const want = v.expected;
    for (const k of ['action', 'target_rail', 'amount_paisa', 'delay_seconds', 'executable', 'error']) {
      if (JSON.stringify(got[k]) !== JSON.stringify(want[k])) mismatches.push(v.id + ' differs on ' + k);
    }
    if ((got.applied_invariants || []).join(',') !== (want.applied_invariants || []).join(',')) {
      mismatches.push(v.id + ' differs on applied_invariants');
    }
    await new Promise((r) => setTimeout(r, 0));
  }
  const ms = Math.round(performance.now() - t0);

  if (!mismatches.length) {
    setState($('replay-state'), 'ok',
      'All ' + RUN.gate_vectors.length + ' decisions re-derived identically in ' + ms + ' ms. The '
      + 'module in your browser and the binary that produced this run agree on every field, '
      + 'including which invariants fired and in what order.', false);
  } else {
    setState($('replay-state'), 'bad', mismatches.length + ' mismatch: ' + mismatches.slice(0, 3).join('; '), false);
  }
  $('replay-run').disabled = false;
}

/* --------------------------------------------------------------- tabs ---- */

function wireTabs() {
  bindTabs('v-tabs', 'v', { chain: 'v-chain', pack: 'v-pack', case: 'v-case' });
  bindTabs('e-tabs', 'e', { arch: 'e-arch', trust: 'e-trust', ai: 'e-ai', broke: 'e-broke', run: 'e-run' });
}

function bindTabs(tabsId, key, panels) {
  const tabs = $(tabsId);
  if (!tabs) return;
  const buttons = $$('.tab', tabs);
  const show = (which) => {
    for (const b of buttons) b.setAttribute('aria-selected', String(b.dataset[key] === which));
    for (const [k, id] of Object.entries(panels)) {
      const p = $(id);
      if (p) p.hidden = k !== which;
    }
  };
  buttons.forEach((b) => b.addEventListener('click', () => show(b.dataset[key])));
  /* Arrow keys move between tabs, which is what role="tablist" promises a
     screen reader and what a keyboard user tries first. */
  tabs.addEventListener('keydown', (ev) => {
    const i = buttons.indexOf(document.activeElement);
    if (i < 0) return;
    let next = null;
    if (ev.key === 'ArrowRight') next = buttons[(i + 1) % buttons.length];
    if (ev.key === 'ArrowLeft') next = buttons[(i - 1 + buttons.length) % buttons.length];
    if (!next) return;
    ev.preventDefault();
    next.focus();
    next.click();
  });
}

/* -------------------------------------------------------------- chrome --- */

function wireChrome() {
  /* Reading progress, driven by scroll position so it moves continuously
     rather than jumping between sections. */
  const bar = $('progress');
  const onScroll = () => {
    const h = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.transform = 'scaleX(' + (h > 0 ? Math.min(1, window.scrollY / h) : 0) + ')';
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  /* The nav reports where you are rather than only offering somewhere to go. */
  const targets = $$('#navlinks .navlink')
    .map((a) => ({ a, el: document.querySelector(a.getAttribute('href')) }))
    .filter((t) => t.el);
  if (targets.length && 'IntersectionObserver' in window) {
    const seen = new Map();
    const io = new IntersectionObserver((recs) => {
      for (const r of recs) seen.set(r.target, r.intersectionRatio);
      let best = null, ratio = 0;
      for (const t of targets) {
        const v = seen.get(t.el) || 0;
        if (v > ratio) { best = t; ratio = v; }
      }
      for (const t of targets) t.a.setAttribute('aria-current', String(best !== null && t === best));
    }, { rootMargin: '-70px 0px -55% 0px', threshold: [0, .1, .25, .5, .75, 1] });
    targets.forEach((t) => io.observe(t.el));
  }

  /* Reveal on scroll. Elements opt in through markup rather than a broad
     selector here, so a failed observer can never leave content invisible. */
  const rise = $$('.rise');
  if (REDUCED || !('IntersectionObserver' in window)) {
    rise.forEach((n) => n.classList.add('in'));
  } else {
    const io = new IntersectionObserver((recs, obs) => {
      recs.forEach((r, i) => {
        if (!r.isIntersecting) return;
        setTimeout(() => r.target.classList.add('in'), Math.min(i, 6) * 45);
        obs.unobserve(r.target);
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: .08 });
    rise.forEach((n) => io.observe(n));
  }
}

boot();
