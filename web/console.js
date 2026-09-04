// Operations console.
//
// Read-only view of the running system. The one action it offers is verifying
// the audit chain, which is the point: an audit trail nobody can check is not
// evidence. The token is held in sessionStorage only, so closing the tab
// forgets it and it never lands in a persistent store.

(function () {
  "use strict";

  var POLL_MS = 2000;
  var TOKEN_KEY = "mesh.ops.token";

  var el = {
    auth: document.getElementById("auth"),
    main: document.getElementById("main"),
    tokenInput: document.getElementById("token-input"),
    tokenSave: document.getElementById("token-save"),
    incidents: document.getElementById("stat-incidents"),
    recovered: document.getElementById("stat-recovered"),
    outbox: document.getElementById("stat-outbox"),
    lag: document.getElementById("stat-lag"),
    dlq: document.getElementById("stat-dlq"),
    sessions: document.getElementById("stat-sessions"),
    link: document.getElementById("stat-link"),
    telemetryBody: document.getElementById("telemetry-body"),
    incidentBody: document.getElementById("incident-body"),
    auditBody: document.getElementById("audit-body"),
    tiers: document.getElementById("tiers"),
    verify: document.getElementById("verify"),
    verdict: document.getElementById("verdict")
  };

  var token = "";
  var timer = null;

  function formatPaisa(paisa) {
    var abs = Math.abs(paisa || 0);
    var rupees = Math.floor(abs / 100);
    var paise = abs % 100;
    var s = String(rupees);
    var head = s.length > 3 ? s.slice(0, s.length - 3) : "";
    var tail = s.slice(-3);
    if (head) {
      s = head.replace(/\B(?=(\d{2})+(?!\d))/g, ",") + "," + tail;
    }
    return "₹" + s + "." + (paise < 10 ? "0" : "") + paise;
  }

  function pct(v) {
    if (typeof v !== "number" || isNaN(v)) { return "—"; }
    return (v * 100).toFixed(1) + "%";
  }

  function api(path) {
    return fetch(path, { headers: { Authorization: "Bearer " + token } })
      .then(function (res) {
        if (res.status === 401 || res.status === 403) {
          throw new Error("unauthorised");
        }
        if (!res.ok) { throw new Error(path + " " + res.status); }
        return res.json();
      });
  }

  // Every cell is written with textContent. Incident fields originate from
  // upstream systems and are untrusted, so nothing here goes near innerHTML.
  function cell(row, text, className) {
    var td = document.createElement("td");
    td.textContent = text === undefined || text === null || text === "" ? "—" : String(text);
    if (className) { td.className = className; }
    row.appendChild(td);
    return td;
  }

  function emptyRow(body, cols, message) {
    body.textContent = "";
    var tr = document.createElement("tr");
    var td = document.createElement("td");
    td.colSpan = cols;
    td.className = "empty";
    td.textContent = message;
    tr.appendChild(td);
    body.appendChild(tr);
  }

  function renderTelemetry(rows) {
    if (!rows || !rows.length) {
      emptyRow(el.telemetryBody, 4, "No traffic yet.");
      return;
    }
    el.telemetryBody.textContent = "";
    rows.forEach(function (t) {
      var tr = document.createElement("tr");
      cell(tr, t.issuer_key);
      cell(tr, pct(t.success_rate), "num");
      cell(tr, t.attempts, "num");

      var td = document.createElement("td");
      var state = t.breaker_state || "CLOSED";
      var wrap = document.createElement("span");
      wrap.className = "lamp-row state-" + state;
      var lamp = document.createElement("span");
      lamp.className = "lamp";
      var label = document.createElement("span");
      label.textContent = state === "HALF_OPEN" ? "Half open" : state === "OPEN" ? "Open" : "Closed";
      wrap.appendChild(lamp);
      wrap.appendChild(label);
      td.appendChild(wrap);
      tr.appendChild(td);

      el.telemetryBody.appendChild(tr);
    });
  }

  function renderIncidents(rows) {
    if (!rows || !rows.length) {
      emptyRow(el.incidentBody, 6, "No incidents yet. Start the outage script to generate traffic.");
      return;
    }
    el.incidentBody.textContent = "";
    rows.forEach(function (i) {
      var tr = document.createElement("tr");
      cell(tr, i.payment_id, "num");
      cell(tr, i.issuer_key);
      cell(tr, i.error_code);
      cell(tr, formatPaisa(i.amount_paisa), "num");
      cell(tr, i.state);

      var td = document.createElement("td");
      if (i.inference_mode) {
        var badge = document.createElement("span");
        badge.className = "tier tier-" + i.inference_mode;
        badge.textContent = i.inference_mode;
        td.appendChild(badge);
      } else {
        td.textContent = "—";
      }
      tr.appendChild(td);

      el.incidentBody.appendChild(tr);
    });
  }

  function renderAudit(rows) {
    if (!rows || !rows.length) {
      emptyRow(el.auditBody, 5, "Chain is empty.");
      return;
    }
    el.auditBody.textContent = "";
    rows.forEach(function (a) {
      var tr = document.createElement("tr");
      cell(tr, a.seq, "num");
      cell(tr, a.kind);
      cell(tr, a.incident_id, "num");
      cell(tr, a.actor);
      cell(tr, (a.hash || "").slice(0, 16), "num hash");
      el.auditBody.appendChild(tr);
    });
  }

  function renderTiers(dist) {
    el.tiers.textContent = "";
    var order = ["LIVE", "REPLAY", "HEURISTIC", "SKIPPED"];
    var any = false;
    order.forEach(function (k) {
      var n = dist && dist[k];
      if (!n) { return; }
      any = true;
      var row = document.createElement("div");
      row.className = "kv";
      var name = document.createElement("span");
      var badge = document.createElement("span");
      badge.className = "tier tier-" + k;
      badge.textContent = k;
      name.appendChild(badge);
      var val = document.createElement("b");
      val.className = "num";
      val.textContent = n;
      row.appendChild(name);
      row.appendChild(val);
      el.tiers.appendChild(row);
    });
    if (!any) {
      var p = document.createElement("p");
      p.className = "empty";
      p.textContent = "No diagnoses yet.";
      el.tiers.appendChild(p);
    }
  }

  function setStat(node, value) {
    node.textContent = value === undefined || value === null ? "—" : String(value);
  }

  function refresh() {
    Promise.all([
      api("/api/v1/ops/metrics"),
      api("/api/v1/ops/telemetry"),
      api("/api/v1/ops/incidents?limit=40"),
      api("/api/v1/ops/audit?limit=40")
    ]).then(function (out) {
      var m = out[0] || {};
      setStat(el.incidents, m.incidents_total);
      setStat(el.recovered, m.incidents_recovered);
      setStat(el.outbox, m.outbox_pending);
      setStat(el.lag, m.queue_lag);
      setStat(el.dlq, m.dead_letters);
      setStat(el.sessions, m.sessions_live);
      renderTiers(m.inference_tiers);
      renderTelemetry(out[1] && out[1].items);
      renderIncidents(out[2] && out[2].items);
      renderAudit(out[3] && out[3].items);
      el.link.textContent = "Live";
    }).catch(function (err) {
      if (err && err.message === "unauthorised") {
        stop();
        showAuth("That token was rejected. Check the value printed at startup.");
        return;
      }
      el.link.textContent = "Reconnecting";
    });
  }

  function start() {
    el.auth.hidden = true;
    el.main.hidden = false;
    refresh();
    timer = window.setInterval(refresh, POLL_MS);
  }

  function stop() {
    if (timer) { window.clearInterval(timer); timer = null; }
    el.main.hidden = true;
  }

  function showAuth(message) {
    el.auth.hidden = false;
    if (message) {
      var p = el.auth.querySelector(".empty");
      if (p) { p.textContent = message; }
    }
    el.tokenInput.focus();
  }

  el.tokenSave.addEventListener("click", function () {
    var v = el.tokenInput.value.trim();
    if (!v) { return; }
    token = v;
    window.sessionStorage.setItem(TOKEN_KEY, v);
    el.tokenInput.value = "";
    start();
  });

  el.tokenInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { el.tokenSave.click(); }
  });

  el.verify.addEventListener("click", function () {
    el.verify.disabled = true;
    el.verdict.className = "verdict";
    api("/api/v1/ops/audit/verify").then(function (r) {
      el.verdict.className = "verdict shown " + (r.valid ? "ok" : "bad");
      if (r.valid) {
        el.verdict.textContent = "Chain intact. " + r.entries +
          " entries verified, head " + String(r.head_hash || "").slice(0, 16) + ".";
      } else {
        el.verdict.textContent = "Chain broken at entry " + r.break_at_seq +
          ": " + r.break_cause + ". Everything after this point is untrustworthy.";
      }
    }).catch(function () {
      el.verdict.className = "verdict shown bad";
      el.verdict.textContent = "Verification could not run. The operations API did not respond.";
    }).then(function () {
      el.verify.disabled = false;
    });
  });

  var saved = window.sessionStorage.getItem(TOKEN_KEY);
  var fromQuery = new URLSearchParams(window.location.search).get("token");
  if (fromQuery) {
    token = fromQuery;
    window.sessionStorage.setItem(TOKEN_KEY, fromQuery);
    // Remove the token from the address bar so it does not linger in history.
    window.history.replaceState({}, "", window.location.pathname);
    start();
  } else if (saved) {
    token = saved;
    start();
  } else {
    showAuth();
  }
})();
