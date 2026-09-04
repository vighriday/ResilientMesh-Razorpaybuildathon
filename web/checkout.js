// Checkout client.
//
// The point of this page is to make in-session healing visible: when the bank
// behind the selected rail degrades, the session is moved to a working rail
// without the customer losing the checkout. Everything here is driven by the
// SSE stream; the page never polls and never decides anything itself.

(function () {
  "use strict";

  var RAILS = [
    { id: "netbanking", label: "Netbanking", field: "Choose your bank", placeholder: "HDFC Bank", hint: "You'll finish payment on your bank's page." },
    { id: "upi_intent", label: "UPI", field: "Your UPI ID", placeholder: "name@okhdfcbank", hint: "We'll send a request to your UPI app. Approve it to finish." },
    { id: "card", label: "Card", field: "Card number", placeholder: "4111 1111 1111 1111", hint: "Your bank may ask you to confirm with an OTP." }
  ];

  var el = {
    amount: document.getElementById("amount"),
    orderRef: document.getElementById("order-ref"),
    notice: document.getElementById("notice"),
    rails: document.getElementById("rails"),
    form: document.getElementById("form"),
    label: document.getElementById("instrument-label"),
    input: document.getElementById("instrument"),
    hint: document.getElementById("hint"),
    pay: document.getElementById("pay"),
    status: document.getElementById("status"),
    linkState: document.getElementById("link-state"),
    seq: document.getElementById("seq")
  };

  var session = null;
  var stream = null;
  var currentRail = null;
  var failedRails = Object.create(null);

  // Money is formatted from integer paisa. The page never does arithmetic on
  // it beyond splitting rupees from paise, because the amount it displays must
  // be exactly the amount the server pinned from the signed payload.
  function formatPaisa(paisa) {
    var neg = paisa < 0;
    var abs = Math.abs(paisa);
    var rupees = Math.floor(abs / 100);
    var paise = abs % 100;
    var s = String(rupees);
    // Indian digit grouping: last three, then pairs.
    var head = s.length > 3 ? s.slice(0, s.length - 3) : "";
    var tail = s.slice(-3);
    if (head) {
      head = head.replace(/\B(?=(\d{2})+(?!\d))/g, ",");
      s = head + "," + tail;
    }
    return (neg ? "-" : "") + "₹ " + s + "." + (paise < 10 ? "0" : "") + paise;
  }

  function railMeta(id) {
    for (var i = 0; i < RAILS.length; i++) {
      if (RAILS[i].id === id) return RAILS[i];
    }
    return { id: id, label: id, field: "Payment details", placeholder: "", hint: "" };
  }

  function renderRails() {
    el.rails.textContent = "";
    RAILS.forEach(function (rail) {
      var wrap = document.createElement("span");
      wrap.className = "rail";
      if (rail.id === currentRail) {
        wrap.setAttribute("data-state", "active");
      } else if (failedRails[rail.id]) {
        wrap.setAttribute("data-state", "failed");
      } else {
        wrap.setAttribute("data-state", "idle");
      }
      var lamp = document.createElement("span");
      lamp.className = "lamp";
      var text = document.createElement("span");
      text.textContent = rail.label;
      wrap.appendChild(lamp);
      wrap.appendChild(text);
      el.rails.appendChild(wrap);
    });
  }

  function renderForm() {
    var meta = railMeta(currentRail);
    el.label.textContent = meta.field;
    el.input.placeholder = meta.placeholder;
    el.input.value = "";
    el.hint.textContent = meta.hint;
    el.pay.textContent = session ? "Pay " + formatPaisa(session.amount_paisa) : "Pay";
  }

  function showNotice(fromRail, toRail) {
    var from = railMeta(fromRail).label;
    var to = railMeta(toRail).label;
    el.notice.textContent = "";
    var strong = document.createElement("strong");
    strong.textContent = from + " isn't responding right now.";
    el.notice.appendChild(strong);
    el.notice.appendChild(document.createTextNode(
      " We've moved you to " + to + " so you can finish paying. The amount hasn't changed."
    ));
    el.notice.classList.add("shown");
  }

  // The switch throw: the only animation on the page, and it exists to show a
  // change the customer would otherwise have to notice on their own.
  function morph(fromRail, toRail) {
    failedRails[fromRail] = true;
    currentRail = toRail;
    showNotice(fromRail, toRail);
    renderRails();
    el.form.classList.remove("switching");
    void el.form.offsetWidth; // restart the animation
    el.form.classList.add("switching");
    window.setTimeout(renderForm, 260);
  }

  function setLink(state, text) {
    el.status.classList.toggle("disconnected", state !== "live");
    el.linkState.textContent = text;
  }

  function connect() {
    // EventSource cannot set headers, so the single-purpose session token is
    // passed as a query parameter. It is short-lived and stored only as a hash.
    var url = "/api/v1/session/stream/" + encodeURIComponent(session.session_id) +
      "?token=" + encodeURIComponent(session.token);
    stream = new EventSource(url);

    stream.onopen = function () { setLink("live", "Connected"); };

    stream.onerror = function () {
      // EventSource reconnects on its own; report honestly while it does.
      setLink("down", "Reconnecting");
    };

    stream.onmessage = function (ev) {
      var msg;
      try {
        msg = JSON.parse(ev.data);
      } catch (err) {
        return;
      }
      if (typeof msg.sequence === "number") {
        el.seq.textContent = "#" + msg.sequence;
      }
      switch (msg.type) {
        case "rail_morph":
          morph(msg.from_rail, msg.to_rail);
          break;
        case "status":
          if (msg.reason) { setLink("live", msg.reason); }
          break;
        case "closed":
          setLink("down", "Session closed");
          stream.close();
          break;
        default:
          break;
      }
    };
  }

  function fail(message) {
    setLink("down", message);
    el.pay.disabled = true;
  }

  function start() {
    var body = JSON.stringify({ amount_paisa: 499900, currency: "INR", rail: "netbanking" });
    fetch("/api/v1/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body
    }).then(function (res) {
      if (!res.ok) { throw new Error("session " + res.status); }
      return res.json();
    }).then(function (data) {
      session = data;
      currentRail = data.current_rail;
      el.amount.textContent = formatPaisa(data.amount_paisa);
      el.orderRef.textContent = data.order_id;
      document.title = "Pay " + formatPaisa(data.amount_paisa) + " — Anantara Textiles";
      renderRails();
      renderForm();
      connect();
    }).catch(function () {
      fail("Checkout unavailable");
    });
  }

  el.pay.addEventListener("click", function () {
    el.pay.disabled = true;
    el.pay.textContent = "Waiting for your bank";
  });

  window.addEventListener("beforeunload", function () {
    if (stream) { stream.close(); }
  });

  start();
})();
