let stripe = null;
let elements = null;
let card = null;
let lastPendingSetupIntentId = null;

const API_BASE_DEFAULT = window.API_BASE || window.location.origin;
let API_BASE = localStorage.getItem("api_base") || API_BASE_DEFAULT;

function accessToken() { return localStorage.getItem("access_token"); }
function sessionId() { return localStorage.getItem("session_id"); }

function setStatus(msg) {
  const el = document.getElementById("status");
  if (el) el.textContent = msg || "";
}

function fmtMoney(cents, currency = "usd") {
  const sign = cents < 0 ? "-" : "";
  const v = Math.abs(cents) / 100.0;
  return sign + v.toFixed(2) + " " + currency.toUpperCase();
}

function checkAuth() {
  if (!accessToken()) {
    throw new Error("Missing access_token. Open the Control Panel to set tokens.");
  }
  if (!sessionId()) {
    throw new Error("Missing session_id. Open the Control Panel to establish a session.");
  }
}

async function api(path, opts = {}) {
  checkAuth();
  const headers = Object.assign({}, opts.headers || {}, {
    "Authorization": "Bearer " + accessToken(),
    "X-SESSION-ID": sessionId(),
  });
  if (opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(API_BASE + path, Object.assign({}, opts, { headers }));
  const txt = await res.text();
  if (!res.ok) throw new Error(txt || res.statusText);
  return txt ? JSON.parse(txt) : null;
}

async function initStripe() {
  const cfg = await api("/api/billing/config");
  stripe = Stripe(cfg.publishable_key);
  elements = stripe.elements();
  card = elements.create("card");
  card.mount("#card-element");
}

async function refreshAll() {
  try {
    setStatus("Refreshing...");
    if (!stripe) await initStripe();
    await Promise.all([loadBalance(), loadPaymentMethods(), loadSettings(), loadLedger()]);
    setStatus("Ready.");
  } catch (e) {
    setStatus("Error: " + e.message);
  }
}

function showPane(name) {
  document.querySelectorAll(".pane").forEach(p => p.classList.add("hidden"));
  const el = document.getElementById("pane_" + name);
  if (el) el.classList.remove("hidden");
  if (name === "list_methods") loadPaymentMethods();
}

async function loadSettings() {
  const res = await api("/api/billing/settings");
  const chk = document.getElementById("autopay");
  if (chk) chk.checked = !!res.autopay_enabled;
}

async function loadBalance() {
  const b = await api("/api/billing/balance");
  const currency = b.currency || "usd";
  document.getElementById("due_settled").innerText = fmtMoney(b.due_settled_cents || 0, currency);
  document.getElementById("due_all").innerText = fmtMoney(b.due_if_all_settles_cents || 0, currency);
  document.getElementById("owed_pending").innerText = fmtMoney(b.owed_pending_cents || 0, currency);
  document.getElementById("owed_settled").innerText = fmtMoney(b.owed_settled_cents || 0, currency);
  document.getElementById("pay_pending").innerText = fmtMoney(b.payments_pending_cents || 0, currency);
  document.getElementById("pay_settled").innerText = fmtMoney(b.payments_settled_cents || 0, currency);
}

async function loadPaymentMethods() {
  const wrap = document.getElementById("methods");
  wrap.innerHTML = "";
  const list = await api("/api/billing/payment-methods");
  if (!list || list.length === 0) {
    wrap.innerHTML = "<div class=\"muted\">No payment methods yet.</div>";
    return;
  }

  list.forEach(pm => {
    const div = document.createElement("div");
    div.className = "item";
    div.innerHTML = `
      <div class="row">
        <div class="mono">${pm.label || pm.payment_method_id}</div>
        <div class="muted">(${pm.method_type})</div>
        <div class="right">
          <button onclick="setDefault('${pm.payment_method_id}')">Set default</button>
          <button class="danger" onclick="removePM('${pm.payment_method_id}')">Remove</button>
        </div>
      </div>
      <div class="row">
        <div class="muted">Priority:</div>
        <input id="prio_${pm.payment_method_id}" value="${pm.priority}" style="width:90px"/>
        <button onclick="updatePriority('${pm.payment_method_id}')">Save priority</button>
        <span id="pm_msg_${pm.payment_method_id}" class="muted"></span>
      </div>
    `;
    wrap.appendChild(div);
  });
}

async function updatePriority(pm) {
  try {
    const val = parseInt(document.getElementById("prio_" + pm).value, 10);
    await api("/api/billing/payment-methods/priority", {
      method: "POST",
      body: JSON.stringify({ payment_method_id: pm, priority: val }),
    });
    document.getElementById("pm_msg_" + pm).innerText = "Priority saved";
  } catch (e) {
    document.getElementById("pm_msg_" + pm).innerText = "Error: " + e.message;
  }
}

async function setDefault(pm) {
  try {
    await api("/api/billing/payment-methods/default", { method: "POST", body: JSON.stringify({ payment_method_id: pm }) });
    document.getElementById("pm_msg_" + pm).innerText = "Default set";
  } catch (e) {
    document.getElementById("pm_msg_" + pm).innerText = "Error: " + e.message;
  }
}

async function removePM(pm) {
  try {
    await api("/api/billing/payment-methods/" + pm, { method: "DELETE" });
    await loadPaymentMethods();
  } catch (e) {
    alert("Remove failed: " + e.message);
  }
}

async function addCard() {
  document.getElementById("add_card_result").innerText = "";
  try {
    const si = await api("/api/billing/setup-intent/card", { method: "POST", body: "{}" });
    const res = await stripe.confirmCardSetup(si.client_secret, { payment_method: { card } });
    if (res.error) throw new Error(res.error.message);

    document.getElementById("add_card_result").innerText = "Saved. (Will appear after webhook)";
    setTimeout(refreshAll, 800);
  } catch (e) {
    document.getElementById("add_card_result").innerText = "Error: " + e.message;
  }
}

async function addBankAccount() {
  document.getElementById("add_bank_result").innerText = "";
  document.getElementById("bank_next").innerText = "";
  try {
    const name = document.getElementById("bank_name").value || "Customer";
    const email = document.getElementById("bank_email").value || undefined;

    const si = await api("/api/billing/setup-intent/us-bank", { method: "POST", body: "{}" });

    const collected = await stripe.collectBankAccountForSetup({
      clientSecret: si.client_secret,
      params: {
        payment_method_type: "us_bank_account",
        payment_method_data: {
          billing_details: { name, email },
        },
      },
    });
    if (collected.error) throw new Error(collected.error.message);

    const confirmed = await stripe.confirmUsBankAccountSetup(si.client_secret);
    if (confirmed.error) throw new Error(confirmed.error.message);

    const setupIntent = confirmed.setupIntent;
    document.getElementById("add_bank_result").innerText = "Submitted. Status: " + setupIntent.status;

    if (setupIntent.status === "requires_action" &&
        setupIntent.next_action &&
        setupIntent.next_action.type === "verify_with_microdeposits") {
      lastPendingSetupIntentId = setupIntent.id;
      document.getElementById("bank_next").innerHTML =
        "Microdeposits required. SetupIntent: <code>" + setupIntent.id + "</code>. " +
        "Go to “Verify microdeposits” tab after deposits arrive.";
      document.getElementById("verify_si").value = setupIntent.id;
      showPane("verify_bank");
    } else {
      document.getElementById("bank_next").innerText = "If it succeeded, it will appear after webhook.";
      setTimeout(refreshAll, 800);
    }
  } catch (e) {
    document.getElementById("add_bank_result").innerText = "Error: " + e.message;
  }
}

function usePendingSetupIntent() {
  if (lastPendingSetupIntentId) {
    document.getElementById("verify_si").value = lastPendingSetupIntentId;
  } else {
    alert("No pending SetupIntent stored in this browser session.");
  }
}

async function verifyByAmounts() {
  document.getElementById("verify_result").innerText = "";
  try {
    const setup_intent_id = document.getElementById("verify_si").value.trim();
    const a1 = parseInt(document.getElementById("amt1").value.trim(), 10);
    const a2 = parseInt(document.getElementById("amt2").value.trim(), 10);
    if (!setup_intent_id) throw new Error("Missing setup_intent_id");
    if (!Number.isFinite(a1) || !Number.isFinite(a2)) throw new Error("Enter both amounts (cents)");

    const res = await api("/api/billing/us-bank/verify-microdeposits", {
      method: "POST",
      body: JSON.stringify({ setup_intent_id, amounts: [a1, a2] }),
    });

    document.getElementById("verify_result").innerText = "Verify result: " + res.status + " (PM will appear after webhook if succeeded)";
    setTimeout(refreshAll, 800);
  } catch (e) {
    document.getElementById("verify_result").innerText = "Error: " + e.message;
  }
}

async function verifyByDescriptor() {
  document.getElementById("verify_result").innerText = "";
  try {
    const setup_intent_id = document.getElementById("verify_si").value.trim();
    const descriptor_code = document.getElementById("desc").value.trim();
    if (!setup_intent_id) throw new Error("Missing setup_intent_id");
    if (!descriptor_code) throw new Error("Missing descriptor code");

    const res = await api("/api/billing/us-bank/verify-microdeposits", {
      method: "POST",
      body: JSON.stringify({ setup_intent_id, descriptor_code }),
    });

    document.getElementById("verify_result").innerText = "Verify result: " + res.status + " (PM will appear after webhook if succeeded)";
    setTimeout(refreshAll, 800);
  } catch (e) {
    document.getElementById("verify_result").innerText = "Error: " + e.message;
  }
}

async function setAutopay() {
  try {
    const enabled = document.getElementById("autopay").checked;
    await api("/api/billing/autopay", { method: "POST", body: JSON.stringify({ enabled }) });
  } catch (e) {
    alert("Autopay update failed: " + e.message);
  }
}

async function paySettledBalance() {
  document.getElementById("pay_result").innerText = "";
  try {
    const amtTxt = document.getElementById("pay_amount").value.trim();
    const amount_cents = amtTxt ? parseInt(amtTxt, 10) : null;

    const payload = {};
    if (amount_cents) payload.amount_cents = amount_cents;

    const res = await api("/api/billing/pay-balance", { method: "POST", body: JSON.stringify(payload) });
    document.getElementById("pay_result").innerText = "PI status: " + res.status + " (" + (res.payment_intent_id || "") + ")";
    setTimeout(refreshAll, 800);
  } catch (e) {
    document.getElementById("pay_result").innerText = "Error: " + e.message;
  }
}

async function loadLedger() {
  const wrap = document.getElementById("ledger");
  wrap.innerHTML = "";
  try {
    const limitTxt = document.getElementById("ledger_limit").value.trim();
    const limit = limitTxt ? parseInt(limitTxt, 10) : 50;
    const res = await api("/api/billing/ledger?limit=" + encodeURIComponent(limit));
    const items = res.items || [];

    for (const it of items) {
      const div = document.createElement("div");
      div.className = "item";

      let pill = "<span class=\"pill\">" + (it.state || "") + "</span>";
      if (it.state === "settled") pill = "<span class=\"pill ok\">settled</span>";
      if (it.state === "pending") pill = "<span class=\"pill warn\">pending</span>";
      if (it.state === "reversed") pill = "<span class=\"pill bad\">reversed</span>";

      div.innerHTML = `
        <div class="row">
          ${pill}
          <div class="muted">${new Date((it.ts || 0) * 1000).toISOString()}</div>
          <div class="mono">${it.type}</div>
          <div class="mono">${it.reason || ""}</div>
          <div class="right mono">${it.amount_cents}</div>
        </div>
        <div class="muted mono w100">
          ${it.stripe_payment_intent_id ? ("pi=" + it.stripe_payment_intent_id + " ") : ""}
          ${it.stripe_charge_id ? ("ch=" + it.stripe_charge_id + " ") : ""}
          ${it.entry_id ? ("entry=" + it.entry_id) : ""}
        </div>
      `;
      wrap.appendChild(div);
    }

    if (items.length === 0) wrap.innerHTML = "<div class=\"muted\">No ledger entries yet.</div>";
  } catch (e) {
    wrap.innerHTML = "<div class=\"muted\">Error loading ledger: " + e.message + "</div>";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  showPane("list_methods");
  refreshAll();
});
