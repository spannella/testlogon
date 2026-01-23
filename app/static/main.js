// Optional WebSocket fanout (set window.WS_URL = "wss://.../prod")
const WS_URL = window.WS_URL || null;

let stripe = null;
let stripeElements = null;
let stripeCard = null;
let lastPendingSetupIntentId = null;

let toastSse = null;


let toastWs = null;

async function startToastWebSocket() {
  if (toastWs) return true;
  if (!WS_URL) return false;
  try {
    await ensureUiSession();
    const tok = await apiGet("/ui/ws_token");
    const url = WS_URL + (WS_URL.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(tok.token);
    toastWs = new WebSocket(url);

    toastWs.onmessage = async (ev) => {
      try {
        const msg = JSON.parse(ev.data || "{}");
        if (msg.type !== "alert") return;
        const a = msg.alert;
        if (!a) return;
        // Use same toast filtering + delivery mark
        const prefs = await loadEmailPrefs();
        const enabled = new Set(prefs.toast_event_types || []);
        if (enabled.size === 0) return;
        const aid = a.alert_id;
        if (!aid || a.toast_delivered || seenToasts.has(aid)) return;
        const t = (a.details && a.details.alert_type) ? a.details.alert_type : "";
        if (!enabled.has(t)) return;
        maybePrependAlertToHistory(a);
        seenToasts.add(aid);
        showToast(a.title || a.event || "Alert", `${t} • ${fmtTs(a.ts)}`);
        await apiPost("/ui/alerts/mark_toast_delivered", { alert_ids: [aid] });
      } catch (e) {}
    };

    toastWs.onclose = () => {
      toastWs = null;
      // retry after short delay
      setTimeout(() => { startToastSSE(); }, 2000);
    };
    return true;
  } catch (e) {
    toastWs = null;
    return false;
  }
}

async function startToastSSE() {
  // Prefer WebSocket fanout when configured; fallback to SSE.
  const ok = await startToastWebSocket();
  if (ok) return;
  if (toastSse) return;
  try {
    toastSse = new EventSource("/ui/alerts/stream");
    toastSse.addEventListener("hello", () => {});
    toastSse.addEventListener("ping", () => {});
    toastSse.addEventListener("alert", async (ev) => {
      try {
        const a = JSON.parse(ev.data || "{}");
        const prefs = await loadEmailPrefs(); // includes toast_event_types
        const enabled = new Set(prefs.toast_event_types || []);
        if (enabled.size === 0) return;

        const aid = a.alert_id;
        if (!aid) return;
        if (a.toast_delivered) return;
        if (seenToasts.has(aid)) return;

        const t = (a.details && a.details.alert_type) ? a.details.alert_type : "";
        if (!enabled.has(t)) return;

        maybePrependAlertToHistory(a);
        seenToasts.add(aid);
        showToast(a.title || a.event || "Alert", `${t} • ${fmtTs(a.ts)}`);
        await apiPost("/ui/alerts/mark_toast_delivered", { alert_ids: [aid] });
      } catch (e) {
        // ignore
      }
    });
    toastSse.onerror = () => {
      // auto-reconnect is handled by EventSource; if it hard fails, recreate
    };
  } catch (e) {
    // If SSE unsupported, keep existing behavior (manual refresh still works)
  }
}

function maybePrependAlertToHistory(a) {
  const el = document.getElementById("alertsList");
  if (!el) return;
  // Avoid duplicates by checking first few items
  const existing = el.querySelectorAll("button[data-aid]");
  for (let i=0; i<Math.min(existing.length, 10); i++) {
    if (existing[i].getAttribute("data-aid") === a.alert_id) return;
  }
  // Prepend to list for live update (optional)
  try {
    const row = renderAlertRow(a);
    el.insertBefore(row, el.firstChild);
  } catch(e) {}
}
/* ===================== CONFIG ===================== */
const API_BASE_DEFAULT = (window.API_BASE || window.location.origin);
let API_BASE = lsGet("api_base") || API_BASE_DEFAULT;

/* ===================== localStorage helpers ===================== */
function lsGet(k){ try{return localStorage.getItem(k);}catch(e){return null;} }
function lsSet(k,v){ try{localStorage.setItem(k,v);}catch(e){} }
function lsDel(k){ try{localStorage.removeItem(k);}catch(e){} }

function accessToken(){ return lsGet("access_token"); }
function sessionId(){ return lsGet("session_id"); }

/* ===================== modal helpers ===================== */
let _modalEl = null;
function modalClose() {
  if (_modalEl) { _modalEl.remove(); _modalEl = null; }
}
function modalShow({title, bodyHtml, actions}) {
  modalClose();
  const back = document.createElement("div");
  back.className = "modal-backdrop";
  back.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true">
      <h2>${title}</h2>
      <div class="modal-body">${bodyHtml || ""}</div>
      <div class="modal-actions"></div>
    </div>
  `;
  const actionsEl = back.querySelector(".modal-actions");
  (actions || []).forEach(a => {
    const b = document.createElement("button");
    b.textContent = a.text;
    b.onclick = a.onClick;
    actionsEl.appendChild(b);
  });
  back.onclick = (e) => { if (e.target === back) modalClose(); };
  document.body.appendChild(back);
  _modalEl = back;
}


/* ===================== token / api base modal ===================== */
function openTokenModal() {
  const curBase = lsGet("api_base") || API_BASE_DEFAULT;
  modalShow({
    title: "Connection + Tokens",
    bodyHtml: `
      <div class="muted">Paste your Cognito <b>access token</b> (JWT). Stored in localStorage.</div>
      <input id="cfgApiBase" class="mono" placeholder="API base URL" value="${curBase}"/>
      <input id="cfgAccessTok" class="mono" placeholder="access_token (Bearer)" value="${lsGet("access_token")||""}"/>
      <div class="muted" style="margin-top:8px;">Optional: id_token / refresh_token (not used by this page)</div>
      <input id="cfgIdTok" class="mono" placeholder="id_token" value="${lsGet("id_token")||""}"/>
      <input id="cfgRefreshTok" class="mono" placeholder="refresh_token" value="${lsGet("refresh_token")||""}"/>
      <div id="cfgErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Save", onClick: async () => {
          const base = document.getElementById("cfgApiBase").value.trim();
          const at = document.getElementById("cfgAccessTok").value.trim();
          if (!base) { document.getElementById("cfgErr").textContent = "API base is required."; return; }
          if (!at) { document.getElementById("cfgErr").textContent = "access_token is required."; return; }
          lsSet("api_base", base);
          API_BASE = base;
          lsSet("access_token", at);
          lsSet("id_token", document.getElementById("cfgIdTok").value.trim());
          lsSet("refresh_token", document.getElementById("cfgRefreshTok").value.trim());
          lsDel("session_id"); // force re-stepup
          modalClose();
          if (!accessToken()) {
            openTokenModal();
          } else {
            await refreshAll();
          }
      }},
    ]
  });
}

/* ===================== generic API helper ===================== */
async function api(path, {method="GET", body=null, includeSession=true}={}) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const headers = { "Authorization": "Bearer " + tok };
  if (includeSession) {
    const sid = sessionId();
    if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
    headers["X-SESSION-ID"] = sid;
  }
  if (body !== null) headers["Content-Type"] = "application/json";

  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: (body !== null ? JSON.stringify(body) : undefined),
  });
  const txt = await res.text();
  if (!res.ok) throw new Error(res.status + ": " + txt);
  return txt ? JSON.parse(txt) : {};
}

function apiGet(path, { includeSession = true } = {}) {
  return api(path, { method: "GET", includeSession });
}

function apiPost(path, body, { includeSession = true } = {}) {
  return api(path, { method: "POST", body, includeSession });
}

function parseHttpError(errStr){
  const m = String(errStr).match(/^(\d+):\s/);
  return m ? parseInt(m[1],10) : null;
}

/* ===================== small formatters ===================== */
function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ===================== billing (CCBill) ===================== */
const billingState = { config: null };

function billingLog(msg, obj=null) {
  const el = document.getElementById("billingLog");
  if (!el) return;
  const line = `[${new Date().toISOString()}] ${msg}` + (obj ? `\n${JSON.stringify(obj,null,2)}\n` : "\n");
  el.value = line + el.value;
}

function billingFmtCents(c) {
  const n = Number(c || 0);
  return `$${(n/100).toFixed(2)}`;
}

async function billingLoadConfig() {
  billingState.config = await apiGet("/api/billing/config");
  const el = document.getElementById("billingConfigBox");
  if (el) {
    el.textContent = `clientAccnum=${billingState.config.clientAccnum} clientSubacc=${billingState.config.clientSubacc} currency=${billingState.config.default_currency}`;
  }
  billingLog("Loaded billing config", billingState.config);
}

async function billingLoadSettings() {
  const s = await apiGet("/api/billing/settings");
  const el = document.getElementById("billingSettingsOut");
  if (el) el.textContent = JSON.stringify(s);
  billingLog("Loaded billing settings", s);
}

async function billingLoadBalance() {
  const b = await apiGet("/api/billing/balance");
  const view = {
    currency: b.currency,
    owed_pending: billingFmtCents(b.owed_pending_cents),
    owed_settled: billingFmtCents(b.owed_settled_cents),
    payments_pending: billingFmtCents(b.payments_pending_cents),
    payments_settled: billingFmtCents(b.payments_settled_cents),
    due_settled: billingFmtCents(b.due_settled_cents),
    due_if_all_settles: billingFmtCents(b.due_if_all_settles_cents),
    updated_at: b.updated_at,
  };
  const el = document.getElementById("billingBalanceOut");
  if (el) el.textContent = JSON.stringify(view);
  billingLog("Loaded billing balance", b);
}

async function billingLoadPaymentMethods() {
  const tbody = document.getElementById("billingPmTbody");
  if (!tbody) return;
  const pms = await apiGet("/api/billing/payment-methods");
  tbody.innerHTML = "";
  for (const pm of pms) {
    const tr = document.createElement("tr");

    const tdTok = document.createElement("td");
    tdTok.className = "mono";
    tdTok.textContent = pm.payment_token_id;
    tr.appendChild(tdTok);

    const tdLabel = document.createElement("td");
    tdLabel.textContent = pm.label || "";
    tr.appendChild(tdLabel);

    const tdPri = document.createElement("td");
    tdPri.textContent = pm.priority;
    tr.appendChild(tdPri);

    const tdAct = document.createElement("td");
    tdAct.className = "right";

    const btnDefault = document.createElement("button");
    btnDefault.textContent = "Set default";
    btnDefault.onclick = async () => {
      await apiPost("/api/billing/payment-methods/default", { payment_token_id: pm.payment_token_id });
      billingLog("Set default token", pm);
      await billingLoadSettings();
    };

    const btnPri = document.createElement("button");
    btnPri.textContent = "Set priority";
    btnPri.style.marginLeft = "8px";
    btnPri.onclick = async () => {
      const p = prompt("New priority (lower = earlier):", String(pm.priority));
      if (p == null) return;
      await apiPost("/api/billing/payment-methods/priority", {
        payment_token_id: pm.payment_token_id,
        priority: Number(p),
      });
      billingLog("Set priority", { token: pm.payment_token_id, priority: p });
      await billingLoadPaymentMethods();
    };

    const btnDel = document.createElement("button");
    btnDel.textContent = "Remove";
    btnDel.style.marginLeft = "8px";
    btnDel.onclick = async () => {
      if (!confirm("Remove this payment method?")) return;
      await api("/api/billing/payment-methods/" + encodeURIComponent(pm.payment_token_id), {
        method: "DELETE",
      });
      billingLog("Removed token", pm);
      await billingRefreshAll();
    };

    tdAct.appendChild(btnDefault);
    tdAct.appendChild(btnPri);
    tdAct.appendChild(btnDel);
    tr.appendChild(tdAct);
    tbody.appendChild(tr);
  }
  billingLog("Loaded payment methods", pms);
}

async function billingRefreshAll() {
  if (!document.getElementById("billingSection")) return;
  await ensureUiSession();
  await billingLoadConfig();
  await billingLoadSettings();
  await billingLoadBalance();
  await billingLoadPaymentMethods();
}

async function billingCreateToken() {
  if (!billingState.config) await billingLoadConfig();
  const t = await apiPost("/api/billing/ccbill/frontend-oauth", {});
  billingLog("Got frontend OAuth", { got: !!t.access_token });
  try {
    await window.createPaymentToken(
      t.access_token,
      billingState.config.clientAccnum,
      billingState.config.clientSubacc,
      true,
      false,
      3600,
      999
    );
    billingLog("createPaymentToken() invoked");
  } catch (e) {
    billingLog("createPaymentToken() threw", { error: String(e) });
    alert("Tokenization failed: " + e);
  }
}

async function billingSubscribeMonthly() {
  const monthly = Number(document.getElementById("billingMonthlyCents").value);
  const planId = document.getElementById("billingPlanId").value.trim() || "monthly";
  const resp = await apiPost("/api/billing/subscribe-monthly", { plan_id: planId, monthly_price_cents: monthly });
  billingLog("subscribe-monthly response", resp);
  await billingRefreshAll();
  alert(resp.approved ? "Subscription started (approved)." : "Subscription failed.");
}

async function billingChargeOnce() {
  const amount = Number(document.getElementById("billingOneTimeCents").value);
  const resp = await apiPost("/api/billing/charge-once", { amount_cents: amount });
  billingLog("charge-once response", resp);
  await billingRefreshAll();
  alert(resp.approved ? "Charge approved." : "Charge failed.");
}

async function billingPayBalance() {
  const resp = await apiPost("/api/billing/pay-balance", {});
  billingLog("pay-balance response", resp);
  await billingRefreshAll();
  alert("Pay balance result: " + JSON.stringify(resp));
}

async function billingLoadSubscriptions() {
  const data = await apiGet("/api/billing/subscriptions");
  const el = document.getElementById("billingDebugOut");
  if (el) el.value = JSON.stringify(data, null, 2);
  billingLog("Loaded subscriptions", data);
}

async function billingLoadPayments() {
  const data = await apiGet("/api/billing/payments");
  const el = document.getElementById("billingDebugOut");
  if (el) el.value = JSON.stringify(data, null, 2);
  billingLog("Loaded payments", data);
}

async function billingLoadLedger() {
  const data = await apiGet("/api/billing/ledger");
  const el = document.getElementById("billingDebugOut");
  if (el) el.value = JSON.stringify(data, null, 2);
  billingLog("Loaded ledger", data);
}

function initBillingUi() {
  if (!document.getElementById("billingSection")) return;
  document.getElementById("billingRefreshBtn").onclick = async () => { await billingRefreshAll(); };
  document.getElementById("billingCreateTokenBtn").onclick = async () => { await ensureUiSession(); await billingCreateToken(); };
  document.getElementById("billingRefreshMethodsBtn").onclick = async () => { await ensureUiSession(); await billingLoadPaymentMethods(); };
  document.getElementById("billingSubscribeBtn").onclick = async () => { await ensureUiSession(); await billingSubscribeMonthly(); };
  document.getElementById("billingChargeOnceBtn").onclick = async () => { await ensureUiSession(); await billingChargeOnce(); };
  document.getElementById("billingPayBalanceBtn").onclick = async () => { await ensureUiSession(); await billingPayBalance(); };
  document.getElementById("billingLoadSubscriptionsBtn").onclick = async () => { await ensureUiSession(); await billingLoadSubscriptions(); };
  document.getElementById("billingLoadPaymentsBtn").onclick = async () => { await ensureUiSession(); await billingLoadPayments(); };
  document.getElementById("billingLoadLedgerBtn").onclick = async () => { await ensureUiSession(); await billingLoadLedger(); };

  window.addEventListener("tokenCreated", async (ev) => {
    try {
      await ensureUiSession();
      const detail = ev.detail || {};
      billingLog("tokenCreated event", detail);

      const tokenId = detail.paymentTokenId || detail.paymentToken || detail.payment_token_id;
      if (!tokenId) {
        alert("Token created but token id not found in event.detail");
        return;
      }

      const label = detail.cardType && detail.last4
        ? `${detail.cardType} ****${detail.last4}`
        : (detail.paymentType ? String(detail.paymentType) : null);

      await apiPost("/api/billing/payment-methods/ccbill-token", {
        payment_token_id: tokenId,
        label: label,
        make_default: document.getElementById("billingMakeDefault").checked,
      });

      billingLog("Saved payment token to backend", { tokenId, label });
      await billingRefreshAll();
      alert("Payment method saved!");
    } catch (e) {
      billingLog("tokenCreated handler failed", { error: String(e) });
      alert("Failed to save token: " + e);
    }
  });
}

function fmtDurSec(sec){
  sec = Math.max(0, Math.floor(sec||0));
  const d=Math.floor(sec/86400); sec-=d*86400;
  const h=Math.floor(sec/3600); sec-=h*3600;
  const m=Math.floor(sec/60); sec-=m*60;
  const parts=[];
  if(d) parts.push(d+'d');
  if(h||d) parts.push(h+'h');
  if(m||h||d) parts.push(m+'m');
  parts.push(sec+'s');
  return parts.join(' ');
}

function fmtTs(ts) {
  if (!ts || ts === 0) return "";
  try { return new Date(ts*1000).toLocaleString(); } catch(e) { return String(ts); }
}

function fmtMoney(cents, currency="usd") {
  const sign = cents < 0 ? "-" : "";
  const v = Math.abs(cents) / 100.0;
  return sign + v.toFixed(2) + " " + currency.toUpperCase();
}

function renderAlertRow(a) {
  const row = document.createElement("button");
  row.type = "button";
  row.className = "list-item list-button";
  if (a.alert_id) row.setAttribute("data-aid", a.alert_id);
  row.innerHTML = `
    <div class="grow">
      <div><b>${escapeHtml(a.title || a.event || "Alert")}</b></div>
      <div class="muted mono">${escapeHtml((a.details && a.details.alert_type) || "")} • ${fmtTs(a.ts)}</div>
    </div>
    <div class="muted">${a.read ? "Read" : "Unread"}</div>
  `;
  row.onclick = async () => {
    if (!a.alert_id || a.read) return;
    try {
      await apiPost("/ui/alerts/mark_read", { alert_ids: [a.alert_id] });
      row.classList.add("list-item-muted");
    } catch (e) {
      // ignore
    }
  };
  return row;
}

function setBillingStatus(msg) {
  const el = document.getElementById("billingStatus");
  if (el) el.textContent = msg || "";
}

async function initStripeBilling() {
  if (stripe) return;
  const cfg = await apiGet("/api/billing/config");
  stripe = Stripe(cfg.publishable_key);
  stripeElements = stripe.elements();
  stripeCard = stripeElements.create("card");
  stripeCard.mount("#card-element");
}

function showBillingPane(name) {
  document.querySelectorAll(".pane").forEach(p => p.classList.add("hidden"));
  const el = document.getElementById("pane_" + name);
  if (el) el.classList.remove("hidden");
  if (name === "list_methods") {
    loadBillingPaymentMethods();
  }
}

async function loadBillingSettings() {
  const res = await apiGet("/api/billing/settings");
  const chk = document.getElementById("autopay");
  if (chk) chk.checked = !!res.autopay_enabled;
}

async function loadBillingBalance() {
  const b = await apiGet("/api/billing/balance");
  const currency = b.currency || "usd";
  document.getElementById("due_settled").innerText = fmtMoney(b.due_settled_cents || 0, currency);
  document.getElementById("due_all").innerText = fmtMoney(b.due_if_all_settles_cents || 0, currency);
  document.getElementById("owed_pending").innerText = fmtMoney(b.owed_pending_cents || 0, currency);
  document.getElementById("owed_settled").innerText = fmtMoney(b.owed_settled_cents || 0, currency);
  document.getElementById("pay_pending").innerText = fmtMoney(b.payments_pending_cents || 0, currency);
  document.getElementById("pay_settled").innerText = fmtMoney(b.payments_settled_cents || 0, currency);
}

async function loadBillingPaymentMethods() {
  const wrap = document.getElementById("methods");
  wrap.innerHTML = "";
  const list = await apiGet("/api/billing/payment-methods");
  if (!list || list.length === 0) {
    wrap.innerHTML = "<div class=\"muted\">No payment methods yet.</div>";
    return;
  }

  list.forEach(pm => {
    const div = document.createElement("div");
    div.className = "item";
    div.innerHTML = `
      <div class="row">
        <div class="mono">${escapeHtml(pm.label || pm.payment_method_id)}</div>
        <div class="muted">(${escapeHtml(pm.method_type)})</div>
        <div class="right">
          <button type="button" data-action="set-default" data-pm="${pm.payment_method_id}">Set default</button>
          <button type="button" class="danger" data-action="remove" data-pm="${pm.payment_method_id}">Remove</button>
        </div>
      </div>
      <div class="row">
        <div class="muted">Priority:</div>
        <input id="prio_${pm.payment_method_id}" value="${pm.priority}" style="width:90px"/>
        <button type="button" data-action="priority" data-pm="${pm.payment_method_id}">Save priority</button>
        <span id="pm_msg_${pm.payment_method_id}" class="muted"></span>
      </div>
    `;
    wrap.appendChild(div);
  });

  wrap.querySelectorAll("button[data-action]").forEach(btn => {
    const action = btn.getAttribute("data-action");
    const pm = btn.getAttribute("data-pm");
    if (!pm) return;
    if (action === "priority") {
      btn.onclick = () => updateBillingPriority(pm);
    } else if (action === "set-default") {
      btn.onclick = () => setBillingDefault(pm);
    } else if (action === "remove") {
      btn.onclick = () => removeBillingPM(pm);
    }
  });
}

async function updateBillingPriority(pm) {
  try {
    const val = parseInt(document.getElementById("prio_" + pm).value, 10);
    await apiPost("/api/billing/payment-methods/priority", { payment_method_id: pm, priority: val });
    document.getElementById("pm_msg_" + pm).innerText = "Priority saved";
  } catch (e) {
    document.getElementById("pm_msg_" + pm).innerText = "Error: " + String(e);
  }
}

async function setBillingDefault(pm) {
  try {
    await apiPost("/api/billing/payment-methods/default", { payment_method_id: pm });
    document.getElementById("pm_msg_" + pm).innerText = "Default set";
  } catch (e) {
    document.getElementById("pm_msg_" + pm).innerText = "Error: " + String(e);
  }
}

async function removeBillingPM(pm) {
  try {
    await api("/api/billing/payment-methods/" + pm, { method: "DELETE" });
    await loadBillingPaymentMethods();
  } catch (e) {
    alert("Remove failed: " + String(e));
  }
}

async function addBillingCard() {
  document.getElementById("add_card_result").innerText = "";
  try {
    const si = await apiPost("/api/billing/setup-intent/card", {});
    const res = await stripe.confirmCardSetup(si.client_secret, { payment_method: { card: stripeCard } });
    if (res.error) throw new Error(res.error.message);

    document.getElementById("add_card_result").innerText = "Saved. (Will appear after webhook)";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("add_card_result").innerText = "Error: " + String(e);
  }
}

async function addBillingBankAccount() {
  document.getElementById("add_bank_result").innerText = "";
  document.getElementById("bank_next").innerText = "";
  try {
    const name = document.getElementById("bank_name").value || "Customer";
    const email = document.getElementById("bank_email").value || undefined;

    const si = await apiPost("/api/billing/setup-intent/us-bank", {});

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
      showBillingPane("verify_bank");
    } else {
      document.getElementById("bank_next").innerText = "If it succeeded, it will appear after webhook.";
      setTimeout(refreshBillingAll, 800);
    }
  } catch (e) {
    document.getElementById("add_bank_result").innerText = "Error: " + String(e);
  }
}

function useBillingPendingSetupIntent() {
  if (lastPendingSetupIntentId) {
    document.getElementById("verify_si").value = lastPendingSetupIntentId;
  } else {
    alert("No pending SetupIntent stored in this browser session.");
  }
}

async function verifyBillingByAmounts() {
  document.getElementById("verify_result").innerText = "";
  try {
    const setup_intent_id = document.getElementById("verify_si").value.trim();
    const a1 = parseInt(document.getElementById("amt1").value.trim(), 10);
    const a2 = parseInt(document.getElementById("amt2").value.trim(), 10);
    if (!setup_intent_id) throw new Error("Missing setup_intent_id");
    if (!Number.isFinite(a1) || !Number.isFinite(a2)) throw new Error("Enter both amounts (cents)");

    const res = await apiPost("/api/billing/us-bank/verify-microdeposits", {
      setup_intent_id,
      amounts: [a1, a2],
    });

    document.getElementById("verify_result").innerText = "Verify result: " + res.status + " (PM will appear after webhook if succeeded)";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("verify_result").innerText = "Error: " + String(e);
  }
}

async function verifyBillingByDescriptor() {
  document.getElementById("verify_result").innerText = "";
  try {
    const setup_intent_id = document.getElementById("verify_si").value.trim();
    const descriptor_code = document.getElementById("desc").value.trim();
    if (!setup_intent_id) throw new Error("Missing setup_intent_id");
    if (!descriptor_code) throw new Error("Missing descriptor code");

    const res = await apiPost("/api/billing/us-bank/verify-microdeposits", {
      setup_intent_id,
      descriptor_code,
    });

    document.getElementById("verify_result").innerText = "Verify result: " + res.status + " (PM will appear after webhook if succeeded)";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("verify_result").innerText = "Error: " + String(e);
  }
}

async function setBillingAutopay() {
  try {
    const enabled = document.getElementById("autopay").checked;
    await apiPost("/api/billing/autopay", { enabled });
  } catch (e) {
    alert("Autopay update failed: " + String(e));
  }
}

async function payBillingSettledBalance() {
  document.getElementById("pay_result").innerText = "";
  try {
    const amtTxt = document.getElementById("pay_amount").value.trim();
    const amount_cents = amtTxt ? parseInt(amtTxt, 10) : null;

    const payload = {};
    if (amount_cents) payload.amount_cents = amount_cents;

    const res = await apiPost("/api/billing/pay-balance", payload);
    document.getElementById("pay_result").innerText = "PI status: " + res.status + " (" + (res.payment_intent_id || "") + ")";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("pay_result").innerText = "Error: " + String(e);
  }
}

async function loadBillingLedger() {
  const wrap = document.getElementById("ledger");
  wrap.innerHTML = "";
  try {
    const limitTxt = document.getElementById("ledger_limit").value.trim();
    const limit = limitTxt ? parseInt(limitTxt, 10) : 50;
    const res = await apiGet("/api/billing/ledger?limit=" + encodeURIComponent(limit));
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
          <div class="mono">${escapeHtml(it.type)}</div>
          <div class="mono">${escapeHtml(it.reason || "")}</div>
          <div class="right mono">${it.amount_cents}</div>
        </div>
        <div class="muted mono w100">
          ${it.stripe_payment_intent_id ? ("pi=" + escapeHtml(it.stripe_payment_intent_id) + " ") : ""}
          ${it.stripe_charge_id ? ("ch=" + escapeHtml(it.stripe_charge_id) + " ") : ""}
          ${it.entry_id ? ("entry=" + escapeHtml(it.entry_id)) : ""}
        </div>
      `;
      wrap.appendChild(div);
    }

    if (items.length === 0) wrap.innerHTML = "<div class=\"muted\">No ledger entries yet.</div>";
  } catch (e) {
    wrap.innerHTML = "<div class=\"muted\">Error loading ledger: " + String(e) + "</div>";
  }
}

async function refreshBillingAll() {
  try {
    setBillingStatus("Refreshing billing…");
    await ensureUiSession();
    await initStripeBilling();
    await Promise.all([loadBillingBalance(), loadBillingPaymentMethods(), loadBillingSettings(), loadBillingLedger()]);
    setBillingStatus("Ready.");
  } catch (e) {
    setBillingStatus(String(e));
  }
}

/* ===================== session start ===================== */
async function sessionStart() {
  const tok = accessToken();
  const res = await fetch(API_BASE + "/ui/session/start", {
    method: "POST",
    headers: { "Authorization": "Bearer " + tok, "Content-Type": "application/json" },
    body: JSON.stringify({})
  });
  const txt = await res.text();
  if (!res.ok) throw new Error(res.status + ": " + txt);
  return txt ? JSON.parse(txt) : {};
}

/* ============================================================
   FULL ensureUiSession() (TOTP + SMS + Email, auto-send SMS/email once)
   ============================================================ */
async function ensureUiSession() {
  if (sessionId()) return true;

  const r = await sessionStart();
  if (!r.auth_required) {
    lsSet("session_id", r.session_id);
    return true;
  }

  const challengeId = r.challenge_id;
  const required = r.required_factors || [];
  const needTotp  = required.includes("totp");
  const needSms   = required.includes("sms");
  const needEmail = required.includes("email");

  async function postBearer(path, payload) {
    const tok = accessToken();
    const res = await fetch(API_BASE + path, {
      method: "POST",
      headers: { "Authorization": "Bearer " + tok, "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const txt = await res.text();
    if (!res.ok) throw new Error(res.status + ": " + txt);
    return txt ? JSON.parse(txt) : {};
  }

  return new Promise((resolve, reject) => {
    const state = {
      challengeId,
      needTotp, needSms, needEmail,

      totpDone: false,
      smsDone: false,
      emailDone: false,

      smsSending: false,
      smsSentOnce: false,
      smsSentTo: [],

      emailSending: false,
      emailSentOnce: false,
      emailSentTo: [],

      lastErr: "",
    };

    function badge(done) {
      return done ? `<span class="pill">✅ verified</span>` : `<span class="pill">required</span>`;
    }

    async function tryFinalizeOrClose(res) {
      if (res && res.session_id) {
        lsSet("session_id", res.session_id);
        modalClose();
        resolve(true);
        return true;
      }
      return false;
    }

    async function autoSendSmsOnce() {
      if (!state.needSms || state.smsDone || state.smsSentOnce || state.smsSending) return;
      state.smsSending = true;
      state.lastErr = "";
      render();
      try {
        const res = await postBearer("/ui/mfa/sms/begin", { challenge_id: challengeId });
        state.smsSentTo = res.sent_to || [];
        state.smsSentOnce = true;
      } catch (e) {
        state.lastErr = String(e);
      } finally {
        state.smsSending = false;
        render();
      }
    }

    async function autoSendEmailOnce() {
      if (!state.needEmail || state.emailDone || state.emailSentOnce || state.emailSending) return;
      state.emailSending = true;
      state.lastErr = "";
      render();
      try {
        const res = await postBearer("/ui/mfa/email/begin", { challenge_id: challengeId });
        state.emailSentTo = res.sent_to || [];
        state.emailSentOnce = true;
      } catch (e) {
        state.lastErr = String(e);
      } finally {
        state.emailSending = false;
        render();
      }
    }

    function render() {
      const totpSection = !state.needTotp ? "" : `
        <div style="border:1px solid #eee; padding:10px; border-radius:10px; margin-top:10px;">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
            <div><b>TOTP</b> ${badge(state.totpDone)}</div>
          </div>

          <input id="totpCode" placeholder="123456" inputmode="numeric" autocomplete="one-time-code"
                 ${state.totpDone ? "disabled" : ""} />

          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button id="totpVerifyBtn" ${state.totpDone ? "disabled" : ""}>Verify TOTP</button>
            <button id="totpRecoveryBtn" ${state.totpDone ? "disabled" : ""}>Use TOTP recovery</button>
          </div>
          <small>Any registered authenticator works.</small>
        </div>
      `;

      const smsSection = !state.needSms ? "" : `
        <div style="border:1px solid #eee; padding:10px; border-radius:10px; margin-top:10px;">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
            <div><b>SMS</b> ${badge(state.smsDone)}</div>
            <div>
              <button id="smsResendBtn" ${state.smsDone || state.smsSending ? "disabled" : ""}>
                ${state.smsSentOnce ? "Resend SMS" : "Send SMS"}
              </button>
            </div>
          </div>

          <div style="margin-top:6px;">
            ${state.smsSentTo.length
              ? `<small>Sent to: ${state.smsSentTo.map(x=>`<code>${x}</code>`).join(" ")}</small>`
              : `<small>We will text a code to all your enabled numbers.</small>`}
          </div>

          <input id="smsCode" placeholder="SMS code" inputmode="numeric" autocomplete="one-time-code"
                 ${state.smsDone ? "disabled" : ""} />

          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button id="smsVerifyBtn" ${state.smsDone ? "disabled" : ""}>Verify SMS</button>
            <button id="smsRecoveryBtn" ${state.smsDone ? "disabled" : ""}>Use SMS recovery</button>
          </div>
        </div>
      `;

      const emailSection = !state.needEmail ? "" : `
        <div style="border:1px solid #eee; padding:10px; border-radius:10px; margin-top:10px;">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
            <div><b>Email</b> ${badge(state.emailDone)}</div>
            <div>
              <button id="emailResendBtn" ${state.emailDone || state.emailSending ? "disabled" : ""}>
                ${state.emailSentOnce ? "Resend Email" : "Send Email"}
              </button>
            </div>
          </div>

          <div style="margin-top:6px;">
            ${state.emailSentTo.length
              ? `<small>Sent to: ${state.emailSentTo.map(x=>`<code>${x}</code>`).join(" ")}</small>`
              : `<small>We will email a code to all your enabled addresses.</small>`}
          </div>

          <input id="emailCode" placeholder="Email code" inputmode="numeric" autocomplete="one-time-code"
                 ${state.emailDone ? "disabled" : ""} />

          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button id="emailVerifyBtn" ${state.emailDone ? "disabled" : ""}>Verify Email</button>
            <button id="emailRecoveryBtn" ${state.emailDone ? "disabled" : ""}>Use Email recovery</button>
          </div>
        </div>
      `;

      modalShow({
        title: "Step-up verification required",
        bodyHtml: `
          <div>Complete all required factors to create a web session.</div>
          <div style="margin-top:6px;"><small>Challenge: <code class="mono">${challengeId}</code></small></div>
          ${totpSection}${smsSection}${emailSection}
          <div id="loginErr" class="err" style="margin-top:10px;">${state.lastErr || ""}</div>
        `,
        actions: [
          { text: "Cancel", onClick: () => { modalClose(); reject(new Error("Login cancelled")); } }
        ]
      });

      // TOTP handlers
      if (state.needTotp) {
        const v = document.getElementById("totpVerifyBtn");
        const r = document.getElementById("totpRecoveryBtn");
        if (v) v.onclick = async () => {
          state.lastErr = ""; render();
          try {
            const code = document.getElementById("totpCode").value.trim();
            const res = await postBearer("/ui/mfa/totp/verify", { challenge_id: challengeId, totp_code: code });
            if (await tryFinalizeOrClose(res)) return;
            state.totpDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
        if (r) r.onclick = async () => {
          const rc = prompt("Enter a TOTP recovery code:") || "";
          if (!rc.trim()) return;
          state.lastErr = ""; render();
          try {
            const res = await postBearer("/ui/recovery/totp", { challenge_id: challengeId, recovery_code: rc.trim() });
            if (await tryFinalizeOrClose(res)) return;
            state.totpDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
      }

      // SMS handlers
      if (state.needSms) {
        const resend = document.getElementById("smsResendBtn");
        const verify = document.getElementById("smsVerifyBtn");
        const recov  = document.getElementById("smsRecoveryBtn");

        if (resend) resend.onclick = async () => {
          if (state.smsDone || state.smsSending) return;
          state.smsSending = true; state.lastErr = ""; render();
          try {
            const res = await postBearer("/ui/mfa/sms/begin", { challenge_id: challengeId });
            state.smsSentTo = res.sent_to || [];
            state.smsSentOnce = true;
          } catch (e) { state.lastErr = String(e); }
          finally { state.smsSending = false; render(); }
        };

        if (verify) verify.onclick = async () => {
          state.lastErr = ""; render();
          try {
            const code = document.getElementById("smsCode").value.trim();
            const res = await postBearer("/ui/mfa/sms/verify", { challenge_id: challengeId, code });
            if (await tryFinalizeOrClose(res)) return;
            state.smsDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };

        if (recov) recov.onclick = async () => {
          const rc = prompt("Enter an SMS recovery code:") || "";
          if (!rc.trim()) return;
          state.lastErr = ""; render();
          try {
            const res = await postBearer("/ui/recovery/sms", { challenge_id: challengeId, recovery_code: rc.trim() });
            if (await tryFinalizeOrClose(res)) return;
            state.smsDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
      }

      // Email handlers
      if (state.needEmail) {
        const resend = document.getElementById("emailResendBtn");
        const verify = document.getElementById("emailVerifyBtn");
        const recov  = document.getElementById("emailRecoveryBtn");

        if (resend) resend.onclick = async () => {
          if (state.emailDone || state.emailSending) return;
          state.emailSending = true; state.lastErr = ""; render();
          try {
            const res = await postBearer("/ui/mfa/email/begin", { challenge_id: challengeId });
            state.emailSentTo = res.sent_to || [];
            state.emailSentOnce = true;
          } catch (e) { state.lastErr = String(e); }
          finally { state.emailSending = false; render(); }
        };

        if (verify) verify.onclick = async () => {
          state.lastErr = ""; render();
          try {
            const code = document.getElementById("emailCode").value.trim();
            const res = await postBearer("/ui/mfa/email/verify", { challenge_id: challengeId, code });
            if (await tryFinalizeOrClose(res)) return;
            state.emailDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };

        if (recov) recov.onclick = async () => {
          const rc = prompt("Enter an Email recovery code:") || "";
          if (!rc.trim()) return;
          state.lastErr = ""; render();
          try {
            const res = await postBearer("/ui/recovery/email", { challenge_id: challengeId, recovery_code: rc.trim() });
            if (await tryFinalizeOrClose(res)) return;
            state.emailDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
      }

      // Focus first incomplete
      setTimeout(() => {
        if (state.needTotp && !state.totpDone) { const el = document.getElementById("totpCode"); if (el) el.focus(); }
        else if (state.needSms && !state.smsDone) { const el = document.getElementById("smsCode"); if (el) el.focus(); }
        else if (state.needEmail && !state.emailDone) { const el = document.getElementById("emailCode"); if (el) el.focus(); }
      }, 50);
    }

    render();
    autoSendSmsOnce();
    autoSendEmailOnce();
  });
}

/* ===================== UI: ME ===================== */
async function refreshMe() {
  await ensureUiSession();
  const me = await api("/ui/me", {method:"GET", includeSession:true});
  document.getElementById("whoami").textContent = `user_sub=${me.user_sub} session=${me.session_id}`;
}

/* ===================== TOTP Devices (wired to backend we wrote) ===================== */
async function totpDevicesList() { return await api("/ui/mfa/totp/devices", {method:"GET", includeSession:true}); }
async function totpBegin(label) { return await api("/ui/mfa/totp/devices/begin", {method:"POST", body:{label}, includeSession:true}); }
async function totpConfirm(device_id, totp_code) { return await api("/ui/mfa/totp/devices/confirm", {method:"POST", body:{device_id, totp_code}, includeSession:true}); }
async function totpRemove(device_id, totp_code) { return await api(`/ui/mfa/totp/devices/${encodeURIComponent(device_id)}/remove`, {method:"POST", body:{totp_code}, includeSession:true}); }

async function refreshTotpDevices() {
  const data = await totpDevicesList();
  const tbody = document.getElementById("totpTbl").querySelector("tbody");
  tbody.innerHTML = "";
  (data.devices || []).forEach(d => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${d.label || ""}</td>
      <td>${d.enabled ? "yes" : "no"}</td>
      <td>${fmtTs(d.last_used_at)}</td>
      <td><button class="rm">Remove</button></td>
    `;
    tr.querySelector(".rm").onclick = async () => {
      const code = prompt("Enter a TOTP code to confirm removal:") || "";
      if (!code.trim()) return;
      await totpRemove(d.device_id, code.trim());
      await refreshTotpDevices();
    };
    tbody.appendChild(tr);
  });
}

/* ===================== SMS Devices (wired to backend we wrote) ===================== */
async function smsDevicesList() { return await api("/ui/mfa/sms/devices", {method:"GET", includeSession:true}); }
async function smsDeviceBegin(phone_e164, label) { return await api("/ui/mfa/sms/devices/begin", {method:"POST", body:{phone_e164, label}, includeSession:true}); }
async function smsDeviceConfirm(challenge_id, code) { return await api("/ui/mfa/sms/devices/confirm", {method:"POST", body:{challenge_id, code}, includeSession:true}); }
async function smsRemoveBegin(sms_device_id) { return await api(`/ui/mfa/sms/devices/${encodeURIComponent(sms_device_id)}/remove/begin`, {method:"POST", includeSession:true}); }
async function smsRemoveConfirm(challenge_id, code) { return await api("/ui/mfa/sms/devices/remove/confirm", {method:"POST", body:{challenge_id, code}, includeSession:true}); }

async function refreshSmsDevices() {
  const data = await smsDevicesList();
  const tbody = document.getElementById("smsTbl").querySelector("tbody");
  tbody.innerHTML = "";
  (data.devices || []).sort((a,b)=> (b.enabled===true)-(a.enabled===true)).forEach(d => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${d.phone_e164 || ""}</code></td>
      <td>${d.label || ""}</td>
      <td>${d.enabled ? "yes" : (d.pending ? "pending" : "no")}</td>
      <td>${fmtTs(d.last_used_at)}</td>
      <td>${d.enabled ? `<button class="rm">Remove</button>` : ""}</td>
    `;
    const rm = tr.querySelector(".rm");
    if (rm) rm.onclick = async () => openSmsRemoveModal(d.sms_device_id, d.phone_e164);
    tbody.appendChild(tr);
  });
}

function openSmsAddModal() {
  modalShow({
    title: "Add SMS phone (E.164)",
    bodyHtml: `
      <div class="muted">Example: <code>+15551234567</code> (max 3 phones)</div>
      <input id="smsPhone" placeholder="+15551234567" class="mono" />
      <input id="smsLabel" placeholder="Label (optional) e.g. Work iPhone" />
      <div id="smsAddErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Send verification SMS", onClick: async () => {
          try {
            const phone = document.getElementById("smsPhone").value.trim();
            const label = document.getElementById("smsLabel").value.trim() || null;
            const r = await smsDeviceBegin(phone, label);
            openSmsAddConfirmModal(r.challenge_id, r.sent_to || [], r.sms_device_id);
          } catch (e) {
            document.getElementById("smsAddErr").textContent = String(e);
          }
      }},
    ]
  });
}

function openSmsAddConfirmModal(challengeId, sentTo, smsDeviceId) {
  modalShow({
    title: "Confirm SMS phone",
    bodyHtml: `
      <div>We sent a verification code to:</div>
      <div style="margin:6px 0;">${sentTo.map(n => `<code>${n}</code>`).join(" ")}</div>
      <input id="smsAddCode" placeholder="SMS code" inputmode="numeric" autocomplete="one-time-code" />
      <div class="muted" style="margin-top:8px;">Challenge: <code class="mono">${challengeId}</code></div>
      <div class="muted">Device: <code class="mono">${smsDeviceId}</code></div>
      <div id="smsAddConfErr" class="err" style="margin-top:8px;"></div>
      <div id="smsRecoveryOut" style="margin-top:10px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Confirm phone", onClick: async () => {
          try {
            const code = document.getElementById("smsAddCode").value.trim();
            const r = await smsDeviceConfirm(challengeId, code);
            const rec = r.recovery_codes || [];
            if (rec.length) {
              document.getElementById("smsRecoveryOut").innerHTML =
                `<div><b>SMS recovery codes (save now — shown once):</b></div>
                 <pre class="mono" style="max-height:160px;">${rec.join("\n")}</pre>`;
              await refreshSmsDevices();
              return;
            }
            modalClose();
            await refreshSmsDevices();
          } catch (e) {
            document.getElementById("smsAddConfErr").textContent = String(e);
          }
      }},
      { text: "Done", onClick: async () => { modalClose(); await refreshSmsDevices(); } },
    ]
  });
}

async function openSmsRemoveModal(smsDeviceId, phoneE164) {
  const r = await smsRemoveBegin(smsDeviceId);
  modalShow({
    title: "Remove SMS phone",
    bodyHtml: `
      <div>To remove <code>${phoneE164}</code>, we sent a code to your other enabled SMS numbers:</div>
      <div style="margin:6px 0;">${(r.sent_to || []).map(n => `<code>${n}</code>`).join(" ")}</div>
      <input id="smsRmCode" placeholder="SMS code" inputmode="numeric" autocomplete="one-time-code" />
      <div class="muted" style="margin-top:8px;">Challenge: <code class="mono">${r.challenge_id}</code></div>
      <div id="smsRmErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Confirm removal", onClick: async () => {
          try {
            const code = document.getElementById("smsRmCode").value.trim();
            await smsRemoveConfirm(r.challenge_id, code);
            modalClose();
            await refreshSmsDevices();
          } catch (e) {
            document.getElementById("smsRmErr").textContent = String(e);
          }
      }},
    ]
  });
}

/* ===================== Email Devices (wired to SES-based backend) ===================== */
async function emailDevicesList() { return await api("/ui/mfa/email/devices", {method:"GET", includeSession:true}); }
async function emailDeviceBegin(email, label) { return await api("/ui/mfa/email/devices/begin", {method:"POST", body:{email, label}, includeSession:true}); }
async function emailDeviceConfirm(challenge_id, code) { return await api("/ui/mfa/email/devices/confirm", {method:"POST", body:{challenge_id, code}, includeSession:true}); }
async function emailRemoveBegin(email_device_id) { return await api(`/ui/mfa/email/devices/${encodeURIComponent(email_device_id)}/remove/begin`, {method:"POST", includeSession:true}); }
async function emailRemoveConfirm(challenge_id, code) { return await api("/ui/mfa/email/devices/remove/confirm", {method:"POST", body:{challenge_id, code}, includeSession:true}); }

async function refreshEmailDevices() {
  const data = await emailDevicesList();
  const tbody = document.getElementById("emailTbl").querySelector("tbody");
  tbody.innerHTML = "";
  (data.devices || []).sort((a,b)=> (b.enabled===true)-(a.enabled===true)).forEach(d => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${d.email || ""}</code></td>
      <td>${d.label || ""}</td>
      <td>${d.enabled ? "yes" : (d.pending ? "pending" : "no")}</td>
      <td>${fmtTs(d.last_used_at)}</td>
      <td>${d.enabled ? `<button class="rm">Remove</button>` : ""}</td>
    `;
    const rm = tr.querySelector(".rm");
    if (rm) rm.onclick = async () => openEmailRemoveModal(d.email_device_id, d.email);
    tbody.appendChild(tr);
  });
}

function openEmailAddModal() {
  modalShow({
    title: "Add Email",
    bodyHtml: `
      <div class="muted">Max 5 emails. Codes are sent to all enabled emails.</div>
      <input id="emailVal" placeholder="name@example.com" />
      <input id="emailLabel" placeholder="Label (optional) e.g. Work" />
      <div id="emailAddErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Send email code", onClick: async () => {
          try {
            const email = document.getElementById("emailVal").value.trim();
            const label = document.getElementById("emailLabel").value.trim() || null;
            const r = await emailDeviceBegin(email, label);
            openEmailAddConfirmModal(r.challenge_id, r.sent_to || [], r.email_device_id);
          } catch (e) {
            document.getElementById("emailAddErr").textContent = String(e);
          }
      }},
    ]
  });
}

function openEmailAddConfirmModal(challengeId, sentTo, emailDeviceId) {
  modalShow({
    title: "Confirm Email",
    bodyHtml: `
      <div>We sent a verification code to:</div>
      <div style="margin:6px 0;">${sentTo.map(e => `<code>${e}</code>`).join(" ")}</div>
      <input id="emailCode" placeholder="Email code" inputmode="numeric" autocomplete="one-time-code" />
      <div class="muted" style="margin-top:8px;">Challenge: <code class="mono">${challengeId}</code></div>
      <div class="muted">Device: <code class="mono">${emailDeviceId}</code></div>
      <div id="emailConfErr" class="err" style="margin-top:8px;"></div>
      <div id="emailRecoveryOut" style="margin-top:10px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Confirm email", onClick: async () => {
          try {
            const code = document.getElementById("emailCode").value.trim();
            const r = await emailDeviceConfirm(challengeId, code);
            const rec = r.recovery_codes || [];
            if (rec.length) {
              document.getElementById("emailRecoveryOut").innerHTML =
                `<div><b>Email recovery codes (save now — shown once):</b></div>
                 <pre class="mono" style="max-height:160px;">${rec.join("\n")}</pre>`;
              await refreshEmailDevices();
              return;
            }
            modalClose();
            await refreshEmailDevices();
          } catch (e) {
            document.getElementById("emailConfErr").textContent = String(e);
          }
      }},
      { text: "Done", onClick: async () => { modalClose(); await refreshEmailDevices(); } },
    ]
  });
}

async function openEmailRemoveModal(emailDeviceId, email) {
  const r = await emailRemoveBegin(emailDeviceId);
  modalShow({
    title: "Remove Email",
    bodyHtml: `
      <div>To remove <code>${email}</code>, we sent a code to your other enabled emails:</div>
      <div style="margin:6px 0;">${(r.sent_to || []).map(e => `<code>${e}</code>`).join(" ")}</div>
      <input id="emailRmCode" placeholder="Email code" inputmode="numeric" autocomplete="one-time-code" />
      <div class="muted" style="margin-top:8px;">Challenge: <code class="mono">${r.challenge_id}</code></div>
      <div id="emailRmErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Confirm removal", onClick: async () => {
          try {
            const code = document.getElementById("emailRmCode").value.trim();
            await emailRemoveConfirm(r.challenge_id, code);
            modalClose();
            await refreshEmailDevices();
          } catch (e) {
            document.getElementById("emailRmErr").textContent = String(e);
          }
      }},
    ]
  });
}

/* ===================== refreshAll ===================== */

/* ===================== Sessions ===================== */
async function refreshSessions() {
  await ensureUiSession();
  const res = await apiGet("/ui/sessions");
  const el = document.getElementById("sessList");
  el.innerHTML = "";
  (res.sessions || []).forEach(s => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(s.session_id)} ${s.is_current ? "<span class='pill'>current</span>" : ""} ${s.revoked ? "<span class='pill'>revoked</span>" : ""}</div>
        <div class="muted">created ${fmtTs(s.created_at)} • last ${fmtTs(s.last_seen_at)} • age ${fmtDurSec((Date.now()/1000)-(s.created_at||0))} • ${escapeHtml(s.ip||"")} • ${escapeHtml((s.user_agent||"").slice(0,80))}</div>
      </div>
      <div>
        <button ${s.is_current || s.revoked ? "disabled" : ""} data-sid="${escapeHtml(s.session_id)}">Revoke</button>
      </div>
    `;
    const btns = row.querySelectorAll("button");
    btns[0].onclick = async (e) => {
      const sid = e.target.getAttribute("data-sid");
      if (!sid) return;
      await apiPost("/ui/sessions/revoke", { session_id: sid });
      await refreshSessions();
    };
    el.appendChild(row);
  });
}

/* ===================== TOTP add flow ===================== */
async function totpBegin(label) {
  return await apiPost("/ui/mfa/totp/devices/begin", { label: label || "" });
}
async function totpConfirm(device_id, totp_code) {
  return await apiPost("/ui/mfa/totp/devices/confirm", { device_id, totp_code });
}

function openTotpAddModal() {
  modalShow({
    title: "Add TOTP Device",
    bodyHtml: `
      <div class="muted">1) Click “Begin” to get a QR code URI. 2) Scan it in your authenticator app. 3) Enter the 6‑digit code to confirm.</div>
      <input id="totpLabel" placeholder="Label (optional)"/>
      <div class="row-inline" style="margin-top:8px;">
        <button id="totpBeginBtn">Begin</button>
      </div>
      <div id="totpBeginOut" style="margin-top:10px;"></div>
      <div id="totpConfirmWrap" style="display:none; margin-top:10px;">
        <input id="totpDeviceId" class="mono" placeholder="device_id" readonly/>
        <input id="totpCode" class="mono" placeholder="6-digit code"/>
        <button id="totpConfirmBtn">Confirm</button>
      </div>
      <div id="totpAddErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [{ text: "Close", onClick: modalClose }]
  });

  document.getElementById("totpBeginBtn").onclick = async () => {
    try {
      await ensureUiSession();
      const label = document.getElementById("totpLabel").value.trim();
      const r = await totpBegin(label);
      // Display otpauth URI as text (user can paste into QR generator if desired).
      document.getElementById("totpBeginOut").innerHTML = `
        <div class="muted">otpauth URI:</div>
        <div class="mono break">${escapeHtml(r.otpauth_uri)}</div>
      `;
      document.getElementById("totpDeviceId").value = r.device_id;
      document.getElementById("totpConfirmWrap").style.display = "block";
    } catch (e) {
      document.getElementById("totpAddErr").textContent = String(e);
    }
  };

  document.getElementById("totpConfirmBtn").onclick = async () => {
    try {
      const device_id = document.getElementById("totpDeviceId").value.trim();
      const code = document.getElementById("totpCode").value.trim();
      const r = await totpConfirm(device_id, code);
      if (r.recovery_codes && r.recovery_codes.length) {
        alert("Recovery codes (save these now):\n\n" + r.recovery_codes.join("\n"));
      }
      modalClose();
      await refreshTotpDevices();
    } catch (e) {
      document.getElementById("totpAddErr").textContent = String(e);
    }
  };
}


/* ===================== API Keys ===================== */
async function refreshKeys() {
  await ensureUiSession();
  const res = await apiGet("/ui/api_keys");
  const el = document.getElementById("keysList");
  if (!el) return;
  el.innerHTML = "";
  (res.keys || []).forEach(k => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div><b>${escapeHtml(k.label||"(no label)")}</b> <span class="muted mono">${escapeHtml(k.prefix||"")}</span></div>
        <div class="muted">id ${escapeHtml(k.key_id)} • created ${fmtTs(k.created_at)} • last used ${k.last_used_at ? fmtTs(k.last_used_at) : "never"} • allow ${((k.allow_cidrs||[]).length)} • deny ${((k.deny_cidrs||[]).length)} ${k.revoked ? "• revoked" : ""}</div>
      </div>
      <div>
        <button ${k.revoked ? "disabled" : ""} data-kid="${escapeHtml(k.key_id)}">Revoke</button>
        <button ${k.revoked ? "disabled" : ""} data-kid="${escapeHtml(k.key_id)}" data-allow="${escapeHtml((k.allow_cidrs||[]).join(","))}" data-deny="${escapeHtml((k.deny_cidrs||[]).join(","))}">Edit IP rules</button>
      </div>
    `;
    const btns = row.querySelectorAll("button");
    btns[0].onclick = async (e) => {
      const kid = e.target.getAttribute("data-kid");
      await apiPost("/ui/api_keys/revoke", { key_id: kid });
      await refreshKeys();
    };
    btns[1].onclick = async (e) => {
      const kid = e.target.getAttribute("data-kid");
      const allowCsv = e.target.getAttribute("data-allow") || "";
      const denyCsv = e.target.getAttribute("data-deny") || "";
      openIpRulesModal(kid, allowCsv, denyCsv);
    };
    el.appendChild(row);
  });
}


async function setIpRules(key_id, allow_cidrs, deny_cidrs) {
  return await apiPost("/ui/api_keys/ip_rules", { key_id, allow_cidrs, deny_cidrs });
}

function csvToList(s) {
  return (s||"").split(/[,\n]/).map(x => x.trim()).filter(Boolean);
}

function openIpRulesModal(key_id, allowCsv, denyCsv) {
  const allow = csvToList(allowCsv);
  const deny = csvToList(denyCsv);
  modalShow({
    title: "API Key IP Rules",
    bodyHtml: `
      <div class="muted">If both lists are empty, the API key has <b>no IP restrictions</b>.<br/>
      If allowlist has entries, the request IP must match <b>at least one</b> allow CIDR/IP.<br/>
      Denylist is applied <b>after</b> allowlist: if it matches, access is blocked.</div>
      <div style="margin-top:10px;"><b>Allowlist (IPs/CIDRs)</b></div>
      <textarea id="ipAllow" class="mono" rows="5" placeholder="1.2.3.4\n10.0.0.0/8">${escapeHtml(allow.join("\n"))}</textarea>
      <div style="margin-top:10px;"><b>Denylist (IPs/CIDRs)</b></div>
      <textarea id="ipDeny" class="mono" rows="5" placeholder="5.6.7.8\n192.168.0.0/16">${escapeHtml(deny.join("\n"))}</textarea>
      <div id="ipRuleErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Save", onClick: async () => {
          try {
            const a = csvToList(document.getElementById("ipAllow").value);
            const d = csvToList(document.getElementById("ipDeny").value);
            await ensureUiSession();
            await setIpRules(key_id, a, d);
            modalClose();
            await refreshKeys();
          } catch (e) {
            document.getElementById("ipRuleErr").textContent = String(e);
          }
      }},
    ]
  });
}

function openCreateKeyModal() {
  modalShow({
    title: "Create API Key",
    bodyHtml: `
      <div class="muted">Add an optional label. The API key will be shown once.</div>
      <input id="keyLabel" placeholder="Label (optional)"/>
      <div id="keyOut" style="margin-top:10px;"></div>
      <div id="keyErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Create", onClick: async () => {
          try {
            await ensureUiSession();
            const label = document.getElementById("keyLabel").value.trim();
            const r = await apiPost("/ui/api_keys", { label });
            document.getElementById("keyOut").innerHTML = `
              <div class="muted">Copy and store this key now:</div>
              <div class="mono break">${escapeHtml(r.api_key)}</div>
            `;
            await refreshKeys();
          } catch (e) {
            document.getElementById("keyErr").textContent = String(e);
          }
      }},
      { text: "Close", onClick: modalClose },
    ]
  });
}


/* ===================== Alert Email Settings ===================== */
let alertTypesCache = [];

async function loadAlertTypes() {
  await ensureUiSession();
  const res = await apiGet("/ui/alerts/types");
  alertTypesCache = res.types || [];
  return alertTypesCache;
}

async function loadEmailPrefs() {
  await ensureUiSession();
  return await apiGet("/ui/alerts/email_prefs");
}

function renderEmailList(emails) {
  const el = document.getElementById("alertEmailList");
  if (!el) return;
  el.innerHTML = "";
  (emails||[]).forEach(e => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow mono">${escapeHtml(e)}</div>
      <div><button data-email="${escapeHtml(e)}">Remove</button></div>
    `;
    row.querySelector("button").onclick = async (ev) => {
      const em = ev.target.getAttribute("data-email");
      await apiPost("/ui/alerts/emails/remove", { email: em });
      await refreshAlertEmailSettings();
    };
    el.appendChild(row);
  });
}

function renderTypeChecklist(types, enabled) {
  const el = document.getElementById("alertTypeChecklist");
  if (!el) return;
  el.innerHTML = "";
  const en = new Set(enabled||[]);
  types.forEach(t => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <label style="display:flex;gap:10px;align-items:center;">
        <input type="checkbox" data-type="${escapeHtml(t)}" ${en.has(t) ? "checked" : ""}/>
        <span class="mono">${escapeHtml(t)}</span>
      </label>
    `;
    el.appendChild(row);
  });
}

async function refreshAlertEmailSettings() {
  const prefs = await loadEmailPrefs();
  const types = alertTypesCache.length ? alertTypesCache : await loadAlertTypes();
  renderEmailList(prefs.emails || []);
  renderTypeChecklist(types, prefs.email_event_types || []);
  renderSmsList(prefs.sms_numbers || []);
  renderSmsTypeChecklist(types, prefs.sms_event_types || []);
  renderToastTypeChecklist(types, prefs.toast_event_types || []);
  const msg = document.getElementById("alertTypesMsg");
  if (msg) msg.textContent = "";
}

async function beginAddAlertEmail(email) {
  await ensureUiSession();
  return await apiPost("/ui/alerts/emails/begin", { email });
}

async function confirmAddAlertEmail(challenge_id, code) {
  await ensureUiSession();
  return await apiPost("/ui/alerts/emails/confirm", { challenge_id, code });
}

function openConfirmEmailModal(sentTo, challenge_id) {
  modalShow({
    title: "Confirm email recipient",
    bodyHtml: `
      <div class="muted">We sent a confirmation code to <b>${escapeHtml(sentTo)}</b>.</div>
      <input id="alertEmailCode" class="mono" placeholder="6-digit code"/>
      <div id="alertEmailErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Confirm", onClick: async () => {
          try {
            const code = document.getElementById("alertEmailCode").value.trim();
            await confirmAddAlertEmail(challenge_id, code);
            modalClose();
            await refreshAlertEmailSettings();
          } catch (e) {
            document.getElementById("alertEmailErr").textContent = String(e);
          }
      }},
    ]
  });
}

async function refreshAll() {
  document.getElementById("globalErr").textContent = "";
  try {
    await refreshMe();
    await Promise.allSettled([
      refreshTotpDevices(),
      refreshSmsDevices(),
      refreshEmailDevices(),
      refreshSessions(),
      refreshKeys(),
      refreshAlertEmailSettings(),
      refreshPushUI(),
      refreshAlerts(),
      billingRefreshAll(),
    ]);
    await pollToastsOnce();
  } catch (e) {
    document.getElementById("globalErr").textContent = String(e);
  }
}

async function refreshAlerts() {
  const el = document.getElementById("alertsList");
  if (!el) return;
  await ensureUiSession();
  const res = await apiGet("/ui/alerts?limit=20");
  el.innerHTML = "";
  (res.alerts || []).forEach(a => {
    el.appendChild(renderAlertRow(a));
  });
}


function renderSmsList(nums) {
  const el = document.getElementById("alertSmsList");
  if (!el) return;
  el.innerHTML = "";
  (nums||[]).forEach(n => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow mono">${escapeHtml(n)}</div>
      <div><button data-phone="${escapeHtml(n)}">Remove</button></div>
    `;
    row.querySelector("button").onclick = async (ev) => {
      const ph = ev.target.getAttribute("data-phone");
      await apiPost("/ui/alerts/sms/remove", { phone: ph });
      await refreshAlertEmailSettings();
    };
    el.appendChild(row);
  });
}

function renderSmsTypeChecklist(types, enabled) {
  const el = document.getElementById("alertSmsTypeChecklist");
  if (!el) return;
  el.innerHTML = "";
  const en = new Set(enabled||[]);
  types.forEach(t => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <label style="display:flex;gap:10px;align-items:center;">
        <input type="checkbox" data-type="${escapeHtml(t)}" ${en.has(t) ? "checked" : ""}/>
        <span class="mono">${escapeHtml(t)}</span>
      </label>
    `;
    el.appendChild(row);
  });
}

async function beginAddAlertSms(phone) {
  await ensureUiSession();
  return await apiPost("/ui/alerts/sms/begin", { phone });
}
async function confirmAddAlertSms(challenge_id, code) {
  await ensureUiSession();
  return await apiPost("/ui/alerts/sms/confirm", { challenge_id, code });
}

function openConfirmSmsModal(sentTo, challenge_id) {
  modalShow({
    title: "Confirm SMS recipient",
    bodyHtml: `
      <div class="muted">We sent a confirmation code to <b>${escapeHtml(sentTo)}</b>.</div>
      <input id="alertSmsCode" class="mono" placeholder="6-digit code"/>
      <div id="alertSmsErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Confirm", onClick: async () => {
          try {
            const code = document.getElementById("alertSmsCode").value.trim();
            await confirmAddAlertSms(challenge_id, code);
            modalClose();
            await refreshAlertEmailSettings();
          } catch (e) {
            document.getElementById("alertSmsErr").textContent = String(e);
          }
      }},
    ]
  });
}

/* ===================== Push (FCM Web) =====================
   You MUST fill firebaseConfig + VAPID key for your Firebase project.
   For production, don't hardcode secrets; these are public config values.
*/
const firebaseConfig = window.FIREBASE_CONFIG || null; // set window.FIREBASE_CONFIG = {...}
const firebaseVapidKey = window.FIREBASE_VAPID_KEY || null; // Web Push certificate key pair (public)

async function loadFirebaseMessaging() {
  if (!firebaseConfig) throw new Error("Missing window.FIREBASE_CONFIG");
  if (!firebaseVapidKey) throw new Error("Missing window.FIREBASE_VAPID_KEY");

  // Lazy-load firebase libs from CDN
  if (!window.firebase) {
    await loadScript("https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js");
    await loadScript("https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js");
  }
  if (!firebase.apps || firebase.apps.length === 0) {
    firebase.initializeApp(firebaseConfig);
  }
  return firebase.messaging();
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error("Failed to load " + src));
    document.head.appendChild(s);
  });
}

async function ensureServiceWorker() {
  if (!("serviceWorker" in navigator)) throw new Error("Service worker not supported");
  // You must host /firebase-messaging-sw.js at your site root.
  // This file handles background notifications.
  const reg = await navigator.serviceWorker.register("/firebase-messaging-sw.js");
  return reg;
}

async function enablePushOnThisBrowser() {
  await ensureUiSession();
  const msgEl = document.getElementById("pushMsg");
  try {
    msgEl.textContent = "Requesting permission...";
    const perm = await Notification.requestPermission();
    if (perm !== "granted") throw new Error("Notification permission not granted");

    const reg = await ensureServiceWorker();
    const messaging = await loadFirebaseMessaging();
    const token = await messaging.getToken({ vapidKey: firebaseVapidKey, serviceWorkerRegistration: reg });
    if (!token) throw new Error("Failed to obtain FCM token");

    await apiPost("/ui/push/register", { token, platform: "web_fcm" });
    msgEl.textContent = "Push enabled for this browser.";
    await refreshPushUI();
  } catch (e) {
    msgEl.textContent = String(e);
  }
}

async function refreshPushUI() {
  await ensureUiSession();
  const [typesRes, prefs, devs] = await Promise.all([apiGet("/ui/alerts/types"), loadEmailPrefs(), apiGet("/ui/push/devices")]);
  renderPushTypeChecklist(typesRes.types || [], prefs.push_event_types || []);
  renderPushDevices(devs.devices || []);
}

function renderPushDevices(devs) {
  const el = document.getElementById("pushDevicesList");
  if (!el) return;
  el.innerHTML = "";
  (devs||[]).forEach(d => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(d.device_id||"")}</div>
        <div class="muted">${escapeHtml(d.platform||"")} • created ${fmtTs(d.created_at)} • last ${fmtTs(d.last_seen_at)}</div>
      </div>
      <div><button data-did="${escapeHtml(d.device_id||"")}">Revoke</button></div>
    `;
    row.querySelector("button").onclick = async (ev) => {
      const did = ev.target.getAttribute("data-did");
      await apiPost("/ui/push/revoke", { device_id: did });
      await refreshPushUI();
    };
    el.appendChild(row);
  });
}

function renderPushTypeChecklist(types, enabled) {
  const el = document.getElementById("alertPushTypeChecklist");
  if (!el) return;
  el.innerHTML = "";
  const en = new Set(enabled||[]);
  types.forEach(t => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <label style="display:flex;gap:10px;align-items:center;">
        <input type="checkbox" data-type="${escapeHtml(t)}" ${en.has(t) ? "checked" : ""}/>
        <span class="mono">${escapeHtml(t)}</span>
      </label>
    `;
    el.appendChild(row);
  });
}

/* ===================== Toasts ===================== */
const seenToasts = new Set();

function showToast(title, subtitle) {
  const cont = document.getElementById("toastContainer");
  if (!cont) return;
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `<div class="t-title">${escapeHtml(title||"Alert")}</div><div class="t-sub">${escapeHtml(subtitle||"")}</div>`;
  cont.appendChild(el);
  setTimeout(() => { try { el.remove(); } catch(e) {} }, 6000);
}

function renderToastTypeChecklist(types, enabled) {
  const el = document.getElementById("alertToastTypeChecklist");
  if (!el) return;
  el.innerHTML = "";
  const en = new Set(enabled||[]);
  types.forEach(t => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <label style="display:flex;gap:10px;align-items:center;">
        <input type="checkbox" data-type="${escapeHtml(t)}" ${en.has(t) ? "checked" : ""}/>
        <span class="mono">${escapeHtml(t)}</span>
      </label>
    `;
    el.appendChild(row);
  });
}

async function pollToastsOnce() {
  try {
    await ensureUiSession();
    const prefs = await loadEmailPrefs(); // contains toast_event_types too
    const enabled = new Set(prefs.toast_event_types || []);
    if (enabled.size === 0) return;

    const res = await apiGet("/ui/alerts?limit=20&unread_only=1");
    const alerts = res.alerts || [];
    const deliver = [];
    for (const a of alerts) {
      const aid = a.alert_id;
      if (!aid) continue;
      if (a.toast_delivered) continue;
      if (seenToasts.has(aid)) continue;
      const t = (a.details && a.details.alert_type) ? a.details.alert_type : "";
      if (!enabled.has(t)) continue;
      seenToasts.add(aid);
      showToast(a.title || a.event || "Alert", `${t} • ${fmtTs(a.ts)}`);
      deliver.push(aid);
    }
    if (deliver.length) {
      await apiPost("/ui/alerts/mark_toast_delivered", { alert_ids: deliver });
    }
  } catch (e) {
    // ignore polling errors
  }
}

let toastPollTimer = null;
function startToastPolling() {
  if (toastPollTimer) return;
  toastPollTimer = setInterval(pollToastsOnce, 5000);
}


/* ===================== wire buttons ===================== */

document.getElementById("sessRefreshBtn").onclick = async () => { await refreshSessions(); };
document.getElementById("sessRevokeOthersBtn").onclick = async () => {
  await apiPost("/ui/sessions/revoke_others", {});
  await refreshSessions();
};
document.getElementById("totpAddBtn").onclick = async () => { await ensureUiSession(); openTotpAddModal(); };


document.getElementById("keysRefreshBtn").onclick = async () => { await refreshKeys(); };
document.getElementById("keysCreateBtn").onclick = async () => { openCreateKeyModal(); };



document.getElementById("alertSmsAddBtn").onclick = async () => {
  const phone = document.getElementById("alertSmsInput").value.trim();
  if (!phone) return;
  try {
    const r = await beginAddAlertSms(phone);
    openConfirmSmsModal(r.sent_to, r.challenge_id);
    document.getElementById("alertSmsInput").value = "";
  } catch (e) {
    alert(String(e));
  }
};


document.getElementById("alertToastTypesSaveBtn").onclick = async () => {
  try {
    await ensureUiSession();
    const boxes = document.querySelectorAll("#alertToastTypeChecklist input[type=checkbox]");
    const enabled = [];
    boxes.forEach(b => { if (b.checked) enabled.push(b.getAttribute("data-type")); });
    await apiPost("/ui/alerts/toast_prefs", { toast_event_types: enabled });
    const msg = document.getElementById("alertToastTypesMsg");
    if (msg) msg.textContent = "Saved.";
  } catch (e) {
    const msg = document.getElementById("alertToastTypesMsg");
    if (msg) msg.textContent = String(e);
  }
};

document.getElementById("alertSmsTypesSaveBtn").onclick = async () => {
  try {
    await ensureUiSession();
    const boxes = document.querySelectorAll("#alertSmsTypeChecklist input[type=checkbox]");
    const enabled = [];
    boxes.forEach(b => { if (b.checked) enabled.push(b.getAttribute("data-type")); });
    await apiPost("/ui/alerts/sms_prefs", { sms_event_types: enabled });
    const msg = document.getElementById("alertSmsTypesMsg");
    if (msg) msg.textContent = "Saved.";
  } catch (e) {
    const msg = document.getElementById("alertSmsTypesMsg");
    if (msg) msg.textContent = String(e);
  }
};

document.getElementById("alertEmailAddBtn").onclick = async () => {
  const email = document.getElementById("alertEmailInput").value.trim();
  if (!email) return;
  try {
    const r = await beginAddAlertEmail(email);
    openConfirmEmailModal(r.sent_to, r.challenge_id);
    document.getElementById("alertEmailInput").value = "";
  } catch (e) {
    alert(String(e));
  }
};

document.getElementById("alertTypesSaveBtn").onclick = async () => {
  try {
    await ensureUiSession();
    const boxes = document.querySelectorAll("#alertTypeChecklist input[type=checkbox]");
    const enabled = [];
    boxes.forEach(b => { if (b.checked) enabled.push(b.getAttribute("data-type")); });
    await apiPost("/ui/alerts/email_prefs", { email_event_types: enabled });
    const msg = document.getElementById("alertTypesMsg");
    if (msg) msg.textContent = "Saved.";
  } catch (e) {
    const msg = document.getElementById("alertTypesMsg");
    if (msg) msg.textContent = String(e);
  }
};


document.getElementById("btnEnablePush").onclick = enablePushOnThisBrowser;
document.getElementById("btnPushTest").onclick = async () => {
  try {
    await ensureUiSession();
    await apiPost("/ui/push/test", {});
    document.getElementById("pushMsg").textContent = "Sent test push (if enabled for this alert type).";
  } catch (e) {
    document.getElementById("pushMsg").textContent = String(e);
  }
};
document.getElementById("alertPushTypesSaveBtn").onclick = async () => {
  try {
    await ensureUiSession();
    const boxes = document.querySelectorAll("#alertPushTypeChecklist input[type=checkbox]");
    const enabled = [];
    boxes.forEach(b => { if (b.checked) enabled.push(b.getAttribute("data-type")); });
    await apiPost("/ui/alerts/push_prefs", { push_event_types: enabled });
    const msg = document.getElementById("alertPushTypesMsg");
    if (msg) msg.textContent = "Saved.";
  } catch (e) {
    const msg = document.getElementById("alertPushTypesMsg");
    if (msg) msg.textContent = String(e);
  }
};

document.getElementById("btnRefreshAll").onclick = refreshAll;
document.getElementById("btnClearSession").onclick = () => { lsDel("session_id"); alert("UI session cleared."); };
document.getElementById("btnSetTokens").onclick = openTokenModal;

document.getElementById("btnClearTokens").onclick = () => { lsDel("access_token"); lsDel("id_token"); lsDel("refresh_token"); lsDel("session_id"); alert("Tokens cleared."); };

document.getElementById("totpRefreshBtn").onclick = async () => { await ensureUiSession(); await refreshTotpDevices(); };


document.getElementById("smsRefreshBtn").onclick = async () => { await ensureUiSession(); await refreshSmsDevices(); };
document.getElementById("smsAddBtn").onclick = async () => { await ensureUiSession(); openSmsAddModal(); };

document.getElementById("emailRefreshBtn").onclick = async () => { await ensureUiSession(); await refreshEmailDevices(); };
document.getElementById("emailAddBtn").onclick = async () => { await ensureUiSession(); openEmailAddModal(); };

initBillingUi();
document.getElementById("billingRefreshBtn").onclick = refreshBillingAll;
document.getElementById("paySettledBalanceBtn").onclick = payBillingSettledBalance;
document.getElementById("autopay").onchange = setBillingAutopay;
document.getElementById("paneAddCardBtn").onclick = () => showBillingPane("add_card");
document.getElementById("paneAddBankBtn").onclick = () => showBillingPane("add_bank");
document.getElementById("paneVerifyBankBtn").onclick = () => showBillingPane("verify_bank");
document.getElementById("paneListMethodsBtn").onclick = () => showBillingPane("list_methods");
document.getElementById("addCardBtn").onclick = addBillingCard;
document.getElementById("addBankAccountBtn").onclick = addBillingBankAccount;
document.getElementById("usePendingSetupIntentBtn").onclick = useBillingPendingSetupIntent;
document.getElementById("verifyByAmountsBtn").onclick = verifyBillingByAmounts;
document.getElementById("verifyByDescriptorBtn").onclick = verifyBillingByDescriptor;
document.getElementById("loadLedgerBtn").onclick = loadBillingLedger;

/* ===================== boot ===================== */
if (!accessToken()) { openTokenModal(); } else { refreshAll(); }
startToastSSE();
startToastPolling();
