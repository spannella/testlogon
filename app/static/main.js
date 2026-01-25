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

async function apiPublic(path, { method = "GET", body = null } = {}) {
  const headers = {};
  if (body !== null) headers["Content-Type"] = "application/json";
  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : undefined,
  });
  const txt = await res.text();
  if (!res.ok) throw new Error(res.status + ": " + txt);
  return txt ? JSON.parse(txt) : {};
}

function apiPatch(path, body, { includeSession = true } = {}) {
  return api(path, { method: "PATCH", body, includeSession });
}

function apiPut(path, body, { includeSession = true } = {}) {
  return api(path, { method: "PUT", body, includeSession });
}

function apiDelete(path, { includeSession = true } = {}) {
  return api(path, { method: "DELETE", includeSession });
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

function fmtBytes(value) {
  const size = Number(value || 0);
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const idx = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1);
  const scaled = size / Math.pow(1024, idx);
  return `${scaled.toFixed(scaled >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

/* ===================== billing (CCBill) ===================== */
const billingState = { config: null };

function billingLog(msg, obj=null) {
  const el = document.getElementById("ccbillLog");
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
  const el = document.getElementById("ccbillConfigBox");
  if (el) {
    el.textContent = `clientAccnum=${billingState.config.clientAccnum} clientSubacc=${billingState.config.clientSubacc} currency=${billingState.config.default_currency}`;
  }
  billingLog("Loaded billing config", billingState.config);
}

async function billingLoadSettings() {
  const s = await apiGet("/api/billing/settings");
  const el = document.getElementById("ccbillSettingsOut");
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
  const el = document.getElementById("ccbillBalanceOut");
  if (el) el.textContent = JSON.stringify(view);
  billingLog("Loaded billing balance", b);
}

async function billingLoadPaymentMethods() {
  const tbody = document.getElementById("ccbillPmTbody");
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
  if (!document.getElementById("ccbillSection")) return;
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
  const monthly = Number(document.getElementById("ccbillMonthlyCents").value);
  const planId = document.getElementById("ccbillPlanId").value.trim() || "monthly";
  const resp = await apiPost("/api/billing/subscribe-monthly", { plan_id: planId, monthly_price_cents: monthly });
  billingLog("subscribe-monthly response", resp);
  await billingRefreshAll();
  alert(resp.approved ? "Subscription started (approved)." : "Subscription failed.");
}

async function billingChargeOnce() {
  const amount = Number(document.getElementById("ccbillOneTimeCents").value);
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
  const el = document.getElementById("ccbillDebugOut");
  if (el) el.value = JSON.stringify(data, null, 2);
  billingLog("Loaded subscriptions", data);
}

async function billingLoadPayments() {
  const data = await apiGet("/api/billing/payments");
  const el = document.getElementById("ccbillDebugOut");
  if (el) el.value = JSON.stringify(data, null, 2);
  billingLog("Loaded payments", data);
}

async function billingLoadLedger() {
  const data = await apiGet("/api/billing/ledger");
  const el = document.getElementById("ccbillDebugOut");
  if (el) el.value = JSON.stringify(data, null, 2);
  billingLog("Loaded ledger", data);
}

function initBillingUi() {
  if (!document.getElementById("ccbillSection")) return;
  document.getElementById("ccbillRefreshBtn").onclick = async () => { await billingRefreshAll(); };
  document.getElementById("ccbillCreateTokenBtn").onclick = async () => { await ensureUiSession(); await billingCreateToken(); };
  document.getElementById("ccbillRefreshMethodsBtn").onclick = async () => { await ensureUiSession(); await billingLoadPaymentMethods(); };
  document.getElementById("ccbillSubscribeBtn").onclick = async () => { await ensureUiSession(); await billingSubscribeMonthly(); };
  document.getElementById("ccbillChargeOnceBtn").onclick = async () => { await ensureUiSession(); await billingChargeOnce(); };
  document.getElementById("ccbillPayBalanceBtn").onclick = async () => { await ensureUiSession(); await billingPayBalance(); };
  document.getElementById("ccbillLoadSubscriptionsBtn").onclick = async () => { await ensureUiSession(); await billingLoadSubscriptions(); };
  document.getElementById("ccbillLoadPaymentsBtn").onclick = async () => { await ensureUiSession(); await billingLoadPayments(); };
  document.getElementById("ccbillLoadLedgerBtn").onclick = async () => { await ensureUiSession(); await billingLoadLedger(); };

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
        make_default: document.getElementById("ccbillMakeDefault").checked,
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
  const el = document.getElementById("stripeStatus");
  if (el) el.textContent = msg || "";
}

async function initStripeBilling() {
  if (stripe) return;
  const cfg = await apiGet("/api/billing/config");
  stripe = Stripe(cfg.publishable_key);
  stripeElements = stripe.elements();
  stripeCard = stripeElements.create("card");
  stripeCard.mount("#stripe_card_element");
}

function showStripePane(name) {
  document.querySelectorAll(".stripe-pane").forEach(p => p.classList.add("hidden"));
  const el = document.getElementById("stripe_pane_" + name);
  if (el) el.classList.remove("hidden");
  if (name === "list_methods") {
    loadBillingPaymentMethods();
  }
}

async function loadBillingSettings() {
  const res = await apiGet("/api/billing/settings");
  const chk = document.getElementById("stripe_autopay");
  if (chk) chk.checked = !!res.autopay_enabled;
}

async function loadBillingBalance() {
  const b = await apiGet("/api/billing/balance");
  const currency = b.currency || "usd";
  document.getElementById("stripe_due_settled").innerText = fmtMoney(b.due_settled_cents || 0, currency);
  document.getElementById("stripe_due_all").innerText = fmtMoney(b.due_if_all_settles_cents || 0, currency);
  document.getElementById("stripe_owed_pending").innerText = fmtMoney(b.owed_pending_cents || 0, currency);
  document.getElementById("stripe_owed_settled").innerText = fmtMoney(b.owed_settled_cents || 0, currency);
  document.getElementById("stripe_pay_pending").innerText = fmtMoney(b.payments_pending_cents || 0, currency);
  document.getElementById("stripe_pay_settled").innerText = fmtMoney(b.payments_settled_cents || 0, currency);
}

async function loadBillingPaymentMethods() {
  const wrap = document.getElementById("stripe_methods");
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
        <input id="stripe_prio_${pm.payment_method_id}" value="${pm.priority}" style="width:90px"/>
        <button type="button" data-action="priority" data-pm="${pm.payment_method_id}">Save priority</button>
        <span id="stripe_pm_msg_${pm.payment_method_id}" class="muted"></span>
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
    const val = parseInt(document.getElementById("stripe_prio_" + pm).value, 10);
    await apiPost("/api/billing/payment-methods/priority", { payment_method_id: pm, priority: val });
    document.getElementById("stripe_pm_msg_" + pm).innerText = "Priority saved";
  } catch (e) {
    document.getElementById("stripe_pm_msg_" + pm).innerText = "Error: " + String(e);
  }
}

async function setBillingDefault(pm) {
  try {
    await apiPost("/api/billing/payment-methods/default", { payment_method_id: pm });
    document.getElementById("stripe_pm_msg_" + pm).innerText = "Default set";
  } catch (e) {
    document.getElementById("stripe_pm_msg_" + pm).innerText = "Error: " + String(e);
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
  document.getElementById("stripe_add_card_result").innerText = "";
  try {
    const si = await apiPost("/api/billing/setup-intent/card", {});
    const res = await stripe.confirmCardSetup(si.client_secret, { payment_method: { card: stripeCard } });
    if (res.error) throw new Error(res.error.message);

    document.getElementById("stripe_add_card_result").innerText = "Saved. (Will appear after webhook)";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("stripe_add_card_result").innerText = "Error: " + String(e);
  }
}

async function addBillingBankAccount() {
  document.getElementById("stripe_add_bank_result").innerText = "";
  document.getElementById("stripe_bank_next").innerText = "";
  try {
    const name = document.getElementById("stripe_bank_name").value || "Customer";
    const email = document.getElementById("stripe_bank_email").value || undefined;

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
    document.getElementById("stripe_add_bank_result").innerText = "Submitted. Status: " + setupIntent.status;

    if (setupIntent.status === "requires_action" &&
        setupIntent.next_action &&
        setupIntent.next_action.type === "verify_with_microdeposits") {
      lastPendingSetupIntentId = setupIntent.id;
      document.getElementById("stripe_bank_next").innerHTML =
        "Microdeposits required. SetupIntent: <code>" + setupIntent.id + "</code>. " +
        "Go to “Verify microdeposits” tab after deposits arrive.";
      document.getElementById("stripe_verify_si").value = setupIntent.id;
      showStripePane("verify_bank");
    } else {
      document.getElementById("stripe_bank_next").innerText = "If it succeeded, it will appear after webhook.";
      setTimeout(refreshBillingAll, 800);
    }
  } catch (e) {
    document.getElementById("stripe_add_bank_result").innerText = "Error: " + String(e);
  }
}

function useBillingPendingSetupIntent() {
  if (lastPendingSetupIntentId) {
    document.getElementById("stripe_verify_si").value = lastPendingSetupIntentId;
  } else {
    alert("No pending SetupIntent stored in this browser session.");
  }
}

async function verifyBillingByAmounts() {
  document.getElementById("stripe_verify_result").innerText = "";
  try {
    const setup_intent_id = document.getElementById("stripe_verify_si").value.trim();
    const a1 = parseInt(document.getElementById("stripe_amt1").value.trim(), 10);
    const a2 = parseInt(document.getElementById("stripe_amt2").value.trim(), 10);
    if (!setup_intent_id) throw new Error("Missing setup_intent_id");
    if (!Number.isFinite(a1) || !Number.isFinite(a2)) throw new Error("Enter both amounts (cents)");

    const res = await apiPost("/api/billing/us-bank/verify-microdeposits", {
      setup_intent_id,
      amounts: [a1, a2],
    });

    document.getElementById("stripe_verify_result").innerText = "Verify result: " + res.status + " (PM will appear after webhook if succeeded)";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("stripe_verify_result").innerText = "Error: " + String(e);
  }
}

async function verifyBillingByDescriptor() {
  document.getElementById("stripe_verify_result").innerText = "";
  try {
    const setup_intent_id = document.getElementById("stripe_verify_si").value.trim();
    const descriptor_code = document.getElementById("stripe_desc").value.trim();
    if (!setup_intent_id) throw new Error("Missing setup_intent_id");
    if (!descriptor_code) throw new Error("Missing descriptor code");

    const res = await apiPost("/api/billing/us-bank/verify-microdeposits", {
      setup_intent_id,
      descriptor_code,
    });

    document.getElementById("stripe_verify_result").innerText = "Verify result: " + res.status + " (PM will appear after webhook if succeeded)";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("stripe_verify_result").innerText = "Error: " + String(e);
  }
}

async function setBillingAutopay() {
  try {
    const enabled = document.getElementById("stripe_autopay").checked;
    await apiPost("/api/billing/autopay", { enabled });
  } catch (e) {
    alert("Autopay update failed: " + String(e));
  }
}

async function payBillingSettledBalance() {
  document.getElementById("stripe_pay_result").innerText = "";
  try {
    const amtTxt = document.getElementById("stripe_pay_amount").value.trim();
    const amount_cents = amtTxt ? parseInt(amtTxt, 10) : null;

    const payload = {};
    if (amount_cents) payload.amount_cents = amount_cents;

    const res = await apiPost("/api/billing/pay-balance", payload);
    document.getElementById("stripe_pay_result").innerText = "PI status: " + res.status + " (" + (res.payment_intent_id || "") + ")";
    setTimeout(refreshBillingAll, 800);
  } catch (e) {
    document.getElementById("stripe_pay_result").innerText = "Error: " + String(e);
  }
}

async function loadBillingLedger() {
  const wrap = document.getElementById("stripe_ledger");
  wrap.innerHTML = "";
  try {
    const limitTxt = document.getElementById("stripe_ledger_limit").value.trim();
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

/* ===================== password recovery ===================== */
const passwordRecoveryState = {
  username: "",
  challengeId: null,
  required: [],
  totpDone: false,
  smsDone: false,
  emailDone: false,
  smsSentTo: [],
  emailSentTo: [],
  delivery: null,
  lastErr: "",
};

function resetPasswordRecoveryState() {
  passwordRecoveryState.challengeId = null;
  passwordRecoveryState.required = [];
  passwordRecoveryState.totpDone = false;
  passwordRecoveryState.smsDone = false;
  passwordRecoveryState.emailDone = false;
  passwordRecoveryState.smsSentTo = [];
  passwordRecoveryState.emailSentTo = [];
  passwordRecoveryState.delivery = null;
  passwordRecoveryState.lastErr = "";
}

function renderPasswordRecovery() {
  const deliveryEl = document.getElementById("pwRecoveryDelivery");
  const challengeEl = document.getElementById("pwRecoveryChallenge");
  const challengesEl = document.getElementById("pwRecoveryChallenges");
  const msgEl = document.getElementById("pwRecoveryMsg");
  if (!deliveryEl || !challengeEl || !challengesEl || !msgEl) return;

  if (passwordRecoveryState.delivery) {
    deliveryEl.textContent = `Delivery: ${passwordRecoveryState.delivery}`;
  } else {
    deliveryEl.textContent = "";
  }

  if (passwordRecoveryState.challengeId) {
    challengeEl.innerHTML = `Challenge: <code class="mono">${passwordRecoveryState.challengeId}</code>`;
  } else if (passwordRecoveryState.required.length) {
    challengeEl.textContent = "Challenge required but not started.";
  } else {
    challengeEl.textContent = "";
  }

  const req = passwordRecoveryState.required;
  if (!req.length) {
    challengesEl.innerHTML = "";
  } else {
    const badge = (done) => done ? `<span class="pill">✅ verified</span>` : `<span class="pill">required</span>`;
    const totpSection = req.includes("totp") ? `
      <div style="border:1px solid #eee; padding:10px; border-radius:10px; margin-top:10px;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
          <div><b>TOTP</b> ${badge(passwordRecoveryState.totpDone)}</div>
        </div>
        <input id="pwRecoveryTotpCode" placeholder="123456" inputmode="numeric" autocomplete="one-time-code"
               ${passwordRecoveryState.totpDone ? "disabled" : ""} />
        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
          <button id="pwRecoveryTotpVerifyBtn" ${passwordRecoveryState.totpDone ? "disabled" : ""}>Verify TOTP</button>
          <button id="pwRecoveryTotpRecoveryBtn" ${passwordRecoveryState.totpDone ? "disabled" : ""}>Use TOTP recovery</button>
        </div>
      </div>
    ` : "";

    const smsSection = req.includes("sms") ? `
      <div style="border:1px solid #eee; padding:10px; border-radius:10px; margin-top:10px;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
          <div><b>SMS</b> ${badge(passwordRecoveryState.smsDone)}</div>
          <button id="pwRecoverySmsSendBtn" ${passwordRecoveryState.smsDone ? "disabled" : ""}>
            ${passwordRecoveryState.smsSentTo.length ? "Resend SMS" : "Send SMS"}
          </button>
        </div>
        <div style="margin-top:6px;">
          ${passwordRecoveryState.smsSentTo.length
            ? `<small>Sent to: ${passwordRecoveryState.smsSentTo.map(x=>`<code>${x}</code>`).join(" ")}</small>`
            : `<small>We will text a code to all your enabled numbers.</small>`}
        </div>
        <input id="pwRecoverySmsCode" placeholder="SMS code" inputmode="numeric" autocomplete="one-time-code"
               ${passwordRecoveryState.smsDone ? "disabled" : ""} />
        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
          <button id="pwRecoverySmsVerifyBtn" ${passwordRecoveryState.smsDone ? "disabled" : ""}>Verify SMS</button>
          <button id="pwRecoverySmsRecoveryBtn" ${passwordRecoveryState.smsDone ? "disabled" : ""}>Use SMS recovery</button>
        </div>
      </div>
    ` : "";

    const emailSection = req.includes("email") ? `
      <div style="border:1px solid #eee; padding:10px; border-radius:10px; margin-top:10px;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
          <div><b>Email</b> ${badge(passwordRecoveryState.emailDone)}</div>
          <button id="pwRecoveryEmailSendBtn" ${passwordRecoveryState.emailDone ? "disabled" : ""}>
            ${passwordRecoveryState.emailSentTo.length ? "Resend Email" : "Send Email"}
          </button>
        </div>
        <div style="margin-top:6px;">
          ${passwordRecoveryState.emailSentTo.length
            ? `<small>Sent to: ${passwordRecoveryState.emailSentTo.map(x=>`<code>${x}</code>`).join(" ")}</small>`
            : `<small>We will email a code to all your enabled addresses.</small>`}
        </div>
        <input id="pwRecoveryEmailCode" placeholder="Email code" inputmode="numeric" autocomplete="one-time-code"
               ${passwordRecoveryState.emailDone ? "disabled" : ""} />
        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;">
          <button id="pwRecoveryEmailVerifyBtn" ${passwordRecoveryState.emailDone ? "disabled" : ""}>Verify Email</button>
          <button id="pwRecoveryEmailRecoveryBtn" ${passwordRecoveryState.emailDone ? "disabled" : ""}>Use Email recovery</button>
        </div>
      </div>
    ` : "";

    challengesEl.innerHTML = `${totpSection}${smsSection}${emailSection}`;
  }

  msgEl.textContent = passwordRecoveryState.lastErr || "";

  const setError = (e) => {
    passwordRecoveryState.lastErr = String(e);
    renderPasswordRecovery();
  };

  if (req.includes("totp")) {
    const verifyBtn = document.getElementById("pwRecoveryTotpVerifyBtn");
    const recoveryBtn = document.getElementById("pwRecoveryTotpRecoveryBtn");
    if (verifyBtn) verifyBtn.onclick = async () => {
      try {
        const code = (document.getElementById("pwRecoveryTotpCode").value || "").trim();
        await apiPublic("/ui/password-recovery/challenge/totp/verify", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId, totp_code: code },
        });
        passwordRecoveryState.totpDone = true;
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
    if (recoveryBtn) recoveryBtn.onclick = async () => {
      const rc = prompt("Enter a TOTP recovery code:") || "";
      if (!rc.trim()) return;
      try {
        await apiPublic("/ui/password-recovery/challenge/recovery", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId, factor: "totp", recovery_code: rc.trim() },
        });
        passwordRecoveryState.totpDone = true;
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
  }

  if (req.includes("sms")) {
    const sendBtn = document.getElementById("pwRecoverySmsSendBtn");
    const verifyBtn = document.getElementById("pwRecoverySmsVerifyBtn");
    const recoveryBtn = document.getElementById("pwRecoverySmsRecoveryBtn");
    if (sendBtn) sendBtn.onclick = async () => {
      try {
        const res = await apiPublic("/ui/password-recovery/challenge/sms/begin", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId },
        });
        passwordRecoveryState.smsSentTo = res.sent_to || [];
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
    if (verifyBtn) verifyBtn.onclick = async () => {
      try {
        const code = (document.getElementById("pwRecoverySmsCode").value || "").trim();
        await apiPublic("/ui/password-recovery/challenge/sms/verify", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId, code },
        });
        passwordRecoveryState.smsDone = true;
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
    if (recoveryBtn) recoveryBtn.onclick = async () => {
      const rc = prompt("Enter an SMS recovery code:") || "";
      if (!rc.trim()) return;
      try {
        await apiPublic("/ui/password-recovery/challenge/recovery", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId, factor: "sms", recovery_code: rc.trim() },
        });
        passwordRecoveryState.smsDone = true;
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
  }

  if (req.includes("email")) {
    const sendBtn = document.getElementById("pwRecoveryEmailSendBtn");
    const verifyBtn = document.getElementById("pwRecoveryEmailVerifyBtn");
    const recoveryBtn = document.getElementById("pwRecoveryEmailRecoveryBtn");
    if (sendBtn) sendBtn.onclick = async () => {
      try {
        const res = await apiPublic("/ui/password-recovery/challenge/email/begin", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId },
        });
        passwordRecoveryState.emailSentTo = res.sent_to || [];
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
    if (verifyBtn) verifyBtn.onclick = async () => {
      try {
        const code = (document.getElementById("pwRecoveryEmailCode").value || "").trim();
        await apiPublic("/ui/password-recovery/challenge/email/verify", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId, code },
        });
        passwordRecoveryState.emailDone = true;
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
    if (recoveryBtn) recoveryBtn.onclick = async () => {
      const rc = prompt("Enter an Email recovery code:") || "";
      if (!rc.trim()) return;
      try {
        await apiPublic("/ui/password-recovery/challenge/recovery", {
          method: "POST",
          body: { username: passwordRecoveryState.username, challenge_id: passwordRecoveryState.challengeId, factor: "email", recovery_code: rc.trim() },
        });
        passwordRecoveryState.emailDone = true;
        renderPasswordRecovery();
      } catch (e) { setError(e); }
    };
  }
}

async function startPasswordRecovery() {
  const username = (document.getElementById("pwRecoveryUsername").value || "").trim();
  if (!username) {
    passwordRecoveryState.lastErr = "Username required.";
    renderPasswordRecovery();
    return;
  }
  resetPasswordRecoveryState();
  passwordRecoveryState.username = username;
  try {
    const res = await apiPublic("/ui/password-recovery/start", {
      method: "POST",
      body: { username },
    });
    const delivery = [res.delivery_medium, res.delivery_destination].filter(Boolean).join(" • ");
    passwordRecoveryState.delivery = delivery || null;
    passwordRecoveryState.challengeId = res.challenge_id || null;
    passwordRecoveryState.required = res.required_factors || [];
    passwordRecoveryState.lastErr = "";
  } catch (e) {
    passwordRecoveryState.lastErr = String(e);
  }
  renderPasswordRecovery();
}

async function confirmPasswordRecovery() {
  const username = (document.getElementById("pwRecoveryUsername").value || "").trim();
  const code = (document.getElementById("pwRecoveryCode").value || "").trim();
  const newPassword = (document.getElementById("pwRecoveryNewPassword").value || "").trim();
  if (!username || !code || !newPassword) {
    passwordRecoveryState.lastErr = "Username, confirmation code, and new password are required.";
    renderPasswordRecovery();
    return;
  }
  try {
    await apiPublic("/ui/password-recovery/confirm", {
      method: "POST",
      body: {
        username,
        confirmation_code: code,
        new_password: newPassword,
        challenge_id: passwordRecoveryState.challengeId,
      },
    });
    passwordRecoveryState.lastErr = "Password updated. You can now log in.";
  } catch (e) {
    passwordRecoveryState.lastErr = String(e);
  }
  renderPasswordRecovery();
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

/* ===================== Account closure ===================== */
async function accountClosureStart() {
  return await apiPost("/ui/account/closure/start", {});
}

async function accountClosureFinalize(challenge_id) {
  return await apiPost("/ui/account/closure/finalize", { challenge_id });
}

function handleAccountClosureSuccess() {
  clearAuthTokens();
  alert("Account permanently closed. All data deleted for this user.");
  window.location.reload();
}

function clearAuthTokens() {
  lsDel("access_token");
  lsDel("id_token");
  lsDel("refresh_token");
  lsDel("session_id");
}

async function runAccountClosureChallenge(challengeId, required) {
  const needTotp = (required || []).includes("totp");
  const needSms = (required || []).includes("sms");
  const needEmail = (required || []).includes("email");

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
      needTotp,
      needSms,
      needEmail,
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

    async function tryFinalizeOrClose() {
      const res = await accountClosureFinalize(challengeId);
      if (res && res.status === "closed") {
        modalClose();
        handleAccountClosureSuccess();
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
        title: "Account permanent closure",
        bodyHtml: `
          <div>Complete all required factors to permanently close your account.</div>
          <div class="muted" style="margin-top:6px;">This action cannot be undone and removes all stored data.</div>
          <div style="margin-top:6px;"><small>Challenge: <code class="mono">${challengeId}</code></small></div>
          ${totpSection}${smsSection}${emailSection}
          <div id="closeErr" class="err" style="margin-top:10px;">${state.lastErr || ""}</div>
        `,
        actions: [
          { text: "Cancel", onClick: () => { modalClose(); reject(new Error("Account closure cancelled")); } }
        ]
      });

      if (state.needTotp) {
        const v = document.getElementById("totpVerifyBtn");
        const r = document.getElementById("totpRecoveryBtn");
        if (v) v.onclick = async () => {
          state.lastErr = ""; render();
          try {
            const code = document.getElementById("totpCode").value.trim();
            await postBearer("/ui/mfa/totp/verify", { challenge_id: challengeId, totp_code: code });
            if (await tryFinalizeOrClose()) return;
            state.totpDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
        if (r) r.onclick = async () => {
          const rc = prompt("Enter a TOTP recovery code:") || "";
          if (!rc.trim()) return;
          state.lastErr = ""; render();
          try {
            await postBearer("/ui/recovery/totp", { challenge_id: challengeId, recovery_code: rc.trim() });
            if (await tryFinalizeOrClose()) return;
            state.totpDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
      }

      if (state.needSms) {
        const resend = document.getElementById("smsResendBtn");
        const verify = document.getElementById("smsVerifyBtn");
        const recov = document.getElementById("smsRecoveryBtn");

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
            await postBearer("/ui/mfa/sms/verify", { challenge_id: challengeId, code });
            if (await tryFinalizeOrClose()) return;
            state.smsDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };

        if (recov) recov.onclick = async () => {
          const rc = prompt("Enter an SMS recovery code:") || "";
          if (!rc.trim()) return;
          state.lastErr = ""; render();
          try {
            await postBearer("/ui/recovery/sms", { challenge_id: challengeId, recovery_code: rc.trim() });
            if (await tryFinalizeOrClose()) return;
            state.smsDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
      }

      if (state.needEmail) {
        const resend = document.getElementById("emailResendBtn");
        const verify = document.getElementById("emailVerifyBtn");
        const recov = document.getElementById("emailRecoveryBtn");

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
            await postBearer("/ui/mfa/email/verify", { challenge_id: challengeId, code });
            if (await tryFinalizeOrClose()) return;
            state.emailDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };

        if (recov) recov.onclick = async () => {
          const rc = prompt("Enter an Email recovery code:") || "";
          if (!rc.trim()) return;
          state.lastErr = ""; render();
          try {
            await postBearer("/ui/recovery/email", { challenge_id: challengeId, recovery_code: rc.trim() });
            if (await tryFinalizeOrClose()) return;
            state.emailDone = true; render();
          } catch (e) { state.lastErr = String(e); render(); }
        };
      }

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

/* ===================== Account Status ===================== */
async function loadAccountStatus() {
  await ensureUiSession();
  return await apiGet("/ui/account/status");
}

async function requestAccountSuspension(reason) {
  await ensureUiSession();
  return await apiPost("/ui/account/suspend", { reason });
}

async function requestAccountReactivation(reason) {
  await ensureUiSession();
  return await apiPost("/ui/account/reactivate", { reason });
}

function renderAccountStatus(state) {
  const pill = document.getElementById("accountStatusPill");
  const meta = document.getElementById("accountStatusMeta");
  const reasonEl = document.getElementById("accountStatusReason");
  const suspendBtn = document.getElementById("accountSuspendBtn");
  const reactivateBtn = document.getElementById("accountReactivateBtn");
  if (!pill || !meta || !reasonEl || !suspendBtn || !reactivateBtn) return;

  const status = (state && state.status) ? state.status : "active";
  const statusMap = {
    active: { label: "Active", pill: "ok", meta: "No pending suspension or reactivation requests." },
    suspension_requested: { label: "Suspension requested", pill: "warn", meta: "Suspension request submitted." },
    reactivation_requested: { label: "Reactivation requested", pill: "warn", meta: "Reactivation request submitted." },
  };
  const info = statusMap[status] || { label: status, pill: "warn", meta: "" };

  pill.textContent = info.label;
  pill.className = `pill ${info.pill}`;
  const updatedAt = state && state.updated_at ? fmtTs(state.updated_at) : "";
  meta.textContent = updatedAt ? `${info.meta} Last updated ${updatedAt}.` : info.meta;
  reasonEl.textContent = state && state.reason ? `Reason: ${state.reason}` : "";

  suspendBtn.disabled = status !== "active";
  reactivateBtn.disabled = status === "active" || status === "reactivation_requested";
}

async function refreshAccountStatus() {
  const msg = document.getElementById("accountStatusMsg");
  if (msg) msg.textContent = "";
  try {
    const state = await loadAccountStatus();
    renderAccountStatus(state);
  } catch (e) {
    if (msg) msg.textContent = String(e);
  }
}

function openAccountActionModal({ title, confirmText, onConfirm }) {
  modalShow({
    title,
    bodyHtml: `
      <div class="muted">Add a short reason for this request (optional).</div>
      <textarea id="accountActionReason" rows="3" placeholder="Reason (optional)"></textarea>
      <div id="accountActionErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: confirmText, onClick: async () => {
          try {
            const reason = document.getElementById("accountActionReason").value.trim();
            await onConfirm(reason);
            modalClose();
            await refreshAccountStatus();
          } catch (e) {
            document.getElementById("accountActionErr").textContent = String(e);
          }
      }},
    ]
  });
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
      refreshAccountStatus(),
      refreshAlertEmailSettings(),
      refreshPushUI(),
      refreshAlerts(),
      refreshProfile(),
      refreshFileManager(),
      refreshAddresses(),
      refreshShoppingCart(),
      billingRefreshAll(),
      refreshCalendarEvents(),
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

/* ===================== calendar ===================== */
function getCalendarId() {
  return lsGet("calendar_id") || "";
}

function setCalendarId(calendarId) {
  if (calendarId) {
    lsSet("calendar_id", calendarId);
  } else {
    lsDel("calendar_id");
  }
  const input = document.getElementById("calendarIdInput");
  if (input) input.value = calendarId || "";
}

function setCalendarStatus(msg) {
  const el = document.getElementById("calendarStatus");
  if (el) el.textContent = msg || "";
}

function renderCalendarEvents(events) {
  const wrap = document.getElementById("calendarEventsList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!events || events.length === 0) {
    wrap.innerHTML = '<div class="muted">No events yet.</div>';
    return;
  }
  events.forEach(evt => {
    const row = document.createElement("div");
    row.className = "item";
    const when = evt.all_day
      ? `All day ${escapeHtml(evt.all_day_date || "")}`
      : `${escapeHtml(evt.start_utc || "")} → ${escapeHtml(evt.end_utc || "")}`;
    row.innerHTML = `
      <div class="row">
        <div class="grow"><b>${escapeHtml(evt.name || "")}</b></div>
        <div class="mono">${escapeHtml(evt.event_id || "")}</div>
      </div>
      <div class="muted">${when} (${escapeHtml(evt.timezone || "")})</div>
      ${evt.description ? `<div class="muted">${escapeHtml(evt.description)}</div>` : ""}
    `;
    wrap.appendChild(row);
  });
}

function renderCalendarOpenings(openings) {
  const wrap = document.getElementById("calendarOpeningsList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!openings || openings.length === 0) {
    wrap.innerHTML = '<div class="muted">No openings for selected window.</div>';
    return;
  }
  openings.forEach(o => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `<div class="mono">${escapeHtml(o.start_utc)} → ${escapeHtml(o.end_utc)}</div>`;
    wrap.appendChild(row);
  });
}

async function createCalendar() {
  try {
    await ensureUiSession();
    const name = document.getElementById("calendarNameInput").value.trim() || "My Calendar";
    const timezone = document.getElementById("calendarTimezoneInput").value.trim() || "UTC";
    const res = await apiPost("/ui/calendars", { name, timezone });
    setCalendarId(res.calendar_id || "");
    setCalendarStatus(`Created calendar ${res.calendar_id}`);
    await refreshCalendarEvents();
  } catch (e) {
    setCalendarStatus("Error: " + e.message);
  }
}

async function refreshCalendarEvents() {
  const calendarId = getCalendarId();
  if (!calendarId) return;
  await ensureUiSession();
  const events = await apiGet(`/ui/calendars/${encodeURIComponent(calendarId)}/events`);
  renderCalendarEvents(events || []);
}

async function createCalendarEvent() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    setCalendarStatus("Set a calendar ID first.");
    return;
  }
  try {
    await ensureUiSession();
    const payload = {
      name: document.getElementById("eventNameInput").value.trim(),
      description: document.getElementById("eventDescriptionInput").value.trim(),
      timezone: document.getElementById("eventTimezoneInput").value.trim() || null,
      all_day: document.getElementById("eventAllDayToggle").checked,
      all_day_date: document.getElementById("eventAllDayDateInput").value || null,
      start_utc: document.getElementById("eventStartInput").value.trim() || null,
      end_utc: document.getElementById("eventEndInput").value.trim() || null,
    };
    const res = await apiPost(`/ui/calendars/${encodeURIComponent(calendarId)}/events`, payload);
    document.getElementById("eventCreateStatus").textContent = `Added event ${res.event_id}`;
    await refreshCalendarEvents();
  } catch (e) {
    document.getElementById("eventCreateStatus").textContent = "Error: " + e.message;
  }
}

async function loadCalendarOpenings() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    setCalendarStatus("Set a calendar ID first.");
    return;
  }
  const start = document.getElementById("openingsStartInput").value.trim();
  const end = document.getElementById("openingsEndInput").value.trim();
  if (!start || !end) {
    setCalendarStatus("Enter start and end window.");
    return;
  }
  try {
    await ensureUiSession();
    const qs = `?start_utc=${encodeURIComponent(start)}&end_utc=${encodeURIComponent(end)}`;
    const res = await apiGet(`/ui/calendars/${encodeURIComponent(calendarId)}/openings${qs}`);
    renderCalendarOpenings(res || []);
  } catch (e) {
    setCalendarStatus("Error: " + e.message);
  }
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

/* ===================== Newsfeed ===================== */
const newsfeedState = {
  feedCursor: null,
  feedItems: [],
  commentItems: [],
  commentsCursor: null,
  activePostId: null,
  notifCursor: null,
  sse: null,
};

function newsfeedApiBase() {
  const base = readInput("newsfeedApiBase") || API_BASE;
  return base.replace(/\/+$/, "");
}

function newsfeedUserId() {
  return readInput("newsfeedUserId");
}

function setNewsfeedStatus(msg) {
  const el = document.getElementById("newsfeedStatus");
  if (el) el.textContent = msg || "";
}

function setNewsfeedCommentStatus(msg) {
  const el = document.getElementById("newsfeedCommentStatus");
  if (el) el.textContent = msg || "";
}

async function newsfeedRequest(path, { method = "GET", qs = null, body = null } = {}) {
  const base = newsfeedApiBase();
  const url = new URL(`${base}${path}`, window.location.origin);
  if (qs) {
    Object.entries(qs).forEach(([k, v]) => {
      if (v !== null && v !== undefined && v !== "") url.searchParams.set(k, v);
    });
  }
  const headers = {};
  const uid = newsfeedUserId();
  if (uid) headers["X-User-Id"] = uid;
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(url.toString(), {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (e) {
    data = text;
  }
  if (!res.ok) {
    throw new Error(data?.detail || text || `Request failed: ${res.status}`);
  }
  return data;
}

function newsfeedBodyText(body) {
  if (!body) return "";
  if (body.doc && typeof body.doc.text === "string") return body.doc.text;
  if (body.doc && body.doc.locked) return "🔒 Locked content";
  return JSON.stringify(body.doc || body);
}

function setActivePost(postId) {
  newsfeedState.activePostId = postId;
  newsfeedState.commentsCursor = null;
  newsfeedState.commentItems = [];
  const label = document.getElementById("newsfeedActivePostLabel");
  if (label) {
    label.textContent = postId ? `Post ${postId}` : "No post selected";
  }
}

function renderNewsfeed(items) {
  const wrap = document.getElementById("newsfeedList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!items || items.length === 0) {
    wrap.innerHTML = '<div class="muted">No feed items.</div>';
    return;
  }
  items.forEach(item => {
    const el = document.createElement("div");
    el.className = "item newsfeed-item";
    const locked = item.body?.doc?.locked;
    const unlockPrice = item.unlock_price_cents ? `${item.unlock_price_cents}¢` : "—";
    el.innerHTML = `
      <div class="row">
        <div class="grow"><b>${escapeHtml(item.user_id || "")}</b></div>
        <div class="mono">${escapeHtml(item.post_id || "")}</div>
      </div>
      <div class="newsfeed-meta">
        <span>${escapeHtml(item.created_at || "")}</span>
        <span>comments: ${escapeHtml(item.comment_count ?? 0)}</span>
        ${locked ? `<span class="pill warn">locked ${escapeHtml(unlockPrice)}</span>` : ""}
      </div>
      <div class="newsfeed-body">${escapeHtml(newsfeedBodyText(item.body))}</div>
      <div class="newsfeed-actions">
        <button data-action="comments" data-id="${escapeHtml(item.post_id)}">View comments</button>
        <button data-action="hide" data-id="${escapeHtml(item.post_id)}">Hide</button>
        ${locked ? `<button data-action="unlock" data-id="${escapeHtml(item.post_id)}">Unlock</button>` : ""}
        ${item.user_id && item.user_id !== newsfeedUserId() ? `
          <button data-action="unfollow" data-user="${escapeHtml(item.user_id)}">Unfollow</button>
          <button data-action="refollow" data-user="${escapeHtml(item.user_id)}">Refollow</button>
        ` : ""}
      </div>
    `;
    wrap.appendChild(el);
  });

  wrap.querySelectorAll("button[data-action]").forEach(btn => {
    btn.onclick = async () => {
      const action = btn.getAttribute("data-action");
      const postId = btn.getAttribute("data-id");
      const userId = btn.getAttribute("data-user");
      try {
        if (action === "comments" && postId) {
          setActivePost(postId);
          await loadNewsfeedComments(true);
        } else if (action === "hide" && postId) {
          await newsfeedRequest("/feed/hide", { method: "POST", body: { post_id: postId } });
          await refreshNewsfeed(true);
        } else if (action === "unlock" && postId) {
          await newsfeedRequest("/posts/unlock", { method: "POST", body: { post_id: postId } });
          await refreshNewsfeed(true);
        } else if (action === "unfollow" && userId) {
          await newsfeedRequest("/social/unfollow", { method: "POST", body: { target_user_id: userId } });
          await refreshNewsfeed(true);
        } else if (action === "refollow" && userId) {
          await newsfeedRequest("/social/refollow", { method: "POST", body: { target_user_id: userId } });
          await refreshNewsfeed(true);
        }
      } catch (e) {
        setNewsfeedStatus(String(e.message || e));
      }
    };
  });
}

function applyNewsfeedPage(result, { listKey, cursorKey, reset }) {
  const items = result?.items || [];
  if (reset) {
    newsfeedState[listKey] = items;
  } else {
    newsfeedState[listKey] = newsfeedState[listKey].concat(items);
  }
  newsfeedState[cursorKey] = result?.next_cursor || null;
  return items;
}

async function refreshNewsfeed(reset = false) {
  if (!newsfeedUserId()) {
    setNewsfeedStatus("Set a user ID first.");
    return;
  }
  if (reset) newsfeedState.feedCursor = null;
  const res = await newsfeedRequest("/feed", {
    qs: { limit: 20, cursor: newsfeedState.feedCursor },
  });
  const items = applyNewsfeedPage(res, {
    listKey: "feedItems",
    cursorKey: "feedCursor",
    reset,
  });
  renderNewsfeed(newsfeedState.feedItems);
  setNewsfeedStatus(`Loaded ${items.length} items.`);
}

async function createNewsfeedPost() {
  if (!newsfeedUserId()) {
    setNewsfeedStatus("Set a user ID first.");
    return;
  }
  const text = readInput("newsfeedPostText");
  if (!text) {
    setNewsfeedStatus("Enter post text.");
    return;
  }
  const unlockPriceRaw = readInput("newsfeedPostUnlockPrice");
  const unlockPrice = unlockPriceRaw ? parseInt(unlockPriceRaw, 10) : null;
  const body = { format: "plain-v1", doc: { text } };
  await newsfeedRequest("/posts", {
    method: "POST",
    body: {
      body,
      attachments: [],
      visibility: "followers",
      unlock_price_cents: Number.isFinite(unlockPrice) ? unlockPrice : null,
    },
  });
  setInputValue("newsfeedPostText", "");
  setInputValue("newsfeedPostUnlockPrice", "");
  await refreshNewsfeed(true);
}

function renderComments(items) {
  const wrap = document.getElementById("newsfeedCommentsList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!items || items.length === 0) {
    wrap.innerHTML = '<div class="muted">No comments yet.</div>';
    return;
  }
  items.forEach(item => {
    const row = document.createElement("div");
    row.className = "item newsfeed-item";
    const bodyText = item.deleted ? "Comment deleted" : newsfeedBodyText(item.body);
    row.innerHTML = `
      <div class="row">
        <div class="grow"><b>${escapeHtml(item.user_id || "")}</b></div>
        <div class="mono">${escapeHtml(item.comment_id || "")}</div>
      </div>
      <div class="newsfeed-meta">
        <span>${escapeHtml(item.created_at || "")}</span>
        ${item.parent_comment_id ? `<span>reply to ${escapeHtml(item.parent_comment_id)}</span>` : ""}
      </div>
      <div class="newsfeed-body">${escapeHtml(bodyText)}</div>
      <div class="newsfeed-actions">
        <button data-action="delete" data-id="${escapeHtml(item.comment_id)}">Delete</button>
      </div>
    `;
    wrap.appendChild(row);
  });

  wrap.querySelectorAll("button[data-action='delete']").forEach(btn => {
    btn.onclick = async () => {
      const commentId = btn.getAttribute("data-id");
      if (!commentId || !newsfeedState.activePostId) return;
      try {
        await newsfeedRequest(`/posts/${encodeURIComponent(newsfeedState.activePostId)}/comments/${encodeURIComponent(commentId)}`, {
          method: "DELETE",
        });
        await loadNewsfeedComments(true);
      } catch (e) {
        setNewsfeedCommentStatus(String(e.message || e));
      }
    };
  });
}

async function loadNewsfeedComments(reset = false) {
  if (!newsfeedState.activePostId) {
    setNewsfeedCommentStatus("Select a post first.");
    return;
  }
  if (reset) newsfeedState.commentsCursor = null;
  const res = await newsfeedRequest(`/posts/${encodeURIComponent(newsfeedState.activePostId)}/comments`, {
    qs: { limit: 20, cursor: newsfeedState.commentsCursor },
  });
  const items = applyNewsfeedPage(res, {
    listKey: "commentItems",
    cursorKey: "commentsCursor",
    reset,
  });
  renderComments(newsfeedState.commentItems);
}

async function sendNewsfeedComment() {
  if (!newsfeedState.activePostId) {
    setNewsfeedCommentStatus("Select a post first.");
    return;
  }
  const text = readInput("newsfeedCommentText");
  if (!text) {
    setNewsfeedCommentStatus("Enter a comment.");
    return;
  }
  const body = { format: "plain-v1", doc: { text } };
  await newsfeedRequest(`/posts/${encodeURIComponent(newsfeedState.activePostId)}/comments`, {
    method: "POST",
    body: { body },
  });
  setInputValue("newsfeedCommentText", "");
  await loadNewsfeedComments(true);
  setNewsfeedCommentStatus("Comment sent.");
}

function renderNewsfeedNotifs(items) {
  const wrap = document.getElementById("newsfeedNotifsList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!items || items.length === 0) {
    wrap.innerHTML = '<div class="muted">No notifications.</div>';
    return;
  }
  items.forEach(item => {
    const row = document.createElement("div");
    row.className = "item newsfeed-item";
    row.innerHTML = `
      <div class="row">
        <div class="grow"><b>${escapeHtml(item.type || "")}</b></div>
        <div class="mono">${escapeHtml(item.notif_id || "")}</div>
      </div>
      <div class="newsfeed-meta">${escapeHtml(item.created_at || "")}</div>
      <div class="newsfeed-body">${escapeHtml(JSON.stringify(item.payload || {}))}</div>
    `;
    wrap.appendChild(row);
  });
}

async function refreshNewsfeedNotifs(reset = true) {
  if (!newsfeedUserId()) {
    setNewsfeedStatus("Set a user ID first.");
    return;
  }
  if (reset) newsfeedState.notifCursor = null;
  const res = await newsfeedRequest("/notifications", {
    qs: { limit: 20, cursor: newsfeedState.notifCursor },
  });
  renderNewsfeedNotifs(res?.items || []);
  newsfeedState.notifCursor = res?.next_cursor || null;
}

function logNewsfeedSse(msg) {
  const el = document.getElementById("newsfeedSseLog");
  if (!el) return;
  const line = `[${new Date().toISOString()}] ${msg}`;
  el.textContent = (el.textContent ? `${el.textContent}\n${line}` : line);
  el.scrollTop = el.scrollHeight;
}

function disconnectNewsfeedSse() {
  if (newsfeedState.sse) {
    newsfeedState.sse.close();
    newsfeedState.sse = null;
  }
}

function connectNewsfeedSse() {
  disconnectNewsfeedSse();
  if (!newsfeedUserId()) {
    setNewsfeedStatus("Set a user ID first.");
    return;
  }
  const url = `${newsfeedApiBase()}/sse?user_id=${encodeURIComponent(newsfeedUserId())}`;
  const es = new EventSource(url);
  newsfeedState.sse = es;
  logNewsfeedSse("Connecting to SSE...");
  es.onmessage = (ev) => {
    try {
      const payload = JSON.parse(ev.data || "{}");
      logNewsfeedSse(JSON.stringify(payload));
    } catch (e) {
      logNewsfeedSse(ev.data || "");
    }
  };
  es.onerror = () => {
    logNewsfeedSse("SSE connection error.");
  };
}

/* ===================== Profile ===================== */
let profileLanguages = [];
let addressBook = [];
let selectedAddressId = null;

function setProfileStatus(msg) {
  const el = document.getElementById("profileStatus");
  if (el) el.textContent = msg || "";
}

function setProfileAuditStatus(msg) {
  const el = document.getElementById("profileAuditStatus");
  if (el) el.textContent = msg || "";
}

function readInput(id) {
  const el = document.getElementById(id);
  if (!el) return "";
  return (el.value || "").trim();
}

function readInputOrNull(id) {
  const v = readInput(id);
  return v ? v : null;
}

function setInputValue(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.value = value || "";
}

/* ===================== Messaging ===================== */
const messagingState = {
  conversations: [],
  activeConversationId: null,
};

function msgApiBase() {
  const base = readInput("msgApiBase");
  return (base || API_BASE).replace(/\/$/, "");
}

function msgUserId() {
  return readInput("msgUserId");
}

function setMsgStatus(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg || "";
}

async function msgRequest(path, { method = "GET", body = null } = {}) {
  const uid = msgUserId();
  const headers = {};
  if (uid) {
    headers.Authorization = `Bearer ${uid}`;
  } else {
    const tok = accessToken();
    if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
    const sid = sessionId();
    if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
    headers.Authorization = `Bearer ${tok}`;
    headers["X-SESSION-ID"] = sid;
  }
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(`${msgApiBase()}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json();
}

function renderMessagingConvos() {
  const list = document.getElementById("msgConvoList");
  if (!list) return;
  list.innerHTML = "";
  if (!messagingState.conversations.length) {
    list.innerHTML = "<div class='muted'>No conversations yet.</div>";
    return;
  }
  messagingState.conversations.forEach((c) => {
    const row = document.createElement("div");
    row.className = "list-item";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "list-button";
    btn.innerHTML = `
      <div style="text-align:left;">
        <div><b>${c.title || c.conversation_id}</b></div>
        <div class="muted">${c.type} • ${c.status} • participants ${c.participant_count}</div>
        <div class="muted">${c.last_message_preview || "No messages yet"}</div>
      </div>
    `;
    if (messagingState.activeConversationId === c.conversation_id) {
      btn.style.borderColor = "#111";
    }
    btn.onclick = () => {
      messagingState.activeConversationId = c.conversation_id;
      const label = document.getElementById("msgActiveConvoLabel");
      if (label) label.textContent = c.title || c.conversation_id;
      renderMessagingConvos();
    };
    row.appendChild(btn);
    list.appendChild(row);
  });
}

function renderMessagingMessages(messages) {
  const list = document.getElementById("msgMessagesList");
  if (!list) return;
  list.innerHTML = "";
  if (!messages.length) {
    list.innerHTML = "<div class='muted'>No messages yet.</div>";
    return;
  }
  messages.forEach((m) => {
    const row = document.createElement("div");
    row.className = "item";
    const body = m.kind === "image"
      ? `<em>[image]</em> ${m.image ? (m.image.key || "") : ""}`
      : (m.text || "");
    row.innerHTML = `
      <div class="muted">${m.sender_id} • ${new Date(m.created_at * 1000).toLocaleString()}</div>
      <div>${body}</div>
    `;
    list.appendChild(row);
  });
}

async function loadMessagingConvos() {
  setMsgStatus("msgGlobalStatus", "Loading...");
  try {
    const data = await msgRequest("/messaging/conversations");
    messagingState.conversations = data || [];
    if (!messagingState.conversations.find((c) => c.conversation_id === messagingState.activeConversationId)) {
      messagingState.activeConversationId = null;
      const label = document.getElementById("msgActiveConvoLabel");
      if (label) label.textContent = "No conversation selected";
    }
    renderMessagingConvos();
    setMsgStatus("msgGlobalStatus", "Loaded.");
  } catch (e) {
    setMsgStatus("msgGlobalStatus", String(e));
  }
}

async function createMessagingConvo() {
  setMsgStatus("msgConvoStatus", "Creating...");
  try {
    const participants = readInput("msgParticipants")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const payload = {
      participant_ids: participants,
      type: readInput("msgConvoType") || "dm",
      title: readInput("msgConvoTitle") || null,
    };
    const convo = await msgRequest("/messaging/conversations", { method: "POST", body: payload });
    messagingState.conversations.unshift(convo);
    messagingState.activeConversationId = convo.conversation_id;
    const label = document.getElementById("msgActiveConvoLabel");
    if (label) label.textContent = convo.title || convo.conversation_id;
    renderMessagingConvos();
    setMsgStatus("msgConvoStatus", "Created.");
  } catch (e) {
    setMsgStatus("msgConvoStatus", String(e));
  }
}

async function acceptMessagingConvo() {
  const cid = messagingState.activeConversationId;
  if (!cid) {
    setMsgStatus("msgConvoStatus", "Select a conversation first.");
    return;
  }
  setMsgStatus("msgConvoStatus", "Accepting...");
  try {
    await msgRequest(`/messaging/conversations/${cid}/accept`, { method: "POST", body: {} });
    await loadMessagingConvos();
    setMsgStatus("msgConvoStatus", "Accepted.");
  } catch (e) {
    setMsgStatus("msgConvoStatus", String(e));
  }
}

async function loadMessagingMessages() {
  const cid = messagingState.activeConversationId;
  if (!cid) {
    setMsgStatus("msgMessageStatus", "Select a conversation first.");
    return;
  }
  setMsgStatus("msgMessageStatus", "Loading...");
  try {
    const data = await msgRequest(`/messaging/conversations/${cid}/messages?limit=50`);
    renderMessagingMessages(data || []);
    setMsgStatus("msgMessageStatus", "Loaded.");
  } catch (e) {
    setMsgStatus("msgMessageStatus", String(e));
  }
}

async function sendMessagingMessage() {
  const cid = messagingState.activeConversationId;
  if (!cid) {
    setMsgStatus("msgMessageStatus", "Select a conversation first.");
    return;
  }
  const text = readInput("msgText");
  if (!text) {
    setMsgStatus("msgMessageStatus", "Message text required.");
    return;
  }
  setMsgStatus("msgMessageStatus", "Sending...");
  try {
    await msgRequest(`/messaging/conversations/${cid}/messages`, {
      method: "POST",
      body: { text },
    });
    setInputValue("msgText", "");
    await loadMessagingMessages();
    await loadMessagingConvos();
    setMsgStatus("msgMessageStatus", "Sent.");
  } catch (e) {
    setMsgStatus("msgMessageStatus", String(e));
  }
function setAddressStatus(msg) {
  const el = document.getElementById("addressStatus");
  if (el) el.textContent = msg || "";
}

function setAddressForm(address) {
  const addr = address || {};
  const postal = String(addr.postal_code || "");
  const zip5 = postal.includes("-") ? postal.split("-")[0] : postal.slice(0, 5);
  const zip4 = postal.includes("-") ? postal.split("-")[1] : postal.slice(5, 9);
  selectedAddressId = addr.address_id || null;
  setInputValue("addressName", addr.name);
  setInputValue("addressLabel", addr.label);
  setInputValue("addressLine1", addr.line1);
  setInputValue("addressLine2", addr.line2);
  setInputValue("addressCity", addr.city);
  setInputValue("addressState", addr.state);
  setInputValue("addressZip5", zip5 || "");
  setInputValue("addressZip4", zip4 || "");
  setInputValue("addressCountry", addr.country || "US");
  setInputValue("addressNotes", addr.notes);
}

function clearAddressForm() {
  selectedAddressId = null;
  setAddressForm({});
}

function buildAddressPayload() {
  const zip5 = readInputOrNull("addressZip5");
  const zip4 = readInputOrNull("addressZip4");
  const postalCode = zip5 ? (zip4 ? `${zip5}-${zip4}` : zip5) : null;
  return {
    name: readInputOrNull("addressName"),
    label: readInputOrNull("addressLabel"),
    line1: readInputOrNull("addressLine1"),
    line2: readInputOrNull("addressLine2"),
    city: readInputOrNull("addressCity"),
    state: readInputOrNull("addressState"),
    postal_code: postalCode,
    country: readInputOrNull("addressCountry"),
    notes: readInputOrNull("addressNotes"),
  };
}

function renderAddressList(addresses) {
  const el = document.getElementById("addressList");
  if (!el) return;
  el.innerHTML = "";
  (addresses || []).forEach((addr) => {
    const row = document.createElement("div");
    row.className = "list-item";
    const label = addr.label || addr.name || "Saved address";
    const meta = [
      addr.line1,
      addr.line2,
      [addr.city, addr.state].filter(Boolean).join(", "),
      addr.postal_code,
      addr.country,
    ].filter(Boolean).join(" · ");
    const primaryBadge = addr.is_primary_mailing
      ? `<span class="pill" style="font-size:11px;">Primary</span>`
      : "";
    row.innerHTML = `
      <div class="grow">
        <div><b>${escapeHtml(label)}</b> ${primaryBadge}</div>
        <div class="muted">${escapeHtml(meta)}</div>
      </div>
      <div class="row-inline">
        <button data-action="edit" data-id="${escapeHtml(addr.address_id)}">Edit</button>
        <button data-action="primary" data-id="${escapeHtml(addr.address_id)}">Set primary</button>
        <button class="danger" data-action="delete" data-id="${escapeHtml(addr.address_id)}">Delete</button>
      </div>
    `;
    row.querySelectorAll("button").forEach((btn) => {
      btn.onclick = async () => {
        const action = btn.getAttribute("data-action");
        const id = btn.getAttribute("data-id");
        if (action === "edit") {
          setAddressForm(addr);
          setAddressStatus("Editing address " + id);
          return;
        }
        if (action === "primary") {
          try {
            setAddressStatus("Setting primary...");
            await ensureUiSession();
            await apiPut("/ui/addresses/primary", { address_id: id });
            await refreshAddresses();
            setAddressStatus("Primary address updated.");
          } catch (e) {
            setAddressStatus(String(e));
          }
          return;
        }
        if (action === "delete") {
          if (!confirm("Delete this address?")) return;
          try {
            setAddressStatus("Deleting...");
            await ensureUiSession();
            await apiDelete(`/ui/addresses/${id}`);
            if (selectedAddressId === id) clearAddressForm();
            await refreshAddresses();
            setAddressStatus("Address deleted.");
          } catch (e) {
            setAddressStatus(String(e));
          }
        }
      };
    });
    el.appendChild(row);
  });
}

async function refreshAddresses() {
  await ensureUiSession();
  const res = await apiGet("/ui/addresses");
  addressBook = Array.isArray(res) ? res : [];
  renderAddressList(addressBook);
}

async function searchAddressBook(query) {
  await ensureUiSession();
  if (!query) {
    await refreshAddresses();
    return;
  }
  const res = await apiPost("/ui/addresses/search", { query });
  renderAddressList(res.matches || []);
}

async function saveAddress() {
  await ensureUiSession();
  const payload = buildAddressPayload();
  if (selectedAddressId) {
    const res = await apiPatch(`/ui/addresses/${selectedAddressId}`, payload);
    setAddressForm(res);
  } else {
    const res = await apiPost("/ui/addresses", payload);
    setAddressForm(res);
  }
  await refreshAddresses();
}

/* ===================== Shopping Cart ===================== */
const cartState = {
  carts: [],
  cartId: "",
  items: [],
  totalCents: 0,
};

function fmtIso(ts) {
  if (!ts) return "";
  try { return new Date(ts).toLocaleString(); } catch (e) { return String(ts); }
}

function setCartStatus(msg) {
  const el = document.getElementById("cartStatusMsg");
  if (el) el.textContent = msg || "";
}

function setCartTotal(cents) {
  const el = document.getElementById("cartTotal");
  if (!el) return;
  el.textContent = fmtMoney(cents || 0, "usd");
}

function updateCartMeta() {
  const statusEl = document.getElementById("cartStatus");
  const metaEl = document.getElementById("cartMeta");
  if (!statusEl || !metaEl) return;
  const cart = cartState.carts.find((c) => c.cart_id === cartState.cartId);
  if (!cart) {
    statusEl.textContent = "—";
    statusEl.className = "pill";
    metaEl.textContent = "";
    return;
  }
  statusEl.textContent = cart.status || "—";
  const statusClass = cart.status === "OPEN" ? "ok" : cart.status === "PURCHASED" ? "warn" : "bad";
  statusEl.className = `pill ${statusClass}`;
  const created = cart.created_at ? `Created ${fmtIso(cart.created_at)}` : "";
  const purchased = cart.purchased_at ? ` • Purchased ${fmtIso(cart.purchased_at)}` : "";
  metaEl.textContent = `${created}${purchased}`;
}

function renderCartSelect() {
  const sel = document.getElementById("cartSelect");
  if (!sel) return;
  sel.innerHTML = "";
  if (!cartState.carts.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "No carts";
    sel.appendChild(opt);
    cartState.cartId = "";
    updateCartMeta();
    return;
  }
  cartState.carts.forEach((cart) => {
    const opt = document.createElement("option");
    opt.value = cart.cart_id;
    opt.textContent = `${cart.cart_id.slice(0, 8)} (${cart.status})`;
    if (cart.cart_id === cartState.cartId) opt.selected = true;
    sel.appendChild(opt);
  });
  updateCartMeta();
}

async function refreshCartDetails() {
  if (!cartState.cartId) {
    renderCartItems([]);
    setCartTotal(0);
    return;
  }
  await ensureUiSession();
  const itemsResp = await apiGet(`/ui/shoppingcart/carts/${cartState.cartId}/items`);
  cartState.items = itemsResp.items || [];
  renderCartItems(cartState.items);
  const totalResp = await apiGet(`/ui/shoppingcart/carts/${cartState.cartId}/total`);
  cartState.totalCents = totalResp.total_cents || 0;
  setCartTotal(cartState.totalCents);
  updateCartMeta();
}

async function refreshShoppingCart() {
  const section = document.getElementById("shoppingCartSection");
  if (!section) return;
  await ensureUiSession();
  const carts = await apiGet("/ui/shoppingcart/carts");
  cartState.carts = Array.isArray(carts) ? carts : [];
  if (!cartState.cartId || !cartState.carts.find((c) => c.cart_id === cartState.cartId)) {
    const openCart = cartState.carts.find((c) => c.status === "OPEN");
    cartState.cartId = (openCart || cartState.carts[0] || {}).cart_id || "";
  }
  renderCartSelect();
  await refreshCartDetails();
}

function renderCartItems(items) {
  const body = document.querySelector("#cartItemsTbl tbody");
  if (!body) return;
  body.innerHTML = "";
  if (!items.length) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan=\"6\" class=\"muted\">No items yet.</td>`;
    body.appendChild(row);
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("tr");
    const qtyId = `cartQty_${item.sku}`;
    row.innerHTML = `
      <td class=\"mono\">${escapeHtml(item.sku)}</td>
      <td>${escapeHtml(item.name)}</td>
      <td><input id=\"${qtyId}\" type=\"number\" min=\"0\" value=\"${item.quantity}\" style=\"width:80px\"/></td>
      <td>${fmtMoney(item.unit_price_cents, \"usd\")}</td>
      <td>${fmtMoney(item.line_total_cents, \"usd\")}</td>
      <td>
        <button data-action=\"update\" data-sku=\"${escapeHtml(item.sku)}\">Update</button>
        <button class=\"danger\" data-action=\"remove\" data-sku=\"${escapeHtml(item.sku)}\">Remove</button>
      </td>
    `;
    row.querySelectorAll("button").forEach((btn) => {
      btn.onclick = async () => {
        const action = btn.getAttribute("data-action");
        const sku = btn.getAttribute("data-sku");
        if (!sku || !cartState.cartId) return;
        if (action === "update") {
          const qtyVal = parseInt(document.getElementById(`cartQty_${sku}`).value, 10);
          if (Number.isNaN(qtyVal)) return;
          try {
            setCartStatus("Updating item...");
            await ensureUiSession();
            await apiPatch(`/ui/shoppingcart/carts/${cartState.cartId}/items/${sku}`, { quantity: qtyVal });
            await refreshCartDetails();
            setCartStatus("Item updated.");
          } catch (e) {
            setCartStatus(String(e));
          }
        }
        if (action === "remove") {
          if (!confirm(`Remove ${sku} from cart?`)) return;
          try {
            setCartStatus("Removing item...");
            await ensureUiSession();
            await apiDelete(`/ui/shoppingcart/carts/${cartState.cartId}/items/${sku}`);
            await refreshCartDetails();
            setCartStatus("Item removed.");
          } catch (e) {
            setCartStatus(String(e));
          }
        }
      };
    });
    body.appendChild(row);
  });
}

async function startNewCart() {
  try {
    setCartStatus("Starting new cart...");
    await ensureUiSession();
    const cart = await apiPost("/ui/shoppingcart/carts", {});
    cartState.cartId = cart.cart_id;
    await refreshShoppingCart();
    setCartStatus("Cart created.");
  } catch (e) {
    setCartStatus(String(e));
  }
}

async function addCartItem() {
  if (!cartState.cartId) {
    setCartStatus("No active cart. Start a cart first.");
    return;
  }
  const sku = readInput("cartSku");
  const name = readInput("cartName");
  const qty = parseInt(readInput("cartQty"), 10);
  const price = parseInt(readInput("cartPrice"), 10);
  if (!sku || !name) {
    setCartStatus("SKU and name are required.");
    return;
  }
  if (Number.isNaN(qty) || qty <= 0) {
    setCartStatus("Quantity must be at least 1.");
    return;
  }
  if (Number.isNaN(price) || price < 0) {
    setCartStatus("Unit price must be 0 or higher.");
    return;
  }
  try {
    setCartStatus("Adding item...");
    await ensureUiSession();
    await apiPost(`/ui/shoppingcart/carts/${cartState.cartId}/items`, {
      sku,
      name,
      quantity: qty,
      unit_price_cents: price,
    });
    await refreshCartDetails();
    setInputValue("cartSku", "");
    setInputValue("cartName", "");
    setCartStatus("Item added.");
  } catch (e) {
    setCartStatus(String(e));
  }
}

async function purchaseCart() {
  if (!cartState.cartId) {
    setCartStatus("No active cart.");
    return;
  }
  if (!confirm("Purchase this cart?")) return;
  try {
    setCartStatus("Purchasing...");
    await ensureUiSession();
    const res = await apiPost(`/ui/shoppingcart/carts/${cartState.cartId}/purchase`, {});
    await refreshShoppingCart();
    setCartStatus(`Purchased cart (order ${res.order_id}).`);
  } catch (e) {
    setCartStatus(String(e));
  }
}

async function deleteActiveCart() {
  if (!cartState.cartId) {
    setCartStatus("No active cart.");
    return;
  }
  if (!confirm("Delete this cart?")) return;
  try {
    setCartStatus("Deleting cart...");
    await ensureUiSession();
    await apiDelete(`/ui/shoppingcart/carts/${cartState.cartId}`);
    cartState.cartId = "";
    await refreshShoppingCart();
    setCartStatus("Cart deleted.");
  } catch (e) {
    setCartStatus(String(e));
  }
}

function renderProfileLanguages() {
  const el = document.getElementById("profileLangList");
  if (!el) return;
  el.innerHTML = "";
  profileLanguages.forEach((lang) => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow"><b>${escapeHtml(lang.name || "")}</b><div class="muted">${escapeHtml(lang.level || "")}</div></div>
      <div><button data-name="${escapeHtml(lang.name || "")}">Remove</button></div>
    `;
    row.querySelector("button").onclick = (ev) => {
      const name = ev.target.getAttribute("data-name");
      profileLanguages = profileLanguages.filter((l) => l.name !== name);
      renderProfileLanguages();
    };
    el.appendChild(row);
  });
}

function setProfileLanguages(langs) {
  profileLanguages = Array.isArray(langs) ? langs : [];
  renderProfileLanguages();
}

function setProfileForm(profile) {
  setInputValue("profileDisplayName", profile.display_name);
  setInputValue("profileFirstName", profile.first_name);
  setInputValue("profileMiddleName", profile.middle_name);
  setInputValue("profileLastName", profile.last_name);
  setInputValue("profileTitle", profile.title);
  setInputValue("profileDescription", profile.description);
  setInputValue("profileBirthday", profile.birthday);
  setInputValue("profileGender", profile.gender);
  setInputValue("profileLocation", profile.location);
  setInputValue("profileEmail", profile.displayed_email);
  setInputValue("profilePhone", profile.displayed_telephone_number);

  const addr = profile.mailing_address || {};
  setInputValue("profileAddrLine1", addr.line1);
  setInputValue("profileAddrLine2", addr.line2);
  setInputValue("profileAddrCity", addr.city);
  setInputValue("profileAddrState", addr.state);
  setInputValue("profileAddrPostal", addr.postal_code);
  setInputValue("profileAddrCountry", addr.country);

  setProfileLanguages(profile.languages || []);

  const profileUrl = profile.profile_photo_url || "";
  const profileUrlEl = document.getElementById("profilePhotoUrl");
  if (profileUrlEl) profileUrlEl.textContent = profileUrl;
  const profileImg = document.getElementById("profilePhotoPreview");
  if (profileImg) {
    if (profileUrl) {
      profileImg.src = profileUrl;
      profileImg.classList.remove("hidden");
    } else {
      profileImg.classList.add("hidden");
    }
  }

  const coverUrl = profile.cover_photo_url || "";
  const coverUrlEl = document.getElementById("profileCoverUrl");
  if (coverUrlEl) coverUrlEl.textContent = coverUrl;
  const coverImg = document.getElementById("profileCoverPreview");
  if (coverImg) {
    if (coverUrl) {
      coverImg.src = coverUrl;
      coverImg.classList.remove("hidden");
    } else {
      coverImg.classList.add("hidden");
    }
  }
}

function resetProfileForm() {
  setProfileForm({});
  setProfileStatus("");
  setProfileAuditStatus("");
  const list = document.getElementById("profileAuditList");
  if (list) list.innerHTML = "";
}

function buildProfilePayload({ includeEmpty }) {
  const payload = {};
  const fields = [
    ["display_name", "profileDisplayName"],
    ["first_name", "profileFirstName"],
    ["middle_name", "profileMiddleName"],
    ["last_name", "profileLastName"],
    ["title", "profileTitle"],
    ["description", "profileDescription"],
    ["birthday", "profileBirthday"],
    ["gender", "profileGender"],
    ["location", "profileLocation"],
    ["displayed_email", "profileEmail"],
    ["displayed_telephone_number", "profilePhone"],
  ];
  fields.forEach(([key, id]) => {
    const val = readInputOrNull(id);
    if (includeEmpty || val) payload[key] = val;
  });

  const addr = {
    line1: readInputOrNull("profileAddrLine1"),
    line2: readInputOrNull("profileAddrLine2"),
    city: readInputOrNull("profileAddrCity"),
    state: readInputOrNull("profileAddrState"),
    postal_code: readInputOrNull("profileAddrPostal"),
    country: readInputOrNull("profileAddrCountry"),
  };
  const addrHasValue = Object.values(addr).some((v) => v);
  if (includeEmpty) {
    payload.mailing_address = addrHasValue ? addr : null;
  } else if (addrHasValue) {
    payload.mailing_address = addr;
  }

  if (includeEmpty || profileLanguages.length) {
    payload.languages = profileLanguages;
  }
  return payload;
}

async function refreshProfile() {
  await ensureUiSession();
  const res = await apiGet("/ui/profile");
  setProfileForm(res.profile || {});
}

async function saveProfile({ replace }) {
  await ensureUiSession();
  const payload = buildProfilePayload({ includeEmpty: replace });
  const path = "/ui/profile";
  const result = replace ? await apiPut(path, payload) : await apiPatch(path, payload);
  setProfileForm(result.profile || {});
}

async function refreshProfileAudit() {
  await ensureUiSession();
  const res = await apiGet("/ui/profile/audit");
  const list = document.getElementById("profileAuditList");
  if (!list) return;
  list.innerHTML = "";
  (res.audit || []).forEach((entry) => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div><b>${escapeHtml(entry.field || "")}</b></div>
        <div class="muted">${escapeHtml(JSON.stringify(entry.to ?? null))}</div>
      </div>
      <div class="muted">${fmtTs(entry.ts)}</div>
    `;
    list.appendChild(row);
  });
}

async function apiUpload(path, file) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(API_BASE + path, {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + tok,
      "X-SESSION-ID": sid,
    },
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}

async function uploadProfilePhoto(kind, fileInputId) {
  const input = document.getElementById(fileInputId);
  if (!input || !input.files || !input.files.length) return;
  const file = input.files[0];
  await ensureUiSession();
  const res = await apiUpload(`/ui/profile/photos/${kind}/upload`, file);
  setProfileForm(res.profile || {});
  input.value = "";
}

/* ===================== File Manager ===================== */
const fileMgrState = {
  path: "/",
  searchResults: [],
};

function fileMgrStatus(msg) {
  const el = document.getElementById("filemgrStatus");
  if (el) el.textContent = msg || "";
}

function normalizeFolderPath(path) {
  const trimmed = (path || "").trim();
  if (!trimmed || trimmed === "/") return "/";
  return trimmed.endsWith("/") ? trimmed : trimmed + "/";
}

function currentFileMgrPath() {
  const input = document.getElementById("filemgrPath");
  return normalizeFolderPath(input ? input.value : fileMgrState.path);
}

function setFileMgrPath(path) {
  fileMgrState.path = normalizeFolderPath(path || "/");
  const input = document.getElementById("filemgrPath");
  if (input) input.value = fileMgrState.path;
}

async function apiUploadFileManager(path, file) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const form = new FormData();
  form.append("file", file);
  const url = `${API_BASE}/v1/fs/upload?path=${encodeURIComponent(path)}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": "Bearer " + tok,
      "X-SESSION-ID": sid,
    },
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}

async function fileMgrDownload(path, filename) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const url = `${API_BASE}/v1/fs/download?path=${encodeURIComponent(path)}`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": "Bearer " + tok,
      "X-SESSION-ID": sid,
    },
  });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename || "download";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
}

function renderFileMgrSearchResults() {
  const list = document.getElementById("filemgrSearchResults");
  if (!list) return;
  list.innerHTML = "";
  const results = fileMgrState.searchResults || [];
  if (!results.length) {
    list.innerHTML = '<div class="muted">No search results.</div>';
    return;
  }
  results.forEach((item) => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(item.name || "")}</div>
        <div class="muted">${escapeHtml(item.path || "")}</div>
      </div>
      <div class="muted">${escapeHtml(item.type || "")}</div>
      <div class="muted">${item.type === "file" ? fmtBytes(item.size || 0) : ""}</div>
      <div><button data-path="${escapeHtml(item.path || "")}" data-type="${escapeHtml(item.type || "")}">Open</button></div>
    `;
    row.querySelector("button").onclick = async (ev) => {
      const p = ev.target.getAttribute("data-path");
      const t = ev.target.getAttribute("data-type");
      if (!p) return;
      if (t === "folder") {
        setFileMgrPath(p);
      } else {
        const parent = p.split("/").slice(0, -1).join("/") + "/";
        setFileMgrPath(parent || "/");
      }
      await refreshFileManager();
    };
    list.appendChild(row);
  });
}

function renderFileMgrList(items) {
  const tbody = document.querySelector("#filemgrTable tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  (items || []).forEach((item) => {
    const row = document.createElement("tr");
    const isFolder = item.type === "folder";
    row.innerHTML = `
      <td class="mono">${escapeHtml(item.name || "")}</td>
      <td>${escapeHtml(item.type || "")}</td>
      <td>${isFolder ? "" : fmtBytes(item.size || 0)}</td>
      <td class="muted">${escapeHtml(item.updated_at || "")}</td>
      <td>
        <div class="row-inline">
          ${isFolder ? '<button data-action="open">Open</button>' : '<button data-action="download">Download</button>'}
          <button data-action="rename">Rename</button>
          <button data-action="delete" class="danger">Delete</button>
        </div>
      </td>
    `;
    row.querySelectorAll("button").forEach((btn) => {
      btn.onclick = async () => {
        const action = btn.getAttribute("data-action");
        if (!action) return;
        try {
          if (action === "open") {
            setFileMgrPath(item.path);
            await refreshFileManager();
            return;
          }
          if (action === "download") {
            await fileMgrDownload(item.path, item.name);
            return;
          }
          if (action === "rename") {
            const newName = prompt("New name:", item.name || "");
            if (!newName) return;
            const endpoint = isFolder ? "/v1/fs/rename-folder" : "/v1/fs/rename-file";
            await apiPost(endpoint, { path: item.path, new_name: newName });
            await refreshFileManager();
            return;
          }
          if (action === "delete") {
            const ok = confirm(`Delete ${item.type} ${item.name}?`);
            if (!ok) return;
            const endpoint = isFolder ? "/v1/fs/folder" : "/v1/fs/file";
            await apiDelete(`${endpoint}?path=${encodeURIComponent(item.path)}`);
            await refreshFileManager();
          }
        } catch (e) {
          fileMgrStatus(String(e));
        }
      };
    });
    tbody.appendChild(row);
  });
  if (!items || items.length === 0) {
    const empty = document.createElement("tr");
    empty.innerHTML = '<td colspan="5" class="muted">No files in this folder.</td>';
    tbody.appendChild(empty);
  }
}

async function refreshFileManager() {
  const table = document.getElementById("filemgrTable");
  if (!table) return;
  try {
    fileMgrStatus("Loading...");
    await ensureUiSession();
    const path = currentFileMgrPath();
    const res = await apiGet(`/v1/fs/list?path=${encodeURIComponent(path)}`);
    setFileMgrPath(res.path || path);
    renderFileMgrList(res.items || []);
    fileMgrStatus(`Loaded ${res.items ? res.items.length : 0} items.`);
  } catch (e) {
    fileMgrStatus(String(e));
  }
}

async function createFileMgrFolder() {
  const nameInput = document.getElementById("filemgrNewFolder");
  if (!nameInput) return;
  const name = nameInput.value.trim();
  if (!name) return;
  const path = currentFileMgrPath() + name + "/";
  await ensureUiSession();
  await apiPost("/v1/fs/folder", { path });
  nameInput.value = "";
  await refreshFileManager();
}

async function uploadFileMgr() {
  const input = document.getElementById("filemgrUploadInput");
  if (!input || !input.files || !input.files.length) return;
  const file = input.files[0];
  const path = currentFileMgrPath() + file.name;
  await ensureUiSession();
  await apiUploadFileManager(path, file);
  input.value = "";
  await refreshFileManager();
}

async function searchFileMgr() {
  const input = document.getElementById("filemgrSearch");
  if (!input) return;
  const prefix = input.value.trim();
  if (!prefix) return;
  await ensureUiSession();
  const res = await apiGet(`/v1/fs/search?prefix=${encodeURIComponent(prefix)}`);
  fileMgrState.searchResults = res.results || [];
  renderFileMgrSearchResults();
}

function clearFileMgrSearch() {
  fileMgrState.searchResults = [];
  const input = document.getElementById("filemgrSearch");
  if (input) input.value = "";
  renderFileMgrSearchResults();
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

document.getElementById("calendarSetBtn").onclick = async () => {
  const calendarId = document.getElementById("calendarIdInput").value.trim();
  setCalendarId(calendarId);
  if (calendarId) {
    setCalendarStatus(`Using calendar ${calendarId}`);
    await refreshCalendarEvents();
  } else {
    setCalendarStatus("Calendar cleared.");
  }
};

document.getElementById("calendarCreateBtn").onclick = async () => {
  await createCalendar();
};

document.getElementById("eventCreateBtn").onclick = async () => {
  await createCalendarEvent();
};

document.getElementById("eventsRefreshBtn").onclick = async () => {
  await refreshCalendarEvents();
};

document.getElementById("openingsLoadBtn").onclick = async () => {
  await loadCalendarOpenings();
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

document.getElementById("btnClearTokens").onclick = () => { clearAuthTokens(); alert("Tokens cleared."); };

document.getElementById("totpRefreshBtn").onclick = async () => { await ensureUiSession(); await refreshTotpDevices(); };

document.getElementById("accountCloseBtn").onclick = async () => {
  await ensureUiSession();
  const confirmText = prompt("Type CLOSE to permanently close your account:") || "";
  if (confirmText.trim() !== "CLOSE") return;
  try {
    const start = await accountClosureStart();
    if (!start.challenge_id) {
      throw new Error("Missing account closure challenge.");
    }
    if (!start.auth_required) {
      const res = await accountClosureFinalize(start.challenge_id);
      if (res.status === "closed") {
        handleAccountClosureSuccess();
      } else {
        alert("Account closure still pending verification.");
      }
      return;
    }
    await runAccountClosureChallenge(start.challenge_id, start.required_factors || []);
  } catch (e) {
    alert(String(e));
  }
};

document.getElementById("smsRefreshBtn").onclick = async () => { await ensureUiSession(); await refreshSmsDevices(); };
document.getElementById("smsAddBtn").onclick = async () => { await ensureUiSession(); openSmsAddModal(); };

document.getElementById("emailRefreshBtn").onclick = async () => { await ensureUiSession(); await refreshEmailDevices(); };
document.getElementById("emailAddBtn").onclick = async () => { await ensureUiSession(); openEmailAddModal(); };
document.getElementById("pwRecoveryStartBtn").onclick = startPasswordRecovery;
document.getElementById("pwRecoveryConfirmBtn").onclick = confirmPasswordRecovery;

document.getElementById("profileLoadBtn").onclick = async () => {
  try {
    setProfileStatus("Loading...");
    await refreshProfile();
    setProfileStatus("Loaded.");
  } catch (e) {
    setProfileStatus(String(e));
  }
};
document.getElementById("profileSavePatchBtn").onclick = async () => {
  try {
    setProfileStatus("Saving...");
    await saveProfile({ replace: false });
    setProfileStatus("Saved.");
  } catch (e) {
    setProfileStatus(String(e));
  }
};
document.getElementById("profileSaveReplaceBtn").onclick = async () => {
  try {
    setProfileStatus("Saving...");
    await saveProfile({ replace: true });
    setProfileStatus("Saved.");
  } catch (e) {
    setProfileStatus(String(e));
  }
};
document.getElementById("profileResetBtn").onclick = () => {
  resetProfileForm();
};
document.getElementById("profileLangAddBtn").onclick = () => {
  const name = readInput("profileLangName");
  if (!name) return;
  const level = readInput("profileLangLevel") || "basic";
  const existing = profileLanguages.find((l) => l.name === name);
  if (existing) {
    existing.level = level;
  } else {
    profileLanguages.push({ name, level });
  }
  setInputValue("profileLangName", "");
  renderProfileLanguages();
};
document.getElementById("profilePhotoUploadBtn").onclick = async () => {
  try {
    setProfileStatus("Uploading profile photo...");
    await uploadProfilePhoto("profile", "profilePhotoFile");
    setProfileStatus("Profile photo updated.");
  } catch (e) {
    setProfileStatus(String(e));
  }
};
document.getElementById("profileCoverUploadBtn").onclick = async () => {
  try {
    setProfileStatus("Uploading cover photo...");
    await uploadProfilePhoto("cover", "profileCoverFile");
    setProfileStatus("Cover photo updated.");
  } catch (e) {
    setProfileStatus(String(e));
  }
};
document.getElementById("profileAuditRefreshBtn").onclick = async () => {
  try {
    setProfileAuditStatus("Refreshing...");
    await refreshProfileAudit();
    setProfileAuditStatus("");
  } catch (e) {
    setProfileAuditStatus(String(e));
  }
};

document.getElementById("filemgrRefreshBtn").onclick = refreshFileManager;
document.getElementById("filemgrGoBtn").onclick = async () => {
  setFileMgrPath(currentFileMgrPath());
  await refreshFileManager();
};
document.getElementById("filemgrUpBtn").onclick = async () => {
  const path = currentFileMgrPath();
  if (path === "/") return;
  const parts = path.split("/").filter(Boolean);
  const parent = parts.length > 1 ? `/${parts.slice(0, -1).join("/")}/` : "/";
  setFileMgrPath(parent);
  await refreshFileManager();
};
document.getElementById("filemgrCreateFolderBtn").onclick = async () => {
  try {
    await createFileMgrFolder();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrUploadBtn").onclick = async () => {
  try {
    await uploadFileMgr();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrSearchBtn").onclick = async () => {
  try {
    await searchFileMgr();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrClearSearchBtn").onclick = clearFileMgrSearch;
document.getElementById("addressRefreshBtn").onclick = async () => {
  try {
    setAddressStatus("Refreshing...");
    await refreshAddresses();
    setAddressStatus("Loaded.");
  } catch (e) {
    setAddressStatus(String(e));
  }
};
document.getElementById("addressSaveBtn").onclick = async () => {
  try {
    setAddressStatus("Saving...");
    await saveAddress();
    setAddressStatus("Saved.");
  } catch (e) {
    setAddressStatus(String(e));
  }
};
document.getElementById("addressClearBtn").onclick = () => {
  clearAddressForm();
  setAddressStatus("");
};
document.getElementById("addressSearchBtn").onclick = async () => {
  try {
    setAddressStatus("Searching...");
    await searchAddressBook(readInput("addressSearchInput"));
    setAddressStatus("");
  } catch (e) {
    setAddressStatus(String(e));
  }
};

document.getElementById("cartRefreshBtn").onclick = async () => {
  try {
    setCartStatus("Refreshing...");
    await refreshShoppingCart();
    setCartStatus("");
  } catch (e) {
    setCartStatus(String(e));
  }
};
document.getElementById("cartStartBtn").onclick = startNewCart;
document.getElementById("cartAddItemBtn").onclick = addCartItem;
document.getElementById("cartPurchaseBtn").onclick = purchaseCart;
document.getElementById("cartDeleteBtn").onclick = deleteActiveCart;
document.getElementById("cartSelect").onchange = async (ev) => {
  cartState.cartId = ev.target.value || "";
  await refreshCartDetails();
};

document.getElementById("accountSuspendBtn").onclick = () => {
  openAccountActionModal({
    title: "Start account suspension",
    confirmText: "Submit suspension request",
    onConfirm: async (reason) => {
      await requestAccountSuspension(reason);
    },
  });
};
document.getElementById("accountReactivateBtn").onclick = () => {
  openAccountActionModal({
    title: "Start account reactivation",
    confirmText: "Submit reactivation request",
    onConfirm: async (reason) => {
      await requestAccountReactivation(reason);
    },
  });
};

initBillingUi();
renderPasswordRecovery();
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
document.getElementById("stripeRefreshBtn").onclick = refreshBillingAll;
document.getElementById("stripePaySettledBalanceBtn").onclick = payBillingSettledBalance;
document.getElementById("stripe_autopay").onchange = setBillingAutopay;
document.getElementById("stripePaneAddCardBtn").onclick = () => showStripePane("add_card");
document.getElementById("stripePaneAddBankBtn").onclick = () => showStripePane("add_bank");
document.getElementById("stripePaneVerifyBankBtn").onclick = () => showStripePane("verify_bank");
document.getElementById("stripePaneListMethodsBtn").onclick = () => showStripePane("list_methods");
document.getElementById("stripeAddCardBtn").onclick = addBillingCard;
document.getElementById("stripeAddBankAccountBtn").onclick = addBillingBankAccount;
document.getElementById("stripeUsePendingSetupIntentBtn").onclick = useBillingPendingSetupIntent;
document.getElementById("stripeVerifyByAmountsBtn").onclick = verifyBillingByAmounts;
document.getElementById("stripeVerifyByDescriptorBtn").onclick = verifyBillingByDescriptor;
document.getElementById("stripeLoadLedgerBtn").onclick = loadBillingLedger;

setInputValue("msgApiBase", API_BASE);
document.getElementById("msgLoadConvosBtn").onclick = loadMessagingConvos;
document.getElementById("msgCreateConvoBtn").onclick = createMessagingConvo;
document.getElementById("msgAcceptConvoBtn").onclick = acceptMessagingConvo;
document.getElementById("msgLoadMessagesBtn").onclick = loadMessagingMessages;
document.getElementById("msgSendBtn").onclick = sendMessagingMessage;

setInputValue("newsfeedApiBase", API_BASE);
setInputValue("newsfeedUserId", lsGet("newsfeed_user_id"));
document.getElementById("newsfeedUserId").onchange = () => {
  const uid = readInput("newsfeedUserId");
  if (uid) {
    lsSet("newsfeed_user_id", uid);
  } else {
    lsDel("newsfeed_user_id");
  }
};
document.getElementById("newsfeedApiBase").onchange = () => {
  setInputValue("newsfeedApiBase", newsfeedApiBase());
};
document.getElementById("newsfeedRefreshBtn").onclick = async () => {
  try {
    await refreshNewsfeed(true);
  } catch (e) {
    setNewsfeedStatus(String(e.message || e));
  }
};
document.getElementById("newsfeedLoadMoreBtn").onclick = async () => {
  try {
    await refreshNewsfeed(false);
  } catch (e) {
    setNewsfeedStatus(String(e.message || e));
  }
};
document.getElementById("newsfeedCreateBtn").onclick = async () => {
  try {
    await createNewsfeedPost();
  } catch (e) {
    setNewsfeedStatus(String(e.message || e));
  }
};
document.getElementById("newsfeedCommentSendBtn").onclick = async () => {
  try {
    await sendNewsfeedComment();
  } catch (e) {
    setNewsfeedCommentStatus(String(e.message || e));
  }
};
document.getElementById("newsfeedCommentsLoadMoreBtn").onclick = async () => {
  try {
    await loadNewsfeedComments(false);
  } catch (e) {
    setNewsfeedCommentStatus(String(e.message || e));
  }
};
document.getElementById("newsfeedNotifsRefreshBtn").onclick = async () => {
  try {
    await refreshNewsfeedNotifs(true);
  } catch (e) {
    setNewsfeedStatus(String(e.message || e));
  }
};
document.getElementById("newsfeedConnectBtn").onclick = connectNewsfeedSse;
document.getElementById("newsfeedDisconnectBtn").onclick = () => {
  disconnectNewsfeedSse();
  logNewsfeedSse("Disconnected.");
};

/* ===================== boot ===================== */
if (!window.__SKIP_BOOT__) {
  setCalendarId(getCalendarId());
  if (!accessToken()) { openTokenModal(); } else { refreshAll(); }
  startToastSSE();
  startToastPolling();
}
