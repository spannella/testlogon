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

/* ===================== storage helpers ===================== */
function lsGet(k){ try{return localStorage.getItem(k);}catch(e){return null;} }
function lsSet(k,v){ try{localStorage.setItem(k,v);}catch(e){} }
function lsDel(k){ try{localStorage.removeItem(k);}catch(e){} }
function ssGet(k){ try{return sessionStorage.getItem(k);}catch(e){return null;} }
function ssSet(k,v){ try{sessionStorage.setItem(k,v);}catch(e){} }
function ssDel(k){ try{sessionStorage.removeItem(k);}catch(e){} }

function migrateToken(k) {
  const existing = ssGet(k);
  if (existing) return existing;
  const legacy = lsGet(k);
  if (legacy) {
    ssSet(k, legacy);
    lsDel(k);
    return legacy;
  }
  return null;
}

function accessToken(){ return migrateToken("access_token"); }
function idToken(){ return migrateToken("id_token"); }
function refreshToken(){ return migrateToken("refresh_token"); }
const CSRF_COOKIE_NAME = window.UI_CSRF_COOKIE_NAME || "ui_csrf";

function getCookie(name) {
  const cookies = document.cookie ? document.cookie.split(";") : [];
  for (const raw of cookies) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf("=");
    const key = idx >= 0 ? trimmed.slice(0, idx) : trimmed;
    if (key === name) {
      return idx >= 0 ? decodeURIComponent(trimmed.slice(idx + 1)) : "";
    }
  }
  return null;
}

function csrfToken() {
  return getCookie(CSRF_COOKIE_NAME);
}

function addCsrfHeader(headers) {
  const token = csrfToken();
  if (token) headers["X-CSRF-Token"] = token;
}

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
      <div class="muted">Paste your Cognito <b>access token</b> (JWT). Stored in sessionStorage.</div>
      <input id="cfgApiBase" class="mono" placeholder="API base URL" value="${curBase}"/>
      <input id="cfgAccessTok" class="mono" placeholder="access_token (Bearer)" value="${accessToken()||""}"/>
      <div class="muted" style="margin-top:8px;">Optional: id_token / refresh_token (used for refresh)</div>
      <input id="cfgIdTok" class="mono" placeholder="id_token" value="${idToken()||""}"/>
      <input id="cfgRefreshTok" class="mono" placeholder="refresh_token" value="${refreshToken()||""}"/>
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
          ssSet("access_token", at);
          ssSet("id_token", document.getElementById("cfgIdTok").value.trim());
          ssSet("refresh_token", document.getElementById("cfgRefreshTok").value.trim());
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
async function refreshAccessToken() {
  const rt = refreshToken();
  if (!rt) throw new Error("Missing refresh_token; please re-authenticate.");
  const res = await fetch(API_BASE + "/ui/token/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: rt }),
  });
  const txt = await res.text();
  if (!res.ok) throw new Error(res.status + ": " + txt);
  const data = txt ? JSON.parse(txt) : {};
  if (!data.access_token) throw new Error("Refresh failed: missing access_token.");
  ssSet("access_token", data.access_token);
  if (data.id_token) ssSet("id_token", data.id_token);
  return data.access_token;
}

async function authFetch(path, {method="GET", body=null, includeSession=true}={}) {
  let tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const headers = { "Authorization": "Bearer " + tok };
  const upperMethod = method.toUpperCase();
  if (includeSession && !["GET", "HEAD", "OPTIONS"].includes(upperMethod)) {
    const csrf = csrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  if (body !== null) headers["Content-Type"] = "application/json";
  const doFetch = () => fetch(API_BASE + path, {
    method,
    headers,
    body: (body !== null ? JSON.stringify(body) : undefined),
    credentials: "include",
  });
  let res = await doFetch();
  if (res.status === 401 && refreshToken()) {
    tok = await refreshAccessToken();
    headers["Authorization"] = "Bearer " + tok;
    res = await doFetch();
  }
  return res;
}

async function api(path, {method="GET", body=null, includeSession=true}={}) {
  const res = await authFetch(path, {method, body, includeSession});
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
    credentials: "include",
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
  const precision = (scaled >= 10 || idx === 0 || Number.isInteger(scaled)) ? 0 : 1;
  return `${scaled.toFixed(precision)} ${units[idx]}`;
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

function fmtMicros(micros, currency="usd") {
  const sign = Number(micros||0) < 0 ? "-" : "";
  const v = Math.abs(Number(micros||0)) / 1000000.0;
  return sign + v.toFixed(4) + " " + currency.toUpperCase();
}

function currentPeriodIdUtc() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2, "0")}`;
}

function utilizationClass(pct) {
  const n = Number(pct||0);
  if (n >= 95) return "bad";
  if (n >= 70) return "warn";
  return "ok";
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

function rememberRecoveryReturn() {
  const state = {
    hash: window.location.hash || "",
    scrollY: window.scrollY || 0,
  };
  ssSet("pw_recovery_return", JSON.stringify(state));
}

function resumeAfterPasswordReset() {
  const pending = ssGet("pw_recovery_resume_pending");
  if (!pending || !accessToken()) return;
  const raw = ssGet("pw_recovery_return");
  ssDel("pw_recovery_resume_pending");
  if (!raw) return;
  try {
    const state = JSON.parse(raw);
    if (state.hash !== undefined) {
      window.location.hash = state.hash;
    }
    if (Number.isFinite(state.scrollY)) {
      window.scrollTo(0, state.scrollY);
    }
  } catch (e) {}
}

async function startPasswordRecovery() {
  const username = (document.getElementById("pwRecoveryUsername").value || "").trim();
  if (!username) {
    passwordRecoveryState.lastErr = "Username required.";
    renderPasswordRecovery();
    return;
  }
  rememberRecoveryReturn();
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
    ssSet("pw_recovery_resume_pending", "1");
    ssDel("access_token");
    ssDel("id_token");
    ssDel("refresh_token");
    passwordRecoveryState.lastErr = "Password updated. Please log in again to continue where you left off.";
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
    body: JSON.stringify({}),
    credentials: "include",
  });
  const txt = await res.text();
  if (!res.ok) throw new Error(res.status + ": " + txt);
  return txt ? JSON.parse(txt) : {};
}

/* ============================================================
   FULL ensureUiSession() (TOTP + SMS + Email, auto-send SMS/email once)
   ============================================================ */
async function ensureUiSession() {
  try {
    await apiGet("/ui/me");
    return true;
  } catch (e) {
    const code = parseHttpError(String(e));
    if (code && code !== 401 && code !== 403) throw e;
  }

  const r = await sessionStart();
  if (!r.auth_required) {
    return true;
  }

  const challengeId = r.challenge_id;
  const required = r.required_factors || [];
  const needTotp  = required.includes("totp");
  const needSms   = required.includes("sms");
  const needEmail = required.includes("email");

  async function postBearer(path, payload) {
    const res = await authFetch(path, { method: "POST", body: payload, includeSession: false });
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
  ssDel("access_token");
  ssDel("id_token");
  ssDel("refresh_token");
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

/* ===================== Devices ===================== */
async function refreshDevices() {
  await ensureUiSession();
  const res = await apiGet("/ui/devices");
  const el = document.getElementById("deviceList");
  if (!el) return;
  el.innerHTML = "";
  (res.devices || []).forEach(d => {
    const row = document.createElement("div");
    row.className = "list-item";
    const trustBadge = d.trusted ? "<span class='pill'>trusted</span>" : "<span class='pill'>new</span>";
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(d.device_id)} ${trustBadge}</div>
        <div class="muted">last ${fmtTs(d.last_seen_at)} • ${escapeHtml(d.last_ip || "")}</div>
        <div class="muted">${escapeHtml((d.user_agent || "").slice(0, 120))}</div>
      </div>
      <div>
        <button class="primary" ${d.trusted ? "disabled" : ""} data-action="trust">Trust</button>
        <button class="danger" ${d.trusted ? "" : "disabled"} data-action="revoke">Revoke</button>
      </div>
    `;
    row.querySelectorAll("button").forEach(btn => {
      btn.onclick = async () => {
        const action = btn.getAttribute("data-action");
        if (!action) return;
        if (action === "trust") {
          await apiPost(`/ui/devices/${encodeURIComponent(d.device_id)}/trust`, {});
        } else {
          await apiPost(`/ui/devices/${encodeURIComponent(d.device_id)}/revoke`, {});
        }
        await refreshDevices();
      };
    });
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
        <button ${k.revoked ? "disabled" : ""} data-kid="${escapeHtml(k.key_id)}">Edit limits</button>
        <button data-kid="${escapeHtml(k.key_id)}">Usage</button>
      </div>
    `;
    const btns = row.querySelectorAll("button");
    btns[0].onclick = async (e) => {
      const kid = e.target.getAttribute("data-kid");
      await apiPost("/ui/api_keys/revoke", { key_id: kid });
      await refreshKeys();
      await refreshApiUsageViews(true);
    };
    btns[1].onclick = async (e) => {
      const kid = e.target.getAttribute("data-kid");
      const allowCsv = e.target.getAttribute("data-allow") || "";
      const denyCsv = e.target.getAttribute("data-deny") || "";
      openIpRulesModal(kid, allowCsv, denyCsv);
    };
    btns[2].onclick = async (e) => {
      const kid = e.target.getAttribute("data-kid");
      await openKeyLimitsModal(kid);
    };
    btns[3].onclick = async (e) => {
      const kid = e.target.getAttribute("data-kid");
      await openKeyUsageModal(kid);
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


const apiUsageState = { routeCursor: null, keyCursor: null };

async function refreshApiUsageSummary(period) {
  const res = await apiGet(`/ui/api-usage/summary?period=${encodeURIComponent(period)}`);
  const callsUsed = Number((res.totals||{}).calls_total || 0);
  const spendUsed = Number((res.totals||{}).estimated_cost_micros || 0);
  const callsLimit = Number((res.limits||{}).monthly_calls_limit || 0);
  const spendLimit = Number((res.limits||{}).monthly_spend_micros_limit || 0);

  const callsPct = callsLimit > 0 ? (callsUsed * 100.0 / callsLimit) : 0;
  const spendPct = spendLimit > 0 ? (spendUsed * 100.0 / spendLimit) : 0;
  const maxPct = Math.max(callsPct, spendPct);

  const callsEl = document.getElementById("apiUsageCallsCard");
  const spendEl = document.getElementById("apiUsageSpendCard");
  const limitEl = document.getElementById("apiUsageLimitCard");
  const remEl = document.getElementById("apiUsageRemainCard");
  if (callsEl) { callsEl.className = `pill ${utilizationClass(callsPct)}`; callsEl.textContent = `Calls: ${callsUsed}`; }
  if (spendEl) { spendEl.className = `pill ${utilizationClass(spendPct)}`; spendEl.textContent = `Spend: ${fmtMicros(spendUsed)}`; }
  if (limitEl) { limitEl.className = `pill ${utilizationClass(maxPct)}`; limitEl.textContent = `Limits: calls ${callsLimit||"∞"}, spend ${spendLimit>0?fmtMicros(spendLimit):"∞"}`; }
  if (remEl) {
    remEl.className = `pill ${utilizationClass(maxPct)}`;
    remEl.textContent = `Remaining: calls ${(res.remaining||{}).monthly_calls_remaining ?? "∞"}, spend ${((res.remaining||{}).monthly_spend_micros_remaining==null)?"∞":fmtMicros((res.remaining||{}).monthly_spend_micros_remaining)}`;
  }
}

function renderUsageTableRows(tableId, items, idField) {
  const tbody = document.querySelector(`#${tableId} tbody`);
  if (!tbody) return;
  tbody.innerHTML = "";
  (items||[]).forEach(it => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${escapeHtml(it[idField] || "")}</td><td>${Number(it.calls_total||0)}</td><td>${Number(it.request_units_total||0)}</td><td>${fmtMicros(Number(it.cost_subtotal_micros||0))}</td>`;
    tbody.appendChild(tr);
  });
}

async function refreshApiUsageRoutes(period, append=false) {
  const search = (document.getElementById("apiUsageRouteSearch")?.value || "").trim();
  const sortBy = document.getElementById("apiUsageRouteSort")?.value || "cost_subtotal_micros";
  const order = document.getElementById("apiUsageRouteOrder")?.value || "desc";
  const cursor = append ? apiUsageState.routeCursor : null;
  const q = new URLSearchParams({ period, sort_by: sortBy, order, limit: "50" });
  if (search) q.set("search", search);
  if (cursor) q.set("cursor", cursor);
  const res = await apiGet(`/ui/api-usage/routes?${q.toString()}`);
  const tbody = document.querySelector('#apiUsageRoutesTbl tbody');
  if (!append && tbody) tbody.innerHTML = "";
  const items = res.items || [];
  if (append && tbody) {
    items.forEach(it => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${escapeHtml(it.route_id||"")}</td><td>${Number(it.calls_total||0)}</td><td>${Number(it.request_units_total||0)}</td><td>${fmtMicros(Number(it.cost_subtotal_micros||0))}</td>`;
      tbody.appendChild(tr);
    });
  } else {
    renderUsageTableRows("apiUsageRoutesTbl", items, "route_id");
  }
  apiUsageState.routeCursor = res.next_cursor || null;
  const moreBtn = document.getElementById("apiUsageRouteMoreBtn");
  if (moreBtn) moreBtn.style.display = apiUsageState.routeCursor ? "" : "none";
}

async function refreshApiUsageKeys(period, append=false) {
  const search = (document.getElementById("apiUsageKeySearch")?.value || "").trim();
  const sortBy = document.getElementById("apiUsageKeySort")?.value || "cost_subtotal_micros";
  const order = document.getElementById("apiUsageKeyOrder")?.value || "desc";
  const cursor = append ? apiUsageState.keyCursor : null;
  const q = new URLSearchParams({ period, sort_by: sortBy, order, limit: "50" });
  if (search) q.set("search", search);
  if (cursor) q.set("cursor", cursor);
  const res = await apiGet(`/ui/api-usage/keys?${q.toString()}`);
  const tbody = document.querySelector('#apiUsageKeysTbl tbody');
  if (!append && tbody) tbody.innerHTML = "";
  const items = res.items || [];
  if (append && tbody) {
    items.forEach(it => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${escapeHtml(it.api_key_id||"")}</td><td>${Number(it.calls_total||0)}</td><td>${Number(it.request_units_total||0)}</td><td>${fmtMicros(Number(it.cost_subtotal_micros||0))}</td>`;
      tbody.appendChild(tr);
    });
  } else {
    renderUsageTableRows("apiUsageKeysTbl", items, "api_key_id");
  }
  apiUsageState.keyCursor = res.next_cursor || null;
  const moreBtn = document.getElementById("apiUsageKeyMoreBtn");
  if (moreBtn) moreBtn.style.display = apiUsageState.keyCursor ? "" : "none";
}

async function refreshApiUsageViews(resetCursors=false) {
  const periodInput = document.getElementById("apiUsagePeriod");
  if (!periodInput) return;
  if (!periodInput.value.trim()) periodInput.value = currentPeriodIdUtc();
  const period = periodInput.value.trim();
  if (!/^\d{4}-\d{2}$/.test(period)) throw new Error("Period must be YYYY-MM");

  if (resetCursors) {
    apiUsageState.routeCursor = null;
    apiUsageState.keyCursor = null;
  }
  await ensureUiSession();
  document.getElementById("apiUsageState").textContent = "Loading…";
  try {
    await refreshApiUsageSummary(period);
    await refreshApiUsageRoutes(period, false);
    await refreshApiUsageKeys(period, false);
    document.getElementById("apiUsageState").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    document.getElementById("apiUsageState").textContent = String(e);
    throw e;
  }
}

async function openKeyLimitsModal(keyId) {
  const key = (await apiGet('/ui/api_keys')).keys.find(k => k.key_id === keyId) || { key_id: keyId, route_caps: {} };
  const routesText = Object.entries(key.route_caps || {}).map(([rid, cap]) => `${rid}|${Number(cap.monthly_calls_cap||0)}|${Number(cap.monthly_spend_cap_micros||0)}`).join("\n");
  modalShow({
    title: `API Key Limits: ${escapeHtml(keyId)}`,
    bodyHtml: `
      <div class="muted">Set stricter key caps. Route caps format: <code class="mono">METHOD:/path|calls_cap|spend_cap_micros</code></div>
      <input id="keyLimitCalls" class="mono" placeholder="monthly_calls_cap" value="${escapeHtml(String(key.monthly_calls_cap||0))}"/>
      <input id="keyLimitSpend" class="mono" placeholder="monthly_spend_cap_micros" value="${escapeHtml(String(key.monthly_spend_cap_micros||0))}"/>
      <textarea id="keyLimitRoutes" class="mono" rows="6" placeholder="GET:/ui/api_keys|100|1000000">${escapeHtml(routesText)}</textarea>
      <div id="keyLimitErr" class="err" style="margin-top:8px;"></div>
    `,
    actions: [
      { text: "Cancel", onClick: modalClose },
      { text: "Save", onClick: async () => {
          try {
            const calls = Number(document.getElementById("keyLimitCalls").value || 0);
            const spend = Number(document.getElementById("keyLimitSpend").value || 0);
            if (!Number.isFinite(calls) || calls < 0 || !Number.isInteger(calls)) throw new Error("monthly_calls_cap must be a non-negative integer");
            if (!Number.isFinite(spend) || spend < 0 || !Number.isInteger(spend)) throw new Error("monthly_spend_cap_micros must be a non-negative integer");

            const routeCaps = {};
            const lines = (document.getElementById("keyLimitRoutes").value || "").split(/\n/).map(x => x.trim()).filter(Boolean);
            for (const line of lines) {
              const parts = line.split("|").map(x => x.trim());
              if (parts.length !== 3) throw new Error(`Invalid route cap line: ${line}`);
              const [routeId, cRaw, sRaw] = parts;
              const c = Number(cRaw);
              const s = Number(sRaw);
              if (!/^([A-Z]+):\/.+/.test(routeId)) throw new Error(`Invalid route_id: ${routeId}`);
              if (!Number.isInteger(c) || c < 0 || !Number.isInteger(s) || s < 0) throw new Error(`Invalid caps for route ${routeId}`);
              routeCaps[routeId] = { monthly_calls_cap: c, monthly_spend_cap_micros: s };
            }

            await apiPatch(`/ui/api_keys/${encodeURIComponent(keyId)}/limits`, {
              monthly_calls_cap: calls,
              monthly_spend_cap_micros: spend,
              route_caps: routeCaps,
            });
            modalClose();
            await refreshKeys();
            await refreshApiUsageViews(true);
          } catch (e) {
            document.getElementById("keyLimitErr").textContent = String(e);
          }
      } }
    ]
  });
}

async function openKeyUsageModal(keyId) {
  await ensureUiSession();
  const period = (document.getElementById("apiUsagePeriod")?.value || currentPeriodIdUtc()).trim();
  const u = await apiGet(`/ui/api_keys/${encodeURIComponent(keyId)}/usage?period=${encodeURIComponent(period)}`);
  modalShow({
    title: `API Key Usage: ${escapeHtml(keyId)}`,
    bodyHtml: `
      <div class="muted">Period ${escapeHtml(period)}</div>
      <div class="row-inline" style="margin-top:8px; gap:8px; flex-wrap:wrap;">
        <span class="pill">Calls ${Number((u.totals||{}).calls_total||0)}</span>
        <span class="pill">Units ${Number((u.totals||{}).request_units_total||0)}</span>
        <span class="pill">Spend ${fmtMicros(Number((u.totals||{}).cost_subtotal_micros||0))}</span>
      </div>
      <div class="muted" style="margin-top:8px;">Remaining calls: ${((u.remaining||{}).monthly_calls_remaining ?? "∞")}, remaining spend: ${((u.remaining||{}).monthly_spend_micros_remaining==null)?"∞":fmtMicros((u.remaining||{}).monthly_spend_micros_remaining)}</div>
      <pre class="mono" style="white-space:pre-wrap; margin-top:10px;">${escapeHtml(JSON.stringify((u.limits||{}).route_caps || {}, null, 2))}</pre>
    `,
    actions: [{ text: "Close", onClick: modalClose }]
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
      refreshDevices(),
      refreshKeys(),
      refreshApiUsageViews(true),
      refreshAccountStatus(),
      refreshAlertEmailSettings(),
      refreshPushUI(),
      refreshAlerts(),
      refreshProfile(),
      refreshFileManager(),
      refreshFileMgrAudit(),
      refreshAddresses(),
      refreshShoppingCart(),
      billingRefreshAll(),
      refreshCalendarAccess(),
      refreshCalendarShares(),
      refreshCalendarEvents(),
    ]);
    await pollToastsOnce();
    resumeAfterPasswordReset();
  } catch (e) {
    document.getElementById("globalErr").textContent = String(e);
  }
}

async function refreshAlerts() {
  const el = document.getElementById("alertsList");
  if (!el) return;
  await ensureUiSession();
  const res = await apiGet("/ui/alerts?limit=20");
  renderAlertsList(res.alerts || []);
}

function renderAlertsList(alerts) {
  const el = document.getElementById("alertsList");
  if (!el) return;
  el.innerHTML = "";
  if (!alerts.length) {
    el.innerHTML = "<div class='muted'>No alerts found.</div>";
    return;
  }
  alerts.forEach((a) => {
    el.appendChild(renderAlertRow(a));
  });
}

async function searchAlerts() {
  const query = readInput("alertsSearchInput");
  if (!query) {
    await refreshAlerts();
    return;
  }
  const status = document.getElementById("alertsSearchStatus");
  if (status) status.textContent = "Searching...";
  await ensureUiSession();
  const res = await apiGet(`/ui/alerts/search?q=${encodeURIComponent(query)}&limit=200`);
  renderAlertsList(res.alerts || []);
  if (status) status.textContent = `Found ${(res.alerts || []).length} alerts.`;
}

async function clearAlertSearch() {
  setInputValue("alertsSearchInput", "");
  const status = document.getElementById("alertsSearchStatus");
  if (status) status.textContent = "";
  await refreshAlerts();
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

const eventsPagination = {
  currentCursor: null,
  nextCursor: null,
  prevStack: [],
  lastQueryKey: "",
};

let calendarAccessItems = [];
let calendarShares = [];
let bookingLinks = [];

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
    const recurrenceButtons = evt.recurrence_rule && evt.start_utc
      ? `
      <div class="row-inline" style="margin-top:6px;">
        <button data-action="exclude" data-id="${escapeHtml(evt.event_id || "")}" data-start="${escapeHtml(evt.start_utc || "")}">Exclude occurrence</button>
        <button data-action="override" data-id="${escapeHtml(evt.event_id || "")}" data-start="${escapeHtml(evt.start_utc || "")}">Edit occurrence</button>
        <button class="muted" data-action="clear" data-id="${escapeHtml(evt.event_id || "")}" data-start="${escapeHtml(evt.start_utc || "")}">Clear exception</button>
      </div>
      `
      : "";
    const buttons = `
      <div class="row-inline" style="margin-top:6px;">
        <button data-action="edit" data-id="${escapeHtml(evt.event_id || "")}">Edit</button>
        <button class="danger" data-action="delete" data-id="${escapeHtml(evt.event_id || "")}">Delete</button>
      </div>
      ${recurrenceButtons}
    `;
    row.innerHTML = `
      <div class="row">
        <div class="grow"><b>${escapeHtml(evt.name || "")}</b></div>
        <div class="mono">${escapeHtml(evt.event_id || "")}</div>
      </div>
      <div class="muted">${when} (${escapeHtml(evt.timezone || "")})</div>
      ${evt.description ? `<div class="muted">${escapeHtml(evt.description)}</div>` : ""}
      ${buttons}
    `;
    row.querySelector('[data-action="edit"]').onclick = () => {
      setEventEditMode(evt);
    };
    row.querySelector('[data-action="delete"]').onclick = async () => {
      await deleteCalendarEvent(evt.event_id);
    };
    if (recurrenceButtons) {
      row.querySelector('[data-action="exclude"]').onclick = async (ev) => {
        await excludeEventOccurrence(ev.target.getAttribute("data-id"), ev.target.getAttribute("data-start"));
      };
      row.querySelector('[data-action="override"]').onclick = async (ev) => {
        await overrideEventOccurrence(ev.target.getAttribute("data-id"), ev.target.getAttribute("data-start"), evt);
      };
      row.querySelector('[data-action="clear"]').onclick = async (ev) => {
        await clearEventOccurrenceException(ev.target.getAttribute("data-id"), ev.target.getAttribute("data-start"));
      };
    }
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

function renderTeamOpenings(openings) {
  const wrap = document.getElementById("calendarTeamOpeningsList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!openings || openings.length === 0) {
    wrap.innerHTML = '<div class="muted">No shared openings for selected window.</div>';
    return;
  }
  openings.forEach(o => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `<div class="mono">${escapeHtml(o.start_utc)} → ${escapeHtml(o.end_utc)}</div>`;
    wrap.appendChild(row);
  });
}

function renderEventConflicts(conflicts) {
  const wrap = document.getElementById("eventConflictsList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!conflicts || conflicts.length === 0) {
    wrap.innerHTML = '<div class="muted">No conflicts found.</div>';
    return;
  }
  conflicts.forEach(evt => {
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
    `;
    wrap.appendChild(row);
  });
}

function renderEventSuggestions(suggestions) {
  const wrap = document.getElementById("eventSuggestionsList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!suggestions || suggestions.length === 0) {
    wrap.innerHTML = '<div class="muted">No suggested slots available.</div>';
    return;
  }
  suggestions.forEach(slot => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="row-inline" style="align-items:center;">
        <div class="mono grow">${escapeHtml(slot.start_utc)} → ${escapeHtml(slot.end_utc)}</div>
        <button data-action="apply" data-start="${escapeHtml(slot.start_utc)}" data-end="${escapeHtml(slot.end_utc)}">Use slot</button>
      </div>
    `;
    row.querySelector('[data-action="apply"]').onclick = (ev) => {
      const start = ev.target.getAttribute("data-start");
      const end = ev.target.getAttribute("data-end");
      if (!start || !end) return;
      document.getElementById("eventAllDayToggle").checked = false;
      document.getElementById("eventAllDayDateInput").value = "";
      document.getElementById("eventStartInput").value = start;
      document.getElementById("eventEndInput").value = end;
      document.getElementById("eventCreateStatus").textContent = "Applied suggested slot.";
    };
    wrap.appendChild(row);
  });
}

function renderCalendarAccess(items) {
  calendarAccessItems = Array.isArray(items) ? items : [];
  const wrap = document.getElementById("calendarAccessList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!calendarAccessItems.length) {
    wrap.innerHTML = '<div class="muted">No accessible calendars yet.</div>';
    return;
  }
  calendarAccessItems.forEach(item => {
    const row = document.createElement("div");
    row.className = "item";
    row.innerHTML = `
      <div class="row">
        <div class="grow"><b>${escapeHtml(item.name || "Calendar")}</b></div>
        <div class="mono">${escapeHtml(item.calendar_id || "")}</div>
      </div>
      <div class="muted">Owner: ${escapeHtml(item.owner_user_id || "")} · Permission: ${escapeHtml(item.permission || "read")}</div>
      <div class="row-inline" style="margin-top:6px;">
        <button data-action="use" data-id="${escapeHtml(item.calendar_id || "")}">Use calendar</button>
      </div>
    `;
    row.querySelector('[data-action="use"]').onclick = async (ev) => {
      const calendarId = ev.target.getAttribute("data-id");
      setCalendarId(calendarId || "");
      if (calendarId) {
        setCalendarStatus(`Using calendar ${calendarId}`);
        resetEventsPagination();
        await refreshBookingLinks();
        await refreshCalendarEvents();
        await refreshCalendarShares();
      }
    };
    wrap.appendChild(row);
  });
}

function renderCalendarShares(items) {
  calendarShares = Array.isArray(items) ? items : [];
  const wrap = document.getElementById("calendarSharesList");
  if (!wrap) return;
  wrap.innerHTML = "";
  if (!calendarShares.length) {
    wrap.innerHTML = '<div class="muted">No shares for this calendar.</div>';
    return;
  }
  calendarShares.forEach(share => {
    const row = document.createElement("div");
    row.className = "item";
    row.innerHTML = `
      <div class="row">
        <div class="grow"><b>${escapeHtml(share.user_sub || "")}</b></div>
        <div class="mono">${escapeHtml(share.permission || "read")}</div>
      </div>
      <div class="muted">Shared at ${escapeHtml(share.created_at_utc || "")}</div>
      <div class="row-inline" style="margin-top:6px;">
        <button class="danger" data-action="revoke" data-user="${escapeHtml(share.user_sub || "")}">Revoke</button>
      </div>
    `;
    row.querySelector('[data-action="revoke"]').onclick = async (ev) => {
      const userSub = ev.target.getAttribute("data-user");
      if (!userSub) return;
      await deleteCalendarShare(userSub);
    };
    wrap.appendChild(row);
  });
}

function renderBookingLinks(links) {
  bookingLinks = Array.isArray(links) ? links : [];
  const wrap = document.getElementById("bookingLinksList");
  if (wrap) {
    wrap.innerHTML = "";
    if (!bookingLinks.length) {
      wrap.innerHTML = '<div class="muted">No booking links yet.</div>';
    } else {
      bookingLinks.forEach(link => {
        const row = document.createElement("div");
        row.className = "item";
        const publicUrl = link.public_url || `/booking/${link.link_id}`;
        row.innerHTML = `
          <div class="row">
            <div class="grow"><b>${escapeHtml(link.name || "")}</b></div>
            <div class="mono">${escapeHtml(link.link_id || "")}</div>
          </div>
          <div class="muted">Duration: ${escapeHtml(String(link.duration_minutes || 0))} min · ${escapeHtml(link.timezone || "UTC")}</div>
          <div class="row-inline" style="margin-top:6px; align-items:center;">
            <div class="mono grow">${escapeHtml(publicUrl)}</div>
            <button data-action="copy" data-url="${escapeHtml(publicUrl)}">Copy URL</button>
            <button data-action="use" data-id="${escapeHtml(link.link_id || "")}">Use for preview</button>
          </div>
        `;
        row.querySelector('[data-action="copy"]').onclick = async (ev) => {
          const url = ev.target.getAttribute("data-url");
          if (!url) return;
          try {
            await navigator.clipboard.writeText(url);
            const status = document.getElementById("bookingLinkStatus");
            if (status) status.textContent = "Copied link URL.";
          } catch (e) {
            prompt("Copy booking link URL:", url);
          }
        };
        row.querySelector('[data-action="use"]').onclick = (ev) => {
          const linkId = ev.target.getAttribute("data-id");
          const select = document.getElementById("bookingLinkSelect");
          if (select && linkId) {
            select.value = linkId;
          }
        };
        wrap.appendChild(row);
      });
    }
  }

  const select = document.getElementById("bookingLinkSelect");
  if (select) {
    select.innerHTML = "";
    if (!bookingLinks.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No booking links available";
      select.appendChild(opt);
    } else {
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "Select booking link";
      select.appendChild(placeholder);
      bookingLinks.forEach(link => {
        const opt = document.createElement("option");
        opt.value = link.link_id || "";
        opt.textContent = `${link.name || "Booking link"} (${link.duration_minutes || 0} min)`;
        select.appendChild(opt);
      });
    }
  }
}

function renderBookingOpenings(openings) {
  const wrap = document.getElementById("bookingOpeningsList");
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

function parseTeamCalendarIds(raw) {
  return raw
    .split(/[\n,]+/)
    .map(value => value.trim())
    .filter(Boolean);
}

function toIsoUtc(value) {
  if (!value) return "";
  if (value.endsWith("Z") || value.includes("+")) return value;
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return value;
  return dt.toISOString();
}

function getEventFilters() {
  const startPicker = document.getElementById("eventsStartPicker").value.trim();
  const endPicker = document.getElementById("eventsEndPicker").value.trim();
  const start = startPicker ? toIsoUtc(startPicker) : document.getElementById("eventsStartInput").value.trim();
  const end = endPicker ? toIsoUtc(endPicker) : document.getElementById("eventsEndInput").value.trim();
  const limitRaw = document.getElementById("eventsLimitSelect").value;
  const limit = limitRaw ? Number.parseInt(limitRaw, 10) : null;
  return { start, end, limit };
}

function updateEventsStatus(message) {
  const status = document.getElementById("eventsStatus");
  if (status) status.textContent = message || "";
}

function updateEventsPaginationControls() {
  const prevBtn = document.getElementById("eventsPrevBtn");
  const nextBtn = document.getElementById("eventsNextBtn");
  if (prevBtn) prevBtn.disabled = eventsPagination.prevStack.length === 0;
  if (nextBtn) nextBtn.disabled = !eventsPagination.nextCursor;
}

function resetEventsPagination() {
  eventsPagination.currentCursor = null;
  eventsPagination.nextCursor = null;
  eventsPagination.prevStack = [];
  updateEventsPaginationControls();
}

function updateBookingLinkStatus(message) {
  const status = document.getElementById("bookingLinkStatus");
  if (status) status.textContent = message || "";
}

function updateBookingOpeningsStatus(message) {
  const status = document.getElementById("bookingOpeningsStatus");
  if (status) status.textContent = message || "";
}

function updateEventConflictStatus(message) {
  const status = document.getElementById("eventConflictStatus");
  if (status) status.textContent = message || "";
}

function updateCalendarAccessStatus(message) {
  const status = document.getElementById("calendarAccessStatus");
  if (status) status.textContent = message || "";
}

function updateCalendarShareStatus(message) {
  const status = document.getElementById("calendarShareStatus");
  if (status) status.textContent = message || "";
}

function setEventEditMode(evt) {
  document.getElementById("eventIdInput").value = evt.event_id || "";
  document.getElementById("eventNameInput").value = evt.name || "";
  document.getElementById("eventDescriptionInput").value = evt.description || "";
  document.getElementById("eventTimezoneInput").value = evt.timezone || "";
  document.getElementById("eventAllDayToggle").checked = !!evt.all_day;
  document.getElementById("eventAllDayDateInput").value = evt.all_day_date || "";
  document.getElementById("eventStartInput").value = evt.start_utc || "";
  document.getElementById("eventEndInput").value = evt.end_utc || "";
  document.getElementById("eventRecurrenceFreq").value = evt.recurrence_rule?.freq || "";
  document.getElementById("eventRecurrenceInterval").value = evt.recurrence_rule?.interval || "";
  document.getElementById("eventRecurrenceCount").value = evt.recurrence_rule?.count || "";
  document.getElementById("eventRecurrenceUntil").value = evt.recurrence_rule?.until_utc || "";
  document.getElementById("eventRecurrenceBymonthday").value = (evt.recurrence_rule?.bymonthday || []).join(",");
  document.getElementById("eventRecurrenceBysetpos").value = (evt.recurrence_rule?.bysetpos || []).join(",");
  document.getElementById("eventRecurrenceExdates").value = (evt.exdates_utc || []).join("\n");
  document.querySelectorAll(".eventRecurrenceByday").forEach(box => {
    const day = box.getAttribute("data-day");
    box.checked = !!evt.recurrence_rule?.byday?.includes(day);
  });
  document.getElementById("eventCreateBtn").textContent = "Save event";
  document.getElementById("eventCreateStatus").textContent = `Editing ${evt.event_id}`;
}

function resetEventForm() {
  document.getElementById("eventIdInput").value = "";
  document.getElementById("eventNameInput").value = "";
  document.getElementById("eventDescriptionInput").value = "";
  document.getElementById("eventTimezoneInput").value = "";
  document.getElementById("eventAllDayToggle").checked = false;
  document.getElementById("eventAllDayDateInput").value = "";
  document.getElementById("eventStartInput").value = "";
  document.getElementById("eventEndInput").value = "";
  document.getElementById("eventRecurrenceFreq").value = "";
  document.getElementById("eventRecurrenceInterval").value = "";
  document.getElementById("eventRecurrenceCount").value = "";
  document.getElementById("eventRecurrenceUntil").value = "";
  document.getElementById("eventRecurrenceBymonthday").value = "";
  document.getElementById("eventRecurrenceBysetpos").value = "";
  document.getElementById("eventRecurrenceExdates").value = "";
  document.querySelectorAll(".eventRecurrenceByday").forEach(box => { box.checked = false; });
  document.getElementById("eventCreateBtn").textContent = "Add event";
  updateEventConflictStatus("");
  renderEventConflicts([]);
  renderEventSuggestions([]);
}

function parseCsvNumbers(value) {
  if (!value) return [];
  return value
    .split(/[\n,]+/)
    .map(v => v.trim())
    .filter(Boolean)
    .map(v => Number.parseInt(v, 10))
    .filter(v => !Number.isNaN(v));
}

function buildRecurrenceRule() {
  const freq = document.getElementById("eventRecurrenceFreq").value;
  if (!freq) return null;
  const intervalRaw = document.getElementById("eventRecurrenceInterval").value.trim();
  const countRaw = document.getElementById("eventRecurrenceCount").value.trim();
  const untilRaw = document.getElementById("eventRecurrenceUntil").value.trim();
  const byday = Array.from(document.querySelectorAll(".eventRecurrenceByday"))
    .filter(box => box.checked)
    .map(box => box.getAttribute("data-day"));
  const bymonthday = parseCsvNumbers(document.getElementById("eventRecurrenceBymonthday").value.trim());
  const bysetpos = parseCsvNumbers(document.getElementById("eventRecurrenceBysetpos").value.trim());
  const rule = {
    freq,
    interval: intervalRaw ? Number.parseInt(intervalRaw, 10) : 1,
  };
  if (countRaw) rule.count = Number.parseInt(countRaw, 10);
  if (untilRaw) rule.until_utc = toIsoUtc(untilRaw);
  if (byday.length) rule.byday = byday;
  if (bymonthday.length) rule.bymonthday = bymonthday;
  if (bysetpos.length) rule.bysetpos = bysetpos;
  return rule;
}

function buildEventPayload() {
  const exdates = document.getElementById("eventRecurrenceExdates").value
    .split(/\n+/)
    .map(value => value.trim())
    .filter(Boolean)
    .map(value => toIsoUtc(value));
  return {
    name: document.getElementById("eventNameInput").value.trim(),
    description: document.getElementById("eventDescriptionInput").value.trim(),
    timezone: document.getElementById("eventTimezoneInput").value.trim() || null,
    all_day: document.getElementById("eventAllDayToggle").checked,
    all_day_date: document.getElementById("eventAllDayDateInput").value || null,
    start_utc: document.getElementById("eventStartInput").value.trim() || null,
    end_utc: document.getElementById("eventEndInput").value.trim() || null,
    recurrence_rule: buildRecurrenceRule(),
    exdates_utc: exdates.length ? exdates : null,
  };
}

function buildWorkingHours() {
  const days = [
    { key: "mon", start: "workMonStart", end: "workMonEnd" },
    { key: "tue", start: "workTueStart", end: "workTueEnd" },
    { key: "wed", start: "workWedStart", end: "workWedEnd" },
    { key: "thu", start: "workThuStart", end: "workThuEnd" },
    { key: "fri", start: "workFriStart", end: "workFriEnd" },
    { key: "sat", start: "workSatStart", end: "workSatEnd" },
    { key: "sun", start: "workSunStart", end: "workSunEnd" },
  ];
  const workingHours = {};
  days.forEach(day => {
    const start = document.getElementById(day.start).value;
    const end = document.getElementById(day.end).value;
    if (start && end) {
      workingHours[day.key] = [{ start, end }];
    }
  });
  return workingHours;
}

async function createCalendar() {
  try {
    await ensureUiSession();
    const name = document.getElementById("calendarNameInput").value.trim() || "My Calendar";
    const timezone = document.getElementById("calendarTimezoneInput").value.trim() || "UTC";
    const res = await apiPost("/ui/calendars", { name, timezone });
    setCalendarId(res.calendar_id || "");
    setCalendarStatus(`Created calendar ${res.calendar_id}`);
    await refreshCalendarAccess();
    await refreshCalendarShares();
    await refreshBookingLinks();
    await refreshCalendarEvents();
  } catch (e) {
    setCalendarStatus("Error: " + e.message);
  }
}

async function refreshCalendarAccess() {
  try {
    await ensureUiSession();
    updateCalendarAccessStatus("Loading...");
    const res = await apiGet("/ui/calendars");
    renderCalendarAccess(res || []);
    updateCalendarAccessStatus(`Loaded ${Array.isArray(res) ? res.length : 0} calendars.`);
  } catch (e) {
    updateCalendarAccessStatus("Error: " + e.message);
  }
}

async function refreshCalendarShares() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    renderCalendarShares([]);
    updateCalendarShareStatus("Set a calendar ID to manage shares.");
    return;
  }
  try {
    await ensureUiSession();
    updateCalendarShareStatus("Loading...");
    const res = await apiGet(`/ui/calendars/${encodeURIComponent(calendarId)}/shares`);
    renderCalendarShares(res || []);
    updateCalendarShareStatus(`Loaded ${Array.isArray(res) ? res.length : 0} shares.`);
  } catch (e) {
    renderCalendarShares([]);
    updateCalendarShareStatus("Error: " + e.message);
  }
}

async function createCalendarShare() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    updateCalendarShareStatus("Set a calendar ID first.");
    return;
  }
  const userSub = document.getElementById("calendarShareUserInput").value.trim();
  const permission = document.getElementById("calendarSharePermissionInput").value;
  if (!userSub) {
    updateCalendarShareStatus("Enter a user sub to share with.");
    return;
  }
  try {
    await ensureUiSession();
    const res = await apiPost(`/ui/calendars/${encodeURIComponent(calendarId)}/shares`, {
      user_sub: userSub,
      permission,
    });
    updateCalendarShareStatus(`Shared with ${res.user_sub}.`);
    document.getElementById("calendarShareUserInput").value = "";
    await refreshCalendarShares();
    await refreshCalendarAccess();
  } catch (e) {
    updateCalendarShareStatus("Error: " + e.message);
  }
}

async function deleteCalendarShare(userSub) {
  const calendarId = getCalendarId();
  if (!calendarId || !userSub) return;
  if (!confirm(`Revoke access for ${userSub}?`)) return;
  try {
    await ensureUiSession();
    await apiDelete(`/ui/calendars/${encodeURIComponent(calendarId)}/shares/${encodeURIComponent(userSub)}`);
    updateCalendarShareStatus(`Revoked access for ${userSub}.`);
    await refreshCalendarShares();
    await refreshCalendarAccess();
  } catch (e) {
    updateCalendarShareStatus("Error: " + e.message);
  }
}

async function refreshBookingLinks() {
  const calendarId = getCalendarId();
  if (!calendarId) return;
  try {
    await ensureUiSession();
    const res = await apiGet(`/ui/calendars/${encodeURIComponent(calendarId)}/booking_links`);
    renderBookingLinks(res || []);
  } catch (e) {
    updateBookingLinkStatus("Error: " + e.message);
  }
}

async function createBookingLink() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    updateBookingLinkStatus("Set a calendar ID first.");
    return;
  }
  try {
    await ensureUiSession();
    const name = document.getElementById("bookingLinkNameInput").value.trim();
    const duration = document.getElementById("bookingLinkDurationInput").value.trim();
    const timezone = document.getElementById("bookingLinkTimezoneInput").value.trim() || null;
    if (!name || !duration) {
      updateBookingLinkStatus("Enter a name and duration.");
      return;
    }
    const payload = { name, duration_minutes: Number.parseInt(duration, 10), timezone };
    const res = await apiPost(`/ui/calendars/${encodeURIComponent(calendarId)}/booking_links`, payload);
    updateBookingLinkStatus(`Created booking link ${res.link_id}`);
    document.getElementById("bookingLinkNameInput").value = "";
    document.getElementById("bookingLinkDurationInput").value = "";
    document.getElementById("bookingLinkTimezoneInput").value = "";
    await refreshBookingLinks();
  } catch (e) {
    updateBookingLinkStatus("Error: " + e.message);
  }
}

async function loadBookingLinkOpenings() {
  const linkId = document.getElementById("bookingLinkSelect").value;
  if (!linkId) {
    updateBookingOpeningsStatus("Select a booking link first.");
    return;
  }
  const startPicker = document.getElementById("bookingOpeningsStartPicker").value.trim();
  const endPicker = document.getElementById("bookingOpeningsEndPicker").value.trim();
  const start = startPicker ? toIsoUtc(startPicker) : document.getElementById("bookingOpeningsStartInput").value.trim();
  const end = endPicker ? toIsoUtc(endPicker) : document.getElementById("bookingOpeningsEndInput").value.trim();
  if (!start || !end) {
    updateBookingOpeningsStatus("Enter start and end window.");
    return;
  }
  const limitRaw = document.getElementById("bookingOpeningsLimitInput").value.trim();
  const params = new URLSearchParams({ start_utc: start, end_utc: end });
  if (limitRaw) params.set("limit", limitRaw);
  try {
    updateBookingOpeningsStatus("Loading...");
    const res = await apiGet(`/booking/${encodeURIComponent(linkId)}/openings?${params.toString()}`);
    renderBookingOpenings(res || []);
    updateBookingOpeningsStatus(`Found ${Array.isArray(res) ? res.length : 0} openings.`);
  } catch (e) {
    updateBookingOpeningsStatus("Error: " + e.message);
  }
}

async function loadTeamOpenings() {
  const status = document.getElementById("calendarTeamStatus");
  const ids = parseTeamCalendarIds(document.getElementById("teamCalendarIdsInput").value);
  const startPicker = document.getElementById("teamOpeningsStartPicker").value.trim();
  const endPicker = document.getElementById("teamOpeningsEndPicker").value.trim();
  const start = startPicker ? toIsoUtc(startPicker) : document.getElementById("teamOpeningsStartInput").value.trim();
  const end = endPicker ? toIsoUtc(endPicker) : document.getElementById("teamOpeningsEndInput").value.trim();
  if (!ids.length) {
    if (status) status.textContent = "Enter at least one calendar ID.";
    return;
  }
  if (!start || !end) {
    if (status) status.textContent = "Enter start and end window.";
    return;
  }
  try {
    await ensureUiSession();
    if (status) status.textContent = "Loading...";
    const res = await apiPost("/ui/calendars/availability", {
      calendar_ids: ids,
      start_utc: start,
      end_utc: end,
    });
    renderTeamOpenings(res || []);
    if (status) status.textContent = `Found ${Array.isArray(res) ? res.length : 0} openings.`;
  } catch (e) {
    if (status) status.textContent = "Error: " + e.message;
  }
}

async function refreshCalendarEvents() {
  const calendarId = getCalendarId();
  if (!calendarId) return;
  await ensureUiSession();
  const filters = getEventFilters();
  if ((filters.start && !filters.end) || (!filters.start && filters.end)) {
    updateEventsStatus("Enter both start and end to filter the event list.");
    return;
  }
  const queryKey = JSON.stringify(filters);
  if (eventsPagination.lastQueryKey && eventsPagination.lastQueryKey !== queryKey) {
    resetEventsPagination();
  }
  eventsPagination.lastQueryKey = queryKey;
  const params = new URLSearchParams();
  if (filters.start) params.set("start_utc", filters.start);
  if (filters.end) params.set("end_utc", filters.end);
  if (filters.limit) params.set("limit", String(filters.limit));
  if (eventsPagination.currentCursor) params.set("cursor", eventsPagination.currentCursor);
  const qs = params.toString();
  updateEventsStatus("Loading...");
  const res = await apiGet(`/ui/calendars/${encodeURIComponent(calendarId)}/events${qs ? `?${qs}` : ""}`);
  const events = Array.isArray(res) ? res : res.events;
  renderCalendarEvents(events || []);
  eventsPagination.nextCursor = res && !Array.isArray(res) ? res.next_cursor : null;
  updateEventsPaginationControls();
  updateEventsStatus(`Loaded ${Array.isArray(events) ? events.length : 0} events.`);
}

async function previewEventConflicts() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    setCalendarStatus("Set a calendar ID first.");
    return;
  }
  try {
    await ensureUiSession();
    updateEventConflictStatus("Checking conflicts...");
    const eventId = document.getElementById("eventIdInput").value.trim();
    const payload = buildEventPayload();
    const res = await apiPost(`/ui/calendars/${encodeURIComponent(calendarId)}/events/conflicts`, {
      ...payload,
      event_id: eventId || null,
    });
    renderEventConflicts(res?.conflicts || []);
    renderEventSuggestions([]);
    const count = Array.isArray(res?.conflicts) ? res.conflicts.length : 0;
    updateEventConflictStatus(count ? `Found ${count} conflict(s).` : "No conflicts found.");
  } catch (e) {
    renderEventConflicts([]);
    updateEventConflictStatus("Error: " + e.message);
  }
}

async function loadEventSuggestions() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    setCalendarStatus("Set a calendar ID first.");
    return;
  }
  const payload = buildEventPayload();
  if (payload.all_day || !payload.start_utc || !payload.end_utc) {
    updateEventConflictStatus("Suggestions require start and end times for a timed event.");
    return;
  }
  try {
    await ensureUiSession();
    updateEventConflictStatus("Loading suggestions...");
    const durationMinutes = Math.max(
      1,
      Math.round((new Date(payload.end_utc).getTime() - new Date(payload.start_utc).getTime()) / 60000)
    );
    const res = await apiPost(`/ui/calendars/${encodeURIComponent(calendarId)}/events/suggestions`, {
      start_utc: payload.start_utc,
      end_utc: payload.end_utc,
      duration_minutes: durationMinutes,
      limit: 5,
      window_days: 7,
    });
    renderEventSuggestions(res || []);
    updateEventConflictStatus(`Found ${Array.isArray(res) ? res.length : 0} suggestion(s).`);
  } catch (e) {
    renderEventSuggestions([]);
    updateEventConflictStatus("Error: " + e.message);
  }
}

async function excludeEventOccurrence(eventId, occurrenceStart) {
  const calendarId = getCalendarId();
  if (!calendarId || !eventId || !occurrenceStart) return;
  if (!confirm("Exclude this occurrence?")) return;
  try {
    await ensureUiSession();
    await apiPost(
      `/ui/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}/occurrences/${encodeURIComponent(occurrenceStart)}/exclude`,
      {}
    );
    setCalendarStatus("Occurrence excluded.");
    await refreshCalendarEvents();
  } catch (e) {
    setCalendarStatus("Error: " + e.message);
  }
}

async function overrideEventOccurrence(eventId, occurrenceStart, evt) {
  const calendarId = getCalendarId();
  if (!calendarId || !eventId || !occurrenceStart) return;
  const defaultStart = evt?.start_utc || occurrenceStart;
  const defaultEnd = evt?.end_utc || "";
  const newStart = prompt("New start (ISO-8601 UTC)", defaultStart || "") || "";
  if (!newStart) return;
  const newEnd = prompt("New end (ISO-8601 UTC)", defaultEnd || "") || "";
  if (!newEnd) return;
  try {
    await ensureUiSession();
    await apiPost(
      `/ui/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}/occurrences/${encodeURIComponent(occurrenceStart)}/override`,
      { start_utc: newStart, end_utc: newEnd }
    );
    setCalendarStatus("Occurrence updated.");
    await refreshCalendarEvents();
  } catch (e) {
    setCalendarStatus("Error: " + e.message);
  }
}

async function clearEventOccurrenceException(eventId, occurrenceStart) {
  const calendarId = getCalendarId();
  if (!calendarId || !eventId || !occurrenceStart) return;
  if (!confirm("Clear exception for this occurrence?")) return;
  try {
    await ensureUiSession();
    await apiDelete(
      `/ui/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}/occurrences/${encodeURIComponent(occurrenceStart)}`
    );
    setCalendarStatus("Occurrence exception cleared.");
    await refreshCalendarEvents();
  } catch (e) {
    setCalendarStatus("Error: " + e.message);
  }
}

async function createCalendarEvent() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    setCalendarStatus("Set a calendar ID first.");
    return;
  }
  try {
    await ensureUiSession();
    const eventId = document.getElementById("eventIdInput").value.trim();
    const payload = buildEventPayload();
    const res = eventId
      ? await apiPatch(`/ui/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}`, payload)
      : await apiPost(`/ui/calendars/${encodeURIComponent(calendarId)}/events`, payload);
    if (eventId) {
      document.getElementById("eventCreateStatus").textContent = `Updated event ${res.event_id}`;
      resetEventForm();
    } else {
      document.getElementById("eventCreateStatus").textContent = `Added event ${res.event_id}`;
    }
    resetEventsPagination();
    await refreshCalendarEvents();
  } catch (e) {
    document.getElementById("eventCreateStatus").textContent = "Error: " + e.message;
  }
}

async function deleteCalendarEvent(eventId) {
  if (!eventId) return;
  if (!confirm("Delete this event?")) return;
  const calendarId = getCalendarId();
  if (!calendarId) return;
  try {
    await ensureUiSession();
    await apiDelete(`/ui/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(eventId)}`);
    setCalendarStatus(`Deleted event ${eventId}`);
    resetEventsPagination();
    await refreshCalendarEvents();
  } catch (e) {
    setCalendarStatus("Error: " + e.message);
  }
}

async function loadCalendarOpenings() {
  const calendarId = getCalendarId();
  if (!calendarId) {
    setCalendarStatus("Set a calendar ID first.");
    return;
  }
  const startPicker = document.getElementById("openingsStartPicker").value.trim();
  const endPicker = document.getElementById("openingsEndPicker").value.trim();
  const start = startPicker ? toIsoUtc(startPicker) : document.getElementById("openingsStartInput").value.trim();
  const end = endPicker ? toIsoUtc(endPicker) : document.getElementById("openingsEndInput").value.trim();
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

async function saveWorkingHours() {
  const calendarId = getCalendarId();
  const status = document.getElementById("workingHoursStatus");
  if (!calendarId) {
    if (status) status.textContent = "Set a calendar ID first.";
    return;
  }
  try {
    await ensureUiSession();
    const workingHours = buildWorkingHours();
    await apiPatch(`/ui/calendars/${encodeURIComponent(calendarId)}`, { working_hours: workingHours });
    if (status) status.textContent = "Saved.";
  } catch (e) {
    if (status) status.textContent = "Error: " + e.message;
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

function setMsgAttachmentStatus(msg) {
  setMsgStatus("msgAttachmentStatus", msg);
}

function uiSessionHeaders() {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const headers = { Authorization: `Bearer ${tok}` };
  addCsrfHeader(headers);
  return headers;
}

async function msgRequest(path, { method = "GET", body = null } = {}) {
  const uid = msgUserId();
  const headers = {};
  if (uid) {
    headers.Authorization = `Bearer ${uid}`;
  } else {
    const tok = accessToken();
    if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
    headers.Authorization = `Bearer ${tok}`;
    if (method !== "GET") addCsrfHeader(headers);
  }
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(`${msgApiBase()}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
    credentials: "include",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json();
}

async function fileManagerUpload(path, file) {
  const headers = uiSessionHeaders();
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${msgApiBase()}/v1/fs/upload?path=${encodeURIComponent(path)}`, {
    method: "POST",
    headers,
    body: form,
    credentials: "include",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Upload failed: ${res.status}`);
  }
  return res.json();
}

async function fileManagerPresignUpload(path, file) {
  const headers = uiSessionHeaders();
  headers["Content-Type"] = "application/json";
  const res = await fetch(`${msgApiBase()}/v1/fs/presign-upload`, {
    method: "POST",
    headers,
    body: JSON.stringify({ path, content_type: file.type || "application/octet-stream" }),
    credentials: "include",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Presign failed: ${res.status}`);
  }
  const data = await res.json();
  const uploadRes = await fetch(data.upload_url, {
    method: "PUT",
    headers: { "Content-Type": data.content_type || "application/octet-stream" },
    body: file,
  });
  if (!uploadRes.ok) {
    throw new Error(`Upload failed: ${uploadRes.status}`);
  }
  const completeRes = await fetch(`${msgApiBase()}/v1/fs/complete-upload`, {
    method: "POST",
    headers,
    body: JSON.stringify({ path: data.path, key: data.key, content_type: data.content_type }),
    credentials: "include",
  });
  if (!completeRes.ok) {
    const text = await completeRes.text();
    throw new Error(text || `Complete upload failed: ${completeRes.status}`);
  }
  return completeRes.json();
}

async function fetchFileBlob(path, { preview }) {
  const headers = uiSessionHeaders();
  const endpoint = preview ? "/v1/fs/preview" : "/v1/fs/download";
  const res = await fetch(`${msgApiBase()}${endpoint}?path=${encodeURIComponent(path)}`, {
    headers,
    credentials: "include",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Download failed: ${res.status}`);
  }
  return res.blob();
}

async function downloadFilePath(path, filename) {
  const blob = await fetchFileBlob(path, { preview: false });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename || "download";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function previewFilePath(path) {
  const blob = await fetchFileBlob(path, { preview: true });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener");
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  if (!bytes) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, idx);
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function buildPreviewPayload() {
  const url = readInput("msgPreviewUrl");
  const title = readInput("msgPreviewTitle");
  const description = readInput("msgPreviewDescription");
  const imageUrl = readInput("msgPreviewImage");
  const siteName = readInput("msgPreviewSite");
  if (!url && (title || description || imageUrl || siteName)) {
    return { error: "Preview URL is required when adding preview metadata." };
  }
  if (!url) return { preview: null };
  return {
    preview: {
      url,
      title: title || null,
      description: description || null,
      image_url: imageUrl || null,
      site_name: siteName || null,
    },
  };
}

function renderLinkPreview(preview) {
  if (!preview) return "";
  const image = preview.image_url
    ? `<div><img src="${preview.image_url}" alt="Preview image" style="max-width:200px;max-height:120px;border-radius:6px;" /></div>`
    : "";
  const title = preview.title ? `<div><b>${preview.title}</b></div>` : "";
  const description = preview.description ? `<div class="muted">${preview.description}</div>` : "";
  const site = preview.site_name ? `<div class="muted">${preview.site_name}</div>` : "";
  const url = preview.url ? `<a href="${preview.url}" target="_blank" rel="noopener">${preview.url}</a>` : "";
  return `
    <div class="item" style="margin-top:8px;">
      ${image}
      ${title}
      ${description}
      ${site}
      ${url}
    </div>
  `;
}

function renderFileMeta(file, kind) {
  if (!file) return "";
  const meta = [];
  if (file.content_type) meta.push(file.content_type);
  if (file.size) meta.push(formatBytes(file.size));
  if (file.duration_seconds) meta.push(`${file.duration_seconds}s`);
  const thumbnail = file.thumbnail
    ? `<div><img src="${msgApiBase()}/v1/fs/thumbnail?path=${encodeURIComponent(file.path)}" alt="Attachment thumbnail" style="max-width:200px;max-height:120px;border-radius:6px;" /></div>`
    : "";
  const label = kind === "audio" ? "Voice note" : kind === "video" ? "Video" : "File";
  return `
    ${thumbnail}
    <div><b>${label}</b> ${file.name || ""}</div>
    <div class="muted">${meta.join(" • ")}</div>
    ${file.path ? `<div class="muted mono">${file.path}</div>` : ""}
  `;
}

async function createInlinePlayer({ kind, path, name, container }) {
  const blob = await fetchFileBlob(path, { preview: false });
  const url = URL.createObjectURL(blob);
  let el = null;
  if (kind === "audio") {
    el = document.createElement("audio");
  } else if (kind === "video") {
    el = document.createElement("video");
    el.style.maxWidth = "320px";
  }
  if (!el) return null;
  el.controls = true;
  el.src = url;
  el.onended = () => URL.revokeObjectURL(url);
  el.onpause = () => {};
  el.title = name || "";
  container.appendChild(el);
  return el;
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
    const unread = c.unread_count ? ` • unread ${c.unread_count}` : "";
    btn.innerHTML = `
      <div style="text-align:left;">
        <div><b>${c.title || c.conversation_id}</b></div>
        <div class="muted">${c.type} • ${c.status} • participants ${c.participant_count}${unread}</div>
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
    const body = document.createElement("div");
    if (m.kind === "image") {
      body.innerHTML = `<div><em>[image]</em> ${m.image ? (m.image.key || "") : ""}</div>`;
    } else if (m.kind === "file" || m.kind === "audio" || m.kind === "video") {
      body.innerHTML = renderFileMeta(m.file, m.kind);
    } else {
      body.innerHTML = `<div>${m.text || ""}</div>`;
    }
    if (m.preview) {
      body.insertAdjacentHTML("beforeend", renderLinkPreview(m.preview));
    }
    if (m.delivered_to_count || m.read_by_count) {
      const delivered = m.delivered_to_count ? `Delivered to ${m.delivered_to_count}` : "";
      const readBy = m.read_by_count ? `Read by ${m.read_by_count}` : "";
      const statusText = [delivered, readBy].filter(Boolean).join(" • ");
      if (statusText) {
        body.insertAdjacentHTML("beforeend", `<div class="muted" style="margin-top:6px;">${statusText}</div>`);
      }
    }
    row.innerHTML = `<div class="muted">${m.sender_id} • ${new Date(m.created_at * 1000).toLocaleString()}</div>`;
    row.appendChild(body);
    if (m.file && m.file.path) {
      const actionRow = document.createElement("div");
      actionRow.className = "row-inline";
      actionRow.style.marginTop = "6px";
      if (m.kind === "audio" || m.kind === "video") {
        const playBtn = document.createElement("button");
        playBtn.type = "button";
        playBtn.textContent = "Play inline";
        playBtn.onclick = async () => {
          setMsgAttachmentStatus("Loading media...");
          try {
            await createInlinePlayer({
              kind: m.kind,
              path: m.file.path,
              name: m.file.name,
              container: actionRow,
            });
            setMsgAttachmentStatus("Media ready.");
          } catch (e) {
            setMsgAttachmentStatus(String(e.message || e));
          }
        };
        actionRow.appendChild(playBtn);
      }
      const downloadBtn = document.createElement("button");
      downloadBtn.type = "button";
      downloadBtn.textContent = "Download";
      downloadBtn.onclick = async () => {
        setMsgAttachmentStatus("Downloading...");
        try {
          await downloadFilePath(m.file.path, m.file.name);
          setMsgAttachmentStatus("Download started.");
        } catch (e) {
          setMsgAttachmentStatus(String(e.message || e));
        }
      };
      const previewBtn = document.createElement("button");
      previewBtn.type = "button";
      previewBtn.textContent = "Preview";
      previewBtn.onclick = async () => {
        setMsgAttachmentStatus("Opening preview...");
        try {
          await previewFilePath(m.file.path);
          setMsgAttachmentStatus("Preview opened.");
        } catch (e) {
          setMsgAttachmentStatus(String(e.message || e));
        }
      };
      actionRow.appendChild(downloadBtn);
      actionRow.appendChild(previewBtn);
      row.appendChild(actionRow);
    }
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

function renderMessagingSearchResults(messages) {
  const list = document.getElementById("msgSearchResults");
  if (!list) return;
  list.innerHTML = "";
  if (!messages.length) {
    list.innerHTML = "<div class='muted'>No search results.</div>";
    return;
  }
  messages.forEach((m) => {
    const row = document.createElement("div");
    row.className = "item";
    let body = "";
    if (m.kind === "image") {
      body = `<em>[image]</em> ${m.image ? (m.image.key || "") : ""}`;
    } else if (m.kind === "file" || m.kind === "audio" || m.kind === "video") {
      body = renderFileMeta(m.file, m.kind);
    } else {
      body = m.text || "";
    }
    const convo = m.conversation_id ? ` • ${m.conversation_id}` : "";
    row.innerHTML = `
      <div class="muted">${m.sender_id}${convo} • ${new Date(m.created_at * 1000).toLocaleString()}</div>
      <div>${body}</div>
    `;
    if (m.preview) {
      row.insertAdjacentHTML("beforeend", renderLinkPreview(m.preview));
    }
    if (m.delivered_to_count || m.read_by_count) {
      const delivered = m.delivered_to_count ? `Delivered to ${m.delivered_to_count}` : "";
      const readBy = m.read_by_count ? `Read by ${m.read_by_count}` : "";
      const statusText = [delivered, readBy].filter(Boolean).join(" • ");
      if (statusText) {
        row.insertAdjacentHTML("beforeend", `<div class="muted" style="margin-top:6px;">${statusText}</div>`);
      }
    }
    list.appendChild(row);
  });
}

async function searchMessagingMessages({ allConversations }) {
  const query = readInput("msgSearchQuery");
  if (!query) {
    setMsgStatus("msgSearchStatus", "Search text required.");
    return;
  }
  const senderId = readInput("msgSearchSender");
  const afterRaw = readInput("msgSearchAfter");
  const kindSelect = document.getElementById("msgSearchKind");
  const kinds = kindSelect
    ? Array.from(kindSelect.selectedOptions).map((opt) => opt.value).filter(Boolean)
    : [];
  let afterTs = null;
  if (afterRaw) {
    afterTs = parseInt(afterRaw, 10);
    if (Number.isNaN(afterTs)) {
      setMsgStatus("msgSearchStatus", "After timestamp must be a number.");
      return;
    }
  }
  if (!allConversations && !messagingState.activeConversationId) {
    setMsgStatus("msgSearchStatus", "Select a conversation first.");
    return;
  }
  const params = new URLSearchParams({ q: query, limit: "200" });
  if (senderId) params.set("sender_id", senderId);
  if (afterTs !== null) params.set("after_ts", String(afterTs));
  if (kinds.length) {
    kinds.forEach((kind) => params.append("kind", kind));
  }
  const path = allConversations
    ? `/messaging/messages/search?${params.toString()}`
    : `/messaging/conversations/${messagingState.activeConversationId}/messages/search?${params.toString()}`;
  setMsgStatus("msgSearchStatus", "Searching...");
  try {
    const data = await msgRequest(path);
    renderMessagingSearchResults(data || []);
    setMsgStatus("msgSearchStatus", `Found ${(data || []).length} messages.`);
  } catch (e) {
    setMsgStatus("msgSearchStatus", String(e));
  }
}

function clearMessagingSearch() {
  setInputValue("msgSearchQuery", "");
  setInputValue("msgSearchSender", "");
  setInputValue("msgSearchAfter", "");
  const kindSelect = document.getElementById("msgSearchKind");
  if (kindSelect) {
    Array.from(kindSelect.options).forEach((opt) => {
      opt.selected = false;
    });
  }
  setMsgStatus("msgSearchStatus", "");
  renderMessagingSearchResults([]);
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
  const previewResult = buildPreviewPayload();
  if (previewResult.error) {
    setMsgStatus("msgMessageStatus", previewResult.error);
    return;
  }
  setMsgStatus("msgMessageStatus", "Sending...");
  try {
    await msgRequest(`/messaging/conversations/${cid}/messages`, {
      method: "POST",
      body: { text, preview: previewResult.preview || null },
    });
    setInputValue("msgText", "");
    setInputValue("msgPreviewUrl", "");
    setInputValue("msgPreviewTitle", "");
    setInputValue("msgPreviewDescription", "");
    setInputValue("msgPreviewImage", "");
    setInputValue("msgPreviewSite", "");
    await loadMessagingMessages();
    await loadMessagingConvos();
    setMsgStatus("msgMessageStatus", "Sent.");
  } catch (e) {
    setMsgStatus("msgMessageStatus", String(e));
  }
}

async function sendMessagingAttachment({ useUpload }) {
  const cid = messagingState.activeConversationId;
  if (!cid) {
    setMsgAttachmentStatus("Select a conversation first.");
    return;
  }
  const kind = readInput("msgFileKind") || "file";
  const durationRaw = readInput("msgFileDuration");
  let duration = null;
  if (durationRaw) {
    duration = parseInt(durationRaw, 10);
    if (Number.isNaN(duration) || duration <= 0) {
      setMsgAttachmentStatus("Duration must be a positive number.");
      return;
    }
  }
  const previewResult = buildPreviewPayload();
  if (previewResult.error) {
    setMsgAttachmentStatus(previewResult.error);
    return;
  }
  let path = readInput("msgFilePath");
  const fileInput = document.getElementById("msgFileInput");
  const file = fileInput ? fileInput.files[0] : null;

  if (useUpload) {
    if (!file) {
      setMsgAttachmentStatus("Choose a file to upload.");
      return;
    }
    if (!path) {
      path = `/messaging/${cid}/${file.name}`;
    }
  } else {
    if (!path) {
      setMsgAttachmentStatus("Provide a file-manager path.");
      return;
    }
  }

  setMsgAttachmentStatus(useUpload ? "Uploading..." : "Sending...");
  try {
    if (useUpload) {
      await fileManagerPresignUpload(path, file);
    }
    await msgRequest(`/messaging/conversations/${cid}/messages/file`, {
      method: "POST",
      body: {
        path,
        kind,
        duration_seconds: duration || null,
        preview: previewResult.preview || null,
      },
    });
    if (fileInput) fileInput.value = "";
    setInputValue("msgFilePath", "");
    setInputValue("msgFileDuration", "");
    await loadMessagingMessages();
    await loadMessagingConvos();
    setMsgAttachmentStatus("Sent.");
  } catch (e) {
    setMsgAttachmentStatus(String(e.message || e));
  }
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
      <td>${fmtMoney(item.unit_price_cents, "usd")}</td>
      <td>${fmtMoney(item.line_total_cents, "usd")}</td>
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

function renderCartSearchResults(items) {
  const list = document.getElementById("cartSearchResults");
  if (!list) return;
  list.innerHTML = "";
  if (!items.length) {
    list.innerHTML = "<div class='muted'>No matches.</div>";
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(item.sku || "")}</div>
        <div class="muted">${escapeHtml(item.name || "")}</div>
        <div class="muted">Cart ${escapeHtml(item.cart_id || "")}</div>
      </div>
      <div class="muted">Qty ${item.quantity || 0}</div>
      <div><button data-cart="${escapeHtml(item.cart_id || "")}">Open cart</button></div>
    `;
    row.querySelector("button").onclick = async (ev) => {
      const cartId = ev.target.getAttribute("data-cart");
      if (!cartId) return;
      cartState.cartId = cartId;
      renderCartSelect();
      await refreshCartDetails();
    };
    list.appendChild(row);
  });
}

async function searchCartItems() {
  const query = readInput("cartSearchQuery");
  if (!query) {
    renderCartSearchResults([]);
    return;
  }
  try {
    setCartStatus("Searching items...");
    await ensureUiSession();
  const res = await apiGet(`/ui/shoppingcart/carts/items/search?q=${encodeURIComponent(query)}&limit=200`);
    renderCartSearchResults(res.items || []);
    setCartStatus(`Found ${(res.items || []).length} matching items.`);
  } catch (e) {
    setCartStatus(String(e));
  }
}

function clearCartSearch() {
  setInputValue("cartSearchQuery", "");
  renderCartSearchResults([]);
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
  const form = new FormData();
  form.append("file", file);
  const headers = { "Authorization": "Bearer " + tok };
  addCsrfHeader(headers);
  const res = await fetch(API_BASE + path, {
    method: "POST",
    headers,
    body: form,
    credentials: "include",
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
  transfers: new Map(),
  activeDownloads: new Set(),
  downloadedPaths: new Set(),
  selectedPaths: new Set(),
  items: [],
  renamePath: null,
  renameValue: "",
  cursor: null,
  hasMore: false,
  sortBy: "name",
  sortDir: "asc",
  pageSize: 50,
  bulkOp: null,
  sharedMode: false,
  sharedOwner: null,
  sharedPermission: "read",
  sharedRoot: null,
  sharedItems: [],
};

function fileMgrStatus(msg) {
  const el = document.getElementById("filemgrStatus");
  if (el) el.textContent = msg || "";
}

function fileMgrAuditStatus(msg) {
  const el = document.getElementById("filemgrAuditStatus");
  if (el) el.textContent = msg || "";
}

function fileMgrPageStatus(msg) {
  const el = document.getElementById("filemgrPageStatus");
  if (el) el.textContent = msg || "";
}

function fileMgrSharedStatus(msg) {
  const el = document.getElementById("filemgrSharedStatus");
  if (el) el.textContent = msg || "";
}

function fileMgrCanWrite() {
  if (!fileMgrState.sharedMode) return true;
  return fileMgrState.sharedPermission === "write";
}

function fileMgrSharedQueryParams() {
  const params = new URLSearchParams();
  if (fileMgrState.sharedOwner) {
    params.set("owner", fileMgrState.sharedOwner);
  }
  return params;
}

function setFileMgrSharedMode({ owner, permission, root }) {
  fileMgrState.sharedMode = Boolean(owner);
  fileMgrState.sharedOwner = owner || null;
  fileMgrState.sharedPermission = permission || "read";
  fileMgrState.sharedRoot = root || null;
  fileMgrState.cursor = null;
  clearFileMgrSelection();
  const banner = document.getElementById("filemgrSharedBanner");
  const label = document.getElementById("filemgrSharedLabel");
  if (banner) {
    if (fileMgrState.sharedMode) {
      banner.classList.remove("hidden");
      if (label) {
        label.textContent = `Shared from ${fileMgrState.sharedOwner} (${fileMgrState.sharedPermission})`;
      }
    } else {
      banner.classList.add("hidden");
      if (label) label.textContent = "";
    }
  }
  updateFileMgrSharedUi();
}

function exitFileMgrSharedMode() {
  setFileMgrSharedMode({ owner: null, permission: "read", root: null });
}

function updateFileMgrSharedUi() {
  const canWrite = fileMgrCanWrite();
  const disableWhenShared = fileMgrState.sharedMode && !canWrite;
  const controls = [
    "filemgrCreateFolderBtn",
    "filemgrUploadInput",
    "filemgrUploadBtn",
    "filemgrUploadZipInput",
    "filemgrUploadZipBtn",
    "filemgrBulkMoveBtn",
    "filemgrBulkDeleteBtn",
    "filemgrSelectAll",
  ];
  controls.forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.disabled = disableWhenShared;
  });
  const searchControls = [
    "filemgrSearch",
    "filemgrSearchBtn",
    "filemgrSearchText",
    "filemgrSearchTextBtn",
    "filemgrClearSearchBtn",
  ];
  searchControls.forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.disabled = fileMgrState.sharedMode;
  });
  if (fileMgrState.sharedMode) {
    clearFileMgrSearch();
  }
}

function formatFileMgrError(err) {
  if (!err) return "Unknown error";
  const msg = String(err).replace(/^Error:\s*/, "");
  return msg || "Unknown error";
}

function renderFileMgrBulkOps() {
  const container = document.getElementById("filemgrBulkOps");
  if (!container) return;
  const op = fileMgrState.bulkOp;
  if (!op) {
    container.innerHTML = "";
    return;
  }
  const failedItems = op.items.filter((item) => item.status === "failed");
  const completed = Math.min(op.completed, op.total);
  const statusText = op.inProgress
    ? "Running"
    : "Completed";
  const summaryPills = `
    <span class="pill ok">Success: ${op.success}</span>
    <span class="pill warn">Skipped: ${op.skipped}</span>
    <span class="pill bad">Failed: ${op.failed}</span>
  `;
  const failuresHtml = failedItems.length
    ? `
      <div style="margin-top:8px;">
        <div class="muted">Failures</div>
        <div class="list" style="margin-top:6px;">
          ${failedItems
            .map((item) => `
              <div class="list-item">
                <div class="grow">
                  <div class="mono">${escapeHtml(item.path || "")}</div>
                  <div class="muted">${escapeHtml(item.error || "Unknown error")}</div>
                </div>
                <span class="pill bad">Failed</span>
              </div>
            `)
            .join("")}
        </div>
      </div>
    `
    : "";
  container.innerHTML = `
    <div class="item">
      <div class="row-inline" style="justify-content:space-between;">
        <div>
          <b>Bulk ${escapeHtml(op.type)}</b>
          <span class="muted">· ${statusText}</span>
        </div>
        <button id="filemgrBulkClearBtn"${op.inProgress ? " disabled" : ""}>Clear</button>
      </div>
      <div class="row-inline" style="margin-top:6px; gap:10px;">
        <progress value="${completed}" max="${op.total}"></progress>
        <span class="muted">${completed}/${op.total}</span>
      </div>
      <div class="row-inline" style="margin-top:6px; gap:8px;">
        ${summaryPills}
      </div>
      ${failuresHtml}
    </div>
  `;
  const clearBtn = document.getElementById("filemgrBulkClearBtn");
  if (clearBtn) {
    clearBtn.onclick = () => {
      fileMgrState.bulkOp = null;
      renderFileMgrBulkOps();
    };
  }
}

function startFileMgrBulkOp(type, items) {
  fileMgrState.bulkOp = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    type,
    total: items.length,
    completed: 0,
    success: 0,
    failed: 0,
    skipped: 0,
    inProgress: true,
    items: items.map((item) => ({
      path: item.path,
      name: item.name,
      type: item.type,
      status: "pending",
      error: "",
    })),
  };
  renderFileMgrBulkOps();
  return fileMgrState.bulkOp;
}

async function runFileMgrBulkOp(type, items, handler) {
  const op = startFileMgrBulkOp(type, items);
  const tasks = items.map((item, index) => (async () => {
    try {
      const result = await handler(item);
      if (result === "skipped") {
        op.items[index].status = "skipped";
        op.skipped += 1;
      } else {
        op.items[index].status = "success";
        op.success += 1;
      }
      return result;
    } catch (e) {
      op.items[index].status = "failed";
      op.items[index].error = formatFileMgrError(e);
      op.failed += 1;
      throw e;
    } finally {
      op.completed += 1;
      renderFileMgrBulkOps();
    }
  })());
  await Promise.allSettled(tasks);
  op.inProgress = false;
  renderFileMgrBulkOps();
  return op;
}

function updateFileMgrPaginationControls() {
  const loadMoreBtn = document.getElementById("filemgrLoadMoreBtn");
  if (loadMoreBtn) {
    loadMoreBtn.disabled = !fileMgrState.hasMore;
  }
  if (fileMgrState.hasMore) {
    fileMgrPageStatus(`Loaded ${fileMgrState.items.length} item(s).`);
  } else {
    fileMgrPageStatus(fileMgrState.items.length ? `Loaded ${fileMgrState.items.length} item(s).` : "");
  }
}

function setFileMgrSort(sortBy, sortDir) {
  fileMgrState.sortBy = sortBy || "name";
  fileMgrState.sortDir = sortDir || "asc";
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
  renderFileMgrBreadcrumb();
}

function renderFileMgrBreadcrumb() {
  const container = document.getElementById("filemgrBreadcrumb");
  if (!container) return;
  const path = normalizeFolderPath(fileMgrState.path || "/");
  const segments = path.split("/").filter(Boolean);
  container.innerHTML = "";
  const root = document.createElement("button");
  root.textContent = fileMgrState.sharedMode ? `Shared: ${fileMgrState.sharedOwner || ""}` : "/";
  root.className = "mono";
  root.onclick = async () => {
    setFileMgrPath(fileMgrState.sharedMode ? fileMgrState.sharedRoot || "/" : "/");
    await refreshFileManager();
  };
  container.appendChild(root);
  let cur = "/";
  segments.forEach((seg) => {
    cur = normalizeFolderPath(cur + seg + "/");
    const sep = document.createElement("span");
    sep.textContent = "›";
    sep.className = "muted";
    container.appendChild(sep);
    const btn = document.createElement("button");
    btn.textContent = seg;
    btn.className = "mono";
    btn.onclick = async () => {
      setFileMgrPath(cur);
      await refreshFileManager();
    };
    container.appendChild(btn);
  });
}

function setFileMgrSelected(path, selected) {
  if (!path) return;
  if (selected) {
    fileMgrState.selectedPaths.add(path);
  } else {
    fileMgrState.selectedPaths.delete(path);
  }
  updateFileMgrSelectionStatus();
  updateFileMgrSelectAll();
}

function clearFileMgrSelection() {
  fileMgrState.selectedPaths.clear();
  updateFileMgrSelectionStatus();
  updateFileMgrSelectAll();
}

function updateFileMgrSelectionStatus() {
  const status = document.getElementById("filemgrStatus");
  if (!status) return;
  if (fileMgrState.selectedPaths.size > 0) {
    status.textContent = `Selected ${fileMgrState.selectedPaths.size} item(s).`;
  } else if (status.textContent.startsWith("Selected")) {
    status.textContent = "";
  }
}

function updateFileMgrSelectAll() {
  const selectAll = document.getElementById("filemgrSelectAll");
  if (!selectAll) return;
  if (!fileMgrState.items.length) {
    selectAll.checked = false;
    selectAll.indeterminate = false;
    return;
  }
  const selectedCount = fileMgrState.items.filter((item) => fileMgrState.selectedPaths.has(item.path)).length;
  selectAll.checked = selectedCount === fileMgrState.items.length;
  selectAll.indeterminate = selectedCount > 0 && selectedCount < fileMgrState.items.length;
}

function selectedFileMgrItems() {
  return fileMgrState.items.filter((item) => fileMgrState.selectedPaths.has(item.path));
}

function toggleFileMgrSelectAll(checked) {
  if (fileMgrState.sharedMode && !fileMgrCanWrite()) {
    return;
  }
  if (checked) {
    fileMgrState.items.forEach((item) => fileMgrState.selectedPaths.add(item.path));
  } else {
    fileMgrState.selectedPaths.clear();
  }
  renderFileMgrList(fileMgrState.items);
  updateFileMgrSelectionStatus();
}

function clearFileMgrErrorTransfers() {
  fileMgrState.transfers.forEach((transfer) => {
    if (transfer.error) {
      transfer.item?.remove();
      fileMgrState.transfers.delete(transfer.id);
    }
  });
}

function createFileMgrTransfer(label, onCancel) {
  const container = document.getElementById("filemgrTransfers");
  if (!container) return null;
  clearFileMgrErrorTransfers();
  const id = `transfer-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const statusId = `${id}-status`;
  const item = document.createElement("div");
  item.className = "list-item transfer-item";
  item.innerHTML = `
    <div class="grow">
      <div class="mono">${escapeHtml(label)}</div>
      <div class="muted" data-role="status" id="${statusId}">Starting...</div>
    </div>
    <progress value="0" max="100" aria-label="${escapeHtml(label)}" aria-describedby="${statusId}"></progress>
    <button class="danger" data-role="cancel">Cancel</button>
  `;
  container.prepend(item);
  const cancelBtn = item.querySelector('[data-role="cancel"]');
  if (cancelBtn) {
    if (onCancel) {
      cancelBtn.onclick = onCancel;
    } else {
      cancelBtn.disabled = true;
    }
  }
  const transfer = {
    id,
    item,
    status: item.querySelector('[data-role="status"]'),
    bar: item.querySelector("progress"),
    cancelBtn,
    error: false,
    startedAt: Date.now(),
    lastTickAt: null,
    lastLoaded: 0,
  };
  fileMgrState.transfers.set(id, transfer);
  return transfer;
}

function updateFileMgrTransfer(transfer, loaded, total, label) {
  if (!transfer) return;
  let speedText = "";
  let etaText = "";
  if (typeof loaded === "number") {
    const now = Date.now();
    if (!transfer.lastTickAt) {
      transfer.lastTickAt = now;
      transfer.lastLoaded = loaded;
    } else {
      const deltaMs = now - transfer.lastTickAt;
      if (deltaMs > 0) {
        const deltaBytes = loaded - transfer.lastLoaded;
        const bytesPerSec = deltaBytes / (deltaMs / 1000);
        if (bytesPerSec > 0) {
          speedText = ` @ ${fmtBytes(bytesPerSec)}/s`;
          if (typeof total === "number" && total > 0 && loaded <= total) {
            const remaining = total - loaded;
            const etaSeconds = remaining / bytesPerSec;
            if (Number.isFinite(etaSeconds)) {
              etaText = `, ETA ${Math.max(1, Math.round(etaSeconds))}s`;
            }
          }
        }
      }
      transfer.lastTickAt = now;
      transfer.lastLoaded = loaded;
    }
  }
  if (transfer.status) {
    const bytes = typeof loaded === "number" ? fmtBytes(loaded) : "";
    const hasTotal = typeof total === "number" && total > 0;
    const totalText = hasTotal ? ` / ${fmtBytes(total)}` : "";
    const sizeText = bytes ? ` (${bytes}${totalText})` : "";
    const fallback = hasTotal ? "" : " (total size unknown)";
    transfer.status.textContent = `${label}${sizeText}${fallback}${speedText}${etaText}`;
  }
  if (transfer.bar) {
    if (typeof total === "number" && total > 0) {
      transfer.bar.max = total;
      transfer.bar.value = loaded;
    } else {
      transfer.bar.removeAttribute("value");
    }
  }
}

function finishFileMgrTransfer(transfer, label, options = {}) {
  if (!transfer) return;
  if (transfer.status) transfer.status.textContent = label;
  if (transfer.cancelBtn) transfer.cancelBtn.disabled = true;
  if (options.error) {
    transfer.error = true;
    transfer.item?.classList.add("error");
  }
  if (options.sticky) return;
  setTimeout(() => {
    transfer.item?.remove();
    fileMgrState.transfers.delete(transfer.id);
  }, 1600);
}



async function deriveKey(password, saltBytes, iterations = 600000) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("WebCrypto is not available in this browser.");
  }
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function toB64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

function fromB64(value) {
  const binary = atob(value || "");
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function encryptFile(file, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const iterations = 600000;
  const key = await deriveKey(password, salt, iterations);
  const plaintext = await file.arrayBuffer();
  const ciphertext = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const encryptedBlob = new Blob([ciphertext], { type: "application/octet-stream" });
  return {
    blob: encryptedBlob,
    metadata: {
      version: 1,
      alg: "AES-256-GCM",
      kdf: "PBKDF2-SHA256",
      iterations,
      salt_b64: toB64(salt),
      iv_b64: toB64(iv),
      orig_name: file.name,
      orig_size: file.size,
      mime: file.type || "application/octet-stream",
    },
  };
}

async function decryptFile(blob, password, metadata) {
  const salt = fromB64(metadata?.salt_b64 || "");
  const iv = fromB64(metadata?.iv_b64 || "");
  const iterations = Number(metadata?.iterations || 600000);
  const key = await deriveKey(password, salt, iterations);
  const ciphertext = await blob.arrayBuffer();
  const plaintext = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Blob([plaintext], { type: metadata?.mime || "application/octet-stream" });
}

function promptFileEncryptionPassword() {
  const pass = prompt("Enter a password to encrypt selected file(s):");
  if (!pass) return null;
  const confirmPass = prompt("Confirm encryption password:");
  if (pass !== confirmPass) {
    throw new Error("Passwords did not match.");
  }
  return pass;
}

async function apiUploadFileManager(path, file, onProgress, onCancelReady, options = {}) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const form = new FormData();
  form.append("file", file);
  const sharedOwner = options.sharedOwner;
  const endpoint = sharedOwner ? "/v1/fs/shared-upload" : "/v1/fs/upload";
  const params = new URLSearchParams();
  params.set("path", path);
  if (sharedOwner) {
    params.set("owner", sharedOwner);
  }
  if (options.encrypted) {
    params.set("encrypted", "true");
    if (options.encryptionMeta) {
      params.set("enc_meta", JSON.stringify(options.encryptionMeta));
    }
  }
  const url = `${API_BASE}${endpoint}?${params.toString()}`;
  return await new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.setRequestHeader("Authorization", "Bearer " + tok);
    const csrf = csrfToken();
    if (csrf) xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.withCredentials = true;
    xhr.responseType = "json";
    xhr.upload.onprogress = (event) => {
      if (onProgress) onProgress(event);
    };
    if (onCancelReady) {
      onCancelReady(() => xhr.abort());
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response);
        return;
      }
      const detail = xhr.response && xhr.response.detail ? xhr.response.detail : xhr.responseText;
      reject(new Error(detail || "Upload failed"));
    };
    xhr.onerror = () => reject(new Error("Upload failed"));
    xhr.onabort = () => reject(new Error("Upload canceled"));
    xhr.send(form);
  });
}

function fileMgrDownloadKey(path, ownerOverride = null) {
  if (ownerOverride) return `shared:${ownerOverride}:${path}`;
  if (!fileMgrState.sharedMode) return path;
  return `${fileMgrState.sharedOwner || "shared"}:${path}`;
}

async function fileMgrFetchInfo(path, ownerOverride = null) {
  const endpoint = ownerOverride || fileMgrState.sharedMode ? "/v1/fs/shared-info" : "/v1/fs/info";
  const params = new URLSearchParams();
  params.set("path", path);
  const owner = ownerOverride || fileMgrState.sharedOwner;
  if ((ownerOverride || fileMgrState.sharedMode) && owner) params.set("owner", owner);
  return apiGet(`${endpoint}?${params.toString()}`);
}

async function fileMgrDownload(path, filename, button, options = {}) {
  const ownerOverride = options.owner || null;
  const downloadKey = fileMgrDownloadKey(path, ownerOverride);
  if (fileMgrState.activeDownloads.has(downloadKey)) {
    fileMgrStatus("Download already in progress for this file.");
    return;
  }
  if (fileMgrState.downloadedPaths.has(downloadKey)) {
    const ok = confirm("Download this file again?");
    if (!ok) return;
  }
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const isShared = Boolean(ownerOverride || fileMgrState.sharedMode);
  const owner = ownerOverride || fileMgrState.sharedOwner;
  const endpoint = isShared ? "/v1/fs/shared-download" : "/v1/fs/download";
  const params = new URLSearchParams();
  params.set("path", path);
  if (isShared && owner) {
    params.set("owner", owner);
  }
  const url = `${API_BASE}${endpoint}?${params.toString()}`;
  let cancel = null;
  let canceled = false;
  const transfer = createFileMgrTransfer(`Download: ${filename || path}`, () => {
    canceled = true;
    if (cancel) cancel();
    finishFileMgrTransfer(transfer, "Download canceled");
  });
  updateFileMgrTransfer(transfer, 0, null, "Preparing download");
  fileMgrState.activeDownloads.add(downloadKey);
  if (button) button.disabled = true;
  try {
    await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("GET", url);
      xhr.setRequestHeader("Authorization", "Bearer " + tok);
      xhr.withCredentials = true;
      xhr.responseType = "blob";
      cancel = () => xhr.abort();
      xhr.onprogress = (event) => {
        if (event.lengthComputable) {
          updateFileMgrTransfer(transfer, event.loaded, event.total, "Downloading");
        } else {
          updateFileMgrTransfer(transfer, event.loaded, null, "Downloading");
        }
      };
      xhr.onload = async () => {
        if (xhr.status < 200 || xhr.status >= 300) {
          reject(new Error(xhr.responseText || "Download failed"));
          return;
        }
        try {
          let blob = xhr.response;
          let downloadName = filename || "download";
          const info = await fileMgrFetchInfo(path, ownerOverride);
          if (info && info.is_encrypted) {
            const password = prompt("This file is encrypted. Enter password to decrypt:");
            if (!password) throw new Error("Decryption canceled.");
            blob = await decryptFile(blob, password, info.enc_metadata || {});
            downloadName = (info.enc_metadata && info.enc_metadata.orig_name) || downloadName;
          }
          const link = document.createElement("a");
          link.href = URL.createObjectURL(blob);
          link.download = downloadName;
          document.body.appendChild(link);
          link.click();
          link.remove();
          setTimeout(() => URL.revokeObjectURL(link.href), 2000);
          resolve();
        } catch (err) {
          reject(err);
        }
      };
      xhr.onerror = () => reject(new Error("Download failed"));
      xhr.onabort = () => reject(new Error("Download canceled"));
      xhr.send();
    });
    finishFileMgrTransfer(transfer, "Download complete");
    fileMgrState.downloadedPaths.add(downloadKey);
  } catch (e) {
    if (!canceled) {
      finishFileMgrTransfer(transfer, "Download failed", { error: true, sticky: true });
      throw e;
    }
  } finally {
    fileMgrState.activeDownloads.delete(downloadKey);
    if (button) button.disabled = false;
  }
}

async function fileMgrPreview(path) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const endpoint = fileMgrState.sharedMode ? "/v1/fs/shared-preview" : "/v1/fs/preview";
  const params = new URLSearchParams();
  params.set("path", path);
  if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
    params.set("owner", fileMgrState.sharedOwner);
  }
  const url = `${API_BASE}${endpoint}?${params.toString()}`;
  const res = await fetch(url, {
    method: "GET",
    headers,
    credentials: "include",
  });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const previewUrl = URL.createObjectURL(blob);
  window.open(previewUrl, "_blank");
  setTimeout(() => URL.revokeObjectURL(previewUrl), 2000);
}



function isEditableImageFile(item) {
  if (!item || item.type !== "file") return false;
  const contentType = String(item.content_type || "").toLowerCase();
  if (contentType.startsWith("image/")) return true;
  const name = String(item.name || item.path || "").toLowerCase();
  return /\.(png|jpe?g|gif|webp|bmp)$/i.test(name);
}

function _fileMgrEditorCanvasPoint(ev, canvas, naturalWidth, naturalHeight) {
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return { x: 0, y: 0 };
  const x = Math.max(0, Math.min(naturalWidth, ((ev.clientX - rect.left) * naturalWidth) / rect.width));
  const y = Math.max(0, Math.min(naturalHeight, ((ev.clientY - rect.top) * naturalHeight) / rect.height));
  return { x, y };
}

function _fileMgrEditorNormalizeRect(start, end, maxW, maxH) {
  const x1 = Math.max(0, Math.min(maxW, Math.min(start.x, end.x)));
  const y1 = Math.max(0, Math.min(maxH, Math.min(start.y, end.y)));
  const x2 = Math.max(0, Math.min(maxW, Math.max(start.x, end.x)));
  const y2 = Math.max(0, Math.min(maxH, Math.max(start.y, end.y)));
  return { x: x1, y: y1, w: x2 - x1, h: y2 - y1 };
}

async function fileMgrFetchBlob(path, ownerOverride = null) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const isShared = Boolean(ownerOverride || fileMgrState.sharedMode);
  const owner = ownerOverride || fileMgrState.sharedOwner;
  const endpoint = isShared ? "/v1/fs/shared-download" : "/v1/fs/download";
  const params = new URLSearchParams();
  params.set("path", path);
  if (isShared && owner) params.set("owner", owner);
  const res = await fetch(`${API_BASE}${endpoint}?${params.toString()}`, {
    method: "GET",
    headers: {
      "Authorization": "Bearer " + tok,
      "X-SESSION-ID": sid,
    },
    credentials: "include",
  });
  if (!res.ok) throw new Error(await res.text());
  return res.blob();
}

async function openFileMgrImageEditor(item) {
  if (!item || !item.path) return;
  await ensureUiSession();
  const ownerOverride = fileMgrState.sharedMode ? fileMgrState.sharedOwner : null;
  const info = await fileMgrFetchInfo(item.path, ownerOverride);
  if (info && info.is_encrypted) {
    fileMgrStatus("Image edit is not available for encrypted files.");
    return;
  }
  const srcBlob = await fileMgrFetchBlob(item.path, ownerOverride);
  const objectUrl = URL.createObjectURL(srcBlob);
  const img = new Image();
  await new Promise((resolve, reject) => {
    img.onload = resolve;
    img.onerror = () => reject(new Error("Unable to load image for editing."));
    img.src = objectUrl;
  });
  const naturalWidth = img.naturalWidth || img.width;
  const naturalHeight = img.naturalHeight || img.height;
  modalShow({
    title: `Edit image: ${item.name || item.path}`,
    bodyHtml: `
      <div class="filemgr-editor-layout">
        <div class="row-inline filemgr-editor-controls">
          <button id="filemgrEditorCropBtn" type="button">Crop selection</button>
          <button id="filemgrEditorBlockBtn" type="button">Block selection</button>
          <button id="filemgrEditorResetBtn" type="button">Reset</button>
          <button id="filemgrEditorSaveBtn" type="button" class="primary">Save image</button>
        </div>
        <div class="muted">Drag on the image to create a selection rectangle. Crop keeps selected area; Block fills the area with black.</div>
        <canvas id="filemgrEditorCanvas" class="filemgr-editor-canvas"></canvas>
        <div id="filemgrEditorStatus" class="muted"></div>
      </div>
    `,
    actions: [{ text: "Close", onClick: modalClose }],
  });
  const canvas = document.getElementById("filemgrEditorCanvas");
  const status = document.getElementById("filemgrEditorStatus");
  const cropBtn = document.getElementById("filemgrEditorCropBtn");
  const blockBtn = document.getElementById("filemgrEditorBlockBtn");
  const resetBtn = document.getElementById("filemgrEditorResetBtn");
  const saveBtn = document.getElementById("filemgrEditorSaveBtn");
  if (!canvas || !status || !cropBtn || !blockBtn || !resetBtn || !saveBtn) throw new Error("Image editor UI failed to initialize.");

  const workingCanvas = document.createElement("canvas");
  workingCanvas.width = naturalWidth;
  workingCanvas.height = naturalHeight;
  let workingCtx = workingCanvas.getContext("2d");
  if (!workingCtx) throw new Error("Unable to start image editor canvas.");
  workingCtx.drawImage(img, 0, 0);

  const draw = (selection) => {
    const scale = Math.min(1, 900 / naturalWidth, 520 / naturalHeight);
    canvas.width = workingCanvas.width;
    canvas.height = workingCanvas.height;
    canvas.style.width = `${Math.max(1, Math.round(workingCanvas.width * scale))}px`;
    canvas.style.height = `${Math.max(1, Math.round(workingCanvas.height * scale))}px`;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(workingCanvas, 0, 0);
    if (selection && selection.w > 1 && selection.h > 1) {
      ctx.fillStyle = "rgba(0,0,0,0.3)";
      ctx.fillRect(selection.x, selection.y, selection.w, selection.h);
      ctx.strokeStyle = "#fff";
      ctx.lineWidth = 3;
      ctx.strokeRect(selection.x, selection.y, selection.w, selection.h);
    }
  };

  let dragStart = null;
  let selection = null;
  draw(selection);
  canvas.onpointerdown = (ev) => {
    dragStart = _fileMgrEditorCanvasPoint(ev, canvas, workingCanvas.width, workingCanvas.height);
    selection = { x: dragStart.x, y: dragStart.y, w: 0, h: 0 };
    draw(selection);
  };
  canvas.onpointermove = (ev) => {
    if (!dragStart) return;
    const current = _fileMgrEditorCanvasPoint(ev, canvas, workingCanvas.width, workingCanvas.height);
    selection = _fileMgrEditorNormalizeRect(dragStart, current, workingCanvas.width, workingCanvas.height);
    draw(selection);
  };
  const onPointerUp = (ev) => {
    if (!dragStart) return;
    const current = _fileMgrEditorCanvasPoint(ev, canvas, workingCanvas.width, workingCanvas.height);
    selection = _fileMgrEditorNormalizeRect(dragStart, current, workingCanvas.width, workingCanvas.height);
    dragStart = null;
    draw(selection);
  };
  window.addEventListener("pointerup", onPointerUp);

  let cleanedUp = false;
  const cleanupEditor = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    window.removeEventListener("pointerup", onPointerUp);
    URL.revokeObjectURL(objectUrl);
  };
  const closeBtn = _modalEl ? _modalEl.querySelector(".modal-actions button") : null;
  if (closeBtn) closeBtn.addEventListener("click", cleanupEditor);
  if (_modalEl) {
    _modalEl.addEventListener("click", (ev) => {
      if (ev.target === _modalEl) cleanupEditor();
    });
  }

  const requireSelection = () => {
    if (!selection || selection.w < 2 || selection.h < 2) {
      status.textContent = "Drag to select an area first.";
      return false;
    }
    return true;
  };

  cropBtn.onclick = () => {
    if (!requireSelection()) return;
    const next = document.createElement("canvas");
    next.width = Math.max(1, Math.round(selection.w));
    next.height = Math.max(1, Math.round(selection.h));
    const nextCtx = next.getContext("2d");
    if (!nextCtx) return;
    nextCtx.drawImage(workingCanvas, selection.x, selection.y, selection.w, selection.h, 0, 0, next.width, next.height);
    workingCanvas.width = next.width;
    workingCanvas.height = next.height;
    workingCtx = workingCanvas.getContext("2d");
    if (!workingCtx) return;
    workingCtx.drawImage(next, 0, 0);
    selection = null;
    status.textContent = `Cropped to ${next.width} × ${next.height}.`;
    draw(selection);
  };

  blockBtn.onclick = () => {
    if (!requireSelection()) return;
    workingCtx.fillStyle = "#000";
    workingCtx.fillRect(selection.x, selection.y, selection.w, selection.h);
    status.textContent = "Blocked selected area.";
    draw(selection);
  };

  resetBtn.onclick = () => {
    workingCanvas.width = naturalWidth;
    workingCanvas.height = naturalHeight;
    workingCtx = workingCanvas.getContext("2d");
    if (!workingCtx) return;
    workingCtx.drawImage(img, 0, 0);
    selection = null;
    status.textContent = "Reset to original image.";
    draw(selection);
  };

  saveBtn.onclick = async () => {
    saveBtn.disabled = true;
    status.textContent = "Saving...";
    try {
      const outBlob = await new Promise((resolve, reject) => {
        workingCanvas.toBlob((blob) => {
          if (blob) resolve(blob);
          else reject(new Error("Failed to encode edited image."));
        }, srcBlob.type || "image/png", 0.92);
      });
      const uploadFile = new File([outBlob], item.name || "edited-image", {
        type: outBlob.type || srcBlob.type || "image/png",
      });
      await apiUploadFileManager(item.path, uploadFile, null, null, {
        sharedOwner: fileMgrState.sharedMode ? fileMgrState.sharedOwner : null,
      });
      status.textContent = "Saved updated image.";
      await refreshFileManager();
      cleanupEditor();
    } catch (e) {
      status.textContent = String(e);
    } finally {
      saveBtn.disabled = false;
    }
  };
}
async function fileMgrDetails(path) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const endpoint = fileMgrState.sharedMode ? "/v1/fs/shared-info" : "/v1/fs/info";
  const params = new URLSearchParams();
  params.set("path", path);
  if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
    params.set("owner", fileMgrState.sharedOwner);
  }
  const url = `${API_BASE}${endpoint}?${params.toString()}`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": "Bearer " + tok,
      "X-SESSION-ID": sid,
    },
  });
  if (!res.ok) throw new Error(await res.text());
  const info = await res.json();
  const rows = [
    ["Path", info.path],
    ["Type", info.type],
    ["Name", info.name],
    ["Parent", info.parent],
    ["Size", info.size != null ? fmtBytes(info.size) : ""],
    ["Content type", info.content_type],
    ["Encrypted", info.is_encrypted ? "Yes" : "No"],
    ["Encryption metadata", info.enc_metadata ? JSON.stringify(info.enc_metadata) : ""],
    ["Created", info.created_at],
    ["Updated", info.updated_at],
    ["Uploaded", info.upload_at],
    ["Uploaded by", info.upload_by],
    ["Last download", info.last_download_at],
    ["Last downloaded by", info.last_download_by],
    ["Duration (s)", info.duration_seconds != null ? String(info.duration_seconds) : ""],
  ];
  const bodyHtml = `
    <div class="stack">
      <table class="mono" style="width:100%; border-collapse:collapse;">
        <tbody>
          ${rows.map(([label, value]) => `
            <tr>
              <td style="padding:4px 8px; color:#666; width:160px;">${escapeHtml(label)}</td>
              <td style="padding:4px 8px;">${escapeHtml(value || "")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
  modalShow({
    title: "File details",
    bodyHtml,
    actions: [{ text: "Close", onClick: modalClose }],
  });
}

async function fileMgrDownloadZip(paths) {
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const sid = sessionId();
  if (!sid) throw new Error("Missing UI session_id; call ensureUiSession() first.");
  const sharedParams = fileMgrSharedQueryParams();
  const endpoint = fileMgrState.sharedMode ? "/v1/fs/shared-download-zip" : "/v1/fs/download-zip";
  const url = `${API_BASE}${endpoint}${sharedParams.toString() ? `?${sharedParams.toString()}` : ""}`;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(paths || []),
    credentials: "include",
  });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "download.zip";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
}

async function refreshSharedWithMe() {
  const list = document.getElementById("filemgrSharedList");
  if (!list) return;
  fileMgrSharedStatus("Loading...");
  await ensureUiSession();
  const res = await apiGet("/v1/fs/shared-with-me");
  fileMgrState.sharedItems = res.items || [];
  renderSharedWithMe();
  fileMgrSharedStatus(`Loaded ${fileMgrState.sharedItems.length} item(s).`);
}

function renderSharedWithMe() {
  const list = document.getElementById("filemgrSharedList");
  if (!list) return;
  list.innerHTML = "";
  const items = fileMgrState.sharedItems || [];
  if (!items.length) {
    list.innerHTML = "<div class='muted'>No shared items.</div>";
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "list-item";
    const isFolder = (item.path || "").endsWith("/");
    const sharedRoot = isFolder ? normalizeFolderPath(item.path || "/") : (item.path || "/");
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(item.path || "")}</div>
        <div class="muted">From ${escapeHtml(item.owner || "")}</div>
        <div class="muted">Shared ${escapeHtml(item.shared_at || "")}</div>
      </div>
      <div class="muted">${escapeHtml(item.permission || "read")}</div>
      <div class="muted">${escapeHtml(item.expires_at || "")}</div>
      <div class="row-inline">
        <button data-action="open">Open</button>
        ${isFolder ? "" : '<button data-action="download">Download</button>'}
      </div>
    `;
    row.querySelectorAll("button").forEach((btn) => {
      btn.onclick = async () => {
        const action = btn.getAttribute("data-action");
        if (action === "open") {
          setFileMgrSharedMode({
            owner: item.owner,
            permission: item.permission || "read",
            root: sharedRoot,
          });
          if (isFolder) {
            setFileMgrPath(item.path || "/");
            await refreshFileManager();
          } else {
            await fileMgrDownload(
              item.path,
              item.path?.split("/").slice(-1)[0] || "download",
              null,
              { owner: item.owner }
            );
            exitFileMgrSharedMode();
          }
          return;
        }
        if (action === "download" && !isFolder) {
          await fileMgrDownload(
            item.path,
            item.path?.split("/").slice(-1)[0] || "download",
            null,
            { owner: item.owner }
          );
        }
      };
    });
    list.appendChild(row);
  });
}

function fileMgrPreviewFallbackMessage(previewKind, previewStatus) {
  const kindLabel = previewKind === "video" ? "Video" : "Audio";
  const statusLabel = {
    pending: "preview pending",
    failed: "preview unavailable",
    unsupported: "preview unsupported",
  }[previewStatus] || "preview unavailable";
  return `${kindLabel} ${statusLabel}`;
}

function renderFileMgrMediaPreview(item) {
  if (!item || item.type !== "file") return "";
  const previewKind = item.preview_kind;
  if (previewKind !== "video" && previewKind !== "audio") return "";
  const previewStatus = item.preview_status || "pending";
  if (previewStatus === "ready") {
    if (previewKind === "video" && item.poster_url) {
      return `<div class="filemgr-preview"><img src="${escapeHtml(item.poster_url)}" alt="Video preview poster" loading="lazy" /></div>`;
    }
    if (previewKind === "audio" && item.waveform_url) {
      return `<div class="filemgr-preview"><img src="${escapeHtml(item.waveform_url)}" alt="Audio waveform preview" loading="lazy" /></div>`;
    }
  }
  return `<div class="filemgr-preview filemgr-preview-fallback muted">${escapeHtml(fileMgrPreviewFallbackMessage(previewKind, previewStatus))}</div>`;
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
    const isFolder = item.type === "folder";
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(item.name || "")}</div>
        <div class="muted">${escapeHtml(item.path || "")}</div>
        ${renderFileMgrMediaPreview(item)}
      </div>
      <div class="muted">${escapeHtml(item.type || "")}</div>
      <div class="muted">${item.type === "file" ? fmtBytes(item.size || 0) : ""}</div>
      <div class="row-inline">
        <button data-action="open" data-path="${escapeHtml(item.path || "")}" data-type="${escapeHtml(item.type || "")}">Open</button>
        <button data-action="details">Details</button>
        ${isFolder ? "" : `<button data-action="download">Download</button><button data-action="preview">Preview</button>${isEditableImageFile(item) ? '<button data-action="edit-image">Edit image</button>' : ''}`}
      </div>
    `;
    row.querySelectorAll("button").forEach((btn) => {
      btn.onclick = async () => {
        const action = btn.getAttribute("data-action");
        const p = btn.getAttribute("data-path") || item.path;
        if (!p) return;
        try {
          if (action === "open") {
            if (item.type === "folder") {
              setFileMgrPath(p);
            } else {
              const parent = p.split("/").slice(0, -1).join("/") + "/";
              setFileMgrPath(parent || "/");
            }
            await refreshFileManager();
            return;
          }
          if (action === "download") {
            await fileMgrDownload(p, item.name);
            return;
          }
          if (action === "preview") {
            await fileMgrPreview(p);
            return;
          }
          if (action === "edit-image") {
            await openFileMgrImageEditor(item);
            return;
          }
          if (action === "details") {
            await fileMgrDetails(p);
            return;
          }
        } catch (e) {
          fileMgrStatus(String(e));
        }
      };
    });
    list.appendChild(row);
  });
}

function formatFileMgrAuditPath(details) {
  if (!details) return "";
  if (details.src && details.dst) return `${details.src} → ${details.dst}`;
  return details.path || "";
}

function renderFileMgrAuditList(alerts) {
  const list = document.getElementById("filemgrAuditList");
  if (!list) return;
  list.innerHTML = "";
  if (!alerts.length) {
    list.innerHTML = "<div class='muted'>No recent file activity.</div>";
    return;
  }
  alerts.forEach((a) => {
    const details = a.details || {};
    const row = document.createElement("button");
    row.type = "button";
    row.className = "list-item list-button";
    if (a.alert_id) row.setAttribute("data-aid", a.alert_id);
    const path = formatFileMgrAuditPath(details);
    const outcome = details.outcome || a.outcome || "";
    row.innerHTML = `
      <div class="grow">
        <div><b>${escapeHtml(a.title || a.event || "File activity")}</b></div>
        <div class="muted mono">${escapeHtml(path)}${path ? " • " : ""}${escapeHtml(outcome)} • ${fmtTs(a.ts)}</div>
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
    list.appendChild(row);
  });
}

async function refreshFileMgrAudit() {
  const list = document.getElementById("filemgrAuditList");
  if (!list) return;
  fileMgrAuditStatus("Loading...");
  await ensureUiSession();
  const res = await apiGet("/ui/alerts?limit=100");
  const items = (res.alerts || []).filter((a) => (a.event || "").startsWith("filemgr_"));
  renderFileMgrAuditList(items);
  fileMgrAuditStatus(`Loaded ${items.length} event(s).`);
}

function renderFileMgrList(items) {
  const tbody = document.querySelector("#filemgrTable tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  (items || []).forEach((item) => {
    const row = document.createElement("tr");
    const isFolder = item.type === "folder";
    const isSelected = fileMgrState.selectedPaths.has(item.path);
    const isRenaming = fileMgrState.renamePath === item.path;
    const canWrite = fileMgrCanWrite();
    const disableEdits = fileMgrState.sharedMode && !canWrite;
    row.innerHTML = `
      <td><input type="checkbox" data-path="${escapeHtml(item.path || "")}" ${isSelected ? "checked" : ""} ${disableEdits ? "disabled" : ""} /></td>
      <td class="mono">
        ${isRenaming ? `<input type="text" class="mono" data-rename-input value="${escapeHtml(fileMgrState.renameValue || item.name || "")}" />` : escapeHtml(item.name || "")}
        ${isRenaming ? "" : renderFileMgrMediaPreview(item)}
      </td>
      <td>${escapeHtml(item.type || "")}</td>
      <td>${isFolder ? "" : fmtBytes(item.size || 0)}</td>
      <td class="muted">${escapeHtml(item.updated_at || "")}</td>
      <td>
        <div class="row-inline">
          ${
            isFolder
              ? '<button data-action="open">Open</button>'
              : `<button data-action="download">Download</button><button data-action="preview">Preview</button>${isEditableImageFile(item) && !disableEdits ? '<button data-action="edit-image">Edit image</button>' : ''}`
          }
          <button data-action="details">Details</button>
          ${
            disableEdits
              ? ""
              : (isRenaming
                ? '<button data-action="rename-save">Save</button><button data-action="rename-cancel">Cancel</button>'
                : '<button data-action="rename">Rename</button>')
          }
          ${disableEdits ? "" : '<button data-action="delete" class="danger">Delete</button>'}
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
            await fileMgrDownload(item.path, item.name, btn);
            return;
          }
          if (action === "preview") {
            await fileMgrPreview(item.path);
            return;
          }
          if (action === "edit-image") {
            await openFileMgrImageEditor(item);
            return;
          }
          if (action === "rename") {
            fileMgrState.renamePath = item.path;
            fileMgrState.renameValue = item.name || "";
            renderFileMgrList(fileMgrState.items);
            return;
          }
          if (action === "details") {
            await fileMgrDetails(item.path);
            return;
          }
          if (action === "rename-cancel") {
            fileMgrState.renamePath = null;
            fileMgrState.renameValue = "";
            renderFileMgrList(fileMgrState.items);
            return;
          }
          if (action === "rename-save") {
            const input = row.querySelector("[data-rename-input]");
            const newName = input ? input.value.trim() : "";
            if (!newName) return;
            const endpoint = fileMgrState.sharedMode
              ? (isFolder ? "/v1/fs/shared-rename-folder" : "/v1/fs/shared-rename-file")
              : (isFolder ? "/v1/fs/rename-folder" : "/v1/fs/rename-file");
            const params = new URLSearchParams();
            if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
              params.set("owner", fileMgrState.sharedOwner);
            }
            await apiPost(`${endpoint}${params.toString() ? `?${params.toString()}` : ""}`, { path: item.path, new_name: newName });
            fileMgrState.renamePath = null;
            fileMgrState.renameValue = "";
            await refreshFileManager();
            return;
          }
          if (action === "delete") {
            const ok = confirm(`Delete ${item.type} ${item.name}?`);
            if (!ok) return;
            const endpoint = fileMgrState.sharedMode
              ? (isFolder ? "/v1/fs/shared-folder" : "/v1/fs/shared-file")
              : (isFolder ? "/v1/fs/folder" : "/v1/fs/file");
            const params = new URLSearchParams();
            params.set("path", item.path);
            if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
              params.set("owner", fileMgrState.sharedOwner);
            }
            await apiDelete(`${endpoint}?${params.toString()}`);
            await refreshFileManager();
          }
        } catch (e) {
          fileMgrStatus(String(e));
        }
      };
    });
    const checkbox = row.querySelector("input[type=\"checkbox\"]");
    if (checkbox) {
      checkbox.onchange = (ev) => {
        const path = ev.target.getAttribute("data-path");
        setFileMgrSelected(path, ev.target.checked);
      };
    }
    const renameInput = row.querySelector("[data-rename-input]");
    if (renameInput) {
      renameInput.focus();
      renameInput.select();
      renameInput.onkeydown = async (ev) => {
        if (ev.key === "Enter") {
          ev.preventDefault();
          const newName = renameInput.value.trim();
          if (!newName) return;
          const endpoint = fileMgrState.sharedMode
            ? (isFolder ? "/v1/fs/shared-rename-folder" : "/v1/fs/shared-rename-file")
            : (isFolder ? "/v1/fs/rename-folder" : "/v1/fs/rename-file");
          const params = new URLSearchParams();
          if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
            params.set("owner", fileMgrState.sharedOwner);
          }
          await apiPost(`${endpoint}${params.toString() ? `?${params.toString()}` : ""}`, { path: item.path, new_name: newName });
          fileMgrState.renamePath = null;
          fileMgrState.renameValue = "";
          await refreshFileManager();
        }
        if (ev.key === "Escape") {
          ev.preventDefault();
          fileMgrState.renamePath = null;
          fileMgrState.renameValue = "";
          renderFileMgrList(fileMgrState.items);
        }
      };
    }
    tbody.appendChild(row);
  });
  if (!items || items.length === 0) {
    const empty = document.createElement("tr");
    empty.innerHTML = '<td colspan="6" class="muted">No files in this folder.</td>';
    tbody.appendChild(empty);
  }
  updateFileMgrSelectAll();
  updateFileMgrPaginationControls();
}

async function refreshFileManager(options = {}) {
  const table = document.getElementById("filemgrTable");
  if (!table) return;
  const append = options.append === true;
  try {
    fileMgrStatus(append ? "Loading more..." : "Loading...");
    await ensureUiSession();
    const path = currentFileMgrPath();
    const params = new URLSearchParams();
    params.set("path", path);
    params.set("limit", String(fileMgrState.pageSize || 50));
    params.set("sort_by", fileMgrState.sortBy || "name");
    params.set("sort_dir", fileMgrState.sortDir || "asc");
    if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
      params.set("owner", fileMgrState.sharedOwner);
    }
    if (append && fileMgrState.cursor) {
      params.set("cursor", fileMgrState.cursor);
    } else {
      fileMgrState.cursor = null;
    }
    const endpoint = fileMgrState.sharedMode ? "/v1/fs/shared-list" : "/v1/fs/list";
    const res = await apiGet(`${endpoint}?${params.toString()}`);
    setFileMgrPath(res.path || path);
    const nextItems = res.items || [];
    fileMgrState.items = append ? fileMgrState.items.concat(nextItems) : nextItems;
    if (!append) {
      clearFileMgrSelection();
    }
    renderFileMgrList(fileMgrState.items);
    fileMgrState.cursor = res.cursor || null;
    fileMgrState.hasMore = Boolean(fileMgrState.cursor);
    updateFileMgrPaginationControls();
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
  if (fileMgrState.sharedMode && !fileMgrCanWrite()) {
    fileMgrStatus("Shared view is read-only.");
    return;
  }
  const endpoint = fileMgrState.sharedMode ? `/v1/fs/shared-folder?owner=${encodeURIComponent(fileMgrState.sharedOwner || "")}` : "/v1/fs/folder";
  await apiPost(endpoint, { path });
  nameInput.value = "";
  await refreshFileManager();
}

async function uploadFileMgr() {
  const input = document.getElementById("filemgrUploadInput");
  if (!input || !input.files || !input.files.length) return;
  await ensureUiSession();
  if (fileMgrState.sharedMode && !fileMgrCanWrite()) {
    fileMgrStatus("Shared view is read-only.");
    return;
  }
  const files = Array.from(input.files);
  const encryptToggle = document.getElementById("filemgrEncryptToggle");
  const encryptionEnabled = Boolean(encryptToggle && encryptToggle.checked);
  let encryptionPassword = null;
  if (encryptionEnabled) {
    encryptionPassword = promptFileEncryptionPassword();
    if (!encryptionPassword) {
      fileMgrStatus("Encryption canceled.");
      return;
    }
  }

  const uploadOne = async (file) => {
    const path = currentFileMgrPath() + file.name;
    let cancel = null;
    let canceled = false;
    const transfer = createFileMgrTransfer(`Upload: ${file.name}`, () => {
      canceled = true;
      if (cancel) cancel();
      finishFileMgrTransfer(transfer, "Upload canceled");
    });
    updateFileMgrTransfer(transfer, 0, file.size, "Uploading");
    try {
      let sourceFile = file;
      let encryptionMeta = null;
      if (encryptionEnabled && encryptionPassword) {
        updateFileMgrTransfer(transfer, 0, file.size, "Encrypting");
        const enc = await encryptFile(file, encryptionPassword);
        sourceFile = new File([enc.blob], file.name, { type: "application/octet-stream" });
        encryptionMeta = enc.metadata;
      }
      await apiUploadFileManager(
        path,
        sourceFile,
        (event) => {
          if (event.lengthComputable) {
            updateFileMgrTransfer(transfer, event.loaded, event.total, "Uploading");
          } else {
            updateFileMgrTransfer(transfer, event.loaded, null, "Uploading");
          }
        },
        (cancelFn) => {
          cancel = cancelFn;
        },
        {
          sharedOwner: fileMgrState.sharedMode ? fileMgrState.sharedOwner : null,
          encrypted: Boolean(encryptionMeta),
          encryptionMeta,
        }
      );
      finishFileMgrTransfer(transfer, "Upload complete");
    } catch (e) {
      if (!canceled) {
        finishFileMgrTransfer(transfer, "Upload failed", { error: true, sticky: true });
        throw e;
      }
    }
  };
  const results = await Promise.allSettled(files.map((file) => uploadOne(file)));
  const failures = results.filter((result) => result.status === "rejected");
  if (failures.length) {
    fileMgrStatus(`Upload failed for ${failures.length} file(s).`);
  }
  input.value = "";
  await refreshFileManager();
}

async function uploadZipFileMgr() {
  const input = document.getElementById("filemgrUploadZipInput");
  if (!input || !input.files || !input.files.length) return;
  const file = input.files[0];
  await ensureUiSession();
  if (fileMgrState.sharedMode && !fileMgrCanWrite()) {
    fileMgrStatus("Shared view is read-only.");
    return;
  }
  const tok = accessToken();
  if (!tok) throw new Error("Missing access_token (Cognito login not completed).");
  const form = new FormData();
  form.append("zip_file", file);
  const dest = currentFileMgrPath();
  const endpoint = fileMgrState.sharedMode ? "/v1/fs/shared-upload-zip" : "/v1/fs/upload-zip";
  const params = new URLSearchParams();
  params.set("dest_folder", dest);
  if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
    params.set("owner", fileMgrState.sharedOwner);
  }
  const res = await fetch(`${API_BASE}${endpoint}?${params.toString()}`, {
    method: "POST",
    headers,
    body: form,
    credentials: "include",
  });
  if (!res.ok) throw new Error(await res.text());
  input.value = "";
  await refreshFileManager();
}

async function downloadSelectedZipFileMgr() {
  const paths = Array.from(fileMgrState.selectedPaths || []);
  if (!paths.length) {
    fileMgrStatus("Select at least one file or folder to download.");
    return;
  }
  await ensureUiSession();
  await fileMgrDownloadZip(paths);
}

async function bulkDeleteFileMgr() {
  const items = selectedFileMgrItems();
  if (!items.length) {
    fileMgrStatus("Select at least one file or folder to delete.");
    return;
  }
  if (fileMgrState.sharedMode && !fileMgrCanWrite()) {
    fileMgrStatus("Shared view is read-only.");
    return;
  }
  const ok = confirm(`Delete ${items.length} item(s)?`);
  if (!ok) return;
  await ensureUiSession();
  const op = await runFileMgrBulkOp("delete", items, async (item) => {
    const endpoint = fileMgrState.sharedMode
      ? (item.type === "folder" ? "/v1/fs/shared-folder" : "/v1/fs/shared-file")
      : (item.type === "folder" ? "/v1/fs/folder" : "/v1/fs/file");
    const params = new URLSearchParams();
    params.set("path", item.path);
    if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
      params.set("owner", fileMgrState.sharedOwner);
    }
    await apiDelete(`${endpoint}?${params.toString()}`);
  });
  if (op.failed > 0) {
    fileMgrStatus(`Delete completed with ${op.failed} failure(s).`);
  } else {
    fileMgrStatus(`Deleted ${op.success} item(s).`);
  }
  await refreshFileManager();
}

async function bulkMoveFileMgr() {
  const items = selectedFileMgrItems();
  if (!items.length) {
    fileMgrStatus("Select at least one file or folder to move.");
    return;
  }
  if (fileMgrState.sharedMode && !fileMgrCanWrite()) {
    fileMgrStatus("Shared view is read-only.");
    return;
  }
  const destInput = prompt("Move selected items to folder:", currentFileMgrPath());
  if (!destInput) return;
  const destFolder = normalizeFolderPath(destInput);
  await ensureUiSession();
  const op = await runFileMgrBulkOp("move", items, async (item) => {
    const dst = item.type === "folder"
      ? `${destFolder}${item.name}/`
      : `${destFolder}${item.name}`;
    if (dst === item.path) {
      return "skipped";
    }
    const endpoint = fileMgrState.sharedMode ? "/v1/fs/shared-move" : "/v1/fs/move";
    const params = new URLSearchParams();
    if (fileMgrState.sharedMode && fileMgrState.sharedOwner) {
      params.set("owner", fileMgrState.sharedOwner);
    }
    await apiPost(`${endpoint}${params.toString() ? `?${params.toString()}` : ""}`, { src: item.path, dst });
  });
  if (op.failed > 0) {
    fileMgrStatus(`Move completed with ${op.failed} failure(s).`);
  } else {
    fileMgrStatus(`Moved ${op.success} item(s).`);
  }
  await refreshFileManager();
}

async function searchFileMgr() {
  const input = document.getElementById("filemgrSearch");
  if (!input) return;
  if (fileMgrState.sharedMode) {
    fileMgrStatus("Search is unavailable in shared view.");
    return;
  }
  const prefix = input.value.trim();
  if (!prefix) return;
  await ensureUiSession();
  const res = await apiGet(`/v1/fs/search?prefix=${encodeURIComponent(prefix)}`);
  fileMgrState.searchResults = res.results || [];
  renderFileMgrSearchResults();
}

async function searchFileMgrText() {
  const input = document.getElementById("filemgrSearchText");
  if (!input) return;
  if (fileMgrState.sharedMode) {
    fileMgrStatus("Search is unavailable in shared view.");
    return;
  }
  const query = input.value.trim();
  if (!query) return;
  await ensureUiSession();
  const res = await apiGet(`/v1/fs/search-text?q=${encodeURIComponent(query)}&limit=200`);
  fileMgrState.searchResults = res.results || [];
  renderFileMgrSearchResults();
}

function clearFileMgrSearch() {
  fileMgrState.searchResults = [];
  const input = document.getElementById("filemgrSearch");
  if (input) input.value = "";
  const textInput = document.getElementById("filemgrSearchText");
  if (textInput) textInput.value = "";
  renderFileMgrSearchResults();
}

/* ===================== Catalog Search ===================== */
function renderCatalogSearchResults(items) {
  const list = document.getElementById("catalogSearchResults");
  if (!list) return;
  list.innerHTML = "";
  if (!items.length) {
    list.innerHTML = "<div class='muted'>No catalog matches.</div>";
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div><b>${escapeHtml(item.name || "")}</b></div>
        <div class="muted">${escapeHtml(item.description || "")}</div>
      </div>
      <div class="mono">${fmtMoney(item.price_cents || 0, item.currency || "usd")}</div>
    `;
    list.appendChild(row);
  });
}

async function searchCatalogItems() {
  const query = readInput("catalogSearchInput");
  const status = document.getElementById("catalogSearchStatus");
  if (!query) {
    renderCatalogSearchResults([]);
    if (status) status.textContent = "";
    return;
  }
  try {
    if (status) status.textContent = "Searching...";
    await ensureUiSession();
    const res = await apiGet(`/ui/catalog/items/search?q=${encodeURIComponent(query)}&page_size=200`);
    renderCatalogSearchResults(res.items || []);
    if (status) status.textContent = `Found ${(res.items || []).length} items.`;
  } catch (e) {
    if (status) status.textContent = String(e);
  }
}

function clearCatalogSearch() {
  setInputValue("catalogSearchInput", "");
  const status = document.getElementById("catalogSearchStatus");
  if (status) status.textContent = "";
  renderCatalogSearchResults([]);
}

/* ===================== Purchase History Search ===================== */
function renderPurchaseSearchResults(items) {
  const list = document.getElementById("purchaseSearchResults");
  if (!list) return;
  list.innerHTML = "";
  if (!items.length) {
    list.innerHTML = "<div class='muted'>No purchase matches.</div>";
    return;
  }
  items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div class="grow">
        <div class="mono">${escapeHtml(item.txn_id || "")}</div>
        <div class="muted">${escapeHtml(item.description || "")}</div>
        <div class="muted">${escapeHtml(item.status || "")}</div>
      </div>
      <div class="mono">${fmtMoney(Math.round((item.amount || 0) * 100), item.currency || "usd")}</div>
    `;
    list.appendChild(row);
  });
}

async function searchPurchaseHistory() {
  const query = readInput("purchaseSearchInput");
  const status = document.getElementById("purchaseSearchStatus");
  if (!query) {
    renderPurchaseSearchResults([]);
    if (status) status.textContent = "";
    return;
  }
  try {
    if (status) status.textContent = "Searching...";
    await ensureUiSession();
    const res = await apiGet(`/ui/purchase-history/transactions/search?q=${encodeURIComponent(query)}&limit=200`);
    renderPurchaseSearchResults(res || []);
    if (status) status.textContent = `Found ${(res || []).length} transactions.`;
  } catch (e) {
    if (status) status.textContent = String(e);
  }
}

function clearPurchaseSearch() {
  setInputValue("purchaseSearchInput", "");
  const status = document.getElementById("purchaseSearchStatus");
  if (status) status.textContent = "";
  renderPurchaseSearchResults([]);
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
document.getElementById("deviceRefreshBtn").onclick = async () => { await refreshDevices(); };
document.getElementById("totpAddBtn").onclick = async () => { await ensureUiSession(); openTotpAddModal(); };


document.getElementById("keysRefreshBtn").onclick = async () => { await refreshKeys(); };
document.getElementById("keysCreateBtn").onclick = async () => { openCreateKeyModal(); };
document.getElementById("apiUsageRefreshBtn").onclick = async () => { await refreshApiUsageViews(true); };
document.getElementById("apiUsageRouteApplyBtn").onclick = async () => { await refreshApiUsageViews(true); };
document.getElementById("apiUsageKeyApplyBtn").onclick = async () => { await refreshApiUsageViews(true); };
document.getElementById("apiUsageRouteMoreBtn").onclick = async () => { await refreshApiUsageRoutes((document.getElementById("apiUsagePeriod")?.value||currentPeriodIdUtc()).trim(), true); };
document.getElementById("apiUsageKeyMoreBtn").onclick = async () => { await refreshApiUsageKeys((document.getElementById("apiUsagePeriod")?.value||currentPeriodIdUtc()).trim(), true); };


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
    resetEventsPagination();
    await refreshCalendarShares();
    await refreshBookingLinks();
    await refreshCalendarEvents();
  } else {
    setCalendarStatus("Calendar cleared.");
    renderBookingLinks([]);
    renderCalendarShares([]);
  }
};

document.getElementById("calendarCreateBtn").onclick = async () => {
  await createCalendar();
  resetEventsPagination();
};

document.getElementById("calendarAccessRefreshBtn").onclick = async () => {
  await refreshCalendarAccess();
};

document.getElementById("calendarShareCreateBtn").onclick = async () => {
  await createCalendarShare();
};

document.getElementById("eventCreateBtn").onclick = async () => {
  await createCalendarEvent();
};

document.getElementById("eventCancelEditBtn").onclick = () => {
  resetEventForm();
  document.getElementById("eventCreateStatus").textContent = "Edit canceled.";
};

document.getElementById("eventPreviewConflictsBtn").onclick = async () => {
  await previewEventConflicts();
};

document.getElementById("eventSuggestSlotsBtn").onclick = async () => {
  await loadEventSuggestions();
};

document.getElementById("eventsRefreshBtn").onclick = async () => {
  await refreshCalendarEvents();
};

document.getElementById("eventsClearFiltersBtn").onclick = async () => {
  document.getElementById("eventsStartInput").value = "";
  document.getElementById("eventsEndInput").value = "";
  document.getElementById("eventsStartPicker").value = "";
  document.getElementById("eventsEndPicker").value = "";
  document.getElementById("eventsLimitSelect").value = "";
  resetEventsPagination();
  await refreshCalendarEvents();
};

document.getElementById("eventsNextBtn").onclick = async () => {
  if (!eventsPagination.nextCursor) return;
  eventsPagination.prevStack.push(eventsPagination.currentCursor);
  eventsPagination.currentCursor = eventsPagination.nextCursor;
  await refreshCalendarEvents();
};

document.getElementById("eventsPrevBtn").onclick = async () => {
  if (!eventsPagination.prevStack.length) return;
  eventsPagination.currentCursor = eventsPagination.prevStack.pop();
  await refreshCalendarEvents();
};

document.getElementById("bookingLinkCreateBtn").onclick = async () => {
  await createBookingLink();
};

document.getElementById("bookingOpeningsLoadBtn").onclick = async () => {
  await loadBookingLinkOpenings();
};

document.getElementById("openingsLoadBtn").onclick = async () => {
  await loadCalendarOpenings();
};

document.getElementById("workingHoursSaveBtn").onclick = async () => {
  await saveWorkingHours();
};

document.getElementById("teamOpeningsLoadBtn").onclick = async () => {
  await loadTeamOpenings();
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

document.getElementById("alertsSearchBtn").onclick = searchAlerts;
document.getElementById("alertsSearchClearBtn").onclick = clearAlertSearch;

document.getElementById("catalogSearchBtn").onclick = searchCatalogItems;
document.getElementById("catalogSearchClearBtn").onclick = clearCatalogSearch;

document.getElementById("purchaseSearchBtn").onclick = searchPurchaseHistory;
document.getElementById("purchaseSearchClearBtn").onclick = clearPurchaseSearch;

document.getElementById("btnRefreshAll").onclick = refreshAll;
document.getElementById("btnClearSession").onclick = async () => {
  try {
    await apiPost("/ui/session/logout", {});
  } catch (e) {}
  alert("UI session cleared.");
};
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
document.getElementById("filemgrSharedRefreshBtn").onclick = async () => {
  try {
    await refreshSharedWithMe();
  } catch (e) {
    fileMgrSharedStatus(String(e));
  }
};
document.getElementById("filemgrSharedClearBtn").onclick = () => {
  fileMgrState.sharedItems = [];
  renderSharedWithMe();
  fileMgrSharedStatus("Cleared.");
};
document.getElementById("filemgrExitSharedBtn").onclick = async () => {
  exitFileMgrSharedMode();
  setFileMgrPath("/");
  await refreshFileManager();
};
document.getElementById("filemgrLoadMoreBtn").onclick = async () => {
  if (!fileMgrState.hasMore) return;
  try {
    await refreshFileManager({ append: true });
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
const filemgrSortBy = document.getElementById("filemgrSortBy");
const filemgrSortDirBtn = document.getElementById("filemgrSortDirBtn");
const filemgrPageSize = document.getElementById("filemgrPageSize");
if (filemgrSortBy) {
  filemgrSortBy.value = fileMgrState.sortBy;
  filemgrSortBy.onchange = async (ev) => {
    setFileMgrSort(ev.target.value, fileMgrState.sortDir);
    fileMgrState.cursor = null;
    await refreshFileManager();
  };
}
if (filemgrSortDirBtn) {
  filemgrSortDirBtn.textContent = fileMgrState.sortDir === "desc" ? "Desc" : "Asc";
  filemgrSortDirBtn.onclick = async () => {
    fileMgrState.sortDir = fileMgrState.sortDir === "desc" ? "asc" : "desc";
    filemgrSortDirBtn.textContent = fileMgrState.sortDir === "desc" ? "Desc" : "Asc";
    fileMgrState.cursor = null;
    await refreshFileManager();
  };
}
if (filemgrPageSize) {
  filemgrPageSize.value = String(fileMgrState.pageSize);
  filemgrPageSize.onchange = async (ev) => {
    fileMgrState.pageSize = Number(ev.target.value) || 50;
    fileMgrState.cursor = null;
    await refreshFileManager();
  };
}
document.getElementById("filemgrAuditRefreshBtn").onclick = async () => {
  try {
    await refreshFileMgrAudit();
  } catch (e) {
    fileMgrAuditStatus(String(e));
  }
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
document.getElementById("filemgrUploadZipBtn").onclick = async () => {
  try {
    await uploadZipFileMgr();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrDownloadZipBtn").onclick = async () => {
  try {
    await downloadSelectedZipFileMgr();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrBulkMoveBtn").onclick = async () => {
  try {
    await bulkMoveFileMgr();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrBulkDeleteBtn").onclick = async () => {
  try {
    await bulkDeleteFileMgr();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrSelectAll").onclick = (ev) => {
  toggleFileMgrSelectAll(ev.target.checked);
};
document.getElementById("filemgrSearchBtn").onclick = async () => {
  try {
    await searchFileMgr();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrSearchTextBtn").onclick = async () => {
  try {
    await searchFileMgrText();
  } catch (e) {
    fileMgrStatus(String(e));
  }
};
document.getElementById("filemgrClearSearchBtn").onclick = clearFileMgrSearch;
refreshSharedWithMe().catch(() => {});
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
document.getElementById("cartSearchBtn").onclick = searchCartItems;
document.getElementById("cartSearchClearBtn").onclick = clearCartSearch;
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

if (!window.__SKIP_BOOT__) {
  initBillingUi();
  initSignatureComposerUi();
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
document.getElementById("msgSendFileBtn").onclick = () => sendMessagingAttachment({ useUpload: true });
document.getElementById("msgSendPathBtn").onclick = () => sendMessagingAttachment({ useUpload: false });
document.getElementById("msgSearchConvoBtn").onclick = () => searchMessagingMessages({ allConversations: false });
document.getElementById("msgSearchAllBtn").onclick = () => searchMessagingMessages({ allConversations: true });
document.getElementById("msgSearchClearBtn").onclick = clearMessagingSearch;
document.getElementById("msgSearchConvoBtn").onclick = () => searchMessagingMessages({ allConversations: false });
document.getElementById("msgSearchAllBtn").onclick = () => searchMessagingMessages({ allConversations: true });
document.getElementById("msgSearchClearBtn").onclick = clearMessagingSearch;

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
document.getElementById("ticketRefreshBtn").onclick = async () => {
  try {
    await refreshTicketList({ append: false });
  } catch (e) {
    setTicketListStatus(String(e.message || e));
  }
};
document.getElementById("ticketLoadMoreBtn").onclick = async () => {
  try {
    if (!ticketUiState.nextCursor) {
      setTicketListStatus("No more tickets.");
      return;
    }
    await refreshTicketList({ append: true });
  } catch (e) {
    setTicketListStatus(String(e.message || e));
  }
};
document.getElementById("ticketCreateBtn").onclick = async () => {
  try {
    await createTicketFromUi();
  } catch (e) {
    setTicketCreateStatus(String(e.message || e));
  }
};
document.getElementById("ticketThreadRefreshBtn").onclick = async () => {
  try {
    if (!ticketUiState.activeTicketId) return;
    await selectTicketThread(ticketUiState.activeTicketId);
  } catch (e) {
    setTicketReplyStatus(String(e.message || e));
  }
};
document.getElementById("ticketReplyBtn").onclick = async () => {
  try {
    await sendTicketReplyFromUi();
  } catch (e) {
    setTicketReplyStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketFilterApplyBtn").onclick = async () => {
  try {
    applyAdminTicketFiltersFromInputs();
    await refreshAdminTicketQueue({ append: false });
  } catch (e) {
    setAdminTicketQueueStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketQueueLoadMoreBtn").onclick = async () => {
  try {
    if (!adminTicketUiState.nextCursor) {
      setAdminTicketQueueStatus("No more queue items.");
      return;
    }
    await refreshAdminTicketQueue({ append: true });
  } catch (e) {
    setAdminTicketQueueStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketThreadRefreshBtn").onclick = async () => {
  try {
    if (!adminTicketUiState.activeTicketId) return;
    await selectAdminTicket(adminTicketUiState.activeTicketId);
  } catch (e) {
    setAdminTicketActionStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketAssignSelfBtn").onclick = async () => {
  try {
    setAdminTicketActionStatus("Assigning to you...");
    await adminAssignTicketToSelf();
    setAdminTicketActionStatus("Assigned.");
  } catch (e) {
    setAdminTicketActionStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketAssignOtherBtn").onclick = async () => {
  try {
    const assignee = readInput("adminTicketAssignOtherInput").trim();
    setAdminTicketActionStatus("Assigning...");
    await adminAssignTicket(assignee);
    setAdminTicketActionStatus("Assigned.");
  } catch (e) {
    setAdminTicketActionStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketReplyBtn").onclick = async () => {
  try {
    setAdminTicketActionStatus("Sending reply...");
    await adminReplyToTicket();
    setAdminTicketActionStatus("Reply sent.");
  } catch (e) {
    setAdminTicketActionStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketMarkDoneBtn").onclick = async () => {
  try {
    setAdminTicketActionStatus("Updating status...");
    await adminSetTicketStatus("done");
    setAdminTicketActionStatus("Ticket marked done.");
  } catch (e) {
    setAdminTicketActionStatus(String(e.message || e));
  }
};
document.getElementById("adminTicketReopenBtn").onclick = async () => {
  try {
    setAdminTicketActionStatus("Updating status...");
    await adminSetTicketStatus("open");
    setAdminTicketActionStatus("Ticket reopened.");
  } catch (e) {
    setAdminTicketActionStatus(String(e.message || e));
  }
};
  document.getElementById("newsfeedDisconnectBtn").onclick = () => {
  disconnectNewsfeedSse();
  logNewsfeedSse("Disconnected.");
};


const ticketUiState = {
  items: [],
  nextCursor: null,
  activeTicketId: "",
};

function setTicketListStatus(msg) {
  const el = document.getElementById("ticketListStatus");
  if (el) el.textContent = msg || "";
}

function setTicketCreateStatus(msg) {
  const el = document.getElementById("ticketCreateStatus");
  if (el) el.textContent = msg || "";
}

function setTicketReplyStatus(msg) {
  const el = document.getElementById("ticketReplyStatus");
  if (el) el.textContent = msg || "";
}

function renderTicketList() {
  const root = document.getElementById("ticketList");
  if (!root) return;
  root.innerHTML = "";
  for (const t of ticketUiState.items) {
    const row = document.createElement("button");
    row.className = "item";
    row.style.width = "100%";
    row.style.textAlign = "left";
    row.innerHTML = `
      <div class="row-inline" style="justify-content:space-between;">
        <b>${escapeHtml(t.subject || "(no subject)")}</b>
        <span class="pill">${escapeHtml(t.status || "open")}</span>
      </div>
      <div class="muted mono">${escapeHtml(t.ticket_id || "")}</div>
    `;
    row.onclick = () => selectTicketThread(t.ticket_id);
    root.appendChild(row);
  }
  if (ticketUiState.items.length === 0) {
    root.innerHTML = '<div class="muted">No tickets yet.</div>';
  }
}

async function refreshTicketList({ append = false } = {}) {
  const q = new URLSearchParams();
  q.set("limit", "10");
  if (append && ticketUiState.nextCursor) q.set("cursor", ticketUiState.nextCursor);
  const res = await apiGet(`/tickets?${q.toString()}`);
  const items = res.items || [];
  ticketUiState.nextCursor = res.next_cursor || null;
  ticketUiState.items = append ? ticketUiState.items.concat(items) : items;
  renderTicketList();
  setTicketListStatus(ticketUiState.nextCursor ? "More available" : "Up to date");
}

function renderTicketThread(ticket) {
  const label = document.getElementById("ticketActiveLabel");
  const meta = document.getElementById("ticketThreadMeta");
  const messages = document.getElementById("ticketThreadMessages");
  if (!ticket) {
    if (label) label.textContent = "No ticket selected";
    if (meta) meta.textContent = "";
    if (messages) messages.innerHTML = '<div class="muted">Select a ticket to view thread.</div>';
    return;
  }
  if (label) label.textContent = `${ticket.ticket_id} • ${ticket.status}`;
  if (meta) meta.textContent = `Subject: ${ticket.subject || ""}`;
  if (messages) {
    messages.innerHTML = "";
    for (const msg of (ticket.messages || [])) {
      const item = document.createElement("div");
      item.className = "item";
      item.innerHTML = `
        <div class="row-inline" style="justify-content:space-between;">
          <b>${escapeHtml(msg.sender_role || "user")}</b>
          <span class="muted">${fmtTs(msg.created_at)}</span>
        </div>
        <div>${escapeHtml(msg.body || "")}</div>
      `;
      messages.appendChild(item);
    }
    if ((ticket.messages || []).length === 0) {
      messages.innerHTML = '<div class="muted">No messages.</div>';
    }
  }
}

async function selectTicketThread(ticketId) {
  if (!ticketId) return;
  ticketUiState.activeTicketId = ticketId;
  const res = await apiGet(`/tickets/${encodeURIComponent(ticketId)}`);
  renderTicketThread(res.ticket);
}

async function createTicketFromUi() {
  const subject = readInput("ticketNewSubject").trim();
  const description = readInput("ticketNewDescription").trim();
  if (!subject || !description) throw new Error("Subject and description are required");
  setTicketCreateStatus("Opening ticket...");
  const res = await apiPost("/tickets", { subject, description });
  setInputValue("ticketNewSubject", "");
  setInputValue("ticketNewDescription", "");
  setTicketCreateStatus("Ticket opened.");
  await refreshTicketList({ append: false });
  await selectTicketThread(res.ticket.ticket_id);
}

async function sendTicketReplyFromUi() {
  if (!ticketUiState.activeTicketId) throw new Error("Select a ticket first");
  const body = readInput("ticketReplyBody").trim();
  if (!body) throw new Error("Reply cannot be empty");
  setTicketReplyStatus("Sending...");
  await apiPost(`/tickets/${encodeURIComponent(ticketUiState.activeTicketId)}/messages`, { body });
  setInputValue("ticketReplyBody", "");
  setTicketReplyStatus("Reply sent.");
  await selectTicketThread(ticketUiState.activeTicketId);
  await refreshTicketList({ append: false });
}

refreshTicketList({ append: false }).catch(() => {});


const adminTicketUiState = {
  items: [],
  nextCursor: null,
  activeTicketId: "",
  activeTicket: null,
  filters: { status: "", assignee: "", owner: "" },
};

function setAdminTicketQueueStatus(msg) {
  const el = document.getElementById("adminTicketQueueStatus");
  if (el) el.textContent = msg || "";
}

function setAdminTicketActionStatus(msg) {
  const el = document.getElementById("adminTicketActionStatus");
  if (el) el.textContent = msg || "";
}

function renderAdminTicketQueue() {
  const root = document.getElementById("adminTicketQueueList");
  if (!root) return;
  root.innerHTML = "";
  for (const t of adminTicketUiState.items) {
    const row = document.createElement("button");
    row.className = "item";
    row.style.width = "100%";
    row.style.textAlign = "left";
    row.innerHTML = `
      <div class="row-inline" style="justify-content:space-between;">
        <b>${escapeHtml(t.subject || "(no subject)")}</b>
        <span class="pill">${escapeHtml(t.status || "open")}</span>
      </div>
      <div class="muted mono">${escapeHtml(t.ticket_id || "")}</div>
      <div class="muted">owner=${escapeHtml(t.owner_sub || "")} assignee=${escapeHtml(t.assigned_admin_sub || "unassigned")}</div>
    `;
    row.onclick = () => selectAdminTicket(t.ticket_id);
    root.appendChild(row);
  }
  if (adminTicketUiState.items.length === 0) {
    root.innerHTML = '<div class="muted">No tickets for current filters.</div>';
  }
}

function renderAdminTicketDetails(ticket) {
  const label = document.getElementById("adminTicketActiveLabel");
  const meta = document.getElementById("adminTicketMeta");
  const messages = document.getElementById("adminTicketThreadMessages");
  if (!ticket) {
    if (label) label.textContent = "No ticket selected";
    if (meta) meta.textContent = "";
    if (messages) messages.innerHTML = '<div class="muted">Select a queue ticket to triage.</div>';
    return;
  }
  if (label) label.textContent = `${ticket.ticket_id} • ${ticket.status}`;
  if (meta) {
    meta.textContent = `Subject: ${ticket.subject || ""} | Owner: ${ticket.owner_sub || ""} | Assignee: ${ticket.assigned_admin_sub || "unassigned"}`;
  }
  if (messages) {
    messages.innerHTML = "";
    for (const msg of (ticket.messages || [])) {
      const item = document.createElement("div");
      item.className = "item";
      item.innerHTML = `
        <div class="row-inline" style="justify-content:space-between;">
          <b>${escapeHtml(msg.sender_role || "user")}</b>
          <span class="muted">${fmtTs(msg.created_at)}</span>
        </div>
        <div>${escapeHtml(msg.body || "")}</div>
      `;
      messages.appendChild(item);
    }
    if ((ticket.messages || []).length === 0) {
      messages.innerHTML = '<div class="muted">No messages.</div>';
    }
  }
}

async function refreshAdminTicketQueue({ append = false } = {}) {
  const q = new URLSearchParams();
  q.set("limit", "10");
  const f = adminTicketUiState.filters;
  if (f.status) q.set("status", f.status);
  if (f.assignee) q.set("assignee_admin_sub", f.assignee);
  if (f.owner) q.set("owner_sub", f.owner);
  if (append && adminTicketUiState.nextCursor) q.set("cursor", adminTicketUiState.nextCursor);

  const res = await apiGet(`/tickets?${q.toString()}`);
  const items = res.items || [];
  adminTicketUiState.nextCursor = res.next_cursor || null;
  adminTicketUiState.items = append ? adminTicketUiState.items.concat(items) : items;
  renderAdminTicketQueue();
  setAdminTicketQueueStatus(adminTicketUiState.nextCursor ? "More queue items available" : "Queue loaded");
}

async function selectAdminTicket(ticketId) {
  if (!ticketId) return;
  adminTicketUiState.activeTicketId = ticketId;
  const res = await apiGet(`/tickets/${encodeURIComponent(ticketId)}`);
  adminTicketUiState.activeTicket = res.ticket;
  renderAdminTicketDetails(adminTicketUiState.activeTicket);
}

async function adminAssignTicket(assigneeSub) {
  if (!adminTicketUiState.activeTicketId) throw new Error("Select a ticket first");
  const assignee = String(assigneeSub || "").trim();
  if (!assignee) throw new Error("Assignee is required");
  await apiPost(`/tickets/${encodeURIComponent(adminTicketUiState.activeTicketId)}/assign`, { assignee_admin_sub: assignee });
  await selectAdminTicket(adminTicketUiState.activeTicketId);
  await refreshAdminTicketQueue({ append: false });
}

async function adminAssignTicketToSelf() {
  const me = await apiGet("/ui/me");
  await adminAssignTicket(me.user_sub);
}

async function adminReplyToTicket() {
  if (!adminTicketUiState.activeTicketId) throw new Error("Select a ticket first");
  const body = readInput("adminTicketReplyBody").trim();
  if (!body) throw new Error("Reply cannot be empty");
  await apiPost(`/tickets/${encodeURIComponent(adminTicketUiState.activeTicketId)}/messages`, { body });
  setInputValue("adminTicketReplyBody", "");
  await selectAdminTicket(adminTicketUiState.activeTicketId);
  await refreshAdminTicketQueue({ append: false });
}

async function adminSetTicketStatus(status) {
  if (!adminTicketUiState.activeTicketId) throw new Error("Select a ticket first");
  await apiPost(`/tickets/${encodeURIComponent(adminTicketUiState.activeTicketId)}/status`, { status });
  await selectAdminTicket(adminTicketUiState.activeTicketId);
  await refreshAdminTicketQueue({ append: false });
}

function applyAdminTicketFiltersFromInputs() {
  adminTicketUiState.filters.status = readInput("adminTicketFilterStatus").trim();
  adminTicketUiState.filters.assignee = readInput("adminTicketFilterAssignee").trim();
  adminTicketUiState.filters.owner = readInput("adminTicketFilterOwner").trim();
  adminTicketUiState.nextCursor = null;
}


refreshAdminTicketQueue({ append: false }).catch((e) => {
  setAdminTicketQueueStatus(String(e.message || e));
  renderAdminTicketDetails(null);
});

const TICKET_AUTO_REFRESH_MS = 15000;
let ticketAutoRefreshHandle = null;

async function refreshTicketPanelsLive() {
  try {
    await refreshTicketList({ append: false });
    if (ticketUiState.activeTicketId) {
      await selectTicketThread(ticketUiState.activeTicketId);
    }
  } catch (e) {
    // keep polling resilient
  }

  try {
    await refreshAdminTicketQueue({ append: false });
    if (adminTicketUiState.activeTicketId) {
      await selectAdminTicket(adminTicketUiState.activeTicketId);
    }
  } catch (e) {
    // keep polling resilient
  }
}

function startTicketAutoRefresh() {
  if (ticketAutoRefreshHandle) return;
  ticketAutoRefreshHandle = setInterval(() => {
    if (document.hidden) return;
    refreshTicketPanelsLive();
  }, TICKET_AUTO_REFRESH_MS);
}

startTicketAutoRefresh();


/* ===================== boot ===================== */
  setCalendarId(getCalendarId());
  if (!accessToken()) { openTokenModal(); } else { refreshAll(); }
  startToastSSE();
  startToastPolling();
}

/* ===================== signature packet composer ===================== */
const sigComposerState = {
  packet: null,
  fields: [],
  signers: [],
};

function sigStatus(msg) {
  const el = document.getElementById("sigComposerStatus");
  if (el) el.textContent = msg || "";
}

function sigFieldDimensions(fieldType) {
  if (fieldType === "text") return { width: 0.32, height: 0.07 };
  if (fieldType === "date") return { width: 0.2, height: 0.05 };
  return { width: 0.22, height: 0.06 };
}

function renderSigSigners() {
  const wrap = document.getElementById("sigSignersList");
  const select = document.getElementById("sigAssignedSignerId");
  if (!wrap || !select) return;
  wrap.innerHTML = "";
  select.innerHTML = '<option value="">Unassigned</option>';
  for (const signer of sigComposerState.signers || []) {
    const signerId = String(signer.signer_id || "");
    const item = document.createElement("div");
    item.className = "list-item";
    item.innerHTML = `<div><b>${signerId || "unknown"}</b><div class="muted">status: ${signer.status || "pending"}</div></div>`;
    wrap.appendChild(item);

    const opt = document.createElement("option");
    opt.value = signerId;
    opt.textContent = `${signerId} (${signer.status || "pending"})`;
    select.appendChild(opt);
  }
  if (!sigComposerState.signers.length) {
    wrap.innerHTML = '<div class="muted">No signers on packet yet.</div>';
  }
}

function renderSigFields() {
  const wrap = document.getElementById("sigFieldsList");
  const canvas = document.getElementById("sigCanvas");
  if (!wrap || !canvas) return;
  wrap.innerHTML = "";
  canvas.innerHTML = "";

  for (const field of sigComposerState.fields || []) {
    const row = document.createElement("div");
    row.className = "list-item";
    row.innerHTML = `
      <div>
        <b>${field.field_type}</b> <span class="mono">${field.field_id}</span>
        <div class="muted">page ${field.page} • signer ${field.assigned_signer_id || "unassigned"} • ${field.required ? "required" : "optional"}</div>
      </div>
      <button data-field-delete="${field.field_id}" class="danger">Delete</button>
    `;
    wrap.appendChild(row);

    const box = document.createElement("div");
    box.className = "signature-composer-field";
    box.style.left = `${Math.max(0, Number(field.x || 0) * 100)}%`;
    box.style.top = `${Math.max(0, Number(field.y || 0) * 100)}%`;
    box.style.width = `${Math.max(1, Number(field.width || 0) * 100)}%`;
    box.style.height = `${Math.max(1, Number(field.height || 0) * 100)}%`;
    box.textContent = field.field_type;
    canvas.appendChild(box);
  }

  if (!sigComposerState.fields.length) {
    wrap.innerHTML = '<div class="muted">No fields yet.</div>';
  }

  wrap.querySelectorAll("button[data-field-delete]").forEach((btn) => {
    btn.onclick = async () => {
      if (!sigComposerState.packet) return;
      try {
        await apiPost(`/v1/signature-packets/${encodeURIComponent(sigComposerState.packet.packet_id)}/fields`, {
          action: "delete",
          field_id: btn.getAttribute("data-field-delete"),
        });
        await sigLoadPacket(sigComposerState.packet.packet_id);
      } catch (e) {
        sigStatus(String(e.message || e));
      }
    };
  });
}

function renderSigPacketSummary() {
  const packetStatus = document.getElementById("sigPacketStatus");
  const packetRole = document.getElementById("sigPacketRole");
  const packet = sigComposerState.packet;
  if (!packetStatus || !packetRole) return;
  if (!packet) {
    packetStatus.textContent = "No packet";
    packetRole.textContent = "";
    return;
  }
  packetStatus.textContent = packet.status || "unknown";
  packetRole.textContent = `role: ${packet.role || "sender"}`;
}

async function sigLoadPacket(packetId) {
  const trimmed = String(packetId || "").trim();
  if (!trimmed) throw new Error("Packet ID is required");
  const packet = await apiGet(`/v1/signature-packets/${encodeURIComponent(trimmed)}`);
  sigComposerState.packet = packet;
  sigComposerState.fields = Array.isArray(packet.fields) ? packet.fields : [];
  sigComposerState.signers = Array.isArray(packet.signers) ? packet.signers : [];
  setInputValue("sigPacketId", trimmed);
  renderSigPacketSummary();
  renderSigSigners();
  renderSigFields();
}

async function sigCreateDraft() {
  const sourcePath = readInput("sigSourcePath");
  const originChannel = document.getElementById("sigOriginChannel")?.value || "share";
  if (!sourcePath) throw new Error("Source PDF path is required");
  const created = await apiPost("/v1/signature-packets", {
    source_path: sourcePath,
    origin_channel: originChannel,
  });
  await sigLoadPacket(created.packet_id);
  sigStatus(`Draft created: ${created.packet_id}`);
}

async function sigSendPacket() {
  const packetId = readInput("sigPacketId");
  if (!packetId) throw new Error("Packet ID is required");
  await apiPost(`/v1/signature-packets/${encodeURIComponent(packetId)}/send`, {});
  await sigLoadPacket(packetId);
  sigStatus("Packet sent.");
}

async function sigPlaceFieldFromEvent(ev) {
  const packet = sigComposerState.packet;
  if (!packet || packet.status !== "draft") {
    sigStatus("Load a draft packet to place fields.");
    return;
  }
  const canvas = document.getElementById("sigCanvas");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const relX = Math.min(0.98, Math.max(0, (ev.clientX - rect.left) / Math.max(1, rect.width)));
  const relY = Math.min(0.98, Math.max(0, (ev.clientY - rect.top) / Math.max(1, rect.height)));
  const fieldType = document.getElementById("sigFieldType")?.value || "signature";
  const assignedSignerId = document.getElementById("sigAssignedSignerId")?.value || null;
  const required = Boolean(document.getElementById("sigFieldRequired")?.checked);
  const dims = sigFieldDimensions(fieldType);
  try {
    await apiPost(`/v1/signature-packets/${encodeURIComponent(packet.packet_id)}/fields`, {
      action: "create",
      page: 1,
      x: relX,
      y: relY,
      width: dims.width,
      height: dims.height,
      field_type: fieldType,
      assigned_signer_id: assignedSignerId,
      required,
    });
    await sigLoadPacket(packet.packet_id);
    sigStatus("Field added.");
  } catch (e) {
    sigStatus(String(e.message || e));
  }
}

function initSignatureComposerUi() {
  if (!document.getElementById("signaturePacketSection")) return;
  document.getElementById("sigCreateDraftBtn").onclick = async () => {
    try {
      await sigCreateDraft();
    } catch (e) {
      sigStatus(String(e.message || e));
    }
  };
  document.getElementById("sigLoadPacketBtn").onclick = async () => {
    try {
      await sigLoadPacket(readInput("sigPacketId"));
      sigStatus("Packet loaded.");
    } catch (e) {
      sigStatus(String(e.message || e));
    }
  };
  document.getElementById("sigSendPacketBtn").onclick = async () => {
    try {
      await sigSendPacket();
    } catch (e) {
      sigStatus(String(e.message || e));
    }
  };
  document.getElementById("sigCanvas").onclick = (ev) => {
    sigPlaceFieldFromEvent(ev);
  };
  renderSigPacketSummary();
  renderSigSigners();
  renderSigFields();
}
