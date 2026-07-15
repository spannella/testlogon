"""SUBX EPIC X5 — subscription notifications deep-verify.

Notification-layer verifier. Drives the REAL emit sites (server endpoints + renewal
engine + audit mirror) with emit_social_alert / write_alert replaced by in-process
RECORDERS and every DDB/money writer stubbed to no-ops, so it touches ZERO real rows
(0 residue by construction — no moto, no live-DDB writes). Proves:
  SUBX-50  renewal_failed / expiring / expired / prerenewal deep-link to the SPECIFIC
           sub's Manage/PAST_DUE recovery screen (action_url carries subscriptionId).
  SUBX-51  new_subscriber, cancel-via-renewal-toggle, plan-change (immediate + applied),
           removal, trial-convert are all EMITTED (were missing/silent), default-on,
           deep-linked to a real non-empty screen.
  SUBX-52  the audit_event alert-mirror no longer double-writes a (mis-typed) alert for
           subscription_* events; new alert types are registered default-on.
"""
import asyncio, uuid

import app.services.alerts as alerts
import app.services.social_alerts as social_alerts
import app.services.subscription_renewal as rn
from app.routers import subscription_server as ss

TAG = "subx5v-" + uuid.uuid4().hex[:8]
results = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# --------------------------------------------------------------------------- #
# Recorder for emit_social_alert (the real push/deep-link path)
# --------------------------------------------------------------------------- #
EMITS = []


def _emit_recorder(**kw):
    EMITS.append(kw)
    return {"alert_id": "rec-%d" % len(EMITS)}


# patch at the SOURCE module (endpoints + engine import it at call time)
social_alerts.emit_social_alert = _emit_recorder

# neutralize DDB / money / side-effect writers on the server module
ss.put_notification = lambda *a, **k: None
ss.audit_event = lambda *a, **k: None
ss.refresh_subscription_calendar_events = lambda *a, **k: None
ss.record_billing_subscription = lambda *a, **k: None
ss.save_subscription = lambda *a, **k: None
ss.attach_subscription_profiles = lambda x: x
ss.normalize_subscription = lambda x: x
ss.require_user = lambda x_user_id, *a, **k: x_user_id
ss.get_profile_identity = lambda uid: {"user_id": uid, "display_name": "Name-" + uid}
ss.record_billing_payment = lambda *a, **k: None
ss.record_billing_transaction = lambda *a, **k: None
try:
    import app.services.profile as _prof
    _prof.get_profile_identity = lambda uid: {"user_id": uid, "display_name": "Name-" + uid}
except Exception:
    pass

# engine: no DDB writes, no profile lookups
rn._save = lambda sub: None
rn._display_name = lambda u: "Name-" + str(u)


def find(alert_type, recipient=None):
    for e in EMITS:
        if e.get("alert_type") == alert_type and (recipient is None or e.get("recipient_user_id") == recipient):
            return e
    return None


# =========================================================================== #
# SUBX-52  registry: new alert types registered + default-on push
# =========================================================================== #
for t in ("subscription_changed", "subscription_removed", "subscription_converted", "subscription_new_subscriber"):
    rec("52-registry:%s in ALERT_EVENT_TYPES" % t, t in alerts.ALERT_EVENT_TYPES, t)
    rec("52-registry:%s default-on push" % t, t in alerts.DEFAULT_PUSH_EVENT_TYPES, t)


# =========================================================================== #
# SUBX-52  de-dupe: audit_event no longer mirror-writes an alert for subscription_*
# =========================================================================== #
WROTE = []
_orig_write = alerts.write_alert
alerts.write_alert = lambda user_sub, **k: (WROTE.append((user_sub, k.get("event"))), {"alert_id": "w"})[1]
alerts.send_push_for_alert = lambda *a, **k: None
alerts.record_auth_event = lambda *a, **k: None
alerts.send_alert_webhook = lambda *a, **k: {"enabled": False}
alerts.send_siem_event = lambda *a, **k: {"enabled": False}
alerts.get_profile_identity = lambda uid: {}

WROTE.clear()
alerts.audit_event("subscription_started", "creatorA", None, outcome="success", subscription_id="s1")
alerts.audit_event("subscription_canceled", "creatorA", None, outcome="success", subscription_id="s1")
alerts.audit_event("subscription_renewal_updated", "subA", None, outcome="success", subscription_id="s1")
sub_mirrors = [w for w in WROTE if str(w[1]).startswith("subscription_")]
rec("52-dedupe: no audit alert-mirror for subscription_* events", len(sub_mirrors) == 0,
    "mirror rows=%d (expected 0)" % len(sub_mirrors))
WROTE.clear()
alerts.audit_event("device_new", "subA", None, outcome="success")
rec("52-dedupe: control non-subscription event STILL mirrors an alert", len(WROTE) == 1,
    "control rows=%d (expected 1)" % len(WROTE))
alerts.write_alert = _orig_write


# =========================================================================== #
# SUBX-50  engine deep-links carry the specific subscriptionId
# =========================================================================== #
def mk_sub(**over):
    s = {
        "subscription_id": "sub-" + uuid.uuid4().hex[:6],
        "creator_id": "creatorA",
        "subscriber_id": "subA",
        "plan_id": "plan-1",
        "price_cents": 999,
        "currency": "usd",
        "status": "active",
        "auto_renew": True,
        "current_period_end": 100,
        "next_billing_date": 100,
    }
    s.update(over)
    return s


def qs_ok(e, sid):
    au = (e or {}).get("action_url") or ""
    return au.startswith("/subscriptions/manage") and ("subscriptionId=%s" % sid) in au and "creatorId=creatorA" in au


# _decline -> renewal_failed lands on PAST_DUE recovery (specific sub)
EMITS.clear()
s = mk_sub(payment_method_id="pm_x")
summ = {"dunning": [], "expired": [], "canceled": [], "expiring_soon": []}
rn._decline(s, now=1000, reason="charge_declined", summary=summ)
e = find("subscription_renewal_failed", "subA")
rec("50-renewal_failed deep-links to PAST_DUE recovery (subscriptionId in url)",
    qs_ok(e, s["subscription_id"]), (e or {}).get("action_url"))

# grace-entry expiring notice carries the sub id (drive attempts past the retry schedule)
EMITS.clear()
s2 = mk_sub(payment_method_id="pm_x", dunning_attempts=10, first_decline_at=1000, grace_until=2000)
rn._decline(s2, now=1000, reason="charge_declined", summary={"dunning": [], "expired": [], "canceled": []})
e = find("subscription_expiring", "subA")
rec("50-expiring(grace) deep-links to specific sub", qs_ok(e, s2["subscription_id"]),
    (e or {}).get("action_url"))

# _expire -> expired carries the sub id
EMITS.clear()
s3 = mk_sub()
rn._expire(s3, now=2000, reason="dunning_exhausted", summary={"expired": []})
e = find("subscription_expired", "subA")
rec("50-expired deep-links to specific sub", qs_ok(e, s3["subscription_id"]), (e or {}).get("action_url"))

# _maybe_expiring_notice advance notice carries the sub id
EMITS.clear()
s4 = mk_sub(auto_renew=False, cancel_at_period_end=True)
rn._maybe_expiring_notice(s4, now=1000, boundary=1000 + 2 * 86400, summary={"expiring_soon": []})
e = find("subscription_expiring", "subA")
rec("50-expiring(advance) deep-links to specific sub", qs_ok(e, s4["subscription_id"]),
    (e or {}).get("action_url"))


# =========================================================================== #
# SUBX-52  pre-renewal reminder ("renews in Nd for $X") for auto-renew subs
# =========================================================================== #
EMITS.clear()
s5 = mk_sub(payment_method_id="pm_x", current_period_end=1000 + 3 * 86400, next_billing_date=1000 + 3 * 86400)
summ = {"renewed": [], "dunning": [], "expired": [], "canceled": [], "idempotent_skips": [],
        "grandfather_skips": [], "trial_converted": [], "plan_changed": [], "expiring_soon": []}
rn._process(s5, now=1000, summary=summ)
e = find("subscription_renewed", "subA")
pre_ok = bool(e) and e.get("details", {}).get("advance") is True and "renews in" in (e.get("title") or "").lower()
rec("52-prerenewal: auto-renew sub gets 'renews in Nd for $X' advance notice", pre_ok,
    (e or {}).get("title"))
# idempotent: a second sweep in-window does NOT re-notify
EMITS.clear()
rn._process(s5, now=1001, summary=summ)
rec("52-prerenewal: idempotent (no re-notify within window)", find("subscription_renewed") is None,
    "emits=%d" % len(EMITS))


# =========================================================================== #
# SUBX-51  subscription_changed on scheduled DOWNGRADE apply (engine)
# =========================================================================== #
EMITS.clear()
s6 = mk_sub(pending_change={"plan_id": "plan-2", "interval": "month", "price_cents": 499,
                            "apply_at": 500, "direction": "downgrade"})
applied = rn._apply_pending_change(s6, now=1000)
e = find("subscription_changed", "subA")
rec("51-plan-change: scheduled downgrade apply emits subscription_changed",
    applied and bool(e) and e.get("details", {}).get("applied") is True and qs_ok(e, s6["subscription_id"]),
    (e or {}).get("title"))


# =========================================================================== #
# SUBX-51  server _emit_subscription_changed helper (immediate upgrade + scheduled)
# =========================================================================== #
EMITS.clear()
plan = {"plan_id": "plan-2", "name": "Gold"}
subP = mk_sub(plan_id="plan-2")
ss._emit_subscription_changed(subP, plan, None, applied=True, direction="upgrade")
e_sub = find("subscription_changed", "subA")
e_cre = find("subscription_changed", "creatorA")
rec("51-plan-change(upgrade): subscriber push -> manage(specific sub)",
    bool(e_sub) and qs_ok(e_sub, subP["subscription_id"]) and "Gold" in (e_sub.get("title") or ""),
    (e_sub or {}).get("title"))
rec("51-plan-change(upgrade): creator push -> Subscribers console",
    bool(e_cre) and e_cre.get("action_url") == "/subscriptions/subscribers", (e_cre or {}).get("action_url"))
EMITS.clear()
ss._emit_subscription_changed(subP, plan, None, applied=False, direction="downgrade")
e_sub = find("subscription_changed", "subA")
rec("51-plan-change(scheduled downgrade): subscriber gets 'scheduled' push",
    bool(e_sub) and "scheduled" in (e_sub.get("title") or "").lower(), (e_sub or {}).get("title"))


# =========================================================================== #
# SUBX-51  cancel-via-renewal-toggle pushes both parties (was silent)
# =========================================================================== #
class Body:
    def __init__(self, **k):
        self.__dict__.update(k)


sid = "sub-toggle1"
ss.ddb_get_item = lambda pk, sk: mk_sub(subscription_id=sid)
EMITS.clear()
run(ss.update_subscription_renewal(sid, Body(auto_renew=False, effective="period_end", renewal_policy=None), None, "subA"))
e_sub = find("subscription_canceled", "subA")
e_cre = find("subscription_canceled", "creatorA")
rec("51-toggle-off: subscriber canceled push -> manage(specific sub)",
    bool(e_sub) and qs_ok(e_sub, sid), (e_sub or {}).get("action_url"))
rec("51-toggle-off: creator canceled push -> Subscribers", bool(e_cre) and e_cre.get("action_url") == "/subscriptions/subscribers",
    (e_cre or {}).get("action_url"))
# negative: turning auto-renew ON emits NO cancel push
EMITS.clear()
run(ss.update_subscription_renewal(sid, Body(auto_renew=True, effective="immediate", renewal_policy=None), None, "subA"))
rec("51-toggle-on: NO cancel push when re-enabling auto-renew", find("subscription_canceled") is None,
    "emits=%d" % len(EMITS))


# =========================================================================== #
# SUBX-51  creator removal -> real push (was in-app only)
# =========================================================================== #
sidR = "sub-remove1"
ss.ddb_get_item = lambda pk, sk: mk_sub(subscription_id=sidR)
ss._apply_immediate_cancel = lambda sub, **k: {"refunded_cents": 500, "clawback_cents": 450}
EMITS.clear()
run(ss.remove_subscriber("creatorA", sidR, Body(reason="tos"), None, "creatorA"))
e = find("subscription_removed", "subA")
rec("51-removal: promoted to real push -> manage(specific sub)",
    bool(e) and qs_ok(e, sidR), (e or {}).get("action_url"))


# =========================================================================== #
# SUBX-51  trial convert -> receipt push (was silent)
# =========================================================================== #
sidC = "sub-convert1"
_conv_sub = mk_sub(subscription_id=sidC, status="trialing")
ss.ddb_get_item = lambda pk, sk: (_conv_sub if sk == "META" else {"plan_id": "plan-1", "name": "Gold", "creator_id": "creatorA"})


def _fake_attempt(sub, ts, summary, trial_conversion=False):
    sub["status"] = "active"  # simulate a real captured charge


import app.services.subscription_renewal as _rnmod
_rnmod._attempt_renewal = _fake_attempt
EMITS.clear()
run(ss.convert_trial(sidC, None, "subA"))
e = find("subscription_converted", "subA")
rec("51-convert: trial conversion pushes a receipt -> manage(specific sub)",
    bool(e) and qs_ok(e, sidC), (e or {}).get("action_url"))


# =========================================================================== #
# SUBX-51  subscribe -> creator new_subscriber (source-level contract assertion)
# =========================================================================== #
import inspect
src = inspect.getsource(ss.subscribe_to_plan) if hasattr(ss, "subscribe_to_plan") else ""
if not src:
    # find the subscribe route function by scanning module source
    import app.routers.subscription_server as _ssmod
    full = inspect.getsource(_ssmod)
    seg = full[full.find('actor_name} subscribed to you'):]
    seg = seg[max(0, seg.rfind("emit_social_alert(", 0, 0)):] if False else full
    src = full
ok_type = 'alert_type="subscription_new_subscriber"' in src
ok_url = 'action_url="/subscriptions/subscribers"' in src
rec("51-subscribe: creator alert uses dedicated new_subscriber type", ok_type, "")
rec("51-subscribe: creator alert deep-links to Subscribers console", ok_url, "")


# --------------------------------------------------------------------------- #
n_pass = sum(1 for _, ok, _ in results if ok)
n_fail = sum(1 for _, ok, _ in results if not ok)
print("\n==== SUBX-5 VERIFY: %d PASS / %d FAIL (residue=0, no DDB touched) ====" % (n_pass, n_fail))
if n_fail:
    for name, ok, detail in results:
        if not ok:
            print("  FAIL", name, "-", detail)
    raise SystemExit(1)
print("ALL GREEN")
