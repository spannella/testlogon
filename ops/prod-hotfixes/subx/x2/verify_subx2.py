import os, sys, time, uuid, asyncio, json
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.routers import subscription_server as ss
from app.services import subscription_renewal as sr
from app.services import subscription_access as sa
from app.services.billing_shared import user_pk

TAG = "subx2v-" + uuid.uuid4().hex[:8]
now = int(time.time())
DAY = 86400
FEE_BPS = ss.FEE_BPS


def net(g):
    return g - int(g * FEE_BPS / 10000)


# isolate unrelated side effects (same approach as verify_subx1) so the verifier is
# self-contained and never pollutes commerce/alert/milestone/ad tables.
ss.audit_event = lambda *a, **k: None
ss.refresh_subscription_calendar_events = lambda *a, **k: None
ss.put_notification = lambda *a, **k: None
try:
    ss.get_profile_identity = lambda uid: {"user_id": uid, "display_name": uid}
except Exception:
    pass
_oc = {"n": 0}


def _emit_stub(**k):
    _oc["n"] += 1
    return {"order_id": "ord-%d" % _oc["n"], "reconciliation": {"status": "processed"}}


ss.emit_subscription_cycle_order_and_reconcile = _emit_stub
for modname, attr in (("app.services.social_alerts", "emit_social_alert"),
                      ("app.services.milestones", "check_milestone"),
                      ("app.services.ad_attribution", "attribute_conversion")):
    try:
        m = __import__(modname, fromlist=[attr]); setattr(m, attr, lambda *a, **k: None)
    except Exception:
        pass

results = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, "-", detail)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def seed_pm(u, pm="pm_x"):
    T.billing.put_item(Item={"pk": user_pk(u), "sk": "PM#" + pm, "payment_method_id": pm, "brand": "visa", "last4": "4242", "user_sub": u, "tag": TAG})
    T.billing.put_item(Item={"pk": user_pk(u), "sk": "BILLING", "default_payment_method_id": pm, "user_sub": u, "tag": TAG})


def add_pm_only(u, pm):
    # add an OWNED PM without making it the default (for the swap path).
    T.billing.put_item(Item={"pk": user_pk(u), "sk": "PM#" + pm, "payment_method_id": pm, "brand": "visa", "last4": "1111", "user_sub": u, "tag": TAG})


def clear_default_pm(u):
    b = ss.ddb_get_item(user_pk(u), "BILLING") if False else T.billing.get_item(Key={"pk": user_pk(u), "sk": "BILLING"}).get("Item")
    if b:
        b.pop("default_payment_method_id", None)
        T.billing.put_item(Item=b)


def mk_plan(cre, price=1000, interval="month"):
    pid = TAG + "-plan-" + uuid.uuid4().hex[:6]
    ss.ddb_put_item({"pk": ss.pk_plan(pid), "sk": "META", "entity": "plan", "plan_id": pid, "creator_id": cre,
                     "price_cents": price, "currency": "usd", "interval": interval, "status": "active", "name": "Gold", "tag": TAG})
    return pid


def meta(sid):
    return ss.normalize_subscription(ss.ddb_get_item(ss.pk_subscription(sid), "META") or {})


def bal(uid):
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(user_pk(uid)) & Key("sk").begins_with("LEDGER#"))
    tot = 0
    for it in r.get("Items", []):
        if (it.get("type") or "") == "credit" and (it.get("state") or "settled") != "reversed":
            tot += int(it.get("amount_cents") or 0)
    return tot


def refunded_total(payer):
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(user_pk(payer)) & Key("sk").begins_with("LEDGER#"))
    return sum(int(it.get("amount_cents") or 0) for it in r.get("Items", []) if (it.get("type") or "") == "refund")


def status_of(exc):
    return getattr(exc, "status_code", None)


def force_past_due(sid, price_ago_days=2):
    m = meta(sid)
    m["status"] = "past_due"
    m["current_period_end"] = now - price_ago_days * DAY
    m["current_period_start"] = now - (price_ago_days + 30) * DAY
    m["dunning_state"] = "retrying"
    m["dunning_attempts"] = 1
    m["first_decline_at"] = now - price_ago_days * DAY
    m["grace_until"] = now + 5 * DAY
    ss.save_subscription(m)
    return m


FAILED_EARLY = False
try:
    Retry = ss.SubscriptionRetryPaymentIn

    # ===== SUBX-22 A: retry recovers a PAST_DUE sub (real charge -> active + creator NET credit) =====
    cre = TAG + "-creA"; pid = mk_plan(cre, price=1000)
    su = TAG + "-subA"; seed_pm(su)
    sid = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-A"), None, x_user_id=su))["subscription_id"]
    force_past_due(sid)
    b0 = bal(cre)
    out = run(ss.retry_subscription_payment(sid, Retry(), None, x_user_id=su))
    m = meta(sid)
    b1 = bal(cre)
    rec("SUBX22-A retry: past_due -> active", (m.get("status") == "active"),
        "status=%s" % m.get("status"))
    rec("SUBX22-A retry: period advanced (future cpe)", int(m.get("current_period_end") or 0) > now,
        "cpe=%d now=%d" % (int(m.get("current_period_end") or 0), now))
    rec("SUBX22-A retry: creator credited NET(1000)=%d once" % net(1000), (b1 - b0) == net(1000),
        "delta=%d" % (b1 - b0))
    rec("SUBX22-A retry: dunning cleared", not m.get("dunning_state") and not m.get("first_decline_at"),
        "dunning_state=%s" % m.get("dunning_state"))
    rec("SUBX22-A retry: access restored (has_active_subscription)", bool(sa.has_active_subscription(su, cre)), "")

    # ===== SUBX-22 B: no PM on file -> 402, stays past_due, NO creator credit =====
    creB = TAG + "-creB"; pidB = mk_plan(creB, price=1000)
    suB = TAG + "-subB"; seed_pm(suB)
    sidB = run(ss.subscribe(pidB, ss.SubscribeIn(client_request_id=TAG + "-B"), None, x_user_id=suB))["subscription_id"]
    force_past_due(sidB)
    # strip the PM so the retry cannot charge
    mB = meta(sidB); mB["payment_method_id"] = ""; ss.save_subscription(mB)
    clear_default_pm(suB)
    b0B = bal(creB)
    code = None
    try:
        run(ss.retry_subscription_payment(sidB, Retry(), None, x_user_id=suB))
    except Exception as e:
        code = status_of(e)
    mB = meta(sidB); b1B = bal(creB)
    rec("SUBX22-B no-PM retry -> 402", code == 402, "code=%s" % code)
    rec("SUBX22-B stays past_due, NO credit", mB.get("status") == "past_due" and (b1B - b0B) == 0,
        "status=%s credit_delta=%d" % (mB.get("status"), b1B - b0B))

    # ===== SUBX-22 C: PM SWAP recovers (update card -> retry) =====
    # reuse suB (still past_due, no default PM). Add an owned card, pass it explicitly.
    newpm = "pm_swap_" + uuid.uuid4().hex[:6]
    add_pm_only(suB, newpm)
    b0C = bal(creB)
    run(ss.retry_subscription_payment(sidB, Retry(payment_method_id=newpm), None, x_user_id=suB))
    mC = meta(sidB); b1C = bal(creB)
    rec("SUBX22-C PM-swap retry -> active", mC.get("status") == "active", "status=%s" % mC.get("status"))
    rec("SUBX22-C PM-swap credits NET(1000)", (b1C - b0C) == net(1000), "delta=%d" % (b1C - b0C))
    rec("SUBX22-C sub now uses swapped PM", mC.get("payment_method_id") == newpm, "pm=%s" % mC.get("payment_method_id"))

    # ===== SUBX-22 D: unowned PM in body -> 402 (resolve rejects), stays past_due =====
    creD = TAG + "-creD"; pidD = mk_plan(creD, price=1000)
    suD = TAG + "-subD"; seed_pm(suD)
    sidD = run(ss.subscribe(pidD, ss.SubscribeIn(client_request_id=TAG + "-D"), None, x_user_id=suD))["subscription_id"]
    force_past_due(sidD)
    code = None
    try:
        run(ss.retry_subscription_payment(sidD, Retry(payment_method_id="pm_not_owned_xyz"), None, x_user_id=suD))
    except Exception as e:
        code = status_of(e)
    rec("SUBX22-D unowned-PM retry -> 402", code == 402, "code=%s" % code)
    rec("SUBX22-D stays past_due", meta(sidD).get("status") == "past_due", "status=%s" % meta(sidD).get("status"))

    # ===== SUBX-22 E: authz — a stranger cannot retry (403) =====
    code = None
    try:
        run(ss.retry_subscription_payment(sidD, Retry(), None, x_user_id=TAG + "-stranger"))
    except Exception as e:
        code = status_of(e)
    rec("SUBX22-E stranger retry -> 403", code == 403, "code=%s" % code)

    # ===== SUBX-22 F: state guards — active is idempotent 200 (no double charge); canceled -> 409 =====
    creF = TAG + "-creF"; pidF = mk_plan(creF, price=1000)
    suF = TAG + "-subF"; seed_pm(suF)
    sidF = run(ss.subscribe(pidF, ss.SubscribeIn(client_request_id=TAG + "-F"), None, x_user_id=suF))["subscription_id"]
    b0F = bal(creF)
    run(ss.retry_subscription_payment(sidF, Retry(), None, x_user_id=suF))  # active -> idempotent
    rec("SUBX22-F active retry idempotent (no extra credit)", (bal(creF) - b0F) == 0, "delta=%d" % (bal(creF) - b0F))
    # cancel immediately then retry -> 409
    run(ss.cancel_subscription(sidF, ss.SubscriptionCancelIn(cancel_at_period_end=False, refund=False), None, x_user_id=suF))
    code = None
    try:
        run(ss.retry_subscription_payment(sidF, Retry(), None, x_user_id=suF))
    except Exception as e:
        code = status_of(e)
    rec("SUBX22-F canceled retry -> 409", code == 409, "code=%s" % code)

    # ===== CORE still holds: subscribe charges+credits; immediate cancel refunds+revokes =====
    creG = TAG + "-creG"; pidG = mk_plan(creG, price=1000)
    suG = TAG + "-subG"; seed_pm(suG)
    b0G = bal(creG)
    sidG = run(ss.subscribe(pidG, ss.SubscribeIn(client_request_id=TAG + "-G"), None, x_user_id=suG))["subscription_id"]
    rec("CORE subscribe credits NET(1000)", (bal(creG) - b0G) == net(1000), "delta=%d" % (bal(creG) - b0G))
    rec("CORE subscribe grants access", bool(sa.has_active_subscription(suG, creG)), "")
    run(ss.cancel_subscription(sidG, ss.SubscriptionCancelIn(cancel_at_period_end=False, refund=True), None, x_user_id=suG))
    rec("CORE immediate cancel refunds", refunded_total(suG) > 0, "refunded=%d" % refunded_total(suG))
    rec("CORE immediate cancel revokes access", not sa.has_active_subscription(suG, creG), "")

except Exception:
    import traceback
    traceback.print_exc()
    FAILED_EARLY = True
finally:
    SCRUB = [
        (T.subscriptions, ["pk", "sk"]),
        (T.billing, ["pk", "sk"]),
        (getattr(T, "purchase_transactions", None), ["user_sub", "sk"]),
        (getattr(T, "purchase_events", None), ["pk", "sk"]),
    ]

    def scrub(tbl, keys):
        if tbl is None:
            return 0
        deleted = 0; lek = None
        while True:
            kw = {"ExclusiveStartKey": lek} if lek else {}
            try:
                r = tbl.scan(**kw)
            except Exception:
                break
            for it in r.get("Items", []):
                if TAG in json.dumps(it, default=str):
                    try:
                        tbl.delete_item(Key={k: it[k] for k in keys if k in it}); deleted += 1
                    except Exception:
                        pass
            lek = r.get("LastEvaluatedKey")
            if not lek:
                break
        return deleted

    total_del = sum(scrub(t, k) for t, k in SCRUB)
    print("CLEANUP: deleted=%d" % total_del)

    def residue(tbl):
        if tbl is None:
            return 0
        c = 0; lek = None
        while True:
            kw = {"ExclusiveStartKey": lek} if lek else {}
            try:
                r = tbl.scan(**kw)
            except Exception:
                break
            c += sum(1 for it in r.get("Items", []) if TAG in json.dumps(it, default=str))
            lek = r.get("LastEvaluatedKey")
            if not lek:
                break
        return c

    res = sum(residue(t) for t, _ in SCRUB)
    npass = sum(1 for _, ok, _ in results if ok)
    ntot = len(results)
    print("\n=== SUBX2 VERIFY: %d/%d PASS; residue=%d ===" % (npass, ntot, res))
    sys.exit(0 if (npass == ntot and res == 0 and not FAILED_EARLY) else 1)
