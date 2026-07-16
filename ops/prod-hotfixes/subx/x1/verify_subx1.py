import os, sys, time, uuid, asyncio, json
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.routers import subscription_server as ss
from app.services import subscription_renewal as sr
from app.services import subscription_access as sa
from app.services.billing_shared import user_pk
from app.services.creator_payouts import get_available_balance

TAG = "subx1v-" + uuid.uuid4().hex[:8]
now = int(time.time())
DAY = 86400
FEE_BPS = ss.FEE_BPS


def net(g):
    return g - int(g * FEE_BPS / 10000)


# isolate side effects UNTOUCHED by X1 so the verifier is self-contained and does
# not pollute unrelated prod tables (commerce orders / alerts / milestones / ad attr).
# X1 changes only proration/discount/dunning/refund MATH, none of which live here.
ss.audit_event = lambda *a, **k: None
ss.refresh_subscription_calendar_events = lambda *a, **k: None
ss.put_notification = lambda *a, **k: None
ss.get_profile_identity = lambda uid: {"user_id": uid, "display_name": uid}
_oc = {"n": 0}


def _emit_stub(**k):
    _oc["n"] += 1
    return {"order_id": "ord-%d" % _oc["n"], "reconciliation": {"status": "processed"}}


ss.emit_subscription_cycle_order_and_reconcile = _emit_stub
try:
    import app.services.social_alerts as _sa
    _sa.emit_social_alert = lambda *a, **k: None
except Exception:
    pass
try:
    import app.services.milestones as _ms
    _ms.check_milestone = lambda *a, **k: None
except Exception:
    pass
try:
    import app.services.ad_attribution as _aa
    _aa.attribute_conversion = lambda *a, **k: None
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


def mk_plan(cre, price=1000, annual=None, interval="month"):
    pid = TAG + "-plan-" + uuid.uuid4().hex[:6]
    item = {"pk": ss.pk_plan(pid), "sk": "META", "entity": "plan", "plan_id": pid, "creator_id": cre,
            "price_cents": price, "currency": "usd", "interval": interval, "status": "active", "name": "Gold", "tag": TAG}
    if annual:
        item["annual_price_cents"] = annual
    ss.ddb_put_item(item)
    return pid


def meta(sid):
    return ss.normalize_subscription(ss.ddb_get_item(ss.pk_subscription(sid), "META") or {})


def bal(uid):
    # billing-direct creator net: sum live (non-reversed) credits minus reversals.
    # Self-contained (reads only T.billing) so it works in dry-run and on prod.
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(user_pk(uid)) & Key("sk").begins_with("LEDGER#"))
    tot = 0
    for it in r.get("Items", []):
        t = (it.get("type") or "")
        a = int(it.get("amount_cents") or 0)
        if t == "credit" and (it.get("state") or "settled") != "reversed":
            tot += a
    return tot


def refunded_total(payer):
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(user_pk(payer)) & Key("sk").begins_with("LEDGER#"))
    return sum(int(it.get("amount_cents") or 0) for it in r.get("Items", []) if (it.get("type") or "") == "refund")


FAILED_EARLY = False
try:
    # ===== SUBX-10: cycle-accurate proration on a RENEWED sub =====
    cre = TAG + "-cre10"
    pid = mk_plan(cre, price=1000)
    su = TAG + "-sub10"; seed_pm(su)
    sid = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-r10"), None, x_user_id=su))["subscription_id"]
    m = meta(sid)
    m["start_at"] = now - 90 * DAY
    m["current_period_start"] = now - 15 * DAY
    m["current_period_end"] = now + 15 * DAY
    ss.save_subscription(m)
    run(ss.cancel_subscription(sid, ss.SubscriptionCancelIn(cancel_at_period_end=False, refund=True), None, x_user_id=su))
    rt = refunded_total(su)
    rec("SUBX10 cycle-denom refund ~half (450-550)", 450 <= rt <= 550, "refunded=%d (lifetime-denom would be ~130)" % rt)

    # ===== SUBX-10b: /refund endpoint stays cycle-accurate for a MID-CYCLE subscriber =====
    # (guards against a false regression: SUBX-10 correctly makes a START-of-cycle
    # default refund frac~1.0 = a full refund, which the SUBX-02 rule restricts to
    # creator/admin. A genuine mid-cycle subscriber self-refund must still work: 200,
    # partial clawback, access revoked.)
    cre = TAG + "-cre10b"
    pid = mk_plan(cre, price=1000)
    su = TAG + "-sub10b"; seed_pm(su)
    sid = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-r10b"), None, x_user_id=su))["subscription_id"]
    b_pre = bal(cre)
    m = meta(sid)
    m["current_period_start"] = now - 15 * DAY
    m["current_period_end"] = now + 15 * DAY
    ss.save_subscription(m)
    resp = run(ss.refund_subscription(sid, ss.SubscriptionRefundIn(), None, x_user_id=su))
    m = meta(sid)
    b_post = bal(cre)
    ok10b = (450 <= int(resp.get("refunded_cents") or 0) <= 550 and m.get("status") == "canceled"
             and sa.has_active_subscription(su, cre) is False and 350 <= (b_pre - b_post) <= 550)
    rec("SUBX10b mid-cycle subscriber /refund 200 partial+revoke", ok10b, "refunded=%s status=%s clawback=%d active=%s" % (resp.get("refunded_cents"), m.get("status"), b_pre - b_post, sa.has_active_subscription(su, cre)))

    # ===== SUBX-11: interval-aware up/downgrade =====
    cre = TAG + "-cre11"
    pid_m = mk_plan(cre, price=1000, annual=15000, interval="month")
    su = TAG + "-sub11a"; seed_pm(su)
    sid = run(ss.subscribe(pid_m, ss.SubscribeIn(client_request_id=TAG + "-r11a"), None, x_user_id=su))["subscription_id"]
    b0 = bal(cre)
    run(ss.change_subscription_plan(sid, ss.SubscriptionChangePlanIn(plan_id=pid_m, interval="year", effective="immediate"), None, x_user_id=su))
    m = meta(sid)
    cpe_ok = abs(int(m["current_period_end"]) - (now + 365 * DAY)) < 3 * DAY
    rec("SUBX11 month->year upgrade+interval reset", m.get("interval") == "year" and cpe_ok, "interval=%s cpe~now+%dd price=%s" % (m.get("interval"), (int(m["current_period_end"]) - now) // DAY, m.get("price_cents")))
    dcredit = bal(cre) - b0
    rec("SUBX11 sane delta credited ~net(14000)", abs(dcredit - net(14000)) < 400, "delta_credit=%d expect~%d" % (dcredit, net(14000)))
    su2 = TAG + "-sub11b"; seed_pm(su2)
    pid_y = mk_plan(cre, price=1000, annual=15000, interval="month")
    sid2 = run(ss.subscribe(pid_y, ss.SubscribeIn(interval="year", client_request_id=TAG + "-r11b"), None, x_user_id=su2))["subscription_id"]
    run(ss.change_subscription_plan(sid2, ss.SubscriptionChangePlanIn(plan_id=pid_y, interval="month", effective="immediate"), None, x_user_id=su2))
    m2 = meta(sid2)
    pc = m2.get("pending_change") or {}
    rec("SUBX11 year->month schedules downgrade", pc.get("interval") == "month" and pc.get("direction") == "downgrade" and m2.get("interval") == "year", "pending=%s/%s cur=%s" % (pc.get("interval"), pc.get("direction"), m2.get("interval")))

    # ===== SUBX-12: real remove-refund =====
    cre = TAG + "-cre12"
    pid = mk_plan(cre, price=1000)
    su = TAG + "-sub12"; seed_pm(su)
    sid = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-r12"), None, x_user_id=su))["subscription_id"]
    b_after_sub = bal(cre)
    run(ss.remove_subscriber(cre, sid, ss.CreatorSubscriberActionIn(reason="creator_removed"), None, x_user_id=cre))
    m = meta(sid)
    rt = refunded_total(su)
    b_after_rm = bal(cre)
    rec("SUBX12 creator remove refunds subscriber card", rt >= 900, "refunded=%d" % rt)
    rec("SUBX12 creator credit clawed back ~0", b_after_rm <= 50, "before=%d after=%d" % (b_after_sub, b_after_rm))
    rec("SUBX12 access revoked after remove", sa.has_active_subscription(su, cre) is False and m.get("status") == "canceled", "status=%s active=%s" % (m.get("status"), sa.has_active_subscription(su, cre)))

    # ===== SUBX-13: dunning cadence 1/3/5/7 anchored =====
    subd = {"subscription_id": TAG + "-d13", "subscriber_id": TAG + "-sd13", "creator_id": TAG + "-cd13",
            "plan_id": "p", "price_cents": 1000, "currency": "usd", "interval": "month",
            "current_period_end": now, "status": "past_due"}
    sr._save = lambda s: None
    summ = {"dunning": [], "expired": []}
    T0 = now
    sr._decline(subd, T0, "charge_declined", summ)
    r1 = int(subd["dunning_next_retry_at"]); fda = int(subd["first_decline_at"]); gu = int(subd["grace_until"])
    sr._decline(subd, T0 + 1 * DAY, "charge_declined", summ); r2 = int(subd["dunning_next_retry_at"])
    sr._decline(subd, T0 + 3 * DAY, "charge_declined", summ); r3 = int(subd["dunning_next_retry_at"])
    sr._decline(subd, T0 + 5 * DAY, "charge_declined", summ); r4 = int(subd["dunning_next_retry_at"])
    sr._decline(subd, T0 + 7 * DAY, "charge_declined", summ); st5 = subd["dunning_state"]; r5 = int(subd["dunning_next_retry_at"])
    days = [(r1 - T0) // DAY, (r2 - T0) // DAY, (r3 - T0) // DAY, (r4 - T0) // DAY]
    rec("SUBX13 retries land absolute d1/3/5/7", days == [1, 3, 5, 7], "retry_days=%s (was 1/4/9/16)" % days)
    rec("SUBX13 grace_until = anchor + 14d", gu == fda + 14 * DAY, "grace-anchor=%dd" % ((gu - fda) // DAY))
    rec("SUBX13 after 4th retry -> grace", st5 == "grace" and r5 == 0, "state=%s next=%d" % (st5, r5))

    # ===== SUBX-14: discount base-price correctness =====
    cre = TAG + "-cre14"
    pid = mk_plan(cre, price=1000)
    ss.ddb_put_item({"pk": ss.pk_creator(cre), "sk": ss._discount_sk("HALF"), "entity": "discount", "code": "HALF",
                     "percent_off": 50, "duration": "once", "active": True, "created_at": now, "updated_at": now, "tag": TAG})
    su = TAG + "-sub14"; seed_pm(su)
    o = run(ss.subscribe(pid, ss.SubscribeIn(discount_code="HALF", client_request_id=TAG + "-r14"), None, x_user_id=su))
    m = meta(o["subscription_id"])
    rec("SUBX14 sub stores LIST price 1000", int(m.get("price_cents")) == 1000, "price_cents=%s" % m.get("price_cents"))
    rec("SUBX14 once -> remaining=0", int(m.get("discount_remaining_months") or 0) == 0, "remaining=%s" % m.get("discount_remaining_months"))
    ramt = sr._renewal_amount(m)
    rec("SUBX14 renewal uses LIST (no double-discount)", ramt == 1000, "renewal_amount=%d (double would be 250/500)" % ramt)
    mrr = ss._sube4_monthly_equiv_cents(int(m.get("price_cents") or 0), m.get("interval"))
    rec("SUBX14 MRR uses LIST price", mrr == 1000, "mrr_contrib=%d" % mrr)
    invs = [it for it in T.subscriptions.query(KeyConditionExpression=Key("pk").eq(ss.pk_subscription(o["subscription_id"]))).get("Items", []) if it.get("sk", "").startswith("INV#")]
    ic = int(invs[0].get("amount_cents")) if invs else -1
    rec("SUBX14 initial charge discounted (500)", ic == 500, "invoice_amount=%d" % ic)
    ss.ddb_put_item({"pk": ss.pk_creator(cre), "sk": ss._discount_sk("REP3"), "entity": "discount", "code": "REP3",
                     "percent_off": 50, "duration": "repeating", "duration_months": 3, "active": True, "created_at": now, "updated_at": now, "tag": TAG})
    su2 = TAG + "-sub14b"; seed_pm(su2)
    o2 = run(ss.subscribe(pid, ss.SubscribeIn(discount_code="REP3", client_request_id=TAG + "-r14b"), None, x_user_id=su2))
    m2 = meta(o2["subscription_id"])
    ra2 = sr._renewal_amount(m2)
    rec("SUBX14 repeating N=3 -> remaining 2, renewal 500 on LIST", int(m2.get("discount_remaining_months") or 0) == 2 and ra2 == 500 and int(m2.get("price_cents")) == 1000, "remaining=%s renewal=%d list=%s" % (m2.get("discount_remaining_months"), ra2, m2.get("price_cents")))

    # ===== SUBX-15: guards + resume + cancel convergence =====
    cre = TAG + "-cre15"
    pid = mk_plan(cre, price=1000)
    su = TAG + "-sub15a"; seed_pm(su)
    a = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-r15a1"), None, x_user_id=su))["subscription_id"]
    bafter = bal(cre)
    b = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-r15a2"), None, x_user_id=su))["subscription_id"]
    bafter2 = bal(cre)
    rec("SUBX15 double-subscribe returns existing (no 2nd charge)", a == b and bafter2 == bafter, "same=%s bal %d->%d" % (a == b, bafter, bafter2))
    su2 = TAG + "-sub15b"; seed_pm(su2)
    s2 = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-r15b"), None, x_user_id=su2))["subscription_id"]
    run(ss.cancel_subscription(s2, ss.SubscriptionCancelIn(cancel_at_period_end=True), None, x_user_id=su2))
    run(ss.resume_subscription(s2, ss.SubscriptionResumeIn(), None, x_user_id=su2))
    m = meta(s2)
    rec("SUBX15 resume restores active + unlocked", m.get("status") == "active" and sa.has_active_subscription(su2, cre) is True, "status=%s active=%s" % (m.get("status"), sa.has_active_subscription(su2, cre)))
    su3 = TAG + "-sub15c"; seed_pm(su3)
    s3 = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-r15c"), None, x_user_id=su3))["subscription_id"]
    m = meta(s3); m["status"] = "canceled"; m["current_period_end"] = now - DAY; ss.save_subscription(m)
    lapsed_409 = False
    try:
        run(ss.resume_subscription(s3, ss.SubscriptionResumeIn(), None, x_user_id=su3))
    except ss.HTTPException as e:
        lapsed_409 = (e.status_code == 409)
    rec("SUBX15 resume LAPSED -> 409 (no active-but-locked)", lapsed_409, "409=%s" % lapsed_409)

    def fresh_sub(u):
        seed_pm(u)
        return run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-" + u[-6:]), None, x_user_id=u))["subscription_id"]
    ua = TAG + "-c15a"; sa1 = fresh_sub(ua); run(ss.cancel_subscription(sa1, ss.SubscriptionCancelIn(cancel_at_period_end=False, refund=True), None, x_user_id=ua)); ra = refunded_total(ua)
    ub = TAG + "-c15b"; sb1 = fresh_sub(ub); run(ss.update_subscription_renewal(sb1, ss.SubscriptionRenewalIn(auto_renew=False, effective="immediate"), None, x_user_id=ub)); rb = refunded_total(ub)
    uc = TAG + "-c15c"; sc1 = fresh_sub(uc); run(ss.remove_subscriber(cre, sc1, ss.CreatorSubscriberActionIn(reason="creator_removed"), None, x_user_id=cre)); rc = refunded_total(uc)
    rec("SUBX15 3 cancel paths refund identically ~1000", ra == rb == rc and ra >= 900, "cancel=%d renewal-off=%d remove=%d" % (ra, rb, rc))

except Exception:
    import traceback
    traceback.print_exc()
    FAILED_EARLY = True
finally:
    # (table, [key attribute names]) — scrub every TAG-tagged synthetic row.
    SCRUB = [
        (T.subscriptions, ["pk", "sk"]),
        (T.billing, ["pk", "sk"]),
        (getattr(T, "purchase_transactions", None), ["user_sub", "sk"]),
        (getattr(T, "purchase_events", None), ["pk", "sk"]),
    ]

    def scrub(tbl, keys):
        if tbl is None:
            return 0
        deleted = 0
        lek = None
        while True:
            kw = {}
            if lek:
                kw["ExclusiveStartKey"] = lek
            try:
                r = tbl.scan(**kw)
            except Exception:
                break
            for it in r.get("Items", []):
                if TAG in json.dumps(it, default=str):
                    try:
                        tbl.delete_item(Key={k: it[k] for k in keys if k in it})
                        deleted += 1
                    except Exception:
                        pass
            lek = r.get("LastEvaluatedKey")
            if not lek:
                break
        return deleted
    total_del = 0
    for tbl, keys in SCRUB:
        total_del += scrub(tbl, keys)
    print("CLEANUP: deleted=%d" % total_del)

    def residue(tbl):
        if tbl is None:
            return 0
        c = 0
        lek = None
        while True:
            kw = {}
            if lek:
                kw["ExclusiveStartKey"] = lek
            try:
                r = tbl.scan(**kw)
            except Exception:
                break
            c += sum(1 for it in r.get("Items", []) if TAG in json.dumps(it, default=str))
            lek = r.get("LastEvaluatedKey")
            if not lek:
                break
        return c
    res = sum(residue(tbl) for tbl, _ in SCRUB)
    npass = sum(1 for _, ok, _ in results if ok)
    ntot = len(results)
    print("\n=== SUBX1 VERIFY: %d/%d PASS; residue=%d ===" % (npass, ntot, res))
    sys.exit(0 if (npass == ntot and res == 0 and not FAILED_EARLY) else 1)
