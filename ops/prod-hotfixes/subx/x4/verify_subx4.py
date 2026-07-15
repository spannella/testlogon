"""SUBX EPIC X4 — reporting reconciliation + tier tooling deep-verify.

In-process against the REAL prod DDB tables (same pattern as verify_subx1/2/3):
every synthetic row is tagged, side-effects stubbed, and all rows scrubbed to 0
residue at the end. Proves:
  * SUBX-42: /earnings net == withdrawable balance after full + partial refund;
    analytics refunded/net fold T.billing reversals; MRR excludes gifts +
    cancel-at-period-end + past_due, and uses LIST (not discounted) price.
  * SUBX-43: past_due_mrr surfaced; cohort churn (active-at-window-start);
    by_tier[] reconciles to creator-wide aggregates; per-tier subscriber filter;
    display_order + reorder.
"""
import os, sys, time, uuid, asyncio, json
from app.core.tables import T
from app.routers import subscription_server as ss
from app.services.creator_payouts import get_available_balance
from app.services.billing_shared import user_pk

TAG = "subx4v-" + uuid.uuid4().hex[:8]
now = int(time.time())
DAY = 86400
FEE_BPS = ss.FEE_BPS


def net_of(g):
    return g - int(g * FEE_BPS / 10000)


# isolate unrelated side effects (mirror verify_subx1/2)
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


def mk_plan(cre, price=1000, interval="month", name="Gold", level=None, display_order=None):
    pid = TAG + "-plan-" + uuid.uuid4().hex[:6]
    item = {"pk": ss.pk_plan(pid), "sk": "META", "entity": "plan", "plan_id": pid, "creator_id": cre,
            "price_cents": price, "currency": "usd", "interval": interval, "status": "active", "name": name, "tag": TAG}
    if level is not None:
        item["level"] = level
    if display_order is not None:
        item["display_order"] = display_order
    ss.save_plan(item)
    return pid


def mk_sub(cre, pid, status="active", price=1000, interval="month", auto_renew=True,
           is_gift=False, cancel_at_period_end=False, start_at=None, list_price=None, updated_at=None):
    sid = TAG + "-sub-" + uuid.uuid4().hex[:6]
    su = TAG + "-fan-" + uuid.uuid4().hex[:6]
    st = start_at if start_at is not None else now
    sub = {
        "subscription_id": sid, "plan_id": pid, "creator_id": cre, "subscriber_id": su,
        "status": status, "price_cents": price, "currency": "usd", "interval": interval,
        "auto_renew": auto_renew, "cancel_at_period_end": cancel_at_period_end,
        "is_gift": is_gift, "start_at": st, "created_at": st,
        "current_period_end": now + 20 * DAY, "updated_at": updated_at if updated_at is not None else now,
        "provider": "stub", "provider_subscription_id": "psub_" + sid, "tag": TAG,
    }
    if list_price is not None:
        sub["list_price_cents"] = list_price
    ss.save_subscription(sub)
    return sid, su


# ======================================================================
# SUBX-42 A — /earnings net == withdrawable balance (full refund)
# ======================================================================
def t_earnings_full_refund():
    cre = TAG + "-creA"
    pid = mk_plan(cre, price=1000)
    su = TAG + "-subA"; seed_pm(su)
    sid = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-A"), None, x_user_id=su))["subscription_id"]

    e0 = run(ss.list_earnings(cre, None, None, x_user_id=cre))
    b0 = get_available_balance(cre)["total_earned_cents"]
    rec("42A1 earnings.net == balance pre-refund",
        e0["net_cents"] == b0 == net_of(1000),
        "net=%d bal=%d exp=%d" % (e0["net_cents"], b0, net_of(1000)))

    run(ss.refund_subscription(sid, ss.SubscriptionRefundIn(fraction=1.0, reason="test"), None, x_user_id=cre))
    e1 = run(ss.list_earnings(cre, None, None, x_user_id=cre))
    b1 = get_available_balance(cre)["total_earned_cents"]
    rec("42A2 earnings.net == balance post full-refund (both 0)",
        e1["net_cents"] == b1 == 0 and e1["refunded_cents"] == net_of(1000),
        "net=%d bal=%d refunded=%d" % (e1["net_cents"], b1, e1["refunded_cents"]))


# ======================================================================
# SUBX-42 B — partial refund reconciliation
# ======================================================================
def t_earnings_partial_refund():
    cre = TAG + "-creB"
    pid = mk_plan(cre, price=1000)
    su = TAG + "-subB"; seed_pm(su)
    sid = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-B"), None, x_user_id=su))["subscription_id"]
    run(ss.refund_subscription(sid, ss.SubscriptionRefundIn(fraction=0.5, reason="test"), None, x_user_id=cre))
    e = run(ss.list_earnings(cre, None, None, x_user_id=cre))
    b = get_available_balance(cre)["total_earned_cents"]
    clawback = int(round(net_of(1000) * 0.5))
    rec("42B earnings.net == balance post partial-refund",
        e["net_cents"] == b and e["refunded_cents"] == clawback,
        "net=%d bal=%d refunded=%d clawback_exp=%d" % (e["net_cents"], b, e["refunded_cents"], clawback))


# ======================================================================
# SUBX-42 C — analytics refunded/net fold T.billing reversals
# ======================================================================
def t_analytics_refund_reconcile():
    cre = TAG + "-creC"
    pid = mk_plan(cre, price=2000)
    su = TAG + "-subC"; seed_pm(su)
    sid = run(ss.subscribe(pid, ss.SubscribeIn(client_request_id=TAG + "-C"), None, x_user_id=su))["subscription_id"]
    run(ss.refund_subscription(sid, ss.SubscriptionRefundIn(fraction=1.0, reason="test"), None, x_user_id=cre))
    a = run(ss.get_creator_subscription_analytics(cre, 30, x_user_id=cre))
    b = get_available_balance(cre)["total_earned_cents"]
    rec("42C analytics.net_to_date == balance post-refund",
        a.net_revenue_to_date_cents == b == 0 and a.refunded_to_date_cents == net_of(2000),
        "net=%d bal=%d refunded=%d" % (a.net_revenue_to_date_cents, b, a.refunded_to_date_cents))


# ======================================================================
# SUBX-42 D — MRR excludes gift + cancel-at-period-end; list price
# ======================================================================
def t_mrr_exclusions():
    cre = TAG + "-creD"
    pid = mk_plan(cre, price=1000)
    mk_sub(cre, pid, status="active", auto_renew=True)                         # counts
    mk_sub(cre, pid, status="active", auto_renew=False, is_gift=True)          # gift -> excluded
    mk_sub(cre, pid, status="active", auto_renew=False, cancel_at_period_end=True)  # canceling -> excluded
    a = run(ss.get_creator_subscription_analytics(cre, 30, x_user_id=cre))
    rec("42D MRR excludes gift + cancel-at-period-end",
        a.mrr_cents == 1000 and a.active_subscribers == 3,
        "mrr=%d active=%d (exp mrr 1000, active 3)" % (a.mrr_cents, a.active_subscribers))


def t_mrr_list_price():
    cre = TAG + "-creE"
    pid = mk_plan(cre, price=1000)
    # a discounted sub: charged price 500 stored, but list is 1000 -> MRR must read list.
    mk_sub(cre, pid, status="active", price=500, list_price=1000)
    a = run(ss.get_creator_subscription_analytics(cre, 30, x_user_id=cre))
    rec("42E MRR off LIST price not discounted",
        a.mrr_cents == 1000, "mrr=%d exp=1000" % a.mrr_cents)


# ======================================================================
# SUBX-43 A — past_due surfaced distinctly, excluded from MRR
# ======================================================================
def t_past_due_mrr():
    cre = TAG + "-creF"
    pid = mk_plan(cre, price=1500)
    mk_sub(cre, pid, status="active", auto_renew=True, price=1500)
    mk_sub(cre, pid, status="past_due", price=1500)
    a = run(ss.get_creator_subscription_analytics(cre, 30, x_user_id=cre))
    rec("43A past_due_mrr distinct; MRR excludes past_due",
        a.mrr_cents == 1500 and a.past_due_mrr_cents == 1500 and a.past_due == 1,
        "mrr=%d past_due_mrr=%d past_due=%d" % (a.mrr_cents, a.past_due_mrr_cents, a.past_due))


# ======================================================================
# SUBX-43 B — cohort churn (active-at-window-start denominator)
# ======================================================================
def t_cohort_churn():
    cre = TAG + "-creG"
    pid = mk_plan(cre, price=1000)
    # 4 subs started BEFORE the 30d window (start 60d ago). 1 churned inside window.
    old = now - 60 * DAY
    for _ in range(3):
        mk_sub(cre, pid, status="active", start_at=old)
    mk_sub(cre, pid, status="canceled", start_at=old, updated_at=now - 5 * DAY)  # churned in window
    # 1 that churned BEFORE the window -> not in cohort denom, not counted churned.
    mk_sub(cre, pid, status="canceled", start_at=old, updated_at=now - 45 * DAY)
    a = run(ss.get_creator_subscription_analytics(cre, 30, x_user_id=cre))
    # active_at_window_start = 3 active + 1 churned-in-window = 4; churned=1; rate=0.25
    rec("43B cohort churn denom = active-at-window-start",
        a.active_at_window_start == 4 and a.churned_30d == 1 and abs(a.churn_rate - 0.25) < 1e-6,
        "denom=%d churned=%d rate=%s" % (a.active_at_window_start, a.churned_30d, a.churn_rate))


# ======================================================================
# SUBX-43 C — by_tier[] reconciles to creator-wide aggregates
# ======================================================================
def t_by_tier():
    cre = TAG + "-creH"
    gold = mk_plan(cre, price=1000, name="Gold", level=1, display_order=0)
    plat = mk_plan(cre, price=2000, name="Platinum", level=2, display_order=1)
    su1 = TAG + "-subH1"; seed_pm(su1)
    su2 = TAG + "-subH2"; seed_pm(su2)
    su3 = TAG + "-subH3"; seed_pm(su3)
    run(ss.subscribe(gold, ss.SubscribeIn(client_request_id=TAG + "-H1"), None, x_user_id=su1))
    run(ss.subscribe(plat, ss.SubscribeIn(client_request_id=TAG + "-H2"), None, x_user_id=su2))
    run(ss.subscribe(plat, ss.SubscribeIn(client_request_id=TAG + "-H3"), None, x_user_id=su3))
    a = run(ss.get_creator_subscription_analytics(cre, 30, x_user_id=cre))
    by = {t.plan_id: t for t in a.by_tier}
    tier_mrr = sum(t.mrr_cents for t in a.by_tier)
    tier_gross = sum(t.gross_revenue_to_date_cents for t in a.by_tier)
    tier_active = sum(t.active_subscribers for t in a.by_tier)
    ok = (
        gold in by and plat in by
        and by[gold].active_subscribers == 1 and by[gold].mrr_cents == 1000
        and by[plat].active_subscribers == 2 and by[plat].mrr_cents == 4000
        and by[gold].gross_revenue_to_date_cents == 1000
        and by[plat].gross_revenue_to_date_cents == 4000
        and by[gold].net_revenue_to_date_cents == net_of(1000)
        and by[plat].net_revenue_to_date_cents == net_of(4000)
        and tier_mrr == a.mrr_cents == 5000
        and tier_gross == a.gross_revenue_to_date_cents == 5000
        and tier_active == a.active_subscribers == 3
        # ordering follows display_order (Gold before Platinum)
        and a.by_tier[0].plan_id == gold and a.by_tier[1].plan_id == plat
    )
    rec("43C by_tier reconciles + ordered",
        ok, "gold=%s plat=%s tier_mrr=%d agg_mrr=%d tier_gross=%d agg_gross=%d order=%s" % (
            by.get(gold) and by[gold].mrr_cents, by.get(plat) and by[plat].mrr_cents,
            tier_mrr, a.mrr_cents, tier_gross, a.gross_revenue_to_date_cents,
            [t.plan_name for t in a.by_tier]))


# ======================================================================
# SUBX-43 D — per-tier subscriber filter
# ======================================================================
def t_tier_filter():
    cre = TAG + "-creI"
    gold = mk_plan(cre, price=1000, name="Gold")
    plat = mk_plan(cre, price=2000, name="Plat")
    mk_sub(cre, gold, status="active")
    mk_sub(cre, gold, status="active")
    mk_sub(cre, plat, status="active")
    allr = run(ss.list_creator_subscribers(cre, None, None, 50, None, x_user_id=cre))
    goldr = run(ss.list_creator_subscribers(cre, None, gold, 50, None, x_user_id=cre))
    rec("43D per-tier subscriber filter",
        allr.total == 3 and goldr.total == 2 and all(s.plan_id == gold for s in goldr.subscribers),
        "all=%d gold=%d" % (allr.total, goldr.total))


# ======================================================================
# SUBX-43 E — display_order + reorder
# ======================================================================
def t_reorder():
    cre = TAG + "-creJ"
    p1 = mk_plan(cre, price=1000, name="A")
    p2 = mk_plan(cre, price=2000, name="B")
    p3 = mk_plan(cre, price=3000, name="C")
    # reorder to C, A, B
    out = run(ss.reorder_plans(cre, ss.PlanReorderIn(plan_ids=[p3, p1, p2]), None, x_user_id=cre))
    order = [p["plan_id"] for p in out]
    listed = run(ss.list_plans(cre, include_profile=False))
    listed_order = [p["plan_id"] for p in listed]
    rec("43E reorder sets display_order + list reflects it",
        order == [p3, p1, p2] and listed_order == [p3, p1, p2],
        "reorder=%s list=%s" % (order, listed_order))


# ======================================================================
# SUBX-40/43 — create/patch/archive tier authoring backend still coherent
# ======================================================================
def t_authoring_roundtrip():
    cre = TAG + "-creK"
    created = run(ss.create_plan(cre, ss.PlanCreateIn(
        name="Founder", price_cents=999, interval="month", level=3, display_order=5,
        benefits=[ss.PlanBenefit(label="Early access", detail="24h before")],
    ), None, x_user_id=cre))
    pid = created["plan_id"]
    patched = run(ss.update_plan(pid, ss.PlanUpdateIn(price_cents=1299, name="Founder+"), None, x_user_id=cre))
    archived = run(ss.archive_plan(pid, None, x_user_id=cre))
    rec("40 create/patch/archive tier roundtrip",
        created["display_order"] == 5 and created["level"] == 3
        and patched["price_cents"] == 1299 and patched["name"] == "Founder+"
        and archived["status"] == "archived"
        and len(created["benefits"]) == 1,
        "created do=%s lvl=%s patched=%d/%s archived=%s" % (
            created["display_order"], created["level"], patched["price_cents"],
            patched["name"], archived["status"]))


def cleanup_and_report():
    SCRUB = [
        (getattr(T, "subscriptions", None), ["pk", "sk"]),
        (getattr(T, "billing", None), ["pk", "sk"]),
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
    print("\n=== SUBX4 VERIFY: %d/%d PASS; residue=%d ===" % (npass, ntot, res))
    sys.exit(0 if (npass == ntot and res == 0) else 1)


if __name__ == "__main__":
    import traceback
    TESTS = [
        t_earnings_full_refund, t_earnings_partial_refund, t_analytics_refund_reconcile,
        t_mrr_exclusions, t_mrr_list_price, t_past_due_mrr, t_cohort_churn,
        t_by_tier, t_tier_filter, t_reorder, t_authoring_roundtrip,
    ]
    try:
        for fn in TESTS:
            try:
                fn()
            except Exception as e:
                rec(fn.__name__ + " RAISED", False, repr(e))
                traceback.print_exc()
    finally:
        cleanup_and_report()
