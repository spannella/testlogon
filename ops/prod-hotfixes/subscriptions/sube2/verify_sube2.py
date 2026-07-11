#!/usr/bin/env python3
"""SUB-E2 in-process verify (dev clone AND prod DDB).

Drives the change-plan endpoint + trial card-up-front + the E1 sweeper's new
auto-convert / pending-change hooks against real DDB + the funds-guarded
stripe-mock rail, asserting the money + lifecycle invariants:

  U  mid-cycle UPGRADE (cheap->expensive) = IMMEDIATE prorated DELTA charge
     (funds-guarded, real PI) + plan switched NOW + creator credited the DELTA NET.
  D  DOWNGRADE (expensive->cheap) = SCHEDULED pending_change, NO immediate money;
     sweeper at period end applies it + renews at the new (lower) price + credits.
  T  TRIAL subscribe (card up front) -> trialing, PM captured, NO charge/NO credit;
     sweeper at trial_end AUTO-CONVERTS = real charge + creator credit + active.
  X  TRIAL convert charge DECLINES -> dunning/past_due, NO creator credit.
"""
import os, sys, time, asyncio
sys.path.insert(0, os.path.expanduser("~/dev/testlogon"))
if os.path.isdir("/home/ubuntu/testlogon"):
    sys.path.insert(0, "/home/ubuntu/testlogon")

from fastapi import HTTPException
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_put, user_pk, ddb_query_pk
from app.services import subscription_access as sa
from app.services import subscription_renewal as sr
from app.routers import subscription_server as ss

DAY = 86400
MONTH = ss.interval_seconds("month")
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def seed_funded_pm(user_id):
    from app.routers.billing import get_or_create_customer, ensure_stripe_configured
    import stripe
    ensure_stripe_configured()
    cust = get_or_create_customer(user_id)
    pm = stripe.PaymentMethod.create(type="card", card={"number": "4242424242424242", "exp_month": 12, "exp_year": 2032, "cvc": "123"})
    stripe.PaymentMethod.attach(pm["id"], customer=cust)
    pk = user_pk(user_id)
    ddb_put(T.billing, {"pk": pk, "sk": f"PM#{pm['id']}", "payment_method_id": pm["id"], "provider": "stripe",
                        "provider_method_id": pm["id"], "method_type": "card", "brand": "visa", "last4": "4242",
                        "exp_month": 12, "exp_year": 2032, "priority": 0, "created_at": now_ts()})
    ddb_put(T.billing, {"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd", "default_payment_method_id": pm["id"]})
    try:
        stripe.Customer.modify(cust, invoice_settings={"default_payment_method": pm["id"]})
    except Exception:
        pass
    return pm["id"]


def credit_rows(creator_id):
    rows = ddb_query_pk(T.billing, user_pk(creator_id))
    return [r for r in rows if r.get("type") == "credit" and (r.get("meta") or {}).get("content_type") == "subscription"]


def newest_credit(creator_id):
    rows = credit_rows(creator_id)
    return sorted(rows, key=lambda r: r.get("ts", 0))[-1] if rows else None


def get_sub(sid):
    return ss.ddb_get_item(ss.pk_subscription(sid), "META")


def invoices(sid):
    items = ss.ddb_query(ss.pk_subscription(sid))
    return [it for it in items if it.get("sk", "").startswith("INV#")]


def mkplan(creator, price, name):
    pid = ss.new_id("plan")
    ss.save_plan({"plan_id": pid, "creator_id": creator, "name": name, "description": "",
                  "price_cents": price, "annual_price_cents": 0, "currency": "usd", "interval": "month",
                  "status": "active", "created_at": now_ts(), "updated_at": now_ts()})
    return pid


def do_subscribe(sub_id, plan_id, *, trial_days=None):
    body = ss.SubscribeIn(subscriber_id=sub_id, trial_days=trial_days)
    return asyncio.run(ss.subscribe(plan_id, body, None, x_user_id=sub_id))


def do_change(sub_id, subscription_id, plan_id):
    body = ss.SubscriptionChangePlanIn(plan_id=plan_id)
    return asyncio.run(ss.change_subscription_plan(subscription_id, body, None, x_user_id=sub_id))


def main():
    stamp = int(time.time())
    creator = f"sube2_creator_{stamp}"
    CHEAP, EXP = 1000, 3000
    cheap = mkplan(creator, CHEAP, "Cheap")
    exp = mkplan(creator, EXP, "Expensive")
    sa.set_subscription_settings(creator, require_subscription=True)
    print("=== creator", creator, "cheap", cheap, CHEAP, "exp", exp, EXP)

    # ================= U: mid-cycle UPGRADE =================
    subU = f"sube2_U_{stamp}"; seed_funded_pm(subU)
    outU = do_subscribe(subU, cheap)
    sidU = outU["subscription_id"]
    cU0 = len(credit_rows(creator))
    check("U0 subscribe(cheap) active + charged", outU["status"] == "active" and outU["price_cents"] == CHEAP, str(outU["status"]))
    # age to EXACTLY mid-cycle: half the interval remains
    row = get_sub(sidU); now = now_ts()
    row["start_at"] = now - MONTH // 2
    row["current_period_end"] = now + MONTH // 2
    row["next_billing_date"] = now + MONTH // 2
    ss.save_subscription(row)
    cpe_before = int(get_sub(sidU)["current_period_end"])
    cU_pre_up = len(credit_rows(creator))
    outU2 = do_change(subU, sidU, exp)
    u = get_sub(sidU)
    inv = [i for i in invoices(sidU) if i.get("is_proration")]
    exp_delta = int(round((EXP - CHEAP) * 0.5))  # 1000
    net = exp_delta - int(exp_delta * 1000 / 10000)  # 900
    nc = newest_credit(creator)
    check("U1 upgrade applied IMMEDIATELY (plan switched now)", u["plan_id"] == exp and int(u["price_cents"]) == EXP, f"{u['plan_id']} {u['price_cents']}")
    check("U2 no pending_change on an immediate upgrade", not u.get("pending_change"), str(u.get("pending_change")))
    check("U3 period end UNCHANGED (keep paid cycle)", int(u["current_period_end"]) == cpe_before, f"{u['current_period_end']} vs {cpe_before}")
    check("U4 prorated DELTA invoice minted ~1000", bool(inv) and int(inv[0]["amount_cents"]) == exp_delta, str([(i['amount_cents']) for i in inv]))
    check("U5 DELTA charge funds-guarded (real PI on invoice)", bool(inv and inv[0].get("payment_intent_id")), str(inv[0].get("payment_intent_id") if inv else None))
    check("U6 creator credited exactly +1 row", len(credit_rows(creator)) == cU_pre_up + 1, f"{cU_pre_up}->{len(credit_rows(creator))}")
    check("U7 credit == DELTA NET (1000-100=900)", nc and int(nc["amount_cents"]) == net, str(nc.get("amount_cents") if nc else None))

    # ================= D: DOWNGRADE (scheduled) =================
    subD = f"sube2_D_{stamp}"; seed_funded_pm(subD)
    outD = do_subscribe(subD, exp)
    sidD = outD["subscription_id"]
    cD_after_sub = len(credit_rows(creator))
    outD2 = do_change(subD, sidD, cheap)
    d = get_sub(sidD)
    pc = d.get("pending_change") or {}
    check("D1 downgrade SCHEDULED (pending_change set)", pc.get("plan_id") == cheap and int(pc.get("price_cents")) == CHEAP, str(pc))
    check("D2 pending applies at period end", int(pc.get("apply_at") or 0) == int(d["current_period_end"]), f"{pc.get('apply_at')} vs {d['current_period_end']}")
    check("D3 plan NOT switched yet (still expensive)", d["plan_id"] == exp and int(d["price_cents"]) == EXP, f"{d['plan_id']} {d['price_cents']}")
    check("D4 NO immediate money on a downgrade", len(credit_rows(creator)) == cD_after_sub, f"{cD_after_sub}->{len(credit_rows(creator))}")
    # sweep at period end -> apply pending + renew at NEW (cheap) price
    cpeD = int(d["current_period_end"])
    cD_pre_sweep = len(credit_rows(creator))
    sD = sr.run_renewal_sweep(now=cpeD + 1)
    d2 = get_sub(sidD)
    ncD = newest_credit(creator)
    netD = CHEAP - int(CHEAP * 1000 / 10000)  # 900
    check("D5 sweeper APPLIED pending change (plan_changed)", sidD in sD["plan_changed"], str(sD["plan_changed"]))
    check("D6 plan now switched to CHEAP + price updated", d2["plan_id"] == cheap and int(d2["price_cents"]) == CHEAP, f"{d2['plan_id']} {d2['price_cents']}")
    check("D7 pending_change cleared", not d2.get("pending_change"), str(d2.get("pending_change")))
    check("D8 renewed at new price + creator credited NET (900)", (sidD in [r['subscription_id'] for r in sD['renewed']]) and ncD and int(ncD["amount_cents"]) == netD, f"credit={ncD.get('amount_cents') if ncD else None}")
    check("D9 period advanced one interval", int(d2["current_period_end"]) == cpeD + MONTH, f"{d2['current_period_end']} vs {cpeD+MONTH}")

    # ================= T: TRIAL card-up-front + auto-convert =================
    subT = f"sube2_T_{stamp}"; pmT = seed_funded_pm(subT)
    outT = do_subscribe(subT, cheap, trial_days=7)
    sidT = outT["subscription_id"]
    t = get_sub(sidT)
    cT_after_sub = len(credit_rows(creator))
    check("T1 trial subscribe -> trialing", t["status"] == "trialing", str(t["status"]))
    check("T2 CARD captured up front (PM stored)", t.get("payment_method_id") == pmT, str(t.get("payment_method_id")))
    check("T3 NO charge during trial (no invoice)", len(invoices(sidT)) == 0, str(len(invoices(sidT))))
    check("T4 trial_end set (=now+7d)", bool(t.get("trial_end")), str(t.get("trial_end")))
    # sweep AT trial_end -> auto-convert (real charge + credit)
    tend = int(t["trial_end"])
    cT_pre = len(credit_rows(creator))
    sT = sr.run_renewal_sweep(now=tend + 1)
    t2 = get_sub(sidT)
    ncT = newest_credit(creator)
    netT = CHEAP - int(CHEAP * 1000 / 10000)  # 900
    check("T5 sweeper AUTO-CONVERTED (trial_converted)", sidT in [r['subscription_id'] for r in sT['trial_converted']], str(sT['trial_converted']))
    check("T6 status trialing -> active", t2["status"] == "active", str(t2["status"]))
    check("T7 trial_converted_at stamped", bool(t2.get("trial_converted_at")), str(t2.get("trial_converted_at")))
    check("T8 REAL charge on convert (PI on invoice)", any(i.get("payment_intent_id") for i in invoices(sidT)), str([i.get('payment_intent_id') for i in invoices(sidT)]))
    check("T9 creator credited NET on convert (900)", len(credit_rows(creator)) == cT_pre + 1 and ncT and int(ncT["amount_cents"]) == netT, f"{cT_pre}->{len(credit_rows(creator))} credit={ncT.get('amount_cents') if ncT else None}")

    # ================= X: TRIAL convert DECLINES -> dunning =================
    subX = f"sube2_X_{stamp}"; seed_funded_pm(subX)
    outX = do_subscribe(subX, cheap, trial_days=7)
    sidX = outX["subscription_id"]
    x = get_sub(sidX)
    cX_pre = len(credit_rows(creator))
    orig = ss._charge_subscription_payment_intent
    def _decline(**kw):
        raise HTTPException(402, {"code": "payment_failed", "message": "forced decline"})
    ss._charge_subscription_payment_intent = _decline
    try:
        sX = sr.run_renewal_sweep(now=int(x["trial_end"]) + 1)
    finally:
        ss._charge_subscription_payment_intent = orig
    x2 = get_sub(sidX)
    check("X1 declined trial convert -> past_due", x2["status"] == "past_due", str(x2["status"]))
    check("X2 dunning attempt recorded", int(x2.get("dunning_attempts") or 0) >= 1, str(x2.get("dunning_attempts")))
    check("X3 in sweep dunning bucket", any(dd["subscription_id"] == sidX for dd in sX["dunning"]), str(sX["dunning"]))
    check("X4 NO creator credit on declined convert", len(credit_rows(creator)) == cX_pre, f"{cX_pre}->{len(credit_rows(creator))}")

    # ================= summary =================
    npass = sum(1 for _, c, _ in RESULTS if c)
    ntot = len(RESULTS)
    print(f"\n==== SUB-E2 VERIFY {npass}/{ntot} " + ("OVERALL ALL_PASS" if npass == ntot else "SOME_FAIL") + " ====")
    if npass != ntot:
        for n, c, d in RESULTS:
            if not c:
                print("  FAILED:", n, d)
    return 0 if npass == ntot else 1


if __name__ == "__main__":
    sys.exit(main())
