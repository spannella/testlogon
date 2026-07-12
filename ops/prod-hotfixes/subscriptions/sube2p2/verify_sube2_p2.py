#!/usr/bin/env python3
"""SUB-E2 PART 2 in-process verify (prod DDB + funds-guarded stripe-mock rail).

Drives the SHIPPED endpoint coroutines (gift_subscription / cancel_subscription /
refund_subscription) + the E1 sweeper against real DDB, asserting the money +
lifecycle invariants:

  G  GIFT: the GIFTER is charged ONCE (real PI) + the RECIPIENT gets a one-cycle sub
     (auto_renew False, NEVER charged) + creator credited NET; the gift LAPSES at
     period end via the sweeper with NO charge.
  C  CANCEL at-period-end: keeps access (status 'canceling') until period end, NO
     refund; sweeper flips to 'canceled' at period end -> access ends.
  I  IMMEDIATE cancel: access revoked NOW + subscriber refunded the prorated unused
     portion + creator credit clawed back (state=reversed, earnings NOT inflated);
     repeat immediate-cancel = no double refund (idempotent).
  R  general /refund path: prorated refund + clawback; a same-key replay is a no-op
     (idempotent, no double refund).
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
FEE = 1000  # bps (10%)
RESULTS = []


def net_of(gross):
    return int(gross) - int(int(gross) * FEE / 10000)


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


def rows(user):
    return ddb_query_pk(T.billing, user_pk(user))


def credit_rows(creator):
    return [r for r in rows(creator) if r.get("type") == "credit" and (r.get("meta") or {}).get("content_type") == "subscription"]


def live_credit_sum(creator):
    return sum(int(r.get("amount_cents") or 0) for r in credit_rows(creator) if (r.get("state") or "") != "reversed")


def refund_rows(user, sid=None):
    out = [r for r in rows(user) if r.get("type") == "refund" and str(r.get("sk", "")).startswith("LEDGER#")]
    if sid:
        out = [r for r in out if (r.get("meta") or {}).get("subscription_id") == sid]
    return out


def reversal_rows(user, sid=None):
    out = [r for r in rows(user) if r.get("type") == "reversal" and str(r.get("sk", "")).startswith("LEDGER#")]
    if sid:
        out = [r for r in out if (r.get("meta") or {}).get("subscription_id") == sid]
    return out


def pay_rows(user):
    return [r for r in rows(user) if str(r.get("sk", "")).startswith("PAY#")]


def pm_rows(user):
    return [r for r in rows(user) if str(r.get("sk", "")).startswith("PM#")]


def get_sub(sid):
    return ss.ddb_get_item(ss.pk_subscription(sid), "META")


def invoices(sid):
    return [it for it in ss.ddb_query(ss.pk_subscription(sid)) if str(it.get("sk", "")).startswith("INV#")]


def paid_invoices(sid):
    return [i for i in invoices(sid) if (i.get("status") or "").lower() == "paid"]


def mkplan(creator, price, name):
    pid = ss.new_id("plan")
    ss.save_plan({"plan_id": pid, "creator_id": creator, "name": name, "description": "",
                  "price_cents": price, "annual_price_cents": 0, "currency": "usd", "interval": "month",
                  "status": "active", "created_at": now_ts(), "updated_at": now_ts()})
    return pid


def do_subscribe(sub_id, plan_id):
    return asyncio.run(ss.subscribe(plan_id, ss.SubscribeIn(subscriber_id=sub_id), None, x_user_id=sub_id))


def do_gift(gifter, plan_id, recipient):
    return asyncio.run(ss.gift_subscription(plan_id, ss.SubscriptionGiftIn(recipient_id=recipient), None, x_user_id=gifter))


def do_cancel(sid, user, cape, refund=None):
    return asyncio.run(ss.cancel_subscription(sid, ss.SubscriptionCancelIn(cancel_at_period_end=cape, refund=refund), None, x_user_id=user))


def do_refund(sid, user, fraction=None):
    return asyncio.run(ss.refund_subscription(sid, ss.SubscriptionRefundIn(fraction=fraction), None, x_user_id=user))


def age_mid_cycle(sid):
    row = get_sub(sid); now = now_ts()
    row["start_at"] = now - MONTH // 2
    row["current_period_end"] = now + MONTH // 2
    row["next_billing_date"] = now + MONTH // 2
    ss.save_subscription(row)


def main():
    stamp = int(time.time())
    creator = f"sube2p2_creator_{stamp}"
    PRICE = 2000
    plan = mkplan(creator, PRICE, "Gold")
    sa.set_subscription_settings(creator, require_subscription=True)
    print("=== creator", creator, "plan", plan, PRICE)

    # ===================== G: GIFTING =====================
    gifter = f"sube2p2_gifter_{stamp}"; seed_funded_pm(gifter)
    recip = f"sube2p2_recip_{stamp}"  # NO PM on purpose
    cG_pre = len(credit_rows(creator))
    outG = do_gift(gifter, plan, recip)
    sidG = outG["subscription_id"]
    g = get_sub(sidG)
    ncG = sorted(credit_rows(creator), key=lambda r: r.get("ts", 0))[-1]
    pinv = paid_invoices(sidG)
    check("G1 recipient gets the sub (active, subscriber=recipient)", g["status"] == "active" and g["subscriber_id"] == recip, f"{g['status']} {g['subscriber_id']}")
    check("G2 gift is NON-renewing (auto_renew False)", g.get("auto_renew") is False and bool(g.get("is_gift")) and g.get("gifter_id") == gifter, f"auto_renew={g.get('auto_renew')} is_gift={g.get('is_gift')} gifter={g.get('gifter_id')}")
    check("G3 gifter charged ONCE (1 paid invoice, real PI)", len(pinv) == 1 and bool(pinv[0].get("payment_intent_id")), f"{len(pinv)} pi={pinv[0].get('payment_intent_id') if pinv else None}")
    check("G4 gift charge amount == price", pinv and int(pinv[0]["amount_cents"]) == PRICE, str(pinv[0]['amount_cents'] if pinv else None))
    check("G5 PAY record under GIFTER (payer), not recipient", any(p.get("subscription_id") == sidG for p in pay_rows(gifter)) and not any(p.get("subscription_id") == sidG for p in pay_rows(recip)), f"gifter_pay={len(pay_rows(gifter))} recip_pay={len(pay_rows(recip))}")
    check("G6 recipient NEVER charged (no PM, no PAY under recipient)", len(pm_rows(recip)) == 0 and len(pay_rows(recip)) == 0, f"pm={len(pm_rows(recip))} pay={len(pay_rows(recip))}")
    check("G7 creator credited NET exactly +1 (price*0.9)", len(credit_rows(creator)) == cG_pre + 1 and int(ncG["amount_cents"]) == net_of(PRICE), f"{cG_pre}->{len(credit_rows(creator))} credit={ncG['amount_cents']} want={net_of(PRICE)}")
    check("G8 recipient HAS access during the gift period", sa.has_active_subscription(recip, creator) is True, "")
    # lapse at period end via the sweeper -> NO charge
    cpeG = int(g["current_period_end"]); cG_before_lapse = len(credit_rows(creator)); inv_before = len(invoices(sidG))
    sG = sr.run_renewal_sweep(now=cpeG + 1)
    g2 = get_sub(sidG)
    check("G9 gift LAPSES at period end (expired, NO charge/credit/invoice)", g2["status"] == "expired" and sidG in sG["expired"] and len(credit_rows(creator)) == cG_before_lapse and len(invoices(sidG)) == inv_before, f"status={g2['status']} credits={cG_before_lapse}->{len(credit_rows(creator))} inv={inv_before}->{len(invoices(sidG))}")
    check("G10 recipient access ENDS after lapse", sa.has_active_subscription(recip, creator) is False, "")

    # ===================== C: CANCEL at-period-end (default, no refund) =====================
    subC = f"sube2p2_C_{stamp}"; seed_funded_pm(subC)
    outC = do_subscribe(subC, plan); sidC = outC["subscription_id"]
    cC_after_sub = live_credit_sum(creator)
    do_cancel(sidC, subC, cape=True)
    c = get_sub(sidC)
    check("C1 cancel-at-period-end -> status 'canceling'", c["status"] == "canceling" and c.get("auto_renew") is False, f"{c['status']} auto_renew={c.get('auto_renew')}")
    check("C2 access KEPT until period end (canceling grants access)", sa.has_active_subscription(subC, creator) is True, "")
    check("C3 NO refund on cancel-at-period-end", len(refund_rows(subC, sidC)) == 0 and len(reversal_rows(creator, sidC)) == 0, f"refunds={len(refund_rows(subC, sidC))}")
    check("C4 creator credit intact (no clawback)", live_credit_sum(creator) == cC_after_sub, str(cC_after_sub) + "->" + str(live_credit_sum(creator)))
    cpeC = int(c["current_period_end"])
    sC = sr.run_renewal_sweep(now=cpeC + 1)
    c2 = get_sub(sidC)
    check("C5 sweeper flips 'canceling' -> 'canceled' at period end", c2["status"] == "canceled" and sidC in sC["canceled"], f"{c2['status']}")
    check("C6 access ENDS after period end", sa.has_active_subscription(subC, creator) is False, "")
    check("C7 still NO refund (cancel-at-period-end never refunds)", len(refund_rows(subC, sidC)) == 0, "")

    # ===================== I: IMMEDIATE cancel + refund + clawback =====================
    subI = f"sube2p2_I_{stamp}"; seed_funded_pm(subI)
    outI = do_subscribe(subI, plan); sidI = outI["subscription_id"]
    age_mid_cycle(sidI)  # ~half the cycle remains -> prorated refund ~half
    net_full = net_of(PRICE)  # 1800
    earn_before = live_credit_sum(creator)
    do_cancel(sidI, subI, cape=False)  # immediate -> default refund
    i = get_sub(sidI)
    rr = refund_rows(subI, sidI); vr = reversal_rows(creator, sidI)
    orig_credit = [r for r in credit_rows(creator) if r.get("subscription_id") == sidI and not (r.get("meta") or {}).get("retained_after_refund")]
    retained = [r for r in credit_rows(creator) if r.get("subscription_id") == sidI and (r.get("meta") or {}).get("retained_after_refund")]
    refund_amt = int(rr[0]["amount_cents"]) if rr else -1
    clawback_amt = int(vr[0]["amount_cents"]) if vr else -1
    earn_after = live_credit_sum(creator)
    check("I1 IMMEDIATE cancel -> status canceled + period ended NOW (access revoked)", i["status"] == "canceled" and int(i["current_period_end"]) <= now_ts() and sa.has_active_subscription(subI, creator) is False, f"status={i['status']} cpe<=now={int(i['current_period_end'])<=now_ts()}")
    check("I2 subscriber REFUNDED prorated unused portion (0<refund<price)", len(rr) == 1 and 0 < refund_amt < PRICE, f"refund={refund_amt} of {PRICE}")
    check("I3 refund entry is type 'refund' (not credit)", rr and rr[0].get("type") == "refund", str(rr[0].get("type") if rr else None))
    check("I4 creator CLAWBACK entry type 'reversal' (not credit -> not inflating)", len(vr) == 1 and vr[0].get("type") == "reversal" and 0 < clawback_amt < net_full, f"clawback={clawback_amt} of {net_full}")
    check("I5 ORIGINAL creator credit flipped state=reversed", orig_credit and (orig_credit[0].get("state") == "reversed"), str(orig_credit[0].get("state") if orig_credit else None))
    check("I6 KEPT (used) fraction re-credited = net_full - clawback", retained and int(retained[0]["amount_cents"]) == net_full - clawback_amt, f"retained={retained[0]['amount_cents'] if retained else None} want={net_full-clawback_amt}")
    check("I7 earnings NOT inflated -> live credit sum DROPPED by exactly the clawback", earn_after == earn_before - clawback_amt, f"{earn_before}->{earn_after} (drop want {clawback_amt})")
    check("I8 refund gross ~ price*(clawback/net_full) proration (both ~half)", abs(refund_amt - int(round(PRICE * (clawback_amt / net_full)))) <= 2, f"refund={refund_amt} vs {int(round(PRICE*(clawback_amt/net_full)))}")
    # idempotency: a repeat immediate cancel must NOT double-refund
    do_cancel(sidI, subI, cape=False)
    check("I9 repeat immediate-cancel = NO double refund (idempotent)", len(refund_rows(subI, sidI)) == 1 and len(reversal_rows(creator, sidI)) == 1, f"refunds={len(refund_rows(subI, sidI))} reversals={len(reversal_rows(creator, sidI))}")

    # ===================== R: general /refund path + idempotency =====================
    subR = f"sube2p2_R_{stamp}"; seed_funded_pm(subR)
    outR = do_subscribe(subR, plan); sidR = outR["subscription_id"]
    age_mid_cycle(sidR)
    r1 = do_refund(sidR, subR, fraction=0.5)
    r2 = do_refund(sidR, subR, fraction=0.5)  # same marker (sid#period_end) -> replay
    check("R1 /refund refunds the subscriber (>0) + claws back creator", int(r1["refunded_cents"]) > 0 and int(r1["clawback_cents"]) > 0 and r1["idempotent_replay"] is False, str(r1))
    check("R2 same-key /refund replay is idempotent (no double refund)", r2["idempotent_replay"] is True and len(refund_rows(subR, sidR)) == 1 and len(reversal_rows(creator, sidR)) == 1, f"replay={r2['idempotent_replay']} refunds={len(refund_rows(subR, sidR))}")
    check("R3 refund == 50% price, clawback == 50% net", int(r1["refunded_cents"]) == int(round(PRICE * 0.5)) and int(r1["clawback_cents"]) == int(round(net_of(PRICE) * 0.5)), f"refund={r1['refunded_cents']} clawback={r1['clawback_cents']}")

    # ===================== summary =====================
    npass = sum(1 for _, c, _ in RESULTS if c); ntot = len(RESULTS)
    print(f"\n==== SUB-E2 PART2 VERIFY {npass}/{ntot} " + ("OVERALL ALL_PASS" if npass == ntot else "SOME_FAIL") + " ====")
    if npass != ntot:
        for n, c, d in RESULTS:
            if not c:
                print("  FAILED:", n, d)
    return 0 if npass == ntot else 1


if __name__ == "__main__":
    sys.exit(main())
