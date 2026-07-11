#!/usr/bin/env python3
"""SUB-E1 in-process lifecycle verify (dev clone AND prod DDB).

Self-seeds funded subscribers + a creator + a plan, then drives the renewal /
dunning / expiry state machine via subscription_renewal.run_renewal_sweep and
asserts the money + lifecycle + access invariants:

  A  DUE sub renews: real charge, creator credited NET a SECOND cycle, period +
     next_billing_date advance by exactly one interval, idempotent (same-cycle
     re-run = no 2nd charge / no 2nd credit).
  B  Renewal decline -> past_due + dunning attempt + renewal_failed; access
     CONTINUES through past_due/grace; drive all retries -> grace -> expired;
     expired sub loses access.
  C  Expiry enforcement: expired sub AND a lapsed (period-elapsed) active sub both
     return has_active_subscription False.
  D  Cancel-at-period-end sub keeps access until period end then (post-period)
     loses access + sweep flips it to canceled.
"""
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.expanduser("~/dev/testlogon"))

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_put, ddb_get, user_pk
from app.services import subscription_access as sa
from app.services import subscription_renewal as sr
from app.routers import subscription_server as ss

DAY = 86400
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def seed_funded_pm(user_id):
    from app.routers.billing import get_or_create_customer, ensure_stripe_configured
    import stripe

    ensure_stripe_configured()
    cust = get_or_create_customer(user_id)
    pm = stripe.PaymentMethod.create(
        type="card",
        card={"number": "4242424242424242", "exp_month": 12, "exp_year": 2032, "cvc": "123"},
    )
    stripe.PaymentMethod.attach(pm["id"], customer=cust)
    pk = user_pk(user_id)
    ddb_put(T.billing, {
        "pk": pk, "sk": f"PM#{pm['id']}", "payment_method_id": pm["id"], "provider": "stripe",
        "provider_method_id": pm["id"], "method_type": "card", "brand": "visa", "last4": "4242",
        "exp_month": 12, "exp_year": 2032, "priority": 0, "created_at": now_ts(),
    })
    ddb_put(T.billing, {"pk": pk, "sk": "BILLING", "autopay_enabled": False, "currency": "usd",
                        "default_payment_method_id": pm["id"]})
    try:
        stripe.Customer.modify(cust, invoice_settings={"default_payment_method": pm["id"]})
    except Exception:
        pass
    return pm["id"]


def creator_credit_rows(creator_id):
    """Subscription creator NET credit rows in T.billing (what payout/earnings read)."""
    from app.services.billing_shared import ddb_query_pk
    rows = ddb_query_pk(T.billing, user_pk(creator_id))
    out = []
    for r in rows:
        if r.get("type") == "credit" and (r.get("meta") or {}).get("content_type") == "subscription":
            out.append(r)
    return out


def make_sub(subscriber_id, creator_id, plan_id, pm_id, *, cpe, status="active",
             cancel_ape=False, auto_renew=True, price_cents=799):
    sid = ss.new_id("sub")
    sub = {
        "subscription_id": sid, "plan_id": plan_id, "creator_id": creator_id,
        "subscriber_id": subscriber_id, "interval": "month", "provider": "stripe",
        "status": status, "start_at": now_ts() - 30 * DAY,
        "current_period_end": cpe, "next_billing_date": cpe,
        "payment_method_id": pm_id, "cancel_at_period_end": cancel_ape,
        "price_cents": price_cents, "currency": "usd", "auto_renew": auto_renew,
        "created_at": now_ts() - 30 * DAY, "updated_at": now_ts(),
    }
    ss.save_subscription(sub)
    return sid


def get_sub(sid):
    return ss.ddb_get_item(ss.pk_subscription(sid), "META")


def main():
    stamp = int(time.time())
    plan_id = ss.new_id("plan")
    creator = f"sube1_creator_{stamp}"
    plan = {
        "plan_id": plan_id, "creator_id": creator, "name": "E1 Tier", "description": "",
        "price_cents": 799, "annual_price_cents": 0, "currency": "usd", "interval": "month",
        "status": "active", "created_at": now_ts(), "updated_at": now_ts(),
    }
    ss.save_plan(plan)
    # creator requires subscription so has_active_subscription is the real gate
    sa.set_subscription_settings(creator, require_subscription=True)
    print("=== seed plan", plan_id, "creator", creator)

    # ---------------- SCENARIO A: renewal ----------------
    subA = f"sube1_subA_{stamp}"
    pmA = seed_funded_pm(subA)
    now = now_ts()
    cpe0 = now - 100
    sidA = make_sub(subA, creator, plan_id, pmA, cpe=cpe0)
    before = len(creator_credit_rows(creator))
    check("A0 access before renewal (period just elapsed, active)",
          sa.has_active_subscription(subA, creator) is False,
          "active+cpe elapsed = lapsed until swept")

    s1 = sr.run_renewal_sweep(now=now)
    subA_row = get_sub(sidA)
    renewedA = [r for r in s1["renewed"] if r["subscription_id"] == sidA]
    after1 = len(creator_credit_rows(creator))
    new_cpe = int(subA_row.get("current_period_end") or 0)
    check("A1 renewed action emitted", len(renewedA) == 1, str(renewedA))
    check("A2 real charge PI present", bool(renewedA and renewedA[0].get("pi")),
          str(renewedA[0].get("pi") if renewedA else None))
    check("A3 creator credited a SECOND cycle (net)", after1 == before + 1,
          f"before={before} after={after1}")
    if after1 == before + 1:
        newest = sorted(creator_credit_rows(creator), key=lambda r: r.get("ts", 0))[-1]
        check("A3b credit amount is NET (799-79=720)", int(newest.get("amount_cents")) == 720,
              str(newest.get("amount_cents")))
    check("A4 period advanced by exactly one interval",
          new_cpe == cpe0 + ss.interval_seconds("month"),
          f"cpe {cpe0} -> {new_cpe} (+{ss.interval_seconds('month')})")
    check("A4b next_billing_date advanced too", int(subA_row.get("next_billing_date")) == new_cpe,
          str(subA_row.get("next_billing_date")))
    check("A5 status active + dunning cleared after renew",
          (subA_row.get("status") == "active") and not subA_row.get("dunning_state"),
          str(subA_row.get("status")))
    check("A6 access restored after renewal (period now future)",
          sa.has_active_subscription(subA, creator) is True, f"new_cpe={new_cpe} now={now}")

    # re-run same wall clock: sub no longer due (nbd future) -> no action
    s2 = sr.run_renewal_sweep(now=now)
    after2 = len(creator_credit_rows(creator))
    check("A7 natural re-run not-due: no 2nd credit", after2 == after1,
          f"after1={after1} after2={after2}")

    # forced same-cycle overlap: reset to old cycle, re-run -> idempotent skip, no credit
    subA_row2 = get_sub(sidA)
    subA_row2["current_period_end"] = cpe0
    subA_row2["next_billing_date"] = cpe0
    subA_row2["status"] = "active"
    ss.save_subscription(subA_row2)
    s3 = sr.run_renewal_sweep(now=now)
    after3 = len(creator_credit_rows(creator))
    check("A8 same-cycle overlap is idempotent (RENEWCYCLE claim)",
          (sidA in s3["idempotent_skips"]) and (after3 == after1),
          f"skips={sidA in s3['idempotent_skips']} credits after3={after3} (== {after1})")

    # ---------------- SCENARIO B: dunning -> grace -> expired ----------------
    subB = f"sube1_subB_{stamp}"
    # deliberately NO stored PM -> every renewal charge is a decline
    now = now_ts()
    cpeB = now - 100
    sidB = make_sub(subB, creator, plan_id, "", cpe=cpeB)
    creditB_before = len(creator_credit_rows(creator))

    sb1 = sr.run_renewal_sweep(now=now)
    b = get_sub(sidB)
    check("B1 declined renewal -> past_due", b.get("status") == "past_due", str(b.get("status")))
    check("B2 dunning attempt #1 recorded", int(b.get("dunning_attempts") or 0) == 1,
          str(b.get("dunning_attempts")))
    check("B3 next retry ~ day 1", int(b.get("dunning_next_retry_at") or 0) == now + 1 * DAY,
          str(b.get("dunning_next_retry_at")))
    check("B4 renewal_failed action emitted",
          any(d["subscription_id"] == sidB for d in sb1["dunning"]), str(sb1["dunning"]))
    check("B5 NO creator credit on decline",
          len(creator_credit_rows(creator)) == creditB_before,
          f"before={creditB_before} now={len(creator_credit_rows(creator))}")
    check("B6 access CONTINUES through past_due (grace horizon)",
          sa.has_active_subscription(subB, creator) is True,
          f"grace_until={b.get('grace_until')} now={now}")

    # drive remaining retries: push next_retry into the past and re-sweep until grace
    grace_seen = False
    for i in range(6):
        b = get_sub(sidB)
        if b.get("dunning_state") == "grace":
            grace_seen = True
            break
        b["dunning_next_retry_at"] = now - 10
        ss.save_subscription(b)
        sr.run_renewal_sweep(now=now)
    b = get_sub(sidB)
    check("B7 after last retry -> grace state", b.get("dunning_state") == "grace" or grace_seen,
          f"state={b.get('dunning_state')} attempts={b.get('dunning_attempts')}")
    check("B8 access still granted during grace",
          sa.has_active_subscription(subB, creator) is True,
          f"grace_until={b.get('grace_until')}")

    # expire: push grace_until into the past, sweep
    b = get_sub(sidB)
    b["grace_until"] = now - 10
    ss.save_subscription(b)
    sbx = sr.run_renewal_sweep(now=now)
    b = get_sub(sidB)
    check("B9 grace elapsed -> status expired",
          b.get("status") == "expired" and sidB in sbx["expired"], str(b.get("status")))
    check("B10 expired sub LOSES access",
          sa.has_active_subscription(subB, creator) is False, "")
    check("B11 dunning produced ZERO creator credit total",
          len(creator_credit_rows(creator)) == creditB_before, "")

    # ---------------- SCENARIO C: lapsed active loses access ----------------
    subC = f"sube1_subC_{stamp}"
    pmC = seed_funded_pm(subC)
    sidC = make_sub(subC, creator, plan_id, pmC, cpe=now_ts() - 5 * DAY)  # 5d past, not swept
    check("C1 lapsed active sub (period elapsed, unswept) loses access",
          sa.has_active_subscription(subC, creator) is False, "")

    # ---------------- SCENARIO D: cancel-at-period-end ----------------
    subD = f"sube1_subD_{stamp}"
    pmD = seed_funded_pm(subD)
    now = now_ts()
    # future period, cancel scheduled -> access retained until period end
    sidD = make_sub(subD, creator, plan_id, pmD, cpe=now + 10 * DAY, cancel_ape=True, auto_renew=False)
    check("D1 cancel-at-period-end keeps access until period end",
          sa.has_active_subscription(subD, creator) is True, "period in future")
    # advance past the period end -> access ends + sweep marks canceled
    d = get_sub(sidD)
    d["current_period_end"] = now - 10
    d["next_billing_date"] = now - 10
    ss.save_subscription(d)
    check("D2 access ends once the period elapses (pre-sweep, enforcement)",
          sa.has_active_subscription(subD, creator) is False, "")
    sd = sr.run_renewal_sweep(now=now)
    d = get_sub(sidD)
    check("D3 sweep flips cancel-at-period-end -> canceled (no charge)",
          d.get("status") == "canceled" and sidD in sd["canceled"], str(d.get("status")))
    check("D4 canceled sub has no access", sa.has_active_subscription(subD, creator) is False, "")

    # ---------------- summary ----------------
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print("\n==== SUB-E1 VERIFY %d/%d ====" % (passed, total))
    print("OVERALL", "ALL_PASS" if passed == total else "FAIL")
    if passed != total:
        for n, ok, d in RESULTS:
            if not ok:
                print("  FAILED:", n, d)


if __name__ == "__main__":
    main()
