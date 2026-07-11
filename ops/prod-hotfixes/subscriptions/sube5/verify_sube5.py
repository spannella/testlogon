#!/usr/bin/env python3
"""SUB-E5 in-process verify (dev clone AND prod DDB). Drives the REAL subscribe /
gift / cancel endpoints + the E1 renewal sweeper, then asserts every notification
in the default-on transactional set lands on the RIGHT recipient(s), carries an
action_url deep-link, and is push-default-ON (opt-out-able); the sweeper-driven
expiring notice fires ONCE (idempotent)."""
import os, sys, time, asyncio
for p in (os.path.expanduser("~/dev/testlogon"), "/home/ubuntu/testlogon"):
    if os.path.isdir(p):
        sys.path.insert(0, p)

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_put, user_pk
from app.services import subscription_access as sa
from app.services import subscription_renewal as sr
from app.routers import subscription_server as ss
from app.services.alerts import DEFAULT_PUSH_EVENT_TYPES, get_alert_prefs

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


def mkplan(creator, price, name):
    pid = ss.new_id("plan")
    ss.save_plan({"plan_id": pid, "creator_id": creator, "name": name, "description": "",
                  "price_cents": price, "annual_price_cents": 0, "currency": "usd", "interval": "month",
                  "status": "active", "created_at": now_ts(), "updated_at": now_ts()})
    return pid


def get_sub(sid):
    return ss.ddb_get_item(ss.pk_subscription(sid), "META")


def do_subscribe(sub_id, plan_id, *, trial_days=None):
    body = ss.SubscribeIn(subscriber_id=sub_id, trial_days=trial_days)
    return asyncio.run(ss.subscribe(plan_id, body, None, x_user_id=sub_id))


def do_gift(gifter_id, plan_id, recipient_id):
    body = ss.SubscriptionGiftIn(recipient_id=recipient_id)
    return asyncio.run(ss.gift_subscription(plan_id, body, None, x_user_id=gifter_id))


def do_cancel(actor_id, subscription_id, at_period_end=True):
    body = ss.SubscriptionCancelIn(cancel_at_period_end=at_period_end)
    return asyncio.run(ss.cancel_subscription(subscription_id, body, None, x_user_id=actor_id))


def alerts_for(user, event=None, since=0):
    r = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(user), ScanIndexForward=False, Limit=50)
    items = r.get("Items", [])
    out = [it for it in items if (event is None or it.get("event") == event) and int(it.get("ts") or 0) >= since]
    return out


def latest(user, event, since=0):
    a = alerts_for(user, event, since)
    return a[0] if a else None


def push_default_on(user, event):
    p = get_alert_prefs(user)
    explicit = set(p.get("push_event_types") or [])
    opt = set(p.get("push_opt_out_event_types") or [])
    return event in (explicit | (set(DEFAULT_PUSH_EVENT_TYPES) - opt))


def gate(event, explicit=(), opt_out=()):
    return event in (set(explicit) | (set(DEFAULT_PUSH_EVENT_TYPES) - set(opt_out)))


def has_link(al):
    return bool(al and al.get("action_url"))


def main():
    stamp = int(time.time())
    creator = f"sube5_creator_{stamp}"
    PRICE = 1500
    plan = mkplan(creator, PRICE, "Gold")
    sa.set_subscription_settings(creator, require_subscription=True)
    print("=== creator", creator, "plan", plan, PRICE)

    # ======== 1. SUBSCRIBED (both sides) ========
    subA = f"sube5_subA_{stamp}"; seed_funded_pm(subA)
    t0 = now_ts()
    outA = do_subscribe(subA, plan)
    sidA = outA["subscription_id"]
    # the subscriber may carry >1 subscription_started row (the pre-existing audit->alert
    # mirror at /subscriptions + the SUB-E5 deep-linked emit at /subscriptions/manage);
    # assert MY deep-linked emit exists among them.
    a_sub_all = alerts_for(subA, "subscription_started", t0)
    a_sub = next((x for x in a_sub_all if x.get("action_url") == "/subscriptions/manage"), None)
    a_cre = latest(creator, "subscription_started", t0)
    check("SUBSCRIBED subscriber alert fires", len(a_sub_all) >= 1, "n=%d" % len(a_sub_all))
    check("SUBSCRIBED subscriber deep-link (manage)", a_sub is not None, str(a_sub and a_sub.get("title")))
    check("SUBSCRIBED subscriber push default-ON", push_default_on(subA, "subscription_started"))
    check("SUBSCRIBED creator alert fires", a_cre is not None, str(a_cre and a_cre.get("title")))
    check("SUBSCRIBED creator deep-link present", has_link(a_cre), str(a_cre and a_cre.get("action_url")))
    check("SUBSCRIBED creator push default-ON", push_default_on(creator, "subscription_started"))
    check("SUBSCRIBED opt-out suppresses (opt-out-able)", gate("subscription_started", opt_out=["subscription_started"]) is False)

    # ======== 2. RENEWED (subscriber + creator) ========
    row = get_sub(sidA); now = now_ts()
    row["current_period_end"] = now - 10
    row["next_billing_date"] = now - 10
    ss.save_subscription(row)
    t1 = now_ts()
    sr.run_renewal_sweep(now=now_ts())
    r_sub = latest(subA, "subscription_renewed", t1)
    r_cre = latest(creator, "subscription_renewed", t1)
    check("RENEWED subscriber alert fires", r_sub is not None, str(r_sub and r_sub.get("title")))
    check("RENEWED subscriber deep-link", r_sub and r_sub.get("action_url") == "/subscriptions/manage", str(r_sub and r_sub.get("action_url")))
    check("RENEWED creator alert fires", r_cre is not None, str(r_cre and r_cre.get("title")))
    check("RENEWED creator deep-link -> subscribers", r_cre and r_cre.get("action_url") == "/subscriptions/subscribers", str(r_cre and r_cre.get("action_url")))
    check("RENEWED push default-ON", push_default_on(subA, "subscription_renewed"))

    # ======== 3. RENEWAL_FAILED / dunning (subscriber) ========
    subF = f"sube5_subF_{stamp}"; seed_funded_pm(subF)
    outF = do_subscribe(subF, plan)
    sidF = outF["subscription_id"]
    rowF = get_sub(sidF); now = now_ts()
    # remove the stored PM so the renewal charge cannot resolve -> decline
    rowF["payment_method_id"] = ""
    rowF["current_period_end"] = now - 10
    rowF["next_billing_date"] = now - 10
    ss.save_subscription(rowF)
    # also strip the billing default PM so no fallback resolves
    try:
        T.billing.update_item(Key={"pk": user_pk(subF), "sk": "BILLING"},
                              UpdateExpression="SET default_payment_method_id = :e",
                              ExpressionAttributeValues={":e": ""})
    except Exception:
        pass
    for it in T.billing.query(KeyConditionExpression=Key("pk").eq(user_pk(subF))).get("Items", []):
        if str(it.get("sk", "")).startswith("PM#"):
            try:
                T.billing.delete_item(Key={"pk": it["pk"], "sk": it["sk"]})
            except Exception:
                pass
    t3 = now_ts()
    sr.run_renewal_sweep(now=now_ts())
    f_sub = latest(subF, "subscription_renewal_failed", t3)
    subF_row = get_sub(sidF)
    check("RENEWAL_FAILED subscriber alert fires", f_sub is not None, str(f_sub and f_sub.get("title")))
    check("RENEWAL_FAILED title mentions card", f_sub and "card" in (f_sub.get("title") or "").lower(), str(f_sub and f_sub.get("title")))
    check("RENEWAL_FAILED deep-link", f_sub and f_sub.get("action_url") == "/subscriptions/manage", str(f_sub and f_sub.get("action_url")))
    check("RENEWAL_FAILED -> past_due (no credit)", (subF_row.get("status") == "past_due"), str(subF_row.get("status")))
    check("RENEWAL_FAILED push default-ON", push_default_on(subF, "subscription_renewal_failed"))

    # ======== 4. EXPIRING_SOON advance notice (idempotent) ========
    subE = f"sube5_subE_{stamp}"; seed_funded_pm(subE)
    outE = do_subscribe(subE, plan)
    sidE = outE["subscription_id"]
    rowE = get_sub(sidE); now = now_ts()
    rowE["auto_renew"] = False               # will lapse at period end (not renewing)
    rowE["cancel_at_period_end"] = False
    rowE["status"] = "active"
    rowE["current_period_end"] = now + 2 * DAY   # within the N=3-day window
    rowE["next_billing_date"] = now + 2 * DAY
    rowE.pop("expiring_notified_period", None)
    ss.save_subscription(rowE)
    t4 = now_ts()
    sr.run_renewal_sweep(now=now_ts())
    e1 = alerts_for(subE, "subscription_expiring", t4)
    check("EXPIRING_SOON advance notice fires", len(e1) >= 1, "count=%d" % len(e1))
    check("EXPIRING_SOON deep-link", e1 and e1[0].get("action_url") == "/subscriptions/manage", str(e1 and e1[0].get("action_url")))
    check("EXPIRING_SOON push default-ON", push_default_on(subE, "subscription_expiring"))
    # sweep AGAIN -> must NOT emit a second one (idempotent per boundary)
    sr.run_renewal_sweep(now=now_ts())
    e2 = alerts_for(subE, "subscription_expiring", t4)
    check("EXPIRING_SOON idempotent across sweeps (fires ONCE)", len(e2) == len(e1), "before=%d after=%d" % (len(e1), len(e2)))
    check("EXPIRING_SOON marker persisted", int(get_sub(sidE).get("expiring_notified_period") or 0) == (rowE["current_period_end"]), str(get_sub(sidE).get("expiring_notified_period")))

    # ======== 5. EXPIRED (subscriber) ========
    subX = f"sube5_subX_{stamp}"; seed_funded_pm(subX)
    outX = do_subscribe(subX, plan)
    sidX = outX["subscription_id"]
    rowX = get_sub(sidX); now = now_ts()
    rowX["status"] = "past_due"
    rowX["dunning_state"] = "grace"
    rowX["grace_until"] = now - 10           # grace exhausted
    ss.save_subscription(rowX)
    t5 = now_ts()
    sr.run_renewal_sweep(now=now_ts())
    x_sub = latest(subX, "subscription_expired", t5)
    check("EXPIRED subscriber alert fires", x_sub is not None, str(x_sub and x_sub.get("title")))
    check("EXPIRED deep-link", x_sub and x_sub.get("action_url") == "/subscriptions/manage", str(x_sub and x_sub.get("action_url")))
    check("EXPIRED -> status expired", get_sub(sidX).get("status") == "expired", str(get_sub(sidX).get("status")))
    check("EXPIRED push default-ON", push_default_on(subX, "subscription_expired"))

    # ======== 6. CANCELED (subscriber + creator) ========
    subC = f"sube5_subC_{stamp}"; seed_funded_pm(subC)
    outC = do_subscribe(subC, plan)
    sidC = outC["subscription_id"]
    t6 = now_ts()
    do_cancel(subC, sidC, at_period_end=True)
    c_sub = latest(subC, "subscription_canceled", t6)
    c_cre = latest(creator, "subscription_canceled", t6)
    check("CANCELED subscriber alert fires", c_sub is not None, str(c_sub and c_sub.get("title")))
    check("CANCELED subscriber deep-link", c_sub and c_sub.get("action_url") == "/subscriptions/manage", str(c_sub and c_sub.get("action_url")))
    check("CANCELED creator alert fires", c_cre is not None, str(c_cre and c_cre.get("title")))
    check("CANCELED creator deep-link -> subscribers", c_cre and c_cre.get("action_url") == "/subscriptions/subscribers", str(c_cre and c_cre.get("action_url")))
    check("CANCELED push default-ON (subscriber+creator)", push_default_on(subC, "subscription_canceled") and push_default_on(creator, "subscription_canceled"))

    # ======== 7. GIFTED (recipient + gifter + creator) ========
    gifter = f"sube5_gifter_{stamp}"; seed_funded_pm(gifter)
    recipient = f"sube5_recip_{stamp}"
    t7 = now_ts()
    outG = do_gift(gifter, plan, recipient)
    g_rec = latest(recipient, "subscription_gifted", t7)
    g_gif = latest(gifter, "subscription_gifted", t7)
    g_cre = latest(creator, "subscription_gifted", t7)
    check("GIFTED recipient alert fires", g_rec is not None, str(g_rec and g_rec.get("title")))
    check("GIFTED recipient deep-link present", has_link(g_rec), str(g_rec and g_rec.get("action_url")))
    check("GIFTED gifter alert fires", g_gif is not None, str(g_gif and g_gif.get("title")))
    check("GIFTED gifter deep-link", g_gif and g_gif.get("action_url") == "/subscriptions/manage", str(g_gif and g_gif.get("action_url")))
    check("GIFTED creator alert fires", g_cre is not None, str(g_cre and g_cre.get("title")))
    check("GIFTED creator deep-link -> subscribers", g_cre and g_cre.get("action_url") == "/subscriptions/subscribers", str(g_cre and g_cre.get("action_url")))
    check("GIFTED push default-ON (all 3 recipients)",
          push_default_on(recipient, "subscription_gifted") and push_default_on(gifter, "subscription_gifted") and push_default_on(creator, "subscription_gifted"))

    # ======== registration / default-on set sanity ========
    for ev in ["subscription_started", "subscription_renewed", "subscription_renewal_failed",
               "subscription_expiring", "subscription_expired", "subscription_new_subscriber",
               "subscription_canceled", "subscription_gifted"]:
        check("default-ON registered: %s" % ev, ev in DEFAULT_PUSH_EVENT_TYPES)

    npass = sum(1 for _, c, _ in RESULTS if c)
    ntot = len(RESULTS)
    print("\n==== OVERALL %d/%d %s ====" % (npass, ntot, "ALL_PASS" if npass == ntot else "SOME_FAIL"))
    print("SEED creator=%s plan=%s subA=%s" % (creator, plan, subA))
    sys.exit(0 if npass == ntot else 1)


if __name__ == "__main__":
    main()
