import os, sys, time, asyncio
sys.path.insert(0, "/home/ubuntu/testlogon")
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_put, user_pk
from app.services import subscription_access as sa
from app.services import subscription_renewal as sr
from app.routers import subscription_server as ss
import app.services.subscription_cycle_orders as sco
import app.services.payment_reconciliation as pr
import app.services.entitlements_service as es

DAY = 86400
RESULTS = []
def check(n, c, d=""):
    RESULTS.append((n, bool(c), d)); print(("PASS" if c else "FAIL"), n, "--", d)

AUDIT = []
_orig = sco.audit_event
def cap(event, *a, **k):
    AUDIT.append((event, dict(k))); return _orig(event, *a, **k)
sco.audit_event = cap; pr.audit_event = cap; es.audit_event = cap

def inv_fails(idx):
    bad = ("subscription_cycle_reconciliation_invariant_failed",
           "subscription_cycle_reconciliation_dead_lettered")
    return [e for e, _ in AUDIT[idx:] if e in bad]
def emitted_since(idx):
    return [k for e, k in AUDIT[idx:] if e == "subscription_cycle_order_emitted"]
def granted_since(idx):
    return [k for e, k in AUDIT[idx:] if e == "entitlement_granted"]

def seed_pm(uid):
    from app.routers.billing import get_or_create_customer, ensure_stripe_configured
    import stripe
    ensure_stripe_configured(); cust = get_or_create_customer(uid)
    pm = stripe.PaymentMethod.create(type="card", card={"number":"4242424242424242","exp_month":12,"exp_year":2032,"cvc":"123"})
    stripe.PaymentMethod.attach(pm["id"], customer=cust)
    pk = user_pk(uid)
    ddb_put(T.billing, {"pk":pk,"sk":"PM#"+pm["id"],"payment_method_id":pm["id"],"provider":"stripe","provider_method_id":pm["id"],"method_type":"card","brand":"visa","last4":"4242","exp_month":12,"exp_year":2032,"priority":0,"created_at":now_ts()})
    ddb_put(T.billing, {"pk":pk,"sk":"BILLING","autopay_enabled":False,"currency":"usd","default_payment_method_id":pm["id"]})
    try: stripe.Customer.modify(cust, invoice_settings={"default_payment_method":pm["id"]})
    except Exception: pass
    return pm["id"]

def read_order(oid):
    if not oid: return None
    try: return T.orders.get_item(Key={"order_id":oid,"sk":"ORDER"}).get("Item")
    except Exception: return None
def ents_for(uid):
    return list(T.entitlements.query(KeyConditionExpression=Key("user_id").eq(uid)).get("Items", []))
def do_subscribe(uid, plan_id, trial_days=None):
    return asyncio.run(ss.subscribe(plan_id, ss.SubscribeIn(subscriber_id=uid, trial_days=trial_days), None, x_user_id=uid))
def make_sub(uid, creator, plan_id, pm, cpe, price=1200):
    sid = ss.new_id("sub")
    sub = {"subscription_id":sid,"plan_id":plan_id,"creator_id":creator,"subscriber_id":uid,"interval":"month","provider":"stripe","status":"active","start_at":now_ts()-30*DAY,"current_period_end":cpe,"next_billing_date":cpe,"payment_method_id":pm,"cancel_at_period_end":False,"price_cents":price,"currency":"usd","auto_renew":True,"created_at":now_ts()-30*DAY,"updated_at":now_ts()}
    ss.save_subscription(sub); return sid

def main():
    stamp = int(time.time())
    plan_id = ss.new_id("plan")
    creator = "subfix_creator_%d" % stamp
    ss.save_plan({"plan_id":plan_id,"creator_id":creator,"name":"Subfix Tier","description":"","price_cents":1200,"annual_price_cents":0,"currency":"usd","interval":"month","status":"active","created_at":now_ts(),"updated_at":now_ts()})
    sa.set_subscription_settings(creator, require_subscription=True)
    print("=== plan", plan_id, "creator", creator)

    # ===== A: REAL SUBSCRIBE =====
    subA = "subfix_A_%d" % stamp; seed_pm(subA)
    dl0 = len(sco.default_reconciliation_gateway.reconciliation_repo.dead_letters)
    iA = len(AUDIT)
    outA = do_subscribe(subA, plan_id)
    check("A0 subscribe active + real PI charged", outA["status"]=="active" and bool(outA.get("payment_intent_id")), str(outA.get("status")))
    em = emitted_since(iA)
    check("A1 exactly one cycle order emitted", len(em)==1, str([e.get("order_id") for e in em]))
    oid = em[0].get("order_id") if em else None
    order = read_order(oid)
    check("A2 cycle order persisted in T.orders (composite-key read works)", order is not None and str(order.get("source_system"))=="subscription_cycle", str(order and order.get("status")))
    check("A3 cycle order stamped paid", bool(order) and str(order.get("status"))=="paid", str(order and order.get("status")))
    rs = [k.get("reconciliation_status") for e,k in AUDIT[iA:] if e=="subscription_cycle_reconciliation_succeeded"]
    check("A4 reconcile SUCCEEDED (status=processed)", "processed" in rs, str(rs))
    check("A5 NO invariant_failed / dead_letter emitted", len(inv_fails(iA))==0, str(inv_fails(iA)))
    check("A6 gateway dead-letter list NOT grown", len(sco.default_reconciliation_gateway.reconciliation_repo.dead_letters)==dl0, "%d->%d" % (dl0, len(sco.default_reconciliation_gateway.reconciliation_repo.dead_letters)))
    entsA = ents_for(subA)
    check("A7 entitlement GRANTED (row in T.entitlements)", len(entsA)>=1 and len(granted_since(iA))>=1, "rows=%d audit=%d" % (len(entsA), len(granted_since(iA))))
    check("A8 granted entitlement is ACTIVE", any(str(e.get("status"))=="active" for e in entsA), str([e.get("status") for e in entsA]))

    # ===== B: IDEMPOTENT RE-EMIT (same subscription+period) =====
    subrow = ss.ddb_get_item(ss.pk_subscription(outA["subscription_id"]), "META")
    plan = {"plan_id":plan_id,"currency":"usd","interval":"month"}
    now = now_ts()
    inv = {"invoice_id":"inv_idem_%d" % stamp,"provider_invoice_id":"inv_idem_%d" % stamp,"subscription_id":outA["subscription_id"],"subscriber_id":subA,"amount_cents":1200,"currency":"usd","status":"paid","period_start":now,"period_end":now+30*DAY,"created_at":now_ts()}
    iB = len(AUDIT)
    r1 = ss.emit_subscription_cycle_order_and_reconcile(subscription=subrow, plan=plan, invoice=inv)
    e1 = len(ents_for(subA))
    r2 = ss.emit_subscription_cycle_order_and_reconcile(subscription=subrow, plan=plan, invoice=inv)
    e2 = len(ents_for(subA))
    check("B1 re-emit SAME cycle -> SAME order_id (deterministic)", r1["order_id"]==r2["order_id"], "%s == %s" % (r1["order_id"], r2["order_id"]))
    check("B2 re-emit -> NO duplicate entitlement", e1==e2, "%d==%d" % (e1, e2))
    check("B3 re-emit -> NO dead-letter/invariant_failed", len(inv_fails(iB))==0, str(inv_fails(iB)))
    check("B4 second reconcile idempotent (processed/duplicate)", str(r2["reconciliation"].get("status")) in ("duplicate","processed"), str(r2["reconciliation"].get("status")))

    # ===== C: RENEWAL via the E1 sweeper -> NEW cycle order for NEW period =====
    subC = "subfix_C_%d" % stamp; pmC = seed_pm(subC)
    now = now_ts(); cpe0 = now - 100
    sidC = make_sub(subC, creator, plan_id, pmC, cpe0)
    iC = len(AUDIT)
    sweep = sr.run_renewal_sweep(now=now)
    renewedC = [r for r in sweep.get("renewed", []) if r["subscription_id"]==sidC]
    check("C1 sweeper renewed the due sub (real charge)", len(renewedC)==1 and bool(renewedC[0].get("pi")), str(renewedC))
    emC = emitted_since(iC)
    check("C2 renewal emitted a NEW cycle order", len(emC)>=1, str([e.get("order_id") for e in emC]))
    newrow = ss.ddb_get_item(ss.pk_subscription(sidC), "META")
    new_cpe = int(newrow.get("current_period_end") or 0)
    check("C3 period advanced one interval (new billing period)", new_cpe == cpe0 + ss.interval_seconds("month"), "%d->%d" % (cpe0, new_cpe))
    oidC = emC[-1].get("order_id") if emC else None
    check("C4 renewal cycle order persisted + paid", (read_order(oidC) or {}).get("status")=="paid", str((read_order(oidC) or {}).get("status")))
    check("C5 renewal entitlement granted", len(ents_for(subC))>=1, str(len(ents_for(subC))))
    check("C6 renewal produced NO invariant_failed / dead_letter", len(inv_fails(iC))==0, str(inv_fails(iC)))

    # ===== D: TRIAL subscribe -> CLEAN NO-OP =====
    subD = "subfix_D_%d" % stamp; seed_pm(subD)
    iD = len(AUDIT)
    outD = do_subscribe(subD, plan_id, trial_days=7)
    check("D0 trial subscribe -> trialing (no charge)", outD["status"]=="trialing" and not outD.get("payment_intent_id"), str(outD.get("status")))
    check("D1 trial emits NO cycle order (clean no-op)", len(emitted_since(iD))==0, str(emitted_since(iD)))
    check("D2 trial -> NO invariant_failed / dead_letter", len(inv_fails(iD))==0, str(inv_fails(iD)))

    npass = sum(1 for _,c,_ in RESULTS if c); ntot = len(RESULTS)
    print("\n===== %d/%d %s =====" % (npass, ntot, "OVERALL ALL_PASS" if npass==ntot else "FAILURES PRESENT"))

main()
