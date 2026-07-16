import os, sys, json, time, uuid, urllib.request, urllib.error
from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.routers import subscription_server as ss
from app.services import subscription_access as sa
from app.services.billing_shared import ddb_put, user_pk
from app.services.creator_payouts import get_available_balance

BASE = "http://localhost:8000"
TAG = "subx0verify-" + uuid.uuid4().hex[:8]
SECRET = os.environ.get("SUBSCRIPTION_WEBHOOK_SECRET", "")
now = int(time.time())
FEE_BPS = ss.FEE_BPS
NET = 1000 - int(1000 * FEE_BPS / 10000)

cre = f"{TAG}-cre"
results = []
def rec(name, ok, detail=""):
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS" if ok else "FAIL"), name, "-", detail)

def http(method, path, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.getcode(), json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read() or b"{}")
        except Exception:
            payload = {}
        return e.code, payload

def total_earned(uid):
    try:
        return int(get_available_balance(uid).get("total_earned_cents") or 0)
    except Exception:
        return -1

def seed_pm(u):
    ddb_put(T.billing, {"pk": user_pk(u), "sk": "PM#pm_x", "payment_method_id": "pm_x", "brand": "visa", "last4": "4242", "user_sub": u, "tag": TAG})
    ddb_put(T.billing, {"pk": user_pk(u), "sk": "BILLING", "default_payment_method_id": "pm_x", "user_sub": u, "tag": TAG})

def mk_sub(status, pm=False, cpe_delta=3600, over=None):
    sid = f"{TAG}-{uuid.uuid4().hex[:6]}"
    su = f"{TAG}-sub-{uuid.uuid4().hex[:6]}"
    pid = f"{TAG}-plan-{uuid.uuid4().hex[:6]}"
    ss.ddb_put_item({"pk": ss.pk_plan(pid), "sk": "META", "entity": "plan", "plan_id": pid,
                     "creator_id": cre, "price_cents": 1000, "currency": "usd", "interval": "month",
                     "status": "active", "name": "Gold", "tag": TAG})
    sub = {"subscription_id": sid, "plan_id": pid, "creator_id": cre, "subscriber_id": su,
           "interval": "month", "status": status, "price_cents": 1000, "currency": "usd",
           "auto_renew": True, "start_at": now - 10, "current_period_end": now + cpe_delta,
           "provider": "stub", "provider_subscription_id": f"stub-{sid}",
           "cancel_at_period_end": False, "next_billing_date": now + cpe_delta,
           "created_at": now, "updated_at": now, "tag": TAG}
    if pm:
        sub["payment_method_id"] = "pm_x"
        seed_pm(su)
    if over:
        sub.update(over)
    ss.save_subscription(sub)
    return sid, su

def get_meta(sid):
    return ss.normalize_subscription(ss.ddb_get_item(ss.pk_subscription(sid), "META") or {})

try:
    # ================= SUBX-01 negative: no PM -> 402 + NO credit =================
    sid, su = mk_sub("trialing", pm=False)
    b0 = total_earned(cre)
    code, resp = http("POST", f"/api/subscriptions/{sid}/trial/convert", headers={"X-User-Id": su})
    m = get_meta(sid)
    b1 = total_earned(cre)
    rec("SUBX01-neg: no-PM convert -> 402", code == 402, f"code={code}")
    rec("SUBX01-neg: not activated", (m.get("status") or "").lower() != "active", f"status={m.get('status')}")
    rec("SUBX01-neg: NO creator credit", b1 == b0, f"before={b0} after={b1}")

    # ================= SUBX-01 positive + core gating + SUBX-02 =================
    sid, su = mk_sub("trialing", pm=True)
    stranger = f"{TAG}-stranger"
    locked_pre = sa.content_locked_for_viewer(stranger, cre, subscriber_only=True)
    rec("CORE-gate: stranger locked pre", locked_pre is True, f"locked={locked_pre}")
    b0 = total_earned(cre)
    code, resp = http("POST", f"/api/subscriptions/{sid}/trial/convert", headers={"X-User-Id": su})
    m = get_meta(sid)
    b1 = total_earned(cre)
    rec("SUBX01-pos: convert -> 200 active", code == 200 and (resp.get("status") == "active"), f"code={code} status={resp.get('status')}")
    rec("SUBX01-pos: creator credited NET once", (b1 - b0) == NET, f"delta={b1-b0} expected={NET}")
    rec("CORE-gate: subscriber unlocked", sa.has_active_subscription(su, cre) is True and sa.content_locked_for_viewer(su, cre, subscriber_only=True) is False, f"active={sa.has_active_subscription(su,cre)}")

    # idempotency: repeat convert -> 400 (not trialing), NO extra credit
    code2, _ = http("POST", f"/api/subscriptions/{sid}/trial/convert", headers={"X-User-Id": su})
    b2 = total_earned(cre)
    rec("SUBX01-pos: idempotent repeat -> 400", code2 == 400, f"code={code2}")
    rec("SUBX01-pos: no double credit", b2 == b1, f"after2={b2} after1={b1}")

    # SUBX-02: subscriber CANNOT full-refund (fraction=1.0 -> 403), sub stays active
    code3, _ = http("POST", f"/api/subscriptions/{sid}/refund", headers={"X-User-Id": su}, body={"fraction": 1.0})
    m3 = get_meta(sid)
    b3 = total_earned(cre)
    rec("SUBX02: subscriber full-refund blocked -> 403", code3 == 403, f"code={code3}")
    rec("SUBX02: sub still active after blocked full-refund", (m3.get("status") or "").lower() == "active" and b3 == b1, f"status={m3.get('status')} bal={b3}")

    # SUBX-02: subscriber prorated refund -> access REVOKED + credit clawed back.
    # SUBX-10 INTERACTION: a JUST-converted sub starts a fresh cycle (unused remainder
    # ~= 100% -> frac~1.0), which the corrected cycle-accurate proration classifies as
    # a FULL refund (subscriber-blocked). To exercise the PARTIAL subscriber refund we
    # seed the sub to mid-cycle (frac~0.5) so the default /refund is genuinely partial;
    # the clawback is then PROPORTIONAL (was: near-full under the old lifetime denom).
    _mc = get_meta(sid)
    _mc["current_period_start"] = now - 15 * 86400
    _mc["current_period_end"] = now + 15 * 86400
    ss.save_subscription(_mc)
    code4, resp4 = http("POST", f"/api/subscriptions/{sid}/refund", headers={"X-User-Id": su}, body={})
    m4 = get_meta(sid)
    b4 = total_earned(cre)
    rec("SUBX02: prorated refund -> 200", code4 == 200, f"code={code4} refunded={resp4.get('refunded_cents')}")
    rec("SUBX02: access REVOKED (status canceled)", (m4.get("status") or "").lower() == "canceled" and int(m4.get("current_period_end") or 0) <= int(time.time()) + 5, f"status={m4.get('status')} cpe={m4.get('current_period_end')}")
    rec("SUBX02: has_active_subscription -> False", sa.has_active_subscription(su, cre) is False, "")
    rec("SUBX02: content re-locks", sa.content_locked_for_viewer(su, cre, subscriber_only=True) is True, "")
    # proportional clawback (~half the NET credit) and NOT inflating (b4 strictly < b1)
    rec("SUBX02: credit clawed back proportionally, NOT inflating", (b4 < b1) and (abs((b1 - b4) - int(NET * 0.5)) <= 60), f"pre={b0} post-convert={b1} post-refund={b4} clawback={b1 - b4}")

    # ================= SUBX-03: webhook auth + no free-extend =================
    exp_cpe = now - 86400
    sid, su = mk_sub("expired", pm=False, cpe_delta=-86400, over={"status": "expired", "auto_renew": False, "expired_at": now - 86400, "dunning_state": "expired"})
    # unauthenticated invoice.paid -> 401, sub unchanged
    code, _ = http("POST", "/api/billing/webhooks/stub", body={"event_type": "invoice.paid", "subscription_id": sid, "metadata": {"amount_cents": 1000, "currency": "usd"}})
    mu = get_meta(sid)
    rec("SUBX03: unauth webhook -> 401", code == 401, f"code={code}")
    rec("SUBX03: unauth did NOT extend/un-expire", (mu.get("status") or "").lower() == "expired" and int(mu.get("current_period_end") or 0) == exp_cpe, f"status={mu.get('status')} cpe={mu.get('current_period_end')}")
    # authenticated invoice.paid (valid secret) -> 200 but BOOKKEEPING-ONLY (no extend)
    code2, _ = http("POST", "/api/billing/webhooks/stub", headers={"X-Subscription-Webhook-Secret": SECRET}, body={"event_type": "invoice.paid", "subscription_id": sid, "invoice_id": f"{TAG}-inv", "metadata": {"amount_cents": 1000, "currency": "usd"}})
    ma = get_meta(sid)
    rec("SUBX03: authed webhook accepted -> 200", code2 == 200, f"code={code2}")
    rec("SUBX03: authed invoice.paid did NOT extend period/status", (ma.get("status") or "").lower() == "expired" and int(ma.get("current_period_end") or 0) == exp_cpe, f"status={ma.get('status')} cpe={ma.get('current_period_end')}")
    rec("SUBX03: expired sub still NOT active", sa.has_active_subscription(su, cre) is False, "")

finally:
    # ================= CLEANUP: TAG sweep across all touched tables (0 residue) =================
    tbl_names = ["subscriptions", "billing", "orders", "order_items", "entitlements"]
    def keynames(tbl):
        return [k["AttributeName"] for k in tbl.key_schema]
    def sweep(tbl):
        deleted = 0
        last = None
        while True:
            kw = {"ExclusiveStartKey": last} if last else {}
            r = tbl.scan(**kw)
            kn = keynames(tbl)
            for it in r.get("Items", []):
                if TAG in json.dumps(it, default=str):
                    tbl.delete_item(Key={k: it[k] for k in kn})
                    deleted += 1
            last = r.get("LastEvaluatedKey")
            if not last:
                break
        return deleted
    def residue(tbl):
        cnt = 0
        last = None
        while True:
            kw = {"ExclusiveStartKey": last} if last else {}
            r = tbl.scan(**kw)
            for it in r.get("Items", []):
                if TAG in json.dumps(it, default=str):
                    cnt += 1
            last = r.get("LastEvaluatedKey")
            if not last:
                break
        return cnt
    total_del = 0
    total_res = 0
    for nm in tbl_names:
        tbl = getattr(T, nm, None)
        if tbl is None:
            continue
        try:
            total_del += sweep(tbl)
        except Exception as e:
            print("sweep-error", nm, e)
    for nm in tbl_names:
        tbl = getattr(T, nm, None)
        if tbl is None:
            continue
        try:
            total_res += residue(tbl)
        except Exception as e:
            print("residue-error", nm, e)
    rec("CLEANUP: 0 residue", total_res == 0, f"deleted={total_del} residue={total_res}")

npass = sum(1 for r in results if r["ok"])
nfail = sum(1 for r in results if not r["ok"])
print("\n==== SUMMARY", npass, "PASS /", nfail, "FAIL ====")
print("RESULT_JSON", json.dumps({"pass": npass, "fail": nfail, "results": results}))
sys.exit(1 if nfail else 0)
