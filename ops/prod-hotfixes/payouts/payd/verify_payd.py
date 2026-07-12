"""PAY-D in-process deep verify on PROD DDB (synthetic users, auto-cleaned).

Exercises the scheduled runner (scoped to synthetic payout_ids so the live
background runner + real payouts are never touched), the retry->fail path,
fail/return reversing the debit, the admin manual hold skip, and the alerts.
"""
import sys, os
sys.path.insert(0, "/home/ubuntu/testlogon")
sys.path.insert(0, os.getcwd())
import uuid
import traceback
from boto3.dynamodb.conditions import Key, Attr

import app.services.creator_payouts as cp
from app.core.tables import T
from app.core.time import now_ts
from app.core.settings import S
from app.services import tax_info_w9
from app.services.kyc_cases import STORE as KYC
from app.services.billing_shared import new_ledger_entry

RESULTS = []
CREATED_PAYOUTS = []
CREATED_METHODS = []
USERS = []


def check(name, cond, detail=""):
    RESULTS.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "|", detail)


def uid_new(tag):
    u = f"payd_verify_{tag}_{uuid.uuid4().hex[:10]}"
    USERS.append(u)
    return u


def seed_creator(uid, credit_cents):
    KYC.create_case(user_sub=uid, status="approved")
    tax_info_w9.submit_tax_info(
        user_sub=uid, legal_name="PAYD Verify", tin="123456789", tin_type="ssn",
        address_line1="1 Test St", city="Austin", state="TX", zip_code="78701", certified=True,
    )
    m = cp.add_payout_method(uid, method_type="paypal", paypal_email=f"{uid}@example.test")
    cp.verify_payout_method(uid, m["method_id"])
    CREATED_METHODS.append((uid, m["method_id"]))
    sk, entry = new_ledger_entry(
        key_name="pk", key_value=f"USER#{uid}", entry_type="credit",
        amount_cents=credit_cents, state="settled", reason="payd_verify_seed", meta={"seed": "payd"},
    )
    entry["ts"] = now_ts() - 8 * 86400  # matured past the 7-day balance hold
    T.billing.put_item(Item=entry)
    return m


def avail(uid):
    return cp.get_available_balance(uid)["available_cents"]


def payout_row(pid):
    return T.creator_payouts.get_item(Key={"payout_id": pid}).get("Item") or {}


def debit_summary(uid):
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{uid}") & Key("sk").begins_with("LEDGER#"),
        FilterExpression=Attr("type").eq("debit") & Attr("reason").eq("payout"),
    )
    items = resp.get("Items", [])
    settled = [i for i in items if str(i.get("state")) == "settled"]
    reversed_ = [i for i in items if str(i.get("state")) == "reversed"]
    return {"count": len(items), "settled": len(settled), "reversed": len(reversed_),
            "settled_sum": sum(int(i.get("amount_cents", 0)) for i in settled)}


def payout_alert_events(uid):
    try:
        resp = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(uid))
        return sorted({str(i.get("event")) for i in resp.get("Items", []) if str(i.get("event", "")).startswith("payout_")})
    except Exception as e:
        return ["<alert_query_err:%s>" % e]


def set_force(pid, val):
    T.creator_payouts.update_item(
        Key={"payout_id": pid},
        UpdateExpression="SET force_transfer_result = :v",
        ExpressionAttributeValues={":v": val},
    )


def request(uid, amt):
    p = cp.request_payout(uid, amount_cents=amt)
    CREATED_PAYOUTS.append(p["payout_id"])
    return p["payout_id"]


def run_scoped(pid, now=None):
    return cp.run_payout_sweep(now=now, payout_id=pid)


# ══════════════════════════════════════════════════════════════════════════
try:
    print("=== ENV ===")
    print("payout_runner_enabled", S.payout_runner_enabled, "interval", S.payout_runner_interval_seconds,
          "max_attempts", S.payout_max_transfer_attempts, "backoff", S.payout_retry_backoff_seconds,
          "hold_period_s", S.payout_hold_period_seconds)

    # ---- S1: happy path -> paid + debit + balance drop + idempotency + return reverses debit
    u1 = uid_new("s1"); seed_creator(u1, 10000)
    check("S1 avail0==10000", avail(u1) == 10000, "avail0=%d" % avail(u1))
    p1 = request(u1, 3000)
    check("S1 requested status", payout_row(p1).get("status") == "requested")
    check("S1 avail after request==7000 (reservation)", avail(u1) == 7000, "avail=%d" % avail(u1))
    r = run_scoped(p1)
    row = payout_row(p1)
    check("S1 runner paid->completed", row.get("status") == "completed", "action=%s status=%s" % (r.get("paid"), row.get("status")))
    check("S1 transfer_provider==mock", row.get("transfer_provider") == "mock", "tp=%s ref=%s" % (row.get("transfer_provider"), row.get("transfer_ref")))
    ds = debit_summary(u1)
    check("S1 exactly one settled debit of 3000", ds["settled"] == 1 and ds["settled_sum"] == 3000, str(ds))
    check("S1 avail after paid==7000 (debit)", avail(u1) == 7000, "avail=%d" % avail(u1))
    # idempotent re-run
    r2 = run_scoped(p1)
    ds2 = debit_summary(u1)
    check("S1 re-run idempotent: still 1 debit, avail 7000", ds2["settled"] == 1 and avail(u1) == 7000,
          "rerun=%s debits=%s avail=%d" % (r2.get("skipped"), ds2, avail(u1)))
    # return reverses the real debit -> funds back
    cp.fail_payout(p1, reason="verify return", returned=True)
    rowr = payout_row(p1)
    dsr = debit_summary(u1)
    check("S1 returned status", rowr.get("status") == "returned", "status=%s" % rowr.get("status"))
    check("S1 debit reversed (0 settled, 1 reversed)", dsr["settled"] == 0 and dsr["reversed"] == 1, str(dsr))
    check("S1 avail back to 10000 after return", avail(u1) == 10000, "avail=%d" % avail(u1))
    # re-return idempotent (no double credit)
    cp.fail_payout(p1, reason="verify return again", returned=True)
    check("S1 re-return idempotent avail==10000", avail(u1) == 10000, "avail=%d" % avail(u1))

    # ---- S2: hard fail -> failed + reverse(no-op, never paid) + funds back via reservation release
    u2 = uid_new("s2"); seed_creator(u2, 8000)
    p2 = request(u2, 3000)
    check("S2 avail after request==5000", avail(u2) == 5000, "avail=%d" % avail(u2))
    set_force(p2, "hard_fail")
    r = run_scoped(p2)
    row2 = payout_row(p2)
    check("S2 hard-fail -> status failed", row2.get("status") == "failed", "status=%s attempts=%s" % (row2.get("status"), row2.get("transfer_attempts")))
    check("S2 no settled debit (never paid)", debit_summary(u2)["settled"] == 0, str(debit_summary(u2)))
    check("S2 avail back to 8000 (reservation released)", avail(u2) == 8000, "avail=%d" % avail(u2))
    check("S2 attempts recorded >=1", int(row2.get("transfer_attempts", 0)) >= 1, "attempts=%s" % row2.get("transfer_attempts"))

    # ---- S3: bounded transient retries -> failed; attempts counted
    u3 = uid_new("s3"); seed_creator(u3, 8000)
    p3 = request(u3, 3000)
    set_force(p3, "transient_fail")
    t0 = now_ts()
    seq = []
    a1 = run_scoped(p3, now=t0);            seq.append(("t0", a1.get("retried") and a1["retried"][0].get("attempts")))
    na1 = int(payout_row(p3).get("next_attempt_at", 0))
    skip = run_scoped(p3, now=t0)  # same clock -> backoff not elapsed -> skipped
    check("S3 retry backoff blocks re-run at same clock", (skip.get("skipped", 0) == 1) and int(payout_row(p3).get("transfer_attempts", 0)) == 1,
          "skip=%s attempts=%s next=%d" % (skip.get("skipped"), payout_row(p3).get("transfer_attempts"), na1))
    a2 = run_scoped(p3, now=na1 + 1)
    a3 = run_scoped(p3, now=int(payout_row(p3).get("next_attempt_at", 0)) + 1)
    a4 = run_scoped(p3, now=int(payout_row(p3).get("next_attempt_at", 0)) + 1)
    row3 = payout_row(p3)
    check("S3 exhausted retries -> failed", row3.get("status") == "failed", "status=%s attempts=%s" % (row3.get("status"), row3.get("transfer_attempts")))
    check("S3 attempts counted == max(4)", int(row3.get("transfer_attempts", 0)) == int(S.payout_max_transfer_attempts),
          "attempts=%s max=%s" % (row3.get("transfer_attempts"), S.payout_max_transfer_attempts))
    check("S3 no settled debit + avail back 8000", debit_summary(u3)["settled"] == 0 and avail(u3) == 8000,
          "debits=%s avail=%d" % (debit_summary(u3), avail(u3)))

    # ---- S4: manual hold -> runner SKIPS until released -> then paid
    u4 = uid_new("s4"); seed_creator(u4, 8000)
    p4 = request(u4, 3000)
    cp.place_payout_hold(p4, "verify_admin", reason="manual hold test")
    held = payout_row(p4)
    check("S4 manual_hold flag set", held.get("manual_hold") is True, "manual_hold=%s status=%s" % (held.get("manual_hold"), held.get("status")))
    rh = run_scoped(p4)
    afterhold = payout_row(p4)
    check("S4 runner SKIPS held payout (not processed)", (rh.get("skipped", 0) == 1) and afterhold.get("status") == "requested" and int(afterhold.get("transfer_attempts", 0)) == 0,
          "run=%s status=%s attempts=%s" % (rh, afterhold.get("status"), afterhold.get("transfer_attempts")))
    cp.release_payout_hold(p4, "verify_admin")
    check("S4 hold released", payout_row(p4).get("manual_hold") is False)
    rr = run_scoped(p4)
    check("S4 after release runner pays it", payout_row(p4).get("status") == "completed", "action=%s status=%s" % (rr.get("paid"), payout_row(p4).get("status")))
    check("S4 one settled debit 3000 + avail 5000", debit_summary(u4)["settled"] == 1 and avail(u4) == 5000,
          "debits=%s avail=%d" % (debit_summary(u4), avail(u4)))

    # ---- Notifications fired (default-on transactional)
    ev1 = payout_alert_events(u1)
    ev2 = payout_alert_events(u2)
    ev4 = payout_alert_events(u4)
    check("N u1 payout_initiated+paid+returned emitted", all(x in ev1 for x in ["payout_initiated", "payout_paid", "payout_returned"]), str(ev1))
    check("N u2 payout_initiated+failed emitted", ("payout_initiated" in ev2) and ("payout_failed" in ev2), str(ev2))
    check("N u4 payout_initiated+paid emitted", ("payout_initiated" in ev4) and ("payout_paid" in ev4), str(ev4))
    import app.services.alerts as _al
    _dpe = set(_al.DEFAULT_PUSH_EVENT_TYPES)
    check("N payout events are default-ON transactional push", {"payout_initiated", "payout_paid", "payout_failed", "payout_returned"}.issubset(_dpe),
          "default_on=%s" % sorted(x for x in _dpe if x.startswith("payout_")))

except Exception:
    print("EXCEPTION during verify:")
    traceback.print_exc()

# ══════════════════════════════════════════════════════════════════════════
# cleanup
print("=== CLEANUP ===")
cleaned = {"payouts": 0, "markers": 0, "methods": 0, "billing": 0, "kyc": 0, "w9": 0, "alerts": 0, "sentinels": 0, "connect": 0}
try:
    for pid in CREATED_PAYOUTS:
        T.creator_payouts.delete_item(Key={"payout_id": pid}); cleaned["payouts"] += 1
        T.creator_payouts.delete_item(Key={"payout_id": f"PAYOUTDEBIT#{pid}"}); cleaned["markers"] += 1
    for uid, mid in CREATED_METHODS:
        T.creator_payouts.delete_item(Key={"payout_id": mid}); cleaned["methods"] += 1
    for uid in USERS:
        T.creator_payouts.delete_item(Key={"payout_id": f"PAYOUT_STATE#{uid}"}); cleaned["sentinels"] += 1
        T.creator_payouts.delete_item(Key={"payout_id": f"CONNECT#{uid}"}); cleaned["connect"] += 1
        # billing ledger rows
        resp = T.billing.query(KeyConditionExpression=Key("pk").eq(f"USER#{uid}") & Key("sk").begins_with("LEDGER#"))
        for it in resp.get("Items", []):
            T.billing.delete_item(Key={"pk": it["pk"], "sk": it["sk"]}); cleaned["billing"] += 1
        # kyc cases
        try:
            for c in KYC.list_cases_by_owner(user_sub=uid, limit=25):
                if c.get("pk"):
                    T.kyc_cases.delete_item(Key={"pk": c["pk"], "sk": c.get("sk", "META")}); cleaned["kyc"] += 1
        except Exception as e:
            print("kyc cleanup warn", uid, e)
        # w9
        try:
            T.tax_info.delete_item(Key={"pk": tax_info_w9._pk(uid), "sk": tax_info_w9._SK}); cleaned["w9"] += 1
        except Exception as e:
            print("w9 cleanup warn", uid, e)
        # alerts
        try:
            aresp = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(uid))
            for a in aresp.get("Items", []):
                T.alerts.delete_item(Key={"user_sub": a["user_sub"], "alert_id": a["alert_id"]}); cleaned["alerts"] += 1
        except Exception as e:
            print("alerts cleanup warn", uid, e)
except Exception:
    traceback.print_exc()
print("cleaned", cleaned)

# residue re-scan
residue = 0
for uid in USERS:
    if T.billing.query(KeyConditionExpression=Key("pk").eq(f"USER#{uid}") & Key("sk").begins_with("LEDGER#")).get("Items"):
        residue += 1
print("residual_users_with_billing", residue)

npass = sum(1 for ok, _, _ in RESULTS if ok)
ntot = len(RESULTS)
print("=== SUMMARY %d/%d PASS ===" % (npass, ntot))
for ok, name, detail in RESULTS:
    if not ok:
        print("  FAILED:", name, "|", detail)
