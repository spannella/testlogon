#!/usr/bin/env python3
"""PAY-50/51 in-process verification on prod DDB.

Seeds a synthetic creator with a MIX of payouts (requested / paid / failed-returned
/ held) + a ledger of credits (some past the 7-day hold, some inside it), then
asserts:
  * get_wallet_summary reconciles to the PAY-A ledger
    (available = past-hold credits - lifetime-paid debits - in-flight payouts;
     held = within-hold credits; pending = active payouts; lifetime = settled debits)
  * list_user_payouts returns the full history
  * get_payout_detail returns a correct statement (timeline / transfer ref /
    method last-4 / fail-return / hold reason)
  * a DIFFERENT user is scoped out (get_payout_detail -> PermissionError; the
    other user's history does not contain user1's payouts)
All seeded rows are deleted in a finally block.
"""
import sys
sys.path.insert(0, "/home/ubuntu/testlogon")
import uuid

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts
import app.services.creator_payouts as cp

HOLD = S.payout_hold_period_seconds
NOW = now_ts()
SUFFIX = uuid.uuid4().hex[:10]
U1 = f"payf_verify_u1_{SUFFIX}"
U2 = f"payf_verify_u2_{SUFFIX}"

created_payout_ids = []
created_ledger_keys = []  # (pk, sk)

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def seed_credit(uid, amount, ts, reversed_=False):
    pk = f"USER#{uid}"
    sk = f"LEDGER#{ts}#{uuid.uuid4().hex}"
    item = {"pk": pk, "sk": sk, "type": "credit", "amount_cents": amount, "ts": ts, "reason": "tip"}
    if reversed_:
        item["state"] = "reversed"
    T.billing.put_item(Item=item)
    created_ledger_keys.append((pk, sk))


def seed_payout_debit(uid, amount, ts, reversed_=False):
    pk = f"USER#{uid}"
    sk = f"LEDGER#{ts}#{uuid.uuid4().hex}"
    item = {"pk": pk, "sk": sk, "type": "debit", "reason": "payout", "amount_cents": amount, "ts": ts}
    if reversed_:
        item["state"] = "reversed"
    T.billing.put_item(Item=item)
    created_ledger_keys.append((pk, sk))


def seed_payout(uid, amount, status, **extra):
    pid = f"payout_payfverify_{uuid.uuid4().hex}"
    item = {
        "payout_id": pid, "user_id": uid, "amount_cents": amount, "method": "bank_ach",
        "status": status, "created_at": NOW - 1000, "updated_at": NOW - 500,
        "notes": "", "reject_reason": "", "approved_by": "",
    }
    item.update(extra)
    T.creator_payouts.put_item(Item=item)
    created_payout_ids.append(pid)
    return pid


def seed_method(uid, last4):
    mid = f"pmth_payfverify_{uuid.uuid4().hex}"
    T.creator_payouts.put_item(Item={
        "payout_id": mid, "method_id": mid, "user_id": uid, "record_kind": "payout_method",
        "method_type": "bank_ach", "account_last4": last4, "routing_last4": "0021",
        "method_status": "verified", "is_default": True, "created_at": NOW, "updated_at": NOW,
    })
    created_payout_ids.append(mid)
    return mid


try:
    # ----- seed ledger: 100000 past-hold (available), 50000 within-hold (held)
    seed_credit(U1, 100000, NOW - HOLD - 86400)      # available pool
    seed_credit(U1, 50000, NOW - 3600)               # held (inside hold window)
    seed_credit(U1, 7777, NOW - HOLD - 100, reversed_=True)  # reversed -> ignored

    method_id = seed_method(U1, "6789")

    # ----- seed payouts (mix of states)
    p_paid = seed_payout(U1, 20000, "completed", method_id=method_id,
                         completed_at=NOW - 400, transfer_provider="mock",
                         transfer_ref="mock_transfer_payfverify", transfer_attempts=1)
    seed_payout_debit(U1, 20000, NOW - 400)          # settled debit -> lifetime paid

    p_failed = seed_payout(U1, 15000, "returned", method_id=method_id,
                          fail_reason="bank returned R01", debit_reversed=True)
    seed_payout_debit(U1, 15000, NOW - 300, reversed_=True)  # reversed -> NOT counted

    p_held = seed_payout(U1, 10000, "requested", method_id=method_id,
                        manual_hold=True, hold_reason="manual review", held_at=NOW - 200,
                        held_by="admin_x")
    p_req = seed_payout(U1, 5000, "requested", method_id=method_id)

    # ---------------------------------------------------------------- WALLET
    w = cp.get_wallet_summary(U1)
    print("WALLET_SUMMARY:", w)
    check("total_earned==150000", w["total_earned_cents"] == 150000, str(w["total_earned_cents"]))
    check("held==50000", w["held_cents"] == 50000, str(w["held_cents"]))
    check("held_count==1", w["held_count"] == 1, str(w["held_count"]))
    check("held_release_at set (~now-3600+HOLD)", w["held_release_at"] == (NOW - 3600) + HOLD, str(w["held_release_at"]))
    check("pending==15000", w["pending_cents"] == 15000, str(w["pending_cents"]))
    check("pending_count==2", w["pending_count"] == 2, str(w["pending_count"]))
    check("lifetime_paid==20000", w["lifetime_paid_cents"] == 20000, str(w["lifetime_paid_cents"]))
    check("available==65000", w["available_cents"] == 65000, str(w["available_cents"]))

    # reconcile vs the raw PAY-A balance (single source of truth)
    bal = cp.get_available_balance(U1)
    check("wallet.available==balance.available", w["available_cents"] == bal["available_cents"], f"{w['available_cents']} vs {bal['available_cents']}")
    check("reconcile avail = pastHold - paid - pending",
          w["available_cents"] == 100000 - w["lifetime_paid_cents"] - w["pending_cents"], str(w["available_cents"]))

    # ---------------------------------------------------------------- HISTORY
    hist = cp.list_user_payouts(U1, limit=25)
    ids = {i["payout_id"] for i in hist["items"]}
    check("history has 4 payouts", len({p_paid, p_failed, p_held, p_req} & ids) == 4, f"{len(ids)} items")
    statuses = sorted(i["status"] for i in hist["items"] if i["payout_id"] in {p_paid, p_failed, p_held, p_req})
    check("history statuses", statuses == ["completed", "requested", "requested", "returned"], str(statuses))
    check("history excludes method row", method_id not in ids, "method row not listed")

    # ---------------------------------------------------------------- STATEMENT
    d_paid = cp.get_payout_detail(U1, p_paid)
    check("paid.status completed", d_paid["status"] == "completed", d_paid["status"])
    check("paid.method_last4==6789", d_paid["method_last4"] == "6789", d_paid["method_last4"])
    check("paid.transfer_ref", d_paid["transfer_ref"] == "mock_transfer_payfverify", d_paid["transfer_ref"])
    tl_statuses = [e["status"] for e in d_paid["timeline"]]
    check("paid.timeline has requested+processing+paid",
          "requested" in tl_statuses and "processing" in tl_statuses and "paid" in tl_statuses, str(tl_statuses))

    d_failed = cp.get_payout_detail(U1, p_failed)
    check("failed.status returned", d_failed["status"] == "returned", d_failed["status"])
    check("failed.fail_reason", d_failed["fail_reason"] == "bank returned R01", d_failed["fail_reason"])
    check("failed.debit_reversed True", d_failed["debit_reversed"] is True, str(d_failed["debit_reversed"]))
    check("failed.timeline has returned", any(e["status"] == "returned" for e in d_failed["timeline"]), str([e["status"] for e in d_failed["timeline"]]))

    d_held = cp.get_payout_detail(U1, p_held)
    check("held.manual_hold True", d_held["manual_hold"] is True, str(d_held["manual_hold"]))
    check("held.hold_reason", d_held["hold_reason"] == "manual review", d_held["hold_reason"])
    check("held.timeline has held event", any(e["status"] == "held" for e in d_held["timeline"]), str([e["status"] for e in d_held["timeline"]]))

    # ---------------------------------------------------------------- SCOPING
    scoped = False
    try:
        cp.get_payout_detail(U2, p_paid)
    except PermissionError:
        scoped = True
    check("cross-user detail -> PermissionError (403)", scoped, "U2 blocked from U1 payout")

    u2_hist = cp.list_user_payouts(U2, limit=25)
    u2_ids = {i["payout_id"] for i in u2_hist["items"]}
    check("U2 history excludes U1 payouts", not ({p_paid, p_failed, p_held, p_req} & u2_ids), f"{len(u2_ids)} items")

    u2_wallet = cp.get_wallet_summary(U2)
    check("U2 wallet all-zero", u2_wallet["available_cents"] == 0 and u2_wallet["lifetime_paid_cents"] == 0 and u2_wallet["pending_cents"] == 0, str(u2_wallet))

    missing = False
    try:
        cp.get_payout_detail(U1, "payout_does_not_exist_xyz")
    except LookupError:
        missing = True
    check("unknown payout -> LookupError (404)", missing, "not found")

finally:
    # ---------------------------------------------------------------- CLEANUP
    for pid in created_payout_ids:
        try:
            T.creator_payouts.delete_item(Key={"payout_id": pid})
        except Exception as e:
            print("cleanup payout err", pid, e)
    for pk, sk in created_ledger_keys:
        try:
            T.billing.delete_item(Key={"pk": pk, "sk": sk})
        except Exception as e:
            print("cleanup ledger err", pk, sk, e)
    print("CLEANED", len(created_payout_ids), "payout rows,", len(created_ledger_keys), "ledger rows")

passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
print(f"\nOVERALL {'ALL_PASS' if passed == total else 'FAIL'} {passed}/{total}")
