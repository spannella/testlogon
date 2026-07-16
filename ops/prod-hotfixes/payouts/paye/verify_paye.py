"""PAY-E (PAY-40) in-process deep-verify against the live DDB.

Synthetic payees, auto-cleaned. Exercises REAL PAY-A ledger writes/reversals via
creator_payouts._write_payout_debit / reverse_payout_debit so the aggregation is
proven against the same rows the money path writes.
"""
import json
import sys
import types
import uuid

sys.path.insert(0, "/home/ubuntu/testlogon")

from app.core.tables import T
from app.core.time import now_ts
from app.services import creator_payouts as cp
from app.services import tax_info_w9
from app.services import tax_1099 as svc
from app.services.billing_shared import new_ledger_entry

YEAR = svc._year_of(now_ts())  # current calendar year (paid ts falls here)
PRIOR = YEAR - 2
TAG = uuid.uuid4().hex[:8]
SUBS = {}
RESULTS = {}
RAW_TINS = {"P1": "123456789", "P4": "222334444"}


def sub(name):
    s = f"PAYE_TEST_{TAG}_{name}"
    SUBS[name] = s
    return s


def pay(user_sub, amount_cents, payout_id, ts=None):
    """Write a PAY-A-shape paid-payout debit. Uses real _write_payout_debit when
    ts is current; writes a direct row for a back-dated (prior-year) test."""
    if ts is None:
        cp._write_payout_debit({
            "payout_id": payout_id, "user_id": user_sub, "amount_cents": amount_cents,
        })
    else:
        skk, entry = new_ledger_entry(
            key_name="pk", key_value=f"USER#{user_sub}", entry_type="debit",
            amount_cents=amount_cents, state="settled", reason="payout",
            meta={"payout_id": payout_id, "kind": "creator_payout"},
        )
        entry["ts"] = ts
        T.billing.put_item(Item=entry)


def reverse(payout_id):
    return cp.reverse_payout_debit(payout_id)


def submit_w9(user_sub, tin, certified=True):
    tax_info_w9.submit_tax_info(
        user_sub=user_sub, legal_name=f"Legal {user_sub[-6:]}", tin=tin,
        tin_type="ssn", address_line1="1 St", city="Town", state="CA",
        zip_code="90001", certified=certified,
    )


def check(name, cond, detail=""):
    RESULTS[name] = bool(cond)
    print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))


def prior_year_ts():
    import datetime
    return int(datetime.datetime(PRIOR, 6, 1, tzinfo=datetime.timezone.utc).timestamp())


def main():
    # P1: over threshold, certified W-9. 400+300=700 in YEAR; 999 in PRIOR (must not count).
    p1 = sub("P1"); submit_w9(p1, RAW_TINS["P1"])
    pay(p1, 40000, f"po_{TAG}_p1a"); pay(p1, 30000, f"po_{TAG}_p1b")
    pay(p1, 99900, f"po_{TAG}_p1prior", ts=prior_year_ts())

    # P2: under threshold. 100.00 only.
    p2 = sub("P2"); submit_w9(p2, "555443333")
    pay(p2, 10000, f"po_{TAG}_p2a")

    # P3: returned/reversed -> nets to 0.
    p3 = sub("P3"); submit_w9(p3, "666554444")
    pay(p3, 80000, f"po_{TAG}_p3a"); reverse(f"po_{TAG}_p3a")

    # P4: 700+500=1200 reportable; late return of the 500 AFTER generation.
    p4 = sub("P4"); submit_w9(p4, RAW_TINS["P4"])
    pay(p4, 70000, f"po_{TAG}_p4a"); pay(p4, 50000, f"po_{TAG}_p4b")

    # P5: no certified W-9, 1000.00 -> backup withholding.
    p5 = sub("P5")  # no W-9 on file
    pay(p5, 100000, f"po_{TAG}_p5a")

    # ---- Aggregation + generation ----
    r1 = svc.generate_or_refresh(user_sub=p1, tax_year=YEAR)
    check("P1 box1==70000 (year-scoped, prior excluded)", r1["box1_nonemployee_comp_cents"] == 70000, str(r1["box1_nonemployee_comp_cents"]))
    check("P1 reportable True", r1["reportable"] is True)
    check("P1 box4==0 (certified W-9)", r1["box4_backup_withholding_cents"] == 0)
    check("P1 masked tin ***-**-6789", r1["payee_tin_masked"] == "***-**-6789", r1["payee_tin_masked"])

    r2 = svc.generate_or_refresh(user_sub=p2, tax_year=YEAR)
    check("P2 box1==10000", r2["box1_nonemployee_comp_cents"] == 10000)
    check("P2 reportable False (under $600)", r2["reportable"] is False)
    check("P2 queryable via get_1099", svc.get_1099(user_sub=p2, tax_year=YEAR) is not None)

    r3 = svc.generate_or_refresh(user_sub=p3, tax_year=YEAR)
    check("P3 returned NOT counted -> box1==0", r3["box1_nonemployee_comp_cents"] == 0, str(r3["box1_nonemployee_comp_cents"]))
    check("P3 reversed_excluded==80000 (reconciles)", r3["reversed_excluded_cents"] == 80000, str(r3["reversed_excluded_cents"]))

    # P4: generate, then late-return, then regenerate -> correction.
    r4a = svc.generate_or_refresh(user_sub=p4, tax_year=YEAR)
    check("P4 pre-correction box1==120000", r4a["box1_nonemployee_comp_cents"] == 120000, str(r4a["box1_nonemployee_comp_cents"]))
    check("P4 initial status generated", r4a["status"] == "generated")
    # idempotent no-op re-run (no change)
    r4noop = svc.generate_or_refresh(user_sub=p4, tax_year=YEAR)
    check("P4 idempotent no-op (still generated, count 0)", r4noop["status"] == "generated" and r4noop["correction_count"] == 0)
    reverse(f"po_{TAG}_p4b")  # late return of the 500
    r4b = svc.generate_or_refresh(user_sub=p4, tax_year=YEAR)
    check("P4 correction box1==70000 (reduced)", r4b["box1_nonemployee_comp_cents"] == 70000, str(r4b["box1_nonemployee_comp_cents"]))
    check("P4 status corrected", r4b["status"] == "corrected", r4b["status"])
    check("P4 correction_count==1", r4b["correction_count"] == 1, str(r4b["correction_count"]))
    check("P4 prior_box1==120000 recorded", r4b["prior_box1_cents"] == 120000, str(r4b["prior_box1_cents"]))
    check("P4 still reportable (>=600)", r4b["reportable"] is True)

    r5 = svc.generate_or_refresh(user_sub=p5, tax_year=YEAR)
    check("P5 box1==100000", r5["box1_nonemployee_comp_cents"] == 100000)
    check("P5 backup_withholding applies", r5["backup_withholding_applies"] is True)
    check("P5 box4==24000 (24%)", r5["box4_backup_withholding_cents"] == 24000, str(r5["box4_backup_withholding_cents"]))
    check("P5 reason no_certified_w9", r5["backup_withholding_reason"] == "no_certified_w9", r5["backup_withholding_reason"])

    # ---- Withholding gap report ----
    wr = svc.withholding_gap_report(tax_year=YEAR)
    p5_in = any(row["user_sub"] == p5 for row in wr["payees"])
    check("Withholding report includes P5", p5_in)
    check("Withholding report total >= 24000", wr["total_would_be_withheld_cents"] >= 24000)

    # ---- Export masks TIN; raw absent ----
    csv_c, csv_ct = svc.export_year(tax_year=YEAR, fmt="csv", include_under_threshold=True)
    json_c, json_ct = svc.export_year(tax_year=YEAR, fmt="json", include_under_threshold=True)
    raw_absent = all(t not in csv_c and t not in json_c for t in RAW_TINS.values())
    check("Export raw TIN ABSENT (csv+json)", raw_absent)
    check("Export masked TIN present", "***-**-6789" in csv_c and "***-**-6789" in json_c)
    check("Export csv content-type", csv_ct == "text/csv")
    # no-raw-TIN proof at rest: stored record has no 9-digit tin field
    stored = T.tax_forms_1099.get_item(Key={"pk": f"USER#{p1}", "sk": svc._rec_sk(YEAR)}).get("Item")
    no_raw_at_rest = all(RAW_TINS["P1"] != str(v) for v in stored.values())
    check("No raw TIN in stored NEC record", no_raw_at_rest)

    # ---- admin-gate 403 (in-process) ----
    from app.auth.policy import require_roles
    from app.auth.roles import Role
    from fastapi import HTTPException
    non_admin = types.SimpleNamespace(role="consumer")
    admin_user = types.SimpleNamespace(role="admin")
    gate_403 = False
    try:
        require_roles(non_admin, {Role.ADMIN, Role.ROOT})
    except HTTPException as e:
        gate_403 = (e.status_code == 403)
    check("Admin-gate: non-admin -> 403", gate_403)
    admin_ok = False
    try:
        require_roles(admin_user, {Role.ADMIN, Role.ROOT})
        admin_ok = True
    except HTTPException:
        admin_ok = False
    check("Admin-gate: admin passes", admin_ok)

    # ---- year set summary ----
    ys = svc.generate_year_set(tax_year=YEAR)
    print("YEAR_SET_SUMMARY " + json.dumps(ys))
    print("CSV_SAMPLE:\n" + "\n".join(csv_c.splitlines()[:8]))

    passed = sum(1 for v in RESULTS.values() if v)
    print(f"\nMATRIX {passed}/{len(RESULTS)} passed")
    return 0 if passed == len(RESULTS) else 1


def cleanup():
    n = 0
    for s in SUBS.values():
        # billing ledger rows
        try:
            from boto3.dynamodb.conditions import Key as K
            resp = T.billing.query(KeyConditionExpression=K("pk").eq(f"USER#{s}"))
            for it in resp.get("Items", []):
                T.billing.delete_item(Key={"pk": it["pk"], "sk": it["sk"]}); n += 1
        except Exception as e:
            print("cleanup billing err", e)
        # tax_info W-9 + audit
        try:
            T.tax_info.delete_item(Key={"pk": f"USER#{s}", "sk": "TAX_INFO"}); n += 1
        except Exception:
            pass
        # tax_forms_1099 NEC records + history
        try:
            from boto3.dynamodb.conditions import Key as K
            resp = T.tax_forms_1099.query(KeyConditionExpression=K("pk").eq(f"USER#{s}"))
            for it in resp.get("Items", []):
                T.tax_forms_1099.delete_item(Key={"pk": it["pk"], "sk": it["sk"]}); n += 1
        except Exception as e:
            print("cleanup 1099 err", e)
    # payout debit markers in creator_payouts (payout_id=PAYOUTDEBIT#po_TAG_*)
    for pid in ["p1a", "p1b", "p1prior", "p2a", "p3a", "p4a", "p4b", "p5a"]:
        try:
            T.creator_payouts.delete_item(Key={"payout_id": f"PAYOUTDEBIT#po_{TAG}_{pid}"}); n += 1
        except Exception:
            pass
    print(f"CLEANUP removed ~{n} rows for tag {TAG}")


if __name__ == "__main__":
    rc = 1
    try:
        rc = main()
    finally:
        cleanup()
    sys.exit(rc)
