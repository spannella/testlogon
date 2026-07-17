"""Focused live check: ecom clawback_only fork (DISP-033) via dispatch_reversal —
a chargeback claws the seller (refund_debit) but does NOT credit the buyer
(refund_credit), vs the normal refund which credits the buyer too."""
import uuid
from app.core.tables import T
from app.services.billing_shared import user_pk, new_ledger_entry
from app.services import dispute_dispatch as DD

R = uuid.uuid4().hex[:6]
results = []
def rec(n, ok, d=""):
    results.append((n, ok, d)); print("PASS" if ok else "FAIL", n, "-", d)

def seed(mode):
    buyer = f"ecb_{mode}_{R}"; seller = f"ecs_{mode}_{R}"; order = f"ord_{mode}_{R}"
    gross = 1200
    _, debit = new_ledger_entry(key_name="pk", key_value=user_pk(buyer),
                                entry_type="debit", amount_cents=gross, state="settled",
                                reason="ecom purchase", meta={"content_type": "ecom",
                                "order_id": order, "refund_seller_ids": [seller],
                                "recipient_user_id": seller})
    T.billing.put_item(Item=debit)
    eid = debit["entry_id"]
    _, credit = new_ledger_entry(key_name="pk", key_value=user_pk(seller),
                                 entry_type="credit", amount_cents=gross, state="settled",
                                 reason="ecom sale", meta={"content_type": "ecom", "order_id": order})
    T.billing.put_item(Item=credit)
    return buyer, seller, order, eid, gross

def rows(uid, typ):
    return [r for r in T.billing.query(KeyConditionExpression="pk=:p",
            ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []) if str(r.get("type")) == typ]

def cleanup(*uids):
    for uid in uids:
        for r in T.billing.query(KeyConditionExpression="pk=:p",
                ExpressionAttributeValues={":p": user_pk(uid)}).get("Items", []):
            T.billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})

# --- normal refund: buyer credited + seller clawed ---
buyer, seller, order, eid, gross = seed("full")
DD.dispatch_reversal(charge_type="ecom", charge_ref=eid, payer_id=buyer, recipient_id=seller,
                     clawback_only=False, reason="dispute", actor="t", use_mutex=True)
rec("ecom FULL refund credits buyer (refund_credit) + claws seller (refund_debit)",
    len(rows(buyer, "refund_credit")) == 1 and len(rows(seller, "refund_debit")) == 1,
    f"buyer_credit={len(rows(buyer,'refund_credit'))} seller_debit={len(rows(seller,'refund_debit'))}")
cleanup(buyer, seller)

# --- chargeback clawback-only: seller clawed, buyer NOT credited ---
buyer, seller, order, eid, gross = seed("cb")
DD.dispatch_reversal(charge_type="ecom", charge_ref=eid, payer_id=buyer, recipient_id=seller,
                     clawback_only=True, reason="chargeback", actor="t", use_mutex=True)
rec("ecom CLAWBACK-ONLY claws seller (refund_debit present)",
    len(rows(seller, "refund_debit")) == 1, f"seller_debit={len(rows(seller,'refund_debit'))}")
rec("ecom CLAWBACK-ONLY does NOT credit buyer (no refund_credit)",
    len(rows(buyer, "refund_credit")) == 0, f"buyer_credit={len(rows(buyer,'refund_credit'))}")
cleanup(buyer, seller)

npass = sum(1 for _, ok, _ in results if ok)
print(f"\n==== ECOM CLAWBACK CHECK: {npass}/{len(results)} PASS ====")
