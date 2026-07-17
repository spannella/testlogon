"""Focused live check: reverse_ad_charge clawback_only fork (DISP-033) — proves a
chargeback on an ad charge claws the creator + backs out spend but does NOT
re-credit the advertiser balance, vs the normal (full) reversal which does."""
import uuid
from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts
from app.services.billing_shared import user_pk
from app.services.ad_billing import reverse_ad_charge, new_ledger_entry

R = uuid.uuid4().hex[:6]
results = []
def rec(n, ok, d=""):
    results.append((n, ok, d)); print("PASS" if ok else "FAIL", n, "-", d)

def seed(mode):
    acct = f"adacct_{mode}_{R}"
    creator = f"adcreator_{mode}_{R}"
    camp = f"camp_{mode}_{R}"
    entry_id = f"chg_{mode}_{R}"
    amount = 1000
    creator_share = 700
    platform_share = 300
    # advertiser account with a starting balance + lifetime spend already booked
    T.ad_accounts.put_item(Item={"pk": f"ACCT#{acct}", "sk": "META",
                                 "balance_cents": 5000, "lifetime_spend_cents": amount})
    T.ad_campaigns.put_item(Item={"pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}",
                                  "spent_today_cents": amount, "lifetime_spent_cents": amount})
    # creator revenue credit (type=credit)
    csk, citem = new_ledger_entry(key_name="pk", key_value=user_pk(creator),
                                  entry_type="credit", amount_cents=creator_share, state="settled",
                                  reason="ad revenue", meta={"content_type": "ad", "campaign_id": camp})
    T.billing.put_item(Item=citem)
    # the ad charge ledger entry the reversal keys off
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{acct}", "sk": f"LEDGER#{now_ts()}#{entry_id}", "entry_id": entry_id,
        "account_id": acct, "campaign_id": camp, "entry_type": "click_charge",
        "amount_cents": amount, "state": "settled",
        "meta": {"creator_id": creator, "creator_share_cents": creator_share,
                 "platform_share_cents": platform_share, "creator_credit_sk": csk}})
    return acct, creator, camp, entry_id, creator_share

def acct_balance(acct):
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0)), int(it.get("lifetime_spend_cents", 0))

def creator_credit_state(creator, camp):
    for r in T.billing.query(KeyConditionExpression="pk=:p",
                             ExpressionAttributeValues={":p": user_pk(creator)}).get("Items", []):
        if (r.get("meta") or {}).get("campaign_id") == camp and r.get("type") == "credit":
            return r.get("state")
    return None

def has_clawback(creator):
    for r in T.billing.query(KeyConditionExpression="pk=:p",
                             ExpressionAttributeValues={":p": user_pk(creator)}).get("Items", []):
        if str(r.get("type")) == "ad_revenue_reversal":
            return int(r.get("amount_cents", 0))
    return None

def cleanup(acct, creator, camp):
    for pk in (f"ACCT#{acct}",):
        for tbl in (T.ad_accounts, T.ad_campaigns, T.ad_billing):
            for r in tbl.query(KeyConditionExpression="pk=:p", ExpressionAttributeValues={":p": pk}).get("Items", []):
                tbl.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
    for r in T.billing.query(KeyConditionExpression="pk=:p", ExpressionAttributeValues={":p": user_pk(creator)}).get("Items", []):
        T.billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})

# --- full reversal: advertiser IS refunded ---
acct, creator, camp, eid, cshare = seed("full")
bal0, _ = acct_balance(acct)
reverse_ad_charge(account_id=acct, entry_id=eid, reason="admin", actor="t", clawback_only=False)
bal1, spend1 = acct_balance(acct)
rec("ad FULL reversal refunds advertiser balance (+amount)", bal1 == bal0 + 1000, f"bal {bal0}->{bal1}")
rec("ad FULL reversal claws creator (state reversed + ad_revenue_reversal)",
    creator_credit_state(creator, camp) == "reversed" and has_clawback(creator) == cshare,
    f"state={creator_credit_state(creator,camp)} claw={has_clawback(creator)}")
cleanup(acct, creator, camp)

# --- clawback-only (chargeback): advertiser NOT refunded, creator still clawed ---
acct, creator, camp, eid, cshare = seed("cb")
bal0, spend0 = acct_balance(acct)
reverse_ad_charge(account_id=acct, entry_id=eid, reason="chargeback", actor="t", clawback_only=True)
bal1, spend1 = acct_balance(acct)
rec("ad CLAWBACK-ONLY does NOT refund advertiser balance (unchanged)", bal1 == bal0, f"bal {bal0}->{bal1}")
rec("ad CLAWBACK-ONLY still backs out lifetime spend", spend1 == spend0 - 1000, f"spend {spend0}->{spend1}")
rec("ad CLAWBACK-ONLY still claws creator (state reversed + reversal row)",
    creator_credit_state(creator, camp) == "reversed" and has_clawback(creator) == cshare,
    f"state={creator_credit_state(creator,camp)} claw={has_clawback(creator)}")
cleanup(acct, creator, camp)

npass = sum(1 for _, ok, _ in results if ok)
print(f"\n==== AD CLAWBACK CHECK: {npass}/{len(results)} PASS ====")
