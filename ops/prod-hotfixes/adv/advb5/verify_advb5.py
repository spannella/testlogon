"""ADV-B5 prod in-process verify: drive a campaign -> ROAS -> reverse.

Writes throwaway rows (unique account/campaign ids) into the real prod tables,
mirroring verify_advb3/advb4. MONEY = int cents.
"""
import time
from app.core.tables import T
from app.services import ad_billing, ad_roas

TS = int(time.time())
ACCT = f"advb5v_{TS}"
CAMP = f"campv_{TS}"
POSTER = f"posterv_{TS}"
OWNER = f"ownerv_{TS}"
OUT = []


def log(*a):
    OUT.append(" ".join(str(x) for x in a))


def bal():
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{ACCT}", "sk": "META"}).get("Item")
    return int(it.get("balance_cents", 0)) if it else 0


# seed account + campaign
T.ad_accounts.put_item(Item={"pk": f"ACCT#{ACCT}", "sk": "META", "account_id": ACCT,
                             "owner_sub": OWNER, "balance_cents": 100000})
T.ad_campaigns.put_item(Item={"pk": f"ACCT#{ACCT}", "sk": f"CAMPAIGN#{CAMP}",
                              "campaign_id": CAMP, "account_id": ACCT,
                              "budget_cents": 1000000, "status": "active",
                              "bid_cpm_cents": 500, "bid_cpc_cents": 50, "bid_cpa_cents": 500})

start = bal()
log("HAS_REVERSE", hasattr(ad_billing, "reverse_ad_charge"))
log("HAS_ROAS", hasattr(ad_roas, "roas_report"))
from app.services import ad_serving
log("HAS_CLEAR", hasattr(ad_serving, "clear_second_price"))
log("CLEAR_2ND_PRICE 20000/15000 ->", ad_serving.clear_second_price(20000, 15000), "(expect 15001)")
log("CLEAR_LONE 20000/None ->", ad_serving.clear_second_price(20000, None), "(expect 50)")

# serve->impression->click->conversion (money path)
r_imp = ad_billing.charge_impression(account_id=ACCT, campaign_id=CAMP, creative_id="crV",
                                     creator_id="", content_id="cV", bid_cpm_cents=5000)
r_clk = ad_billing.charge_click(account_id=ACCT, campaign_id=CAMP, creative_id="crV",
                                creator_id="", content_id="cV", bid_cpc_cents=50)
r_cnv = ad_billing.charge_conversion(account_id=ACCT, campaign_id=CAMP, creative_id="crV",
                                     creator_id=POSTER, content_id="vidV", bid_cpa_cents=500,
                                     conversion_value_cents=1999)
log("IMP", r_imp.get("charge_cents"), "CLICK", r_clk.get("charge_cents"), "CONV", r_cnv.get("charge_cents"))
log("BALANCE after charges", bal(), "expect", start - 5 - 50 - 500)

# idempotent click (repeat key) must not double-charge
key = f"idemp#{TS}"
a = ad_billing.charge_click(account_id=ACCT, campaign_id=CAMP, creative_id="crV",
                            creator_id="", content_id="cV", bid_cpc_cents=50, idempotency_key=key)
b = ad_billing.charge_click(account_id=ACCT, campaign_id=CAMP, creative_id="crV",
                            creator_id="", content_id="cV", bid_cpc_cents=50, idempotency_key=key)
log("IDEMP first", a.get("charge_cents"), "repeat", b.get("charge_cents"), b.get("reason"))

# ROAS endpoint (ADV-501)
rep = ad_roas.roas_report(ACCT, days=30)
tot = rep["totals"]
log("ROAS totals:", {k: tot[k] for k in ("impressions","clicks","conversions","spend_cents",
                                         "conversion_value_cents","ctr_pct","cpa_cents","roas")})
log("ROAS campaigns", [c["campaign_id"] for c in rep["campaigns"]])

# creator credit present (video placement -> poster 70%)
from boto3.dynamodb.conditions import Key
pc = T.billing.query(KeyConditionExpression=Key("pk").eq(f"USER#{POSTER}") & Key("sk").begins_with("LEDGER#")).get("Items", [])
log("CREATOR credits", [(c.get("type"), int(c.get("amount_cents",0)), c.get("state")) for c in pc])

# reverse the conversion charge (ADV-502)
conv_entry = [r for r in T.ad_billing.query(
    KeyConditionExpression=Key("pk").eq(f"ACCT#{ACCT}") & Key("sk").begins_with("LEDGER#")
).get("Items", []) if r.get("entry_type") == "conversion_charge"][0]
eid = conv_entry["entry_id"]
bal_before_rev = bal()
rev1 = ad_billing.reverse_ad_charge(account_id=ACCT, entry_id=eid, reason="verify_fraud", actor="verifier")
log("REVERSE1", {k: rev1.get(k) for k in ("reversed","refunded_cents","creator_clawback_cents",
                                          "platform_reversal_cents","idempotent_replay")})
log("BALANCE after reverse", bal(), "was", bal_before_rev, "(refund +", conv_entry.get("amount_cents"), ")")

# creator rows after reverse: original credit flipped reversed + a non-credit clawback
pc2 = T.billing.query(KeyConditionExpression=Key("pk").eq(f"USER#{POSTER}") & Key("sk").begins_with("LEDGER#")).get("Items", [])
credits_only = [c for c in pc2 if c.get("type") == "credit"]
claw = [c for c in pc2 if c.get("type") == "ad_revenue_reversal"]
log("AFTER-REV creator credit rows (type==credit):", [(int(c.get("amount_cents",0)), c.get("state")) for c in credits_only])
log("AFTER-REV clawback rows (type!=credit):", [(c.get("type"), int(c.get("amount_cents",0))) for c in claw])
log("EARNINGS_NOT_INFLATED", all(c.get("type") == "credit" for c in credits_only) and len(claw) == 1)

# idempotent double-reversal guard
rev2 = ad_billing.reverse_ad_charge(account_id=ACCT, entry_id=eid, reason="verify_fraud")
log("REVERSE2 idempotent_replay", rev2.get("idempotent_replay"), "balance", bal(), "(no second refund)")

print("\n".join(OUT))
print("VERIFY_DONE")
