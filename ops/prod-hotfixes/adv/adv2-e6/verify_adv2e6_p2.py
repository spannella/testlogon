"""ADV2-E6 (F7) phase 2 verify -- the 3-way syndicate placement split, in-process
on prod DDB (ADV2-705..708 money-path).

Proves:
  A) SYNDICATE-OWNED ad on member M ($1.00 charge, default 7000 bps): the
     content-owner 70c share splits member 49c (type:credit) + syndicate treasury
     21c (type:credit); platform 30c. The 3 credits SUM EXACTLY to 100c. All
     ledger writes are real (member billing credit row + treasury balance delta).
  B) IDEMPOTENT: re-charging with the same idempotency_key does NOT double-charge
     or double-credit (member credit + treasury balance unchanged).
  C) CONFIGURABLE: set member_share_bps=5000 -> the split shifts to member 35c +
     treasury 35c + platform 30c (still sums to 100c).
  D) EXTERNAL (non-syndicate) advertiser on member M ($1.00): member keeps the
     FULL 70c, platform 30c, syndicate treasury 0 -- NO SKIM (is_syndicate_split
     False, treasury balance unchanged).
  E) FUNDS-GUARD: a syndicate charge that exceeds the ad-account balance is
     rejected (ok False) and writes NO credits.
"""
import uuid
from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates, ad_billing, syndicate_treasury
from app.services import syndicate_revenue_split as srs
from app.services.ad_accounts import create_syndicate_ad_account, get_ad_account
from app.models import AdAccountCreateIn

SUF = uuid.uuid4().hex[:8]
ADMIN = "e6p2_admin_" + SUF
M = "e6p2_member_" + SUF
EXT = "e6p2_extadv_" + SUF

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append({"name": name, "pass": bool(cond)})
    print(("PASS " if cond else "FAIL ") + name + (("  :: " + str(detail)) if detail else ""))


def fund_active(acct_id, bal):
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{acct_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, balance_cents = :b",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "active", ":b": bal},
    )


def put_ext_acct(acct_id, owner, bal):
    T.ad_accounts.put_item(Item={
        "pk": f"ACCT#{acct_id}", "sk": "META", "account_id": acct_id,
        "owner_sub": owner, "owner_type": "user", "status": "active",
        "balance_cents": bal, "lifetime_spend_cents": 0, "created_at": now_ts(),
    })


def treasury_balance(synd):
    return int(syndicate_treasury.get_treasury_balance(synd)["balance_cents"])


def charge_row(acct_id, entry_id):
    resp = T.ad_billing.query(
        KeyConditionExpression=Key("pk").eq(f"ACCT#{acct_id}") & Key("sk").begins_with("LEDGER#"),
    )
    for it in resp.get("Items", []):
        if it.get("entry_id") == entry_id:
            return it
    return {}


def do_charge(acct_id, creator, amount, key):
    return ad_billing._process_charge(
        account_id=acct_id, campaign_id="camp_" + SUF, entry_type="click_charge",
        charge_cents=amount, creator_id=creator, reason="Ad click",
        meta={"creative_id": "cr_" + SUF, "content_id": "post_" + M, "model": "cpc",
              "campaign_id": "camp_" + SUF},
        idempotency_key=key,
    )


def member_credit_amount(sk):
    if not sk:
        return None
    it = T.billing.get_item(Key={"pk": f"USER#{M}", "sk": sk}).get("Item") or {}
    return it


# -- Setup ------------------------------------------------------------------
synd = syndicates.create_syndicate(creator_sub=ADMIN, name="E6P2 Syndicate " + SUF)
synd_id = synd["syndicate_id"]
syndicates._add_member(synd_id, M, role="member")
check("setup: syndicate created + M is a member",
      syndicates.is_member(synd_id, M), f"synd={synd_id}")

acct_S = create_syndicate_ad_account(synd_id, ADMIN, AdAccountCreateIn(
    company_name="E6P2 Syndicate Ads", billing_email="e6p2@syndicate.example"))["account_id"]
check("setup: syndicate ad account owner_type=syndicate",
      (get_ad_account(acct_S) or {}).get("owner_type") == "syndicate", f"acct={acct_S}")
fund_active(acct_S, 5_000_000)

acct_E = "adacct_e6p2ext_" + SUF
put_ext_acct(acct_E, EXT, 5_000_000)

# ==========================================================================
# CASE A: syndicate-owned ad on member M, DEFAULT config (7000 bps)
# ==========================================================================
cfg0 = srs.get_ad_placement_config(synd_id)
check("A: default member_share_bps == 7000 (member keeps 70% of the 70%)",
      cfg0["member_share_bps"] == 7000 and cfg0["treasury_share_bps"] == 3000,
      f"cfg={cfg0['member_share_bps']}/{cfg0['treasury_share_bps']}")

tb0 = treasury_balance(synd_id)
keyA = "e6p2A_" + SUF
rA = do_charge(acct_S, M, 100, keyA)
rowA = charge_row(acct_S, rA.get("entry_id", ""))
mA = (rowA.get("meta") or {})
tb1 = treasury_balance(synd_id)

member_A = int(mA.get("member_share_cents", -1))
treas_A = int(mA.get("syndicate_treasury_share_cents", -1))
plat_A = int(mA.get("platform_share_cents", -1))
creator_A = int(mA.get("creator_share_cents", -1))

check("A: charge succeeded ($1.00 debited, funds-guarded)",
      rA.get("ok") and rA.get("charge_cents") == 100, rA)
check("A: is_syndicate_split=True + syndicate_id on the charge row",
      mA.get("is_syndicate_split") is True and mA.get("syndicate_id") == synd_id, mA.get("syndicate_id"))
check("A: content-owner share == 70c (creator 7000 bps default)", creator_A == 70, creator_A)
check("A: member share == 49c (70% of the 70c)", member_A == 49, member_A)
check("A: syndicate treasury share == 21c (remainder of the 70c)", treas_A == 21, treas_A)
check("A: platform share == 30c (unchanged)", plat_A == 30, plat_A)
check("A: 3-way SUM == charge (member+treasury+platform == 100c, no drop/no double)",
      member_A + treas_A + plat_A == 100, f"{member_A}+{treas_A}+{plat_A}")
check("A: treasury BALANCE increased by exactly 21c (real credit)",
      tb1 - tb0 == 21, f"delta={tb1 - tb0}")
mcA = member_credit_amount(mA.get("creator_credit_sk", ""))
check("A: member billing credit row is type:credit for 49c",
      mcA.get("type") == "credit" and int(mcA.get("amount_cents", 0)) == 49,
      f"type={mcA.get('type')} amt={mcA.get('amount_cents')}")

# ==========================================================================
# CASE B: IDEMPOTENT re-charge (same key) does not double
# ==========================================================================
rB = do_charge(acct_S, M, 100, keyA)
tb2 = treasury_balance(synd_id)
check("B: duplicate charge (same idempotency_key) is a no-op (charge_cents 0)",
      rB.get("charge_cents") == 0 and rB.get("reason") == "duplicate", rB)
check("B: treasury balance UNCHANGED after the duplicate (no double-credit)",
      tb2 == tb1, f"tb1={tb1} tb2={tb2}")

# ==========================================================================
# CASE C: CONFIGURABLE -- set member_share_bps=5000 -> split shifts
# ==========================================================================
srs.set_ad_placement_member_share_bps(syndicate_id=synd_id, admin_sub=ADMIN, member_share_bps=5000)
cfg1 = srs.get_ad_placement_config(synd_id)
check("C: config updated member_share_bps -> 5000", cfg1["member_share_bps"] == 5000, cfg1)

tb3 = treasury_balance(synd_id)
keyC = "e6p2C_" + SUF
rC = do_charge(acct_S, M, 100, keyC)
mC = (charge_row(acct_S, rC.get("entry_id", "")).get("meta") or {})
tb4 = treasury_balance(synd_id)
member_C = int(mC.get("member_share_cents", -1))
treas_C = int(mC.get("syndicate_treasury_share_cents", -1))
plat_C = int(mC.get("platform_share_cents", -1))
check("C: split SHIFTED -> member 35c + treasury 35c + platform 30c",
      member_C == 35 and treas_C == 35 and plat_C == 30, f"{member_C}/{treas_C}/{plat_C}")
check("C: shifted 3-way still SUMS to 100c", member_C + treas_C + plat_C == 100,
      f"{member_C}+{treas_C}+{plat_C}")
check("C: treasury balance increased by exactly 35c under the new ratio",
      tb4 - tb3 == 35, f"delta={tb4 - tb3}")

# ==========================================================================
# CASE D: EXTERNAL advertiser on member M -> NO SKIM
# ==========================================================================
tb5 = treasury_balance(synd_id)
keyD = "e6p2D_" + SUF
rD = do_charge(acct_E, M, 100, keyD)
mD = (charge_row(acct_E, rD.get("entry_id", "")).get("meta") or {})
tb6 = treasury_balance(synd_id)
member_D = int(mD.get("member_share_cents", -1))
treas_D = int(mD.get("syndicate_treasury_share_cents", -1))
plat_D = int(mD.get("platform_share_cents", -1))
check("D: EXTERNAL ad -> is_syndicate_split False (no 3-way)",
      not mD.get("is_syndicate_split") and not mD.get("syndicate_id"), mD.get("is_syndicate_split"))
check("D: member keeps the FULL 70c (membership does NOT skim external earnings)",
      member_D == 70, member_D)
check("D: syndicate treasury share == 0 (NO skim)", treas_D == 0, treas_D)
check("D: platform 30c; external 2-way SUMS to 100c", plat_D == 30 and member_D + treas_D + plat_D == 100,
      f"{member_D}+{treas_D}+{plat_D}")
check("D: treasury balance UNCHANGED by the external ad", tb6 == tb5, f"tb5={tb5} tb6={tb6}")
mcD = member_credit_amount(mD.get("creator_credit_sk", ""))
check("D: member billing credit row is type:credit for the full 70c",
      mcD.get("type") == "credit" and int(mcD.get("amount_cents", 0)) == 70,
      f"type={mcD.get('type')} amt={mcD.get('amount_cents')}")

# ==========================================================================
# CASE E: FUNDS-GUARD on a syndicate charge
# ==========================================================================
acct_LOW = create_syndicate_ad_account(synd_id, ADMIN, AdAccountCreateIn(
    company_name="E6P2 Low Ads", billing_email="low@syndicate.example"))["account_id"]
fund_active(acct_LOW, 10)  # only 10c
tb7 = treasury_balance(synd_id)
rE = do_charge(acct_LOW, M, 100, "e6p2E_" + SUF)
tb8 = treasury_balance(synd_id)
check("E: funds-guard rejects an over-balance syndicate charge (ok False)",
      not rE.get("ok") and rE.get("reason") == "insufficient_funds", rE)
check("E: rejected charge writes NO treasury credit", tb8 == tb7, f"tb7={tb7} tb8={tb8}")

# -- Summary ----------------------------------------------------------------
npass = sum(1 for r in RESULTS if r["pass"])
ntot = len(RESULTS)
print(f"\nADV2-E6 phase2 verify: {npass}/{ntot} " +
      ("OVERALL ALL_PASS" if npass == ntot else "*** SOME FAILED ***"))
print(f"synd_id={synd_id} acct_S={acct_S} acct_E={acct_E} member={M}")
