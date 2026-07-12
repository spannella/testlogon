#!/usr/bin/env python3
"""In-process prod-DDB verify for ADV2 residuals R1 + R2.

R1 syndicate-aware reversal: advertiser refunded full, member credit reversed
(withdrawable excludes it), treasury debited back its share, platform reversed,
SUM reversed == charge; repeat reverse = idempotent no-op; non-syndicate reverse
unchanged. R2: AdClicks.charged_cents == the real charge across surfaces.
"""
import time
import uuid

from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_billing, ad_serving, broadcast_ads, syndicate_treasury
from app.services.ad_accounts import get_ad_account  # noqa: F401
from app.services.creator_payouts import get_available_balance

SUF = uuid.uuid4().hex[:10]
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), name, "|", detail)


def _fund_acct(acct, balance, owner_type="user", synd=""):
    item = {
        "pk": f"ACCT#{acct}", "sk": "META", "account_id": acct,
        "balance_cents": balance, "lifetime_spend_cents": 0,
        "status": "active", "owner_type": owner_type,
        "company_name": "VerifyCo", "owner_sub": f"admin_{SUF}",
    }
    if synd:
        item["owner_syndicate_id"] = synd
    T.ad_accounts.put_item(Item=item)


def _seed_campaign(acct, camp):
    T.ad_campaigns.put_item(Item={
        "pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}", "campaign_id": camp,
        "account_id": acct, "status": "active", "objective": "awareness",
        "budget_cents": 100_000_000, "lifetime_spent_cents": 0,
        "spent_today_cents": 0, "bid_cpm_cents": 20000, "bid_cpc_cents": 55,
        "bid_cpa_cents": 500,
    })


def _acct_balance(acct):
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0) or 0)


def _earned(user):
    return int(get_available_balance(user).get("total_earned_cents", 0) or 0)


def _treasury_bal(synd):
    return int(syndicate_treasury.get_treasury_balance(synd).get("balance_cents", 0) or 0)


# ===========================================================================
# SCENARIO A: syndicate 3-way charge + reverse
# ===========================================================================
print("\n=== SCENARIO A: syndicate 3-way charge + reverse ===")
acctA = f"adacct_synA_{SUF}"
campA = f"camp_synA_{SUF}"
synd = f"synd_res_{SUF}"
member = f"member_{SUF}"
CHARGE = 10000
FUND = 5_000_000
_fund_acct(acctA, FUND, owner_type="syndicate", synd=synd)
_seed_campaign(acctA, campA)
# membership + member-share config (6000 bps of the 70% creator share)
T.syndicates.put_item(Item={"pk": f"SYND#{synd}", "sk": f"MEMBER#{member}",
                            "user_id": member, "status": "active", "role": "member"})
T.syndicates.put_item(Item={"pk": f"SYND#{synd}", "sk": "AD_PLACEMENT_CONFIG",
                            "member_share_bps": 6000})

bal0 = _acct_balance(acctA)
earned0 = _earned(member)
tre0 = _treasury_bal(synd)

res = ad_billing._process_charge(
    account_id=acctA, campaign_id=campA, entry_type="impression_charge",
    charge_cents=CHARGE, creator_id=member, reason="verify syndicate charge",
    meta={"model": "cpm", "campaign_id": campA, "creative_id": f"cr_{SUF}",
          "content_id": f"vid_{SUF}"},
)
entryA = res.get("entry_id", "")
# find the charge ledger row (read back the denormalized split)
q = T.ad_billing.query(
    KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq(f"ACCT#{acctA}")
    & __import__("boto3").dynamodb.conditions.Key("sk").begins_with("LEDGER#"))
crow = next((i for i in q.get("Items", []) if i.get("entry_id") == entryA), {})
cmeta = crow.get("meta", {}) or {}
member_share = int(cmeta.get("member_share_cents", 0) or 0)
treasury_share = int(cmeta.get("syndicate_treasury_share_cents", 0) or 0)
creator_share = int(cmeta.get("creator_share_cents", 0) or 0)
platform_share = int(cmeta.get("platform_share_cents", 0) or 0)
is_syn = bool(cmeta.get("is_syndicate_split"))
print(f"charge denorm: is_syn={is_syn} member={member_share} treasury={treasury_share} "
      f"creator_share={creator_share} platform={platform_share}")

bal1 = _acct_balance(acctA)
earned1 = _earned(member)
tre1 = _treasury_bal(synd)
check("A.charge_is_syndicate_split", is_syn, f"is_syndicate_split={is_syn}")
check("A.charge_debit", bal0 - bal1 == CHARGE, f"debit={bal0-bal1}")
check("A.member_credited", earned1 - earned0 == member_share and member_share > 0,
      f"member earned +{earned1-earned0} (share={member_share})")
check("A.treasury_credited", tre1 - tre0 == treasury_share and treasury_share > 0,
      f"treasury +{tre1-tre0} (share={treasury_share})")
check("A.split_sums_to_charge",
      member_share + treasury_share + platform_share == CHARGE,
      f"{member_share}+{treasury_share}+{platform_share}={member_share+treasury_share+platform_share}")

# --- REVERSE ---
rev = ad_billing.reverse_ad_charge(account_id=acctA, entry_id=entryA, reason="verify_reversal")
print("reverse receipt:", {k: rev.get(k) for k in
      ("refunded_cents", "creator_clawback_cents", "treasury_debit_cents",
       "platform_reversal_cents", "is_syndicate_split", "idempotent_replay")})
bal2 = _acct_balance(acctA)
earned2 = _earned(member)
tre2 = _treasury_bal(synd)
refunded = int(rev.get("refunded_cents", 0) or 0)
claw = int(rev.get("creator_clawback_cents", 0) or 0)
tdebit = int(rev.get("treasury_debit_cents", 0) or 0)
prev = int(rev.get("platform_reversal_cents", 0) or 0)
check("A.advertiser_refunded_full", bal2 - bal1 == CHARGE and refunded == CHARGE,
      f"balance +{bal2-bal1}, receipt refunded={refunded}")
check("A.member_credit_reversed_excluded", earned2 == earned0,
      f"member earned back to {earned2} (was {earned0}, peaked {earned1})")
check("A.treasury_debited_back", tre2 == tre0 and tdebit == treasury_share,
      f"treasury back to {tre2} (was {tre0}); receipt treasury_debit={tdebit}")
check("A.reversal_components_sum_eq_charge", claw + tdebit + prev == CHARGE,
      f"{claw}+{tdebit}+{prev}={claw+tdebit+prev} (charge={CHARGE})")
check("A.clawback_is_member_share_not_full", claw == member_share,
      f"clawback={claw} member_share={member_share} (full creator_share={creator_share})")

# ===========================================================================
# SCENARIO B: repeat reverse = idempotent no-op
# ===========================================================================
print("\n=== SCENARIO B: repeat reverse idempotent ===")
balB0 = _acct_balance(acctA)
treB0 = _treasury_bal(synd)
earnB0 = _earned(member)
rev2 = ad_billing.reverse_ad_charge(account_id=acctA, entry_id=entryA, reason="verify_reversal")
balB1 = _acct_balance(acctA)
treB1 = _treasury_bal(synd)
earnB1 = _earned(member)
check("B.idempotent_replay_flag", rev2.get("idempotent_replay") is True,
      f"idempotent_replay={rev2.get('idempotent_replay')}")
check("B.no_extra_refund", balB1 == balB0, f"balance {balB0}->{balB1}")
check("B.no_extra_treasury_move", treB1 == treB0, f"treasury {treB0}->{treB1}")
check("B.no_extra_member_move", earnB1 == earnB0, f"earned {earnB0}->{earnB1}")
check("B.replay_receipt_numbers",
      int(rev2.get("refunded_cents", 0)) == CHARGE
      and int(rev2.get("treasury_debit_cents", 0)) == treasury_share
      and int(rev2.get("creator_clawback_cents", 0)) == member_share,
      f"replay refunded={rev2.get('refunded_cents')} treasury={rev2.get('treasury_debit_cents')} "
      f"claw={rev2.get('creator_clawback_cents')}")

# ===========================================================================
# SCENARIO C: non-syndicate ad charge reverse still works (unchanged)
# ===========================================================================
print("\n=== SCENARIO C: non-syndicate charge + reverse (unchanged) ===")
acctC = f"adacct_norm_{SUF}"
campC = f"camp_norm_{SUF}"
poster = f"poster_{SUF}"
_fund_acct(acctC, FUND, owner_type="user")
_seed_campaign(acctC, campC)
balC0 = _acct_balance(acctC)
earnC0 = _earned(poster)
resC = ad_billing._process_charge(
    account_id=acctC, campaign_id=campC, entry_type="impression_charge",
    charge_cents=CHARGE, creator_id=poster, reason="verify normal charge",
    meta={"model": "cpm", "campaign_id": campC})
entryC = resC.get("entry_id", "")
qC = T.ad_billing.query(
    KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq(f"ACCT#{acctC}")
    & __import__("boto3").dynamodb.conditions.Key("sk").begins_with("LEDGER#"))
crowC = next((i for i in qC.get("Items", []) if i.get("entry_id") == entryC), {})
cmetaC = crowC.get("meta", {}) or {}
c_creator_share = int(cmetaC.get("creator_share_cents", 0) or 0)
c_platform_share = int(cmetaC.get("platform_share_cents", 0) or 0)
earnC1 = _earned(poster)
check("C.not_syndicate_split", not bool(cmetaC.get("is_syndicate_split")),
      f"is_syndicate_split={cmetaC.get('is_syndicate_split')}")
check("C.creator_credited", earnC1 - earnC0 == c_creator_share and c_creator_share > 0,
      f"poster +{earnC1-earnC0} (share={c_creator_share})")
revC = ad_billing.reverse_ad_charge(account_id=acctC, entry_id=entryC, reason="verify_reversal")
balC1 = _acct_balance(acctC)
earnC2 = _earned(poster)
check("C.advertiser_refunded", balC1 - balC0 == 0 and int(revC.get("refunded_cents", 0)) == CHARGE,
      f"net balance delta={balC1-balC0}, refunded={revC.get('refunded_cents')}")
check("C.creator_clawed_back", earnC2 == earnC0
      and int(revC.get("creator_clawback_cents", 0)) == c_creator_share,
      f"poster earned back to {earnC2}; clawback={revC.get('creator_clawback_cents')}")
check("C.no_treasury_on_normal", int(revC.get("treasury_debit_cents", 0)) == 0,
      f"treasury_debit={revC.get('treasury_debit_cents')}")
check("C.normal_sum_eq_charge",
      int(revC.get("creator_clawback_cents", 0)) + int(revC.get("platform_reversal_cents", 0)) == CHARGE,
      f"claw+plat={int(revC.get('creator_clawback_cents',0))+int(revC.get('platform_reversal_cents',0))}")

# ===========================================================================
# SCENARIO D: R2 charged_cents newsfeed impression + click + dup
# ===========================================================================
print("\n=== SCENARIO D: R2 charged_cents newsfeed impression/click ===")
# disable fraud gate for synthetic events
import app.services.ad_fraud_prevention as _fp


class _NoFraud:
    score = 0
    flagged = False


_fp.check_fraud = lambda **k: _NoFraud()
acctD = f"adacct_nf_{SUF}"
campD = f"camp_nf_{SUF}"
ownerD = f"nfowner_{SUF}"
clickD = f"click_nf_{SUF}"
_fund_acct(acctD, FUND)
_seed_campaign(acctD, campD)
T.ad_clicks.put_item(Item={
    "ad_click_id": clickD, "content_owner_sub": ownerD, "effective_price_cents": 20000,
    "bid_cpc_cents": 55, "account_id": acctD, "campaign_id": campD,
    "creative_id": f"cr_{SUF}", "content_id": f"vid_{SUF}", "status": "served",
    "charged_cents": 0, "self_promo": False,
})


def _click_row(cid):
    return T.ad_clicks.get_item(Key={"ad_click_id": cid}).get("Item") or {}


def _track(event):
    return ad_serving.track_ad_event(
        event=event, creative_id=f"cr_{SUF}", campaign_id=campD, account_id=acctD,
        surface="newsfeed", slot_type="feed", content_id=f"vid_{SUF}",
        creator_id=ownerD, user_id=f"viewer_{SUF}", ad_click_id=clickD, view_time_ms=3000)


ri = _track("impression")
cc_after_imp = int(_click_row(clickD).get("charged_cents", 0) or 0)
rc = _track("click")
cc_after_click = int(_click_row(clickD).get("charged_cents", 0) or 0)
rdup = _track("impression")  # duplicate -> 0
cc_after_dup = int(_click_row(clickD).get("charged_cents", 0) or 0)
imp_charge = int(ri.get("charge_cents", 0) or 0)
click_charge = int(rc.get("charge_cents", 0) or 0)
check("D.impression_charged_cents", cc_after_imp == imp_charge and imp_charge == 20,
      f"charged_cents={cc_after_imp} eff_charge={imp_charge}")
check("D.click_accumulates", cc_after_click == imp_charge + click_charge and click_charge == 55,
      f"charged_cents={cc_after_click} = {imp_charge}+{click_charge}")
check("D.duplicate_no_double_count", cc_after_dup == cc_after_click
      and int(rdup.get("charge_cents", 0)) == 0,
      f"charged_cents stayed {cc_after_dup} on dup (dup charge={rdup.get('charge_cents')})")

# ===========================================================================
# SCENARIO E: R2 charged_cents CTA tap
# ===========================================================================
print("\n=== SCENARIO E: R2 charged_cents CTA ===")
clickE = f"click_cta_{SUF}"
T.ad_clicks.put_item(Item={
    "ad_click_id": clickE, "content_owner_sub": ownerD, "effective_price_cents": 20000,
    "bid_cpc_cents": 77, "account_id": acctD, "campaign_id": campD,
    "creative_id": f"cr_{SUF}", "content_id": f"vid_{SUF}", "status": "served",
    "charged_cents": 0, "self_promo": False,
})
rcta = ad_serving.record_cta_click(ad_click_id=clickE, cta_type="buy_product",
                                   viewer_sub=f"viewer_{SUF}", target_id="prod_1")
cc_cta = int(_click_row(clickE).get("charged_cents", 0) or 0)
cta_charge = int(rcta.get("charge_cents", 0) or 0)
check("E.cta_charged_cents", cc_cta == cta_charge and cta_charge == 77,
      f"charged_cents={cc_cta} eff_charge={cta_charge}")
rcta_dup = ad_serving.record_cta_click(ad_click_id=clickE, cta_type="buy_product",
                                       viewer_sub=f"viewer_{SUF}", target_id="prod_1")
cc_cta_dup = int(_click_row(clickE).get("charged_cents", 0) or 0)
check("E.cta_duplicate_no_double", cc_cta_dup == cc_cta,
      f"charged_cents stayed {cc_cta_dup} (dup charge={rcta_dup.get('charge_cents')})")

# ===========================================================================
# SCENARIO F: R2 broadcast pre-roll + mid-roll completion (clobber fix)
# ===========================================================================
print("\n=== SCENARIO F: R2 broadcast pre-roll/mid-roll charged_cents (no clobber) ===")
for surface, label in (("broadcast_preroll", "F.preroll"), ("broadcast_midroll", "F.midroll")):
    clickF = f"click_{surface}_{SUF}"
    T.ad_clicks.put_item(Item={
        "ad_click_id": clickF, "content_owner_sub": ownerD, "effective_price_cents": 25001,
        "account_id": acctD, "campaign_id": campD, "creative_id": f"cr_{SUF}",
        "content_id": f"sess_{SUF}", "surface": surface, "status": "served",
        "charged_cents": 0, "self_promo": False,
    })
    r1 = broadcast_ads._charge_broadcast_completion(
        ad_click_id=clickF, session_id=f"sess_{SUF}", surface=surface)
    cc1 = int(_click_row(clickF).get("charged_cents", 0) or 0)
    # duplicate completion -> _process_charge returns duplicate (0); must NOT clobber
    r2 = broadcast_ads._charge_broadcast_completion(
        ad_click_id=clickF, session_id=f"sess_{SUF}", surface=surface)
    cc2 = int(_click_row(clickF).get("charged_cents", 0) or 0)
    check(f"{label}_charged_cents_real", cc1 == 25001 and int(r1.get("charge_cents", 0)) == 25001,
          f"charged_cents={cc1} charge={r1.get('charge_cents')}")
    check(f"{label}_dup_not_clobbered", cc2 == 25001 and int(r2.get("charge_cents", 0)) == 0,
          f"charged_cents stayed {cc2} after dup (dup charge={r2.get('charge_cents')})")

# ===========================================================================
print("\n=== SUMMARY ===")
npass = sum(1 for _, ok, _ in RESULTS if ok)
ntot = len(RESULTS)
for name, ok, detail in RESULTS:
    if not ok:
        print("  FAILED:", name, "|", detail)
print(f"OVERALL {'ALL_PASS' if npass == ntot else 'FAIL'} {npass}/{ntot}")
