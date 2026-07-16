"""ADV3 EPIC E1 verification harness (service-level, real DDB engine via moto +
real stripe-mock money rail). Zero prod-DDB residue: this process spins up its
own in-memory moto DynamoDB, exercises the EXACT patched service functions, and
discards everything on exit. Stripe calls hit the shared stripe-mock at
$STRIPE_API_BASE (localhost:12111), same rail tips/subs/ads use.
"""
import os, sys, traceback, uuid, time
from concurrent.futures import ThreadPoolExecutor

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)

# ---- boot moto BEFORE any app import ----
from moto import mock_aws
_mock = mock_aws(); _mock.start()
import boto3
REGION = os.environ.get("AWS_REGION", "us-east-1")
ddb = boto3.resource("dynamodb", region_name=REGION)
client = ddb.meta.client

from app.core.settings import S

def mktable(name, hash_k, range_k=None, gsis=None, num_attrs=None):
    num_attrs = num_attrs or set()
    attrs = {hash_k: "S"}
    if range_k: attrs[range_k] = "S"
    ks = [{"AttributeName": hash_k, "KeyType": "HASH"}]
    if range_k: ks.append({"AttributeName": range_k, "KeyType": "RANGE"})
    gsi_defs = []
    for g in (gsis or []):
        attrs.setdefault(g["pk"], "S")
        gk = [{"AttributeName": g["pk"], "KeyType": "HASH"}]
        if g.get("sk"):
            attrs.setdefault(g["sk"], "S")
            gk.append({"AttributeName": g["sk"], "KeyType": "RANGE"})
        gsi_defs.append({"IndexName": g["name"], "KeySchema": gk,
                         "Projection": {"ProjectionType": "ALL"}})
    for a in num_attrs:
        attrs[a] = "N"
    kwargs = dict(TableName=name,
                  AttributeDefinitions=[{"AttributeName": k, "AttributeType": v} for k, v in attrs.items()],
                  KeySchema=ks, BillingMode="PAY_PER_REQUEST")
    if gsi_defs:
        kwargs["GlobalSecondaryIndexes"] = gsi_defs
    try:
        client.create_table(**kwargs)
    except client.exceptions.ResourceInUseException:
        pass

mktable(S.ad_accounts_table_name, "pk", "sk")
mktable(S.ad_campaigns_table_name, "pk", "sk",
        gsis=[{"name": "ByStatusCreatedAt", "pk": "status", "sk": "created_at"},
              {"name": "ByCampaignId", "pk": "campaign_id", "sk": "created_at"}],
        num_attrs={"created_at"})
mktable(S.ad_billing_table_name, "pk", "sk",
        gsis=[{"name": "ByCampaign", "pk": "campaign_id", "sk": "created_at"},
              {"name": "ByMonth", "pk": "month_key", "sk": "created_at"}],
        num_attrs={"created_at"})
mktable(S.ad_clicks_table_name, "ad_click_id", None,
        gsis=[{"name": "ByViewer", "pk": "viewer_sub", "sk": "created_at"}],
        num_attrs={"created_at"})
mktable(S.billing_table_name, "pk", "sk")

# ---- now import app services (T binds to the moto tables above) ----
from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_billing, ad_serving, ad_attribution
from fastapi import HTTPException

TAG = "adv3v_" + uuid.uuid4().hex[:8]

def new_acct(balance):
    aid = TAG + "_" + uuid.uuid4().hex[:6]
    T.ad_accounts.put_item(Item={"pk": f"ACCT#{aid}", "sk": "META",
                                 "account_id": aid, "owner_sub": "OW_" + aid,
                                 "balance_cents": balance, "status": "active",
                                 "company_name": "Synth Co", "created_at": now_ts()})
    return aid

def new_campaign(aid, budget, bid_cpc=50):
    cid = "camp_" + uuid.uuid4().hex[:6]
    T.ad_campaigns.put_item(Item={"pk": f"ACCT#{aid}", "sk": f"CAMPAIGN#{cid}",
                                  "campaign_id": cid, "account_id": aid, "status": "active",
                                  "budget_cents": budget, "bid_cpc_cents": bid_cpc,
                                  "bid_cpm_cents": 500, "lifetime_spent_cents": 0,
                                  "spent_today_cents": 0, "created_at": now_ts()})
    return cid

def new_click(aid, cid, viewer, bid_cpc=50, bid_cpa=0, creator="", status="served"):
    ck = "ack_" + uuid.uuid4().hex[:10]
    T.ad_clicks.put_item(Item={"ad_click_id": ck, "account_id": aid, "campaign_id": cid,
                               "creative_id": "cr_x", "content_id": "content_x",
                               "content_owner_sub": creator, "viewer_sub": viewer,
                               "bid_cpc_cents": bid_cpc, "bid_cpa_cents": bid_cpa,
                               "status": status, "created_at": now_ts(),
                               "expires_at": now_ts() + 604800})
    return ck

def bal(aid):
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{aid}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0))

def camp_spent(aid, cid):
    it = T.ad_campaigns.get_item(Key={"pk": f"ACCT#{aid}", "sk": f"CAMPAIGN#{cid}"}).get("Item") or {}
    return int(it.get("lifetime_spent_cents", 0))

def ledger_rows(aid, etype=None):
    from boto3.dynamodb.conditions import Key
    rows = T.ad_billing.query(KeyConditionExpression=Key("pk").eq(f"ACCT#{aid}") & Key("sk").begins_with("LEDGER#")).get("Items", [])
    if etype:
        rows = [r for r in rows if r.get("entry_type") == etype]
    return rows

# ======================================================================
# ADV3-1 : deposit honest charge
# ======================================================================
print("\n=== ADV3-1 deposit ===")
try:
    import stripe
    from app.routers.billing import ensure_stripe_configured, get_or_create_customer
    ensure_stripe_configured()
    a1 = new_acct(0)
    ow = "OW_" + a1
    cust = get_or_create_customer(ow)
    pm = stripe.PaymentMethod.create(type="card", card={"number": "4242424242424242",
                                                        "exp_month": 12, "exp_year": 2030, "cvc": "123"})
    pm_id = pm["id"]
    stripe.PaymentMethod.attach(pm_id, customer=cust)
    stripe_ok = True
except Exception as e:
    stripe_ok = False
    print("STRIPE SETUP FAILED:", repr(e))
    traceback.print_exc()

if stripe_ok:
    # N1: no PM -> 400, no credit, no budget_deposit row
    try:
        ad_billing.deposit_funds(a1, 5000, "", internal=False)
        check("ADV3-1 N1 no-PM rejected", False, "expected HTTPException")
    except HTTPException as ex:
        check("ADV3-1 N1 no-PM rejected", ex.status_code == 400 and bal(a1) == 0 and len(ledger_rows(a1, "budget_deposit")) == 0,
              f"status={ex.status_code} bal={bal(a1)} rows={len(ledger_rows(a1,'budget_deposit'))}")

    # P1: with PM -> charge + credit, PI recorded
    r = ad_billing.deposit_funds(a1, 5000, pm_id, internal=False)
    rows = ledger_rows(a1, "budget_deposit")
    pi = rows[0]["meta"].get("stripe_payment_intent_id") if rows else ""
    check("ADV3-1 P1 PM charges+credits", r.get("ok") and bal(a1) == 5000 and len(rows) == 1 and bool(pi),
          f"bal={bal(a1)} pi={pi!r}")

    # P2: idempotent double-fire (same acct+amount+pm -> same PI -> credit once)
    b_before = bal(a1)
    r2 = ad_billing.deposit_funds(a1, 5000, pm_id, internal=False)
    check("ADV3-1 P2 double-fire idempotent", bal(a1) == b_before,
          f"reason={r2.get('reason')} bal_before={b_before} bal_after={bal(a1)} (5000 expected -> credit-once)")

    # N2: decline -> 402, no credit
    _orig_create = stripe.PaymentIntent.create
    def _decline(*a, **k):
        raise stripe.error.CardError("Your card was declined.", param=None, code="card_declined")
    stripe.PaymentIntent.create = _decline
    b_before = bal(a1)
    try:
        ad_billing.deposit_funds(a1, 6000, pm_id, internal=False)
        check("ADV3-1 N2 decline->402 no-credit", False, "expected HTTPException")
    except HTTPException as ex:
        newrows = [x for x in ledger_rows(a1, "budget_deposit") if int(x.get("amount_cents", 0)) == 6000]
        check("ADV3-1 N2 decline->402 no-credit", ex.status_code == 402 and bal(a1) == b_before and len(newrows) == 0,
              f"status={ex.status_code} bal={bal(a1)} 6000rows={len(newrows)}")
    finally:
        stripe.PaymentIntent.create = _orig_create

    # Internal seed path preserved: no PM still credits
    a_int = new_acct(0)
    ad_billing.deposit_funds(a_int, 5000, "", internal=True)
    check("ADV3-1 internal seed credits w/o PM", bal(a_int) == 5000, f"bal={bal(a_int)}")

# ======================================================================
# ADV3-2 A3 : click + CTA share one canonical key -> bill CPC once
# ======================================================================
print("\n=== ADV3-2 A3 click double-charge ===")
a2 = new_acct(100000); c2 = new_campaign(a2, 100000, bid_cpc=50)
ck = new_click(a2, c2, "V_"+a2, bid_cpc=50)
# simulate a /track click charge (canonical {id}#click key)
r_click = ad_billing.charge_click(account_id=a2, campaign_id=c2, creative_id="cr_x",
                                  creator_id="", content_id="content_x", bid_cpc_cents=50,
                                  idempotency_key=f"{ck}#click")
# now a CTA tap on the SAME click -> must no-op (duplicate) after the fix
r_cta = ad_serving.record_cta_click(ad_click_id=ck, cta_type="buy_product",
                                    viewer_sub="V_"+a2, ip_address="1.2.3.4", user_agent="Mozilla/5.0")
check("ADV3-2 A3 click+CTA bills CPC once",
      r_click.get("ok") and r_cta.get("charge_cents") == 0 and r_cta.get("reason") == "duplicate"
      and bal(a2) == 99950 and len(ledger_rows(a2, "click_charge")) == 1,
      f"cta_reason={r_cta.get('reason')} bal={bal(a2)} click_rows={len(ledger_rows(a2,'click_charge'))}")
# control: a fresh click's CTA DOES bill
ck_fresh = new_click(a2, c2, "V2_"+a2, bid_cpc=50)
r_cta2 = ad_serving.record_cta_click(ad_click_id=ck_fresh, cta_type="buy_product",
                                     viewer_sub="V2_"+a2, ip_address="1.2.3.5", user_agent="Mozilla/5.0")
check("ADV3-2 A3 control: fresh CTA bills", r_cta2.get("charged") and r_cta2.get("charge_cents") == 50,
      f"charged={r_cta2.get('charged')} cents={r_cta2.get('charge_cents')}")

# ======================================================================
# ADV3-2 A4 : hard budget guard -- no overshoot
# ======================================================================
print("\n=== ADV3-2 A4 budget hard guard ===")
# sequential (deterministic authoritative check): budget 300, bid 50 -> exactly 6 charges
a3 = new_acct(1000000); c3 = new_campaign(a3, 300, bid_cpc=50)
seq_ok = 0
for i in range(20):
    rr = ad_billing.charge_click(account_id=a3, campaign_id=c3, creative_id="cr", creator_id="",
                                 content_id="ct", bid_cpc_cents=50)
    if rr.get("ok"): seq_ok += 1
check("ADV3-2 A4 sequential no-overshoot", seq_ok == 6 and camp_spent(a3, c3) == 300 and bal(a3) == 1000000 - 300,
      f"ok={seq_ok} spent={camp_spent(a3,c3)} bal_debited={1000000-bal(a3)} (budget=300)")
# concurrent (race): fire 20 at once, budget 300 -> spend must never exceed 300
a3c = new_acct(1000000); c3c = new_campaign(a3c, 300, bid_cpc=50)
def _fire(_):
    try:
        return ad_billing.charge_click(account_id=a3c, campaign_id=c3c, creative_id="cr",
                                       creator_id="", content_id="ct", bid_cpc_cents=50).get("ok")
    except Exception as e:
        return ("err", repr(e))
with ThreadPoolExecutor(max_workers=20) as ex:
    conc = list(ex.map(_fire, range(20)))
conc_ok = sum(1 for x in conc if x is True)
check("ADV3-2 A4 concurrent no-overshoot", camp_spent(a3c, c3c) <= 300 and bal(a3c) == 1000000 - camp_spent(a3c, c3c),
      f"ok={conc_ok} spent={camp_spent(a3c,c3c)} (budget=300, bound<=300) bal_debited={1000000-bal(a3c)}")

# ======================================================================
# ADV3-2 A5 : insufficient-funds conversion does NOT consume the click; retriable
# ======================================================================
print("\n=== ADV3-2 A5 attribution revert+retry ===")
a4 = new_acct(0); c4 = new_campaign(a4, 100000)
ck4 = new_click(a4, c4, "V_"+a4, bid_cpc=50, bid_cpa=500, status="clicked")
r_att1 = ad_attribution.attribute_conversion(viewer_sub="V_"+a4, conversion_type="purchase",
                                             conversion_value_cents=1000, ad_click_id=ck4)
row_after = T.ad_clicks.get_item(Key={"ad_click_id": ck4}).get("Item") or {}
check("ADV3-2 A5 underfunded conversion not consumed",
      (r_att1.get("attributed") is False) and row_after.get("status") != "converted" and not row_after.get("converted_at"),
      f"reason={r_att1.get('reason')} status={row_after.get('status')} converted_at={row_after.get('converted_at')}")
# fund + retry -> settles exactly once
ad_billing.deposit_funds(a4, 5000, "", internal=True)
r_att2 = ad_attribution.attribute_conversion(viewer_sub="V_"+a4, conversion_type="purchase",
                                             conversion_value_cents=1000, ad_click_id=ck4)
row2 = T.ad_clicks.get_item(Key={"ad_click_id": ck4}).get("Item") or {}
conv_rows = ledger_rows(a4, "conversion_charge")
check("ADV3-2 A5 retry settles once", r_att2.get("attributed") and row2.get("status") == "converted"
      and len(conv_rows) == 1 and bal(a4) == 5000 - 500,
      f"attributed={r_att2.get('attributed')} conv_rows={len(conv_rows)} bal={bal(a4)}")

# ======================================================================
# ADV3-2 A6 : reversal ledger meta labels the MEMBER clawback (syndicate)
# ======================================================================
print("\n=== ADV3-2 A6 reversal clawback label ===")
a5 = new_acct(0); c5 = new_campaign(a5, 100000)
synd_entry = {"entry_type": "conversion_charge", "amount_cents": 200, "campaign_id": c5,
              "meta": {"creator_id": "CR_"+a5, "creator_share_cents": 100, "platform_share_cents": 100,
                       "is_syndicate_split": True, "member_share_cents": 70,
                       "syndicate_treasury_share_cents": 30, "syndicate_id": "synthsynd",
                       "creator_credit_sk": "", "platform_entry_sk": ""}}
ad_billing.reverse_ad_charge(account_id=a5, entry_id="fake_synd", reason="test", entry=synd_entry)
rev_rows = [r for r in ledger_rows(a5, "charge_reversal")]
m = rev_rows[0]["meta"] if rev_rows else {}
check("ADV3-2 A6 syndicate reversal labels member clawback",
      int(m.get("creator_clawback_cents", -1)) == 70 and int(m.get("member_clawback_cents", -1)) == 70
      and int(m.get("treasury_debit_cents", -1)) == 30 and m.get("is_syndicate_split") is True,
      f"meta_clawback={m.get('creator_clawback_cents')} member={m.get('member_clawback_cents')} treasury={m.get('treasury_debit_cents')}")
# control: non-syndicate reversal claws full creator_share
a5b = new_acct(0); c5b = new_campaign(a5b, 100000)
plain_entry = {"entry_type": "click_charge", "amount_cents": 100, "campaign_id": c5b,
               "meta": {"creator_id": "CR_"+a5b, "creator_share_cents": 100, "platform_share_cents": 0,
                        "is_syndicate_split": False, "member_share_cents": 0,
                        "syndicate_treasury_share_cents": 0, "creator_credit_sk": "", "platform_entry_sk": ""}}
ad_billing.reverse_ad_charge(account_id=a5b, entry_id="fake_plain", reason="test", entry=plain_entry)
mb = ([r for r in ledger_rows(a5b, "charge_reversal")] or [{"meta": {}}])[0]["meta"]
check("ADV3-2 A6 control non-syndicate claws creator_share",
      int(mb.get("creator_clawback_cents", -1)) == 100 and mb.get("is_syndicate_split") is False,
      f"meta_clawback={mb.get('creator_clawback_cents')}")

# ======================================================================
# E4 : CTA CPC charge runs through the fraud gate
# ======================================================================
print("\n=== ADV3-2/E4 CTA fraud gate ===")
from app.services import ad_fraud_prevention as fraud
a6 = new_acct(100000); c6 = new_campaign(a6, 100000, bid_cpc=50)
ck6 = new_click(a6, c6, "V_"+a6, bid_cpc=50)
calls = {"record_fraud_event": 0, "maybe_auto_suspend": 0, "record_account_activity": []}
class _FR:  # duck-typed fraud result
    flagged = True; score = 99; rule_scores = {}; details = {}
_orig = (fraud.check_fraud, fraud.record_fraud_event, fraud.maybe_auto_suspend, fraud.record_account_activity)
fraud.check_fraud = lambda **k: _FR()
def _rfe(**k): calls["record_fraud_event"] += 1
def _mas(**k): calls["maybe_auto_suspend"] += 1
def _raa(**k): calls["record_account_activity"].append(k.get("flagged"))
fraud.record_fraud_event = _rfe; fraud.maybe_auto_suspend = _mas; fraud.record_account_activity = _raa
try:
    r_f = ad_serving.record_cta_click(ad_click_id=ck6, cta_type="buy_product", viewer_sub="V_"+a6,
                                      ip_address="9.9.9.9", user_agent="python-bot")
    check("ADV3-2/E4 flagged CTA not charged",
          r_f.get("reason") == "fraud_flagged" and not r_f.get("charged") and r_f.get("charge_cents") == 0
          and calls["record_fraud_event"] == 1 and calls["maybe_auto_suspend"] == 1
          and bal(a6) == 100000 and len(ledger_rows(a6, "click_charge")) == 0,
          f"reason={r_f.get('reason')} rfe={calls['record_fraud_event']} mas={calls['maybe_auto_suspend']} bal={bal(a6)}")
    # legit CTA passes gate + charges + records activity
    fraud.check_fraud = lambda **k: type("R", (), {"flagged": False, "score": 0, "rule_scores": {}, "details": {}})()
    ck6b = new_click(a6, c6, "V2_"+a6, bid_cpc=50)
    r_ok = ad_serving.record_cta_click(ad_click_id=ck6b, cta_type="buy_product", viewer_sub="V2_"+a6,
                                       ip_address="1.1.1.1", user_agent="Mozilla/5.0")
    check("ADV3-2/E4 legit CTA passes gate + charges",
          r_ok.get("charged") and r_ok.get("charge_cents") == 50 and (False in calls["record_account_activity"]),
          f"charged={r_ok.get('charged')} activity={calls['record_account_activity']}")
finally:
    fraud.check_fraud, fraud.record_fraud_event, fraud.maybe_auto_suspend, fraud.record_account_activity = _orig

# ======================================================================
print("\n=== SUMMARY ===")
passed = sum(1 for _, ok, _ in RESULTS if ok)
total = len(RESULTS)
for n, ok, d in RESULTS:
    print(f"  [{'PASS' if ok else 'FAIL'}] {n}")
print(f"\nRESULT {passed}/{total} passed")
sys.exit(0 if passed == total else 1)
