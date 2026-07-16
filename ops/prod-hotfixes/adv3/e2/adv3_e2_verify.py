"""ADV3 EPIC E2 verification harness (router/endpoint-level, real DDB engine via
moto). Proves the ADV3-3 gate move: a brand-new (pending_review) advertiser can
CREATE a draft campaign (previously a guaranteed 403), while LAUNCH (submit for
review) is gated on the account being active. Zero prod-DDB residue: own in-memory
moto DynamoDB, discarded on exit.
"""
import os, sys, uuid, asyncio, traceback

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)

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
    for a in num_attrs: attrs[a] = "N"
    kwargs = dict(TableName=name,
                  AttributeDefinitions=[{"AttributeName": k, "AttributeType": v} for k, v in attrs.items()],
                  KeySchema=ks, BillingMode="PAY_PER_REQUEST")
    if gsi_defs: kwargs["GlobalSecondaryIndexes"] = gsi_defs
    try: client.create_table(**kwargs)
    except client.exceptions.ResourceInUseException: pass

mktable(S.ad_accounts_table_name, "pk", "sk",
        gsis=[{"name": "ByOwner", "pk": "owner_sub", "sk": "created_at"},
              {"name": "ByStatus", "pk": "status", "sk": "created_at"}],
        num_attrs={"created_at"})
mktable(S.ad_campaigns_table_name, "pk", "sk",
        gsis=[{"name": "ByStatusCreatedAt", "pk": "status", "sk": "created_at"},
              {"name": "ByCampaignId", "pk": "campaign_id", "sk": "created_at"}],
        num_attrs={"created_at"})

from app.models import AdAccountCreateIn, CampaignCreateIn
from app.services.ad_accounts import create_ad_account, get_ad_account
from app.core.tables import T
from app.core.time import now_ts
from app.routers import ads as ads_router
from fastapi import HTTPException

TAG = "adv3e2_" + uuid.uuid4().hex[:8]

def run(coro): return asyncio.get_event_loop().run_until_complete(coro)

def make_account(owner):
    acct = create_ad_account(owner, AdAccountCreateIn(company_name="Synth Co", billing_email="synth@example.com"))
    return acct["account_id"]

def paid_body(name="Synth paid"):
    return CampaignCreateIn(name=name, objective="awareness", budget_cents=10000,
                            budget_type="lifetime", bid_cpm_cents=500,
                            bid_cpc_cents=50, bid_cpa_cents=500)

def selfpromo_body():
    return CampaignCreateIn(name="Synth promo", objective="awareness", budget_cents=0,
                            budget_type="lifetime", is_self_promo=True, self_promo_mode="fill_only")

def status_code(exc):
    return getattr(exc, "status_code", None)

owner = "OW_" + TAG
other = "OTHER_" + TAG
ctx = {"user_sub": owner}
octx = {"user_sub": other}

print("\n=== ADV3-3 : create-under-pending + launch gate ===")

# Setup: brand-new account -> pending_review
aid = make_account(owner)
acct0 = get_ad_account(aid)
check("acct starts pending_review", acct0.get("status") == "pending_review", acct0.get("status"))

# P1: create a PAID draft campaign under a PENDING account -> succeeds (was a guaranteed 403 before ADV3-3)
try:
    camp = run(ads_router.create_campaign_endpoint(aid, paid_body(), ctx=ctx))
    created_ok = True
    cid = camp.get("campaign_id")
    cstatus = camp.get("status")
except HTTPException as e:
    created_ok = False; cid = None; cstatus = None
    print("  create raised", status_code(e), e.detail)
check("P1 create paid campaign under pending -> no 403", created_ok, f"status={cstatus}")
check("P1 created campaign is inert draft (won't serve)", cstatus == "draft", str(cstatus))

# N1: submit-for-review while account pending -> 403 (launch gate moved here)
gate_403 = False; gate_detail = ""
try:
    run(ads_router.submit_for_review_endpoint(aid, cid, ctx=ctx))
except HTTPException as e:
    gate_403 = (status_code(e) == 403); gate_detail = str(e.detail)
check("N1 submit while pending -> 403 launch gate", gate_403, gate_detail)

# confirm the campaign stayed draft (submit did not transition it)
c_after = T.ad_campaigns.get_item(Key={"pk": f"ACCT#{aid}", "sk": f"CAMPAIGN#{cid}"}).get("Item") or {}
check("N1 campaign remains draft after blocked submit", c_after.get("status") == "draft", c_after.get("status"))

# P2: admin approves the account (-> active), submit now succeeds
T.ad_accounts.update_item(Key={"pk": f"ACCT#{aid}", "sk": "META"},
                          UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
                          ExpressionAttributeValues={":s": "active"})
try:
    ack = run(ads_router.submit_for_review_endpoint(aid, cid, ctx=ctx))
    submit_ok = bool(ack.get("ok"))
except HTTPException as e:
    submit_ok = False; print("  submit-after-approve raised", status_code(e), e.detail)
check("P2 submit after account active -> ok", submit_ok, "")
c_sub = T.ad_campaigns.get_item(Key={"pk": f"ACCT#{aid}", "sk": f"CAMPAIGN#{cid}"}).get("Item") or {}
check("P2 campaign -> pending_review after submit", c_sub.get("status") == "pending_review", c_sub.get("status"))

print("\n=== regression / negative ===")

# R1: ownership guard still enforced (a non-owner cannot create under this account)
own_guard = False; own_detail = ""
aid2 = make_account(owner)
try:
    run(ads_router.create_campaign_endpoint(aid2, paid_body("intruder"), ctx=octx))
except HTTPException as e:
    own_guard = (status_code(e) in (403, 404)); own_detail = f"{status_code(e)} {e.detail}"
check("R1 non-owner create blocked (ownership guard intact)", own_guard, own_detail)

# R2: self-promo still auto-activates under a pending account (unchanged carve-out)
aid3 = make_account(owner)
try:
    sp = run(ads_router.create_campaign_endpoint(aid3, selfpromo_body(), ctx={"user_sub": owner}))
    sp_ok = sp.get("status") == "active" and sp.get("is_self_promo") is True
except HTTPException as e:
    sp_ok = False; print("  self-promo raised", status_code(e), e.detail)
check("R2 self-promo auto-active under pending (carve-out intact)", sp_ok, "")

# R3: submit gate uses account status, not campaign; a paid draft under an ACTIVE account submits fine
aid4 = make_account(owner)
T.ad_accounts.update_item(Key={"pk": f"ACCT#{aid4}", "sk": "META"},
                          UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
                          ExpressionAttributeValues={":s": "active"})
camp4 = run(ads_router.create_campaign_endpoint(aid4, paid_body("active-acct"), ctx=ctx))
try:
    run(ads_router.submit_for_review_endpoint(aid4, camp4["campaign_id"], ctx=ctx))
    r3 = True
except HTTPException as e:
    r3 = False; print("  active-acct submit raised", status_code(e), e.detail)
check("R3 create+submit under active account -> ok", r3, "")

# ---- cleanup (belt-and-braces; the moto tables are discarded on exit anyway) ----
for a in (aid, aid2, aid3, aid4):
    for it in T.ad_campaigns.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("pk").eq(f"ACCT#{a}")).get("Items", []):
        T.ad_campaigns.delete_item(Key={"pk": it["pk"], "sk": it["sk"]})
    T.ad_accounts.delete_item(Key={"pk": f"ACCT#{a}", "sk": "META"})
resid = 0
for a in (aid, aid2, aid3, aid4):
    if get_ad_account(a): resid += 1
check("cleanup: 0 synthetic accounts remain", resid == 0, f"residual={resid}")

print("\n==== SUMMARY ====")
npass = sum(1 for _, ok, _ in RESULTS if ok)
for n, ok, d in RESULTS:
    print(("PASS" if ok else "FAIL"), n)
print(f"{npass}/{len(RESULTS)} PASS")
sys.exit(0 if npass == len(RESULTS) else 1)
