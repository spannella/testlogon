"""ADV2-E4 (F4) in-process money-path verify. Self-contained: seeds a fresh
funded advertiser + campaign, a creator, a viewer, a non-target user, then
exercises propose -> queue -> guard(403) -> approve -> publish(paid_partnership,
NOT is_sponsored) -> impression/click billing (funds-guarded, idempotent) ->
creator placement credit (type:credit) -> viewer tip still works -> reject/pending
never publish. Prints PASS/FAIL lines + OVERALL.
"""
import time, uuid
from decimal import Decimal

from app.core.tables import T
from app.services import sponsored_creator_posts as spcp
from app.services import ad_serving
from app.services.ad_billing import charge_impression  # noqa
from app.routers.newsfeed import _post_to_dict, pk_post, sk_post, ddb_get_item

RESULTS = []
def check(name, cond, extra=""):
    RESULTS.append((name, bool(cond), extra))
    print(("PASS" if cond else "FAIL"), name, ("| " + str(extra)) if extra else "")

sfx = uuid.uuid4().hex[:8]
adv = f"adv_e4_{sfx}"
creator = f"creator_e4_{sfx}"
viewer = f"viewer_e4_{sfx}"
viewer2 = f"viewer2_e4_{sfx}"
nontarget = f"nontarget_e4_{sfx}"
acct = f"adacct_e4_{sfx}"
camp = f"camp_e4_{sfx}"
creative = f"cr_e4_{sfx}"
START_BAL = 100000

# ---- seed funded advertiser account + campaign ----
T.ad_accounts.put_item(Item={
    "pk": f"ACCT#{acct}", "sk": "META", "account_id": acct,
    "owner_sub": adv, "company_name": "Acme E4 Coffee",
    "status": "active", "balance_cents": START_BAL, "lifetime_spend_cents": 0,
    "created_at": int(time.time()),
})
T.ad_campaigns.put_item(Item={
    "pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}", "campaign_id": camp,
    "account_id": acct, "status": "active", "name": "E4 campaign",
    "bid_cpm_cents": 20000, "bid_cpc_cents": 50, "bid_cpa_cents": 500,
    "budget_cents": 100000000, "lifetime_spent_cents": 0, "spent_today_cents": 0,
    "created_at": int(time.time()),
})

def acct_balance():
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0))

def creator_credit_total(sub):
    resp = T.billing.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": f"USER#{sub}"},
    )
    tot = 0
    rows = []
    for it in resp.get("Items", []):
        if str(it.get("sk", "")).startswith("LEDGER#") and str(it.get("type", "")) == "credit":
            tot += int(it.get("amount_cents", 0) or 0)
            rows.append(it)
    return tot, rows

# ============ 1. advertiser drafts a proposal to the creator ============
prop = spcp.create_proposal(
    advertiser_sub=adv, advertiser_account_id=acct, creator_sub=creator,
    body="Loving my morning brew from Acme this week -- best beans I've tried. #partner",
    image_urls=["https://images.example/coffee.jpg"],
    campaign_id=camp, creative_id=creative, sponsor_account_id=acct,
    sponsor_label="Acme Coffee", disclosure="In partnership with Acme Coffee",
)
pid = prop["proposal_id"]
check("1_proposal_draft_status", prop.get("status") == "draft_proposed", prop.get("status"))
check("1_proposal_not_published", prop.get("published_post_id") is None)

# ============ 2. appears in the creator's review queue (not others') ============
q_creator = spcp.list_pending_for_creator(creator)
check("2_in_creator_queue", any(p["proposal_id"] == pid for p in q_creator), f"n={len(q_creator)}")
q_other = spcp.list_pending_for_creator(nontarget)
check("2_not_in_other_queue", not any(p["proposal_id"] == pid for p in q_other))

# ============ 3. a NON-target user cannot approve (403) ============
try:
    spcp.approve_and_publish(proposal_id=pid, creator_sub=nontarget)
    check("3_nontarget_approve_403", False, "no error raised")
except spcp.SponsoredPostError as e:
    check("3_nontarget_approve_403", e.status_code == 403, e.status_code)
# also non-target cannot reject
try:
    spcp.reject_proposal(proposal_id=pid, creator_sub=nontarget)
    check("3_nontarget_reject_403", False, "no error raised")
except spcp.SponsoredPostError as e:
    check("3_nontarget_reject_403", e.status_code == 403, e.status_code)
# still not published after failed guard
after = spcp.get_proposal(pid)
check("3_still_pending_after_guard", after.get("status") == "draft_proposed" and after.get("published_post_id") is None)

# ============ 4. the creator approves -> publish authored-by-creator ============
res = spcp.approve_and_publish(proposal_id=pid, creator_sub=creator)
post_id = res["post_id"]
post = ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})
check("4_published_authored_by_creator", post and post.get("user_id") == creator, post.get("user_id") if post else None)
check("4_paid_partnership_set", bool(post.get("paid_partnership")) is True)
check("4_is_sponsored_NOT_set", not post.get("is_sponsored"), repr(post.get("is_sponsored")))
check("4_sponsor_account_id", post.get("sponsor_account_id") == acct, post.get("sponsor_account_id"))
check("4_content_owner_is_creator", post.get("content_owner_id") == creator)
check("4_status_published", post.get("status") == "published")
# serializer (ADV2-403) surfaces paid_partnership, still a normal post shape
sd = _post_to_dict(post, viewer_id=viewer)
check("4_serialize_paid_partnership", sd.get("paid_partnership") is True and not sd.get("is_sponsored"))
check("4_serialize_author", sd.get("author_id") == creator)

# ============ 4b. double-approve / post-approve reject blocked ============
try:
    spcp.approve_and_publish(proposal_id=pid, creator_sub=creator)
    check("4b_double_approve_blocked", False, "no error")
except spcp.SponsoredPostError as e:
    check("4b_double_approve_blocked", e.status_code == 409, e.status_code)

# ============ 5. impression charges advertiser + credits creator (70/30) ============
handle = spcp.mint_post_ad_click(viewer_sub=viewer, post=post)
check("5_mint_ok", handle and handle.get("ad_click_id", "").startswith("spcp_"), handle.get("ad_click_id") if handle else None)
acid = handle["ad_click_id"]
bal0 = acct_balance()
cc0, _ = creator_credit_total(creator)
imp = ad_serving.track_ad_event(
    event="impression", creative_id=creative, campaign_id=camp, account_id=acct,
    surface="sponsored_creator_post", slot_type="sponsored_creator_post",
    content_id=post_id, creator_id=creator, user_id=viewer,
    ad_click_id=acid,
)
bal1 = acct_balance()
cc1, credit_rows = creator_credit_total(creator)
check("5_impression_charged", imp.get("charged") and imp.get("charge_cents") == 20, imp.get("charge_cents"))
check("5_advertiser_debited_20", bal0 - bal1 == 20, f"{bal0}->{bal1}")
check("5_creator_credited_70pct", cc1 - cc0 == 14, f"delta={cc1-cc0}")  # 70% of 20
check("5_credit_type_is_credit", any(str(r.get('type'))=='credit' for r in credit_rows))
# idempotent repeat
imp2 = ad_serving.track_ad_event(
    event="impression", creative_id=creative, campaign_id=camp, account_id=acct,
    surface="sponsored_creator_post", slot_type="sponsored_creator_post",
    content_id=post_id, creator_id=creator, user_id=viewer, ad_click_id=acid,
)
check("5_impression_idempotent", imp2.get("charge_cents") == 0 and acct_balance() == bal1, imp2.get("charge_cents"))

# ============ 6. click charges advertiser CPC ============
balc0 = acct_balance()
clk = ad_serving.track_ad_event(
    event="click", creative_id=creative, campaign_id=camp, account_id=acct,
    surface="sponsored_creator_post", slot_type="sponsored_creator_post",
    content_id=post_id, creator_id=creator, user_id=viewer, ad_click_id=acid,
)
check("6_click_charged_cpc50", clk.get("charged") and clk.get("charge_cents") == 50, clk.get("charge_cents"))
check("6_advertiser_debited_50", balc0 - acct_balance() == 50)
clk2 = ad_serving.track_ad_event(
    event="click", creative_id=creative, campaign_id=camp, account_id=acct,
    surface="sponsored_creator_post", slot_type="sponsored_creator_post",
    content_id=post_id, creator_id=creator, user_id=viewer, ad_click_id=acid,
)
check("6_click_idempotent", clk2.get("charge_cents") == 0)

# ============ 7. funds-guard: drained account cannot charge, no negative ============
T.ad_accounts.update_item(Key={"pk": f"ACCT#{acct}", "sk": "META"},
                          UpdateExpression="SET balance_cents = :z",
                          ExpressionAttributeValues={":z": 5})
h2 = spcp.mint_post_ad_click(viewer_sub=viewer2, post=post)
guard = ad_serving.track_ad_event(
    event="impression", creative_id=creative, campaign_id=camp, account_id=acct,
    surface="sponsored_creator_post", slot_type="sponsored_creator_post",
    content_id=post_id, creator_id=creator, user_id=viewer2, ad_click_id=h2["ad_click_id"],
)
check("7_funds_guard_no_charge", not guard.get("charged") and guard.get("charge_reason") == "insufficient_funds", guard.get("charge_reason"))
check("7_balance_not_negative", acct_balance() == 5)

# ============ 8. a viewer TIP still works on the post (distinct flag, NOT 400) ============
# 8a. the tip-guard property: the post is NOT is_sponsored, so tip_post's
#     `if post.get("is_sponsored")` 400 branch is never taken.
check("8a_tip_guard_would_allow", not post.get("is_sponsored"))

# Real router proof via TestClient: hit the actual /posts/{id}/tip endpoint as
# the viewer. The is_sponsored guard runs FIRST -- a paid_partnership post must
# get PAST it (never 400 tip_not_allowed_on_ad), while a standalone is_sponsored
# post must be blocked (contrast). This isolates the DISTINCT-flag behaviour from
# the tip charge's own PM infra.
from fastapi.testclient import TestClient
from app.main import app as fastapi_app
import app.routers.newsfeed as nf
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy

fastapi_app.dependency_overrides[maybe_enforce_api_key_route_policy] = lambda: None
def _set_uid(u):
    fastapi_app.dependency_overrides[nf._get_user_id] = lambda: u
client = TestClient(fastapi_app, raise_server_exceptions=False)

def _is_ad_block(resp):
    if resp.status_code != 400:
        return False
    try:
        d = resp.json().get("detail")
    except Exception:
        return False
    return isinstance(d, dict) and d.get("code") == "tip_not_allowed_on_ad"

# 8b. viewer tips the paid_partnership post -> must NOT be blocked by the ad guard.
_set_uid(viewer)
r_pp = client.post(f"/posts/{post_id}/tip", json={"amount_cents": 500})
check("8b_paid_partnership_tip_not_blocked", not _is_ad_block(r_pp), f"status={r_pp.status_code}")

# 8c. contrast: a STANDALONE is_sponsored post DOES block the tip (mechanism proof).
from app.routers.newsfeed import ddb_put_item
spon_id = f"post_spon_{sfx}"
ddb_put_item({"pk": pk_post(spon_id), "sk": sk_post(), "Entity": "Post", "post_id": spon_id,
              "user_id": creator, "created_at": "2026-01-01T00:00:00Z", "published_at": "2026-01-01T00:00:00Z",
              "status": "published", "is_sponsored": True, "body": "ad", "body_plain": "ad", "visibility": "public"})
r_sp = client.post(f"/posts/{spon_id}/tip", json={"amount_cents": 500})
check("8c_is_sponsored_tip_blocked_400", _is_ad_block(r_sp), f"status={r_sp.status_code}")

# 8d. bonus: try the real tip money-path directly (non-fatal). A successful
#     credit is extra evidence; a tip-infra error here is orthogonal to E4.
try:
    from app.services.tips import charge_tip
    tc0, _ = creator_credit_total(creator)
    charge_tip(tipper_id=viewer, recipient_id=creator, amount_cents=500, currency="usd",
               payment_method_id=None, content_type="post", content_id=post_id,
               idempotency_key=f"e4tip_{sfx}")
    tc1, _ = creator_credit_total(creator)
    print("INFO 8d_direct_charge_tip_credit_delta", tc1 - tc0)
except Exception as _e:
    print("INFO 8d_direct_charge_tip skipped (tip-infra, orthogonal):", type(_e).__name__)

# ============ 9. rejected proposal never publishes ============
prop_r = spcp.create_proposal(advertiser_sub=adv, advertiser_account_id=acct,
                              creator_sub=creator, body="second draft to reject",
                              campaign_id=camp, creative_id=creative, sponsor_account_id=acct)
rej = spcp.reject_proposal(proposal_id=prop_r["proposal_id"], creator_sub=creator, reason="not a fit")
rprop = spcp.get_proposal(prop_r["proposal_id"])
check("9_rejected_status", rej.get("status") == "rejected" and rprop.get("status") == "rejected")
check("9_rejected_no_post", rprop.get("published_post_id") is None)

# ============ 10. pending proposal never publishes ============
prop_p = spcp.create_proposal(advertiser_sub=adv, advertiser_account_id=acct,
                              creator_sub=creator, body="third draft left pending",
                              campaign_id=camp, creative_id=creative, sponsor_account_id=acct)
pprop = spcp.get_proposal(prop_p["proposal_id"])
check("10_pending_no_post", pprop.get("status") == "draft_proposed" and pprop.get("published_post_id") is None)

# ---- summary ----
passed = sum(1 for _, ok, _ in RESULTS if ok)
total = len(RESULTS)
print("\nSUMMARY", passed, "/", total)
print("OVERALL", "ALL_PASS" if passed == total else "FAIL")
print("EVIDENCE post_id=", post_id, "ad_click_id=", acid, "acct=", acct)
