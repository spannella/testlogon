#!/usr/bin/env python3
"""ADV-B1 seed + money-path verification (runs on prod with app venv + env loaded).

Proves: ADV-101 deposit charges the PM (PaymentIntent + credit) / failed charge no credit;
ADV-102 funds-guard rejects an over-balance charge with no negative balance;
ADV-103 serve mints ad_click_id into AdClicks (+ content_owner + 7d TTL);
ADV-104 newsfeed injection surfaces the sponsored fields end-to-end.
"""
import time, uuid, traceback

OWNER = "advb1_owner_" + uuid.uuid4().hex[:8]
VIEWER = "advb1_viewer_" + uuid.uuid4().hex[:8]
ADMIN = "advb1_admin"

def line(msg): print("EVIDENCE| " + msg, flush=True)

from fastapi import HTTPException
from app.core.tables import T
from app.core.time import now_ts
from app.models import AdAccountCreateIn, CampaignCreateIn, CreativeCreateIn
from app.services import ad_accounts, ad_campaigns, ad_creatives, ad_billing
from app.services.ad_serving import serve_ad
from app.routers.billing import ensure_stripe_configured, get_or_create_customer
import stripe

RESULTS = {}

# ── 0. Stripe PM for the advertiser (real stripe-mock PaymentMethod) ──
ensure_stripe_configured()
cust = get_or_create_customer(OWNER)
pm = stripe.PaymentMethod.create(type="card", card={
    "number": "4242424242424242", "exp_month": 12, "exp_year": 2030, "cvc": "123"})
PM_ID = pm["id"]
stripe.PaymentMethod.attach(PM_ID, customer=cust)
line(f"stripe customer={cust} payment_method={PM_ID}")

# ── 1. Account -> approve ──
acct = ad_accounts.create_ad_account(OWNER, AdAccountCreateIn(
    company_name="ADVB1 Seed Co", billing_email="advb1@example.com"))
ACCOUNT = acct["account_id"]
ad_accounts.review_ad_account(ACCOUNT, ADMIN, "approve")
line(f"account_id={ACCOUNT} status=active (approved)")

# ── ADV-101: deposit charges the PM ──
bal_before = ad_billing._get_balance(ACCOUNT)
dep = ad_billing.deposit_funds(ACCOUNT, 500000, PM_ID)   # $5000
bal_after = ad_billing._get_balance(ACCOUNT)
# read the ledger row to confirm the PaymentIntent id was recorded
hist = ad_billing.get_billing_history(ACCOUNT, 20)
pi_id = ""
for row in (hist if isinstance(hist, list) else hist.get("items", hist.get("entries", []))):
    if row.get("entry_type") == "budget_deposit":
        pi_id = (row.get("meta") or {}).get("stripe_payment_intent_id", "")
        break
ok_101 = bal_after == bal_before + 500000 and bool(pi_id)
RESULTS["ADV-101 deposit charges PM + credits"] = ok_101
line(f"ADV-101 deposit: bal {bal_before}->{bal_after} (+500000) PaymentIntent={pi_id} => {'PASS' if ok_101 else 'FAIL'}")

# ── ADV-101: failed charge -> NO balance credit ──
bal_pre_fail = ad_billing._get_balance(ACCOUNT)
_orig_create = stripe.PaymentIntent.create
def _boom(*a, **k):
    raise stripe.error.CardError("Your card was declined.", None, "card_declined")
stripe.PaymentIntent.create = _boom
raised = None
try:
    ad_billing.deposit_funds(ACCOUNT, 20000, PM_ID)  # $200 attempt, must be declined
except HTTPException as e:
    raised = e.status_code
except Exception as e:
    raised = "exc:" + type(e).__name__
finally:
    stripe.PaymentIntent.create = _orig_create
bal_post_fail = ad_billing._get_balance(ACCOUNT)
ok_101f = raised == 402 and bal_post_fail == bal_pre_fail
RESULTS["ADV-101 failed charge -> no credit"] = ok_101f
line(f"ADV-101 decline: raised={raised} bal {bal_pre_fail}->{bal_post_fail} (unchanged) => {'PASS' if ok_101f else 'FAIL'}")

# ── ADV-102: funds-guard (no negative balance) ──
# A separate campaign with NO creative so it never wins serving.
guard_camp = ad_campaigns.create_campaign(ACCOUNT, CampaignCreateIn(
    name="ADVB1 Guard", objective="traffic", budget_cents=100000,
    budget_type="lifetime", bid_cpm_cents=500))
GUARD_CID = guard_camp["campaign_id"]
bal_g0 = ad_billing._get_balance(ACCOUNT)
over = bal_g0 + 999999  # more than the whole balance
res_over = ad_billing.charge_click(
    account_id=ACCOUNT, campaign_id=GUARD_CID, creative_id="none",
    creator_id="", content_id="c", bid_cpc_cents=over)
bal_g1 = ad_billing._get_balance(ACCOUNT)
# a small legitimate charge must still succeed + debit
res_small = ad_billing.charge_click(
    account_id=ACCOUNT, campaign_id=GUARD_CID, creative_id="none",
    creator_id="", content_id="c", bid_cpc_cents=100)
bal_g2 = ad_billing._get_balance(ACCOUNT)
ok_102 = (res_over.get("ok") is False and res_over.get("reason") == "insufficient_funds"
          and bal_g1 == bal_g0 and bal_g1 >= 0
          and res_small.get("ok") is True and bal_g2 == bal_g1 - 100)
RESULTS["ADV-102 funds-guard (no negative)"] = ok_102
line(f"ADV-102 over-charge({over}): {res_over}; bal {bal_g0}->{bal_g1} (unchanged, >=0); small charge ok, bal->{bal_g2} => {'PASS' if ok_102 else 'FAIL'}")

# ── Seed the serve-eligible campaign + creative ──
camp = ad_campaigns.create_campaign(ACCOUNT, CampaignCreateIn(
    name="ADVB1 Sponsored", objective="traffic", budget_cents=100000,
    budget_type="lifetime", bid_cpm_cents=800))
CAMPAIGN = camp["campaign_id"]
ad_campaigns.submit_campaign_for_review(ACCOUNT, CAMPAIGN)
ad_campaigns.review_campaign(CAMPAIGN, ADMIN, "approve")   # -> active
cr = ad_creatives.create_creative(CAMPAIGN, ACCOUNT, CreativeCreateIn(
    format="native_post", title="Try ADVB1", headline="A real sponsored unit",
    body_text="This paid ad reached your feed.", cta_text="Learn more",
    cta_url="https://example.com/advb1"))
CREATIVE = cr["creative_id"]
# give it an image so the feed card is rich
T.ad_creatives.update_item(
    Key={"pk": cr["pk"], "sk": cr["sk"]},
    UpdateExpression="SET image_url = :u",
    ExpressionAttributeValues={":u": "https://picsum.photos/seed/advb1/800/450"})
ad_creatives.submit_creative_for_review(CAMPAIGN, CREATIVE)
ad_creatives.review_creative(CREATIVE, ADMIN, "approve")   # -> approved
line(f"seeded campaign_id={CAMPAIGN} (active) creative_id={CREATIVE} (approved)")

# ── ADV-103: serve mints ad_click_id + AdClicks row ──
ad1 = serve_ad(surface="newsfeed", content_type="post", creator_id="platform",
               content_id="feed_slot_1", slot_type="sponsored_post", user_id=VIEWER)
ad2 = serve_ad(surface="newsfeed", content_type="post", creator_id="platform",
               content_id="feed_slot_2", slot_type="sponsored_post", user_id=VIEWER)
cid1, cid2 = ad1.get("ad_click_id"), ad2.get("ad_click_id")
row1 = T.ad_clicks.get_item(Key={"ad_click_id": cid1 or "x"}).get("Item") or {}
now = now_ts()
ttl_ok = abs(int(row1.get("expires_at", 0)) - (now + 604800)) < 120
ok_103 = (ad1.get("filled") and not ad1.get("is_house_ad")
          and ad1.get("campaign_id") == CAMPAIGN and ad1.get("creative_id") == CREATIVE
          and bool(cid1) and cid1 != cid2
          and row1.get("viewer_sub") == VIEWER and row1.get("status") == "served"
          and row1.get("campaign_id") == CAMPAIGN and ttl_ok
          and row1.get("content_owner_sub") == "")
RESULTS["ADV-103 serve mints ad_click_id + AdClicks row"] = ok_103
line(f"ADV-103 serve: filled={ad1.get('filled')} house={ad1.get('is_house_ad')} campaign={ad1.get('campaign_id')} ad_click_id={cid1} distinct={cid1!=cid2}")
line(f"ADV-103 AdClicks row: viewer={row1.get('viewer_sub')} status={row1.get('status')} owner='{row1.get('content_owner_sub')}' expires_at={row1.get('expires_at')} (now+7d={now+604800}, ttl_ok={ttl_ok}) => {'PASS' if ok_103 else 'FAIL'}")

# content_owner carry
ad3 = serve_ad(surface="newsfeed", content_type="post", creator_id="platform",
               content_id="feed_slot_3", slot_type="sponsored_post", user_id=VIEWER,
               content_owner_id="advb1_content_owner")
row3 = T.ad_clicks.get_item(Key={"ad_click_id": ad3.get("ad_click_id") or "x"}).get("Item") or {}
ok_owner = row3.get("content_owner_sub") == "advb1_content_owner"
RESULTS["ADV-103 content_owner carry"] = ok_owner
line(f"ADV-103 content_owner carry: row.content_owner_sub='{row3.get('content_owner_sub')}' => {'PASS' if ok_owner else 'FAIL'}")

# ── ADV-104: newsfeed injection surfaces sponsored fields ──
from app.routers.newsfeed import _fetch_sponsored_post
sp = _fetch_sponsored_post(VIEWER, 5, set())
ok_104 = bool(sp) and sp.get("is_sponsored") is True and bool(sp.get("ad_click_id")) \
    and sp.get("campaign_id") == CAMPAIGN and "account_id" in sp and "content_owner_id" in sp \
    and bool(sp.get("impression_url")) and bool(sp.get("click_url"))
RESULTS["ADV-104 newsfeed injection carries fields"] = ok_104
if sp:
    line(f"ADV-104 sponsored dict: is_sponsored={sp.get('is_sponsored')} campaign={sp.get('campaign_id')} account_id={sp.get('account_id')} ad_click_id={sp.get('ad_click_id')} content_owner_id='{sp.get('content_owner_id')}' cta={sp.get('cta_text')} img={sp.get('image_urls')}")
line(f"ADV-104 => {'PASS' if ok_104 else 'FAIL'}")

# ── Summary ──
line("SEED_IDS account_id=%s campaign_id=%s creative_id=%s viewer=%s pm=%s pi=%s" % (
    ACCOUNT, CAMPAIGN, CREATIVE, VIEWER, PM_ID, pi_id))
allpass = all(RESULTS.values())
for k, v in RESULTS.items():
    line(f"RESULT {'PASS' if v else 'FAIL'} :: {k}")
line("OVERALL " + ("ALL_PASS" if allpass else "SOME_FAIL"))
