"""ADV2 residuals R3 (self-promo moderation) + R4 (F6 subscriber enumeration)
verify -- in-process on prod DDB.

R3: a self-promo whose ONLY creative is unapproved/rejected does NOT serve (no
    self-promo fill, never an unmoderated creative); adding an APPROVED creative
    makes it serve. R4: an active SUBSCRIBER who does NOT follow the advertiser is
    now INCLUDED in the F6 audience; an opted-out subscriber is EXCLUDED; a
    non-relationship non-subscriber is still excluded.
"""
import uuid, time
from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_campaigns, social, ad_messaging
from app.services.ad_serving import serve_ad
from app.services.ad_dm_audience import resolve_advertiser_audience, is_recipient_eligible
from app.routers import subscription_server as subs
from app.models import CampaignCreateIn

SUF = uuid.uuid4().hex[:8]
RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("  :: " + str(detail) if detail else ""))

def put_acct(acct_id, owner, bal):
    T.ad_accounts.put_item(Item={
        "pk": f"ACCT#{acct_id}", "sk": "META", "account_id": acct_id,
        "owner_sub": owner, "status": "active", "balance_cents": bal,
        "lifetime_spend_cents": 0, "created_at": now_ts()})

def creative(campaign_id, title, status):
    cid = "cr_" + uuid.uuid4().hex[:10]
    T.ad_creatives.put_item(Item={
        "pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{cid}", "creative_id": cid,
        "campaign_id": campaign_id, "format": "native_post", "title": title,
        "status": status, "created_at": now_ts()})
    return cid

def set_status(acct_id, camp_id, status):
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{acct_id}", "sk": f"CAMPAIGN#{camp_id}"},
        UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": status})

def profile(sub):
    T.profile.put_item(Item={"user_sub": sub, "username": sub, "display_name": sub})

print("\n========== R3: SELF-PROMO SERVES ONLY APPROVED CREATIVES ==========")
C   = "r3_creator_" + SUF
V   = "r3_viewer_" + SUF
FAKE_CAT = "adv2r3cat_" + SUF
acct_C = "adacct_r3C_" + SUF
# category-isolate so no real prod PAID campaign wins on C's slot (self-promo
# bypasses the category filter, so this does not gate the self-promo itself)
T.billing.put_item(Item={"pk": f"USER#{C}", "sk": "AD_SETTINGS",
    "allow_ads": True, "min_cpm_cents": 0, "allowed_ad_categories": [FAKE_CAT]})
put_acct(acct_C, C, 0)

sp_item = ad_campaigns.create_campaign(acct_C, CampaignCreateIn(
    name="Promote my content", objective="awareness",
    budget_cents=0, budget_type="lifetime",
    is_self_promo=True, self_promo_mode="always_win"))
sp = sp_item["campaign_id"]
set_status(acct_C, sp, "active")

# ONLY unmoderated creatives exist: one pending, one rejected. NONE approved.
cid_pending  = creative(sp, "unmoderated promo", "pending")
cid_rejected = creative(sp, "rejected promo", "rejected")

r_none = serve_ad(surface="newsfeed", content_type="video", creator_id=C,
                  content_id="vid_" + SUF, slot_type="feed", user_id=V, content_owner_id=C)
served_cid = r_none.get("creative_id", "")
check("R3.1 self-promo with only unmoderated creatives does NOT fill self-promo",
      r_none.get("is_self_promo") is not True and r_none.get("campaign_id") != sp,
      f"is_self_promo={r_none.get('is_self_promo')} winner={r_none.get('campaign_id')} filled={r_none.get('filled')} house={r_none.get('is_house_ad')}")
check("R3.2 the unmoderated/rejected creative is NEVER served",
      served_cid not in (cid_pending, cid_rejected),
      f"served_creative={served_cid} pending={cid_pending} rejected={cid_rejected}")

# now add an APPROVED creative -> self-promo fills with the approved one
cid_approved = creative(sp, "approved promo", "approved")
r_ok = serve_ad(surface="newsfeed", content_type="video", creator_id=C,
                content_id="vid2_" + SUF, slot_type="feed", user_id=V, content_owner_id=C)
check("R3.3 with an APPROVED creative the self-promo serves",
      r_ok.get("is_self_promo") is True and r_ok.get("campaign_id") == sp,
      f"is_self_promo={r_ok.get('is_self_promo')} winner={r_ok.get('campaign_id')}")
check("R3.4 the served creative is the APPROVED one (never pending/rejected)",
      r_ok.get("creative_id") == cid_approved,
      f"served={r_ok.get('creative_id')} approved={cid_approved}")

print("\n========== R4: F6 SUBSCRIBER ENUMERATION ==========")
A    = "r4_adv_" + SUF     # advertiser (ad-account owner + subscription creator)
FOL  = "r4_fol_" + SUF     # follower (baseline union member)
SUB1 = "r4_sub1_" + SUF    # active subscriber, does NOT follow, not opted out -> INCLUDE
SUB2 = "r4_sub2_" + SUF    # active subscriber, does NOT follow, OPTED OUT -> EXCLUDE
NON  = "r4_non_" + SUF     # neither follows nor subscribes -> never enumerated
for u in (A, FOL, SUB1, SUB2, NON):
    profile(u)

# follower via the real social service (writes GSI5 that get_followers reads)
social.follow_user(FOL, A)

# two active subscriptions to A (save_subscription writes the CREATOR# index the
# enumeration reads AND the SUBSCRIBER# index the has_active_subscription re-gate reads)
for s in (SUB1, SUB2):
    subs.save_subscription({
        "subscription_id": "subx_" + uuid.uuid4().hex[:10],
        "creator_id": A, "subscriber_id": s, "status": "active",
        "plan_id": "plan_" + SUF, "price_cents": 500, "created_at": now_ts()})

# SUB2 opts out of ad messages
ad_messaging.set_ad_messages_optout(SUB2, False)

aud = resolve_advertiser_audience(A)
rec = set(aud["recipients"])
optout = set(aud["excluded_optout"])

check("R4.1 active SUBSCRIBER (non-follower) is INCLUDED in the audience",
      SUB1 in rec, f"recipients={aud['recipients']}")
check("R4.2 opted-out subscriber is EXCLUDED (in excluded_optout, not recipients)",
      SUB2 in optout and SUB2 not in rec, f"optout={aud['excluded_optout']} in_rec={SUB2 in rec}")
check("R4.3 non-relationship non-subscriber is NOT in the audience",
      NON not in rec, f"NON_in_rec={NON in rec}")
check("R4.4 follower still included (audience = followers UNION subscribers)",
      FOL in rec, f"FOL_in_rec={FOL in rec}")
check("R4.5 subscriber_enumeration flag flipped to creator_index_partition + >=1 added",
      aud.get("subscriber_enumeration") == "creator_index_partition" and aud.get("subscribers_added", 0) >= 1,
      f"flag={aud.get('subscriber_enumeration')} subs_added={aud.get('subscribers_added')}")
# send-time re-gate parity
check("R4.6 send-time re-gate: subscriber eligible, opted-out NOT, non-rel NOT",
      is_recipient_eligible(A, SUB1) is True and is_recipient_eligible(A, SUB2) is False and is_recipient_eligible(A, NON) is False,
      f"SUB1={is_recipient_eligible(A, SUB1)} SUB2={is_recipient_eligible(A, SUB2)} NON={is_recipient_eligible(A, NON)}")

print("\n========== OVERALL ==========")
n = len(RESULTS); p = sum(1 for x in RESULTS if x)
print(f"OVERALL {'ALL_PASS' if p == n else 'FAIL'} {p}/{n}")
