"""ADV2-E6 (F7) phase 1 verify -- in-process on prod DDB.

Proves ADV2-701..704 model + cross-member serve eligibility (the syndicate-
tagged click; the 3-way SPLIT is the NEXT phase):

  1) create_syndicate_ad_account writes owner_type=syndicate + owner_syndicate_id
     (reuses the advertiser model + funding + admin lifecycle).
  2) _require_admin gates syndicate ad management (admin passes / non-admin 403).
  3) serve_ad in front of a MEMBER's content FILLS with the syndicate creative;
     the AdClicks row carries is_syndicate_ad + syndicate_id + content_owner=member.
  4) serve_ad in front of a NON-member's content does NOT serve the syndicate ad
     (house ad; is_syndicate_ad falsey).
  5) An EXTERNAL (non-syndicate) campaign is UNAFFECTED on a member slot -- still
     serves, is_syndicate_ad falsey (membership gate is syndicate-only, no skim).

Category-whitelist isolation (SCAT/ECAT) makes the auction deterministic against
whatever real prod campaigns exist.
"""
import uuid
from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_campaigns, syndicates
from app.services.ad_serving import serve_ad
from app.services.ad_accounts import create_syndicate_ad_account, get_ad_account
from app.models import CampaignCreateIn, AdAccountCreateIn

SUF = uuid.uuid4().hex[:8]
ADMIN = "e6_admin_" + SUF     # syndicate admin (creates + manages the ad account)
M     = "e6_member_" + SUF    # member creator (owns the content the ad runs on)
NM    = "e6_nonmem_" + SUF    # NON-member creator
V     = "e6_viewer_" + SUF    # separate viewer
EXT   = "e6_extadv_" + SUF    # external (non-syndicate) advertiser
SCAT  = "e6scat_" + SUF       # syndicate campaign category (isolates the auction)
ECAT  = "e6ecat_" + SUF       # external campaign category

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

def approved_creative(campaign_id, title):
    cid = "cr_" + uuid.uuid4().hex[:10]
    T.ad_creatives.put_item(Item={
        "pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{cid}", "creative_id": cid,
        "campaign_id": campaign_id, "format": "native_post", "title": title,
        "status": "approved", "created_at": now_ts(),
    })
    return cid

def set_status(acct_id, camp_id, status):
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{acct_id}", "sk": f"CAMPAIGN#{camp_id}"},
        UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": status})

def tag_category(acct_id, camp_id, cat):
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{acct_id}", "sk": f"CAMPAIGN#{camp_id}"},
        UpdateExpression="SET category = :c", ExpressionAttributeValues={":c": cat})

def click_row(acid):
    return T.ad_clicks.get_item(Key={"ad_click_id": acid}).get("Item") or {}

# ── Syndicate + membership ─────────────────────────────────────────────────
synd = syndicates.create_syndicate(creator_sub=ADMIN, name="E6 Test Syndicate " + SUF)
synd_id = synd["syndicate_id"]
syndicates._add_member(synd_id, M, role="member")   # M is a member; NM is NOT
check("ADV2: syndicate created + M is member + NM is not",
      syndicates.is_member(synd_id, M) and not syndicates.is_member(synd_id, NM),
      f"synd={synd_id}")

# ── ADV2-701: syndicate-owned ad account via the REAL create fn ─────────────
acct_S = create_syndicate_ad_account(synd_id, ADMIN, AdAccountCreateIn(
    company_name="E6 Syndicate Ads", billing_email="e6@syndicate.example"))["account_id"]
_s = get_ad_account(acct_S) or {}
check("ADV2-701: account owner_type=syndicate + owner_syndicate_id + owner_sub=admin",
      _s.get("owner_type") == "syndicate" and _s.get("owner_syndicate_id") == synd_id
      and _s.get("owner_sub") == ADMIN, f"acct={acct_S} {_s.get('owner_type')}")
fund_active(acct_S, 5_000_000)

# ── ADV2-701 admin gate: _require_admin passes for admin, 403 for non-admin ─
admin_ok = True
try:
    syndicates._require_admin(synd_id, ADMIN)
except Exception:
    admin_ok = False
nonadmin_blocked = False
try:
    syndicates._require_admin(synd_id, M)   # a plain member is not the admin
except Exception:
    nonadmin_blocked = True
check("ADV2-701: admin-gated management (admin passes, member blocked)",
      admin_ok and nonadmin_blocked)

# ── External (non-syndicate) advertiser account ────────────────────────────
acct_E = "adacct_e6ext_" + SUF
put_ext_acct(acct_E, EXT, 5_000_000)

# ── Campaigns + creatives ──────────────────────────────────────────────────
synd_camp = ad_campaigns.create_campaign(acct_S, CampaignCreateIn(
    name="Syndicate promo", objective="awareness",
    budget_cents=1_000_000, budget_type="lifetime", bid_cpm_cents=20000))["campaign_id"]
set_status(acct_S, synd_camp, "active"); tag_category(acct_S, synd_camp, SCAT)
synd_cr = approved_creative(synd_camp, "Syndicate Creative")

ext_camp = ad_campaigns.create_campaign(acct_E, CampaignCreateIn(
    name="External promo", objective="awareness",
    budget_cents=1_000_000, budget_type="lifetime", bid_cpm_cents=20000))["campaign_id"]
set_status(acct_E, ext_camp, "active"); tag_category(acct_E, ext_camp, ECAT)
ext_cr = approved_creative(ext_camp, "External Creative")

# ── AD_SETTINGS (category whitelist isolates the auction) ───────────────────
# For a DETERMINISTIC T1 (no equal-bid auction tie against a competing prod/ext
# creative), M initially allows ONLY the syndicate category (SCAT); ECAT is
# re-enabled for M just before T3. NM allows ONLY SCAT so the NON-member test is
# a clean "syndicate campaign excluded -> house ad".
T.billing.put_item(Item={"pk": f"USER#{M}", "sk": "AD_SETTINGS", "allow_ads": True,
    "min_cpm_cents": 0, "allowed_ad_categories": [SCAT]})
T.billing.put_item(Item={"pk": f"USER#{NM}", "sk": "AD_SETTINGS", "allow_ads": True,
    "min_cpm_cents": 0, "allowed_ad_categories": [SCAT]})

def serve_on(owner):
    return serve_ad(surface="feed", content_type="feed", creator_id=owner,
                    content_id="post_" + owner, slot_type="feed_native",
                    user_id=V, content_owner_id=owner)

# ── T1: syndicate ad FILLS on a MEMBER's content + tags the click ──────────
r1 = serve_on(M)
c1 = click_row(r1.get("ad_click_id", ""))
check("T1: serve on MEMBER fills with the SYNDICATE creative",
      r1.get("filled") and not r1.get("is_house_ad") and r1.get("creative_id") == synd_cr,
      f"creative={r1.get('creative_id')} vs synd={synd_cr}")
check("T1: serve response carries is_syndicate_ad + syndicate_id",
      r1.get("is_syndicate_ad") is True and r1.get("syndicate_id") == synd_id,
      f"is_synd={r1.get('is_syndicate_ad')} synd_id={r1.get('syndicate_id')}")
check("T1: AdClicks row carries is_syndicate_ad + syndicate_id + content_owner=member",
      c1.get("is_syndicate_ad") is True and c1.get("syndicate_id") == synd_id
      and c1.get("content_owner_sub") == M,
      f"click is_synd={c1.get('is_syndicate_ad')} synd={c1.get('syndicate_id')} owner={c1.get('content_owner_sub')}")

# ── T2: syndicate ad does NOT serve on a NON-member's content ───────────────
r2 = serve_on(NM)
c2 = click_row(r2.get("ad_click_id", "")) if r2.get("ad_click_id") else {}
check("T2: serve on NON-member does NOT serve the syndicate creative",
      r2.get("creative_id") != synd_cr and not r2.get("is_syndicate_ad"),
      f"creative={r2.get('creative_id')} is_synd={r2.get('is_syndicate_ad')} house={r2.get('is_house_ad')}")
check("T2: NON-member click (if any) is not syndicate-tagged",
      (not c2) or (not c2.get("is_syndicate_ad") and not c2.get("syndicate_id")),
      f"click={ {k: c2.get(k) for k in ('is_syndicate_ad','syndicate_id')} if c2 else {} }")

T.billing.put_item(Item={"pk": f"USER#{M}", "sk": "AD_SETTINGS", "allow_ads": True,
    "min_cpm_cents": 0, "allowed_ad_categories": [SCAT, ECAT]})
# ── T3: EXTERNAL campaign is UNAFFECTED on the member slot (no membership gate,
#        no skim) -- deactivate the syndicate campaign so the external one wins.
set_status(acct_S, synd_camp, "paused")
r3 = serve_on(M)
c3 = click_row(r3.get("ad_click_id", ""))
check("T3: EXTERNAL ad still serves on a MEMBER slot (membership gate is syndicate-only)",
      r3.get("filled") and r3.get("creative_id") == ext_cr and not r3.get("is_syndicate_ad"),
      f"creative={r3.get('creative_id')} vs ext={ext_cr} is_synd={r3.get('is_syndicate_ad')}")
check("T3: EXTERNAL click carries content_owner=member but is NOT syndicate-tagged",
      c3.get("content_owner_sub") == M and not c3.get("is_syndicate_ad")
      and not c3.get("syndicate_id"),
      f"owner={c3.get('content_owner_sub')} is_synd={c3.get('is_syndicate_ad')}")

# ── Summary ────────────────────────────────────────────────────────────────
npass = sum(1 for r in RESULTS if r["pass"]); ntot = len(RESULTS)
print(f"\nADV2-E6 phase1 verify: {npass}/{ntot} " +
      ("OVERALL ALL_PASS" if npass == ntot else "*** SOME FAILED ***"))
print(f"synd_id={synd_id} acct_S={acct_S} synd_camp={synd_camp} synd_cr={synd_cr}")
