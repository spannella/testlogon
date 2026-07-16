"""ADV3 EPIC E3 — LIVE prod-DDB verification (real inventory).

Runs on the prod host against the live DynamoDB Local (env from .env.local).
Proves against REAL inventory, with explicit cleanup (targeted deletes of every
synthetic/committed row it creates):
  L0 ADV3-6 live flags (VOD deterministic OFF, broadcast billing ON, sponsored ON)
  L1 live inventory count (active campaigns + approved creatives)
  L2 real fill diversity via exclusion (C4) -- zero residue (deferred)
  L3 deferred mint leaves NO orphan; commit writes exactly one (C4)
  L4 ADV3-6 real paid PRE-ROLL fill (not placeholder) (C1) -- zero residue
  L5 ADV3-6 pre-roll completion CHARGES advertiser + CREDITS poster + idempotent
  L6 shop 3-unit fetch writes AT MOST 3 AdClicks rows (no 9-spin orphans) (C4)
  L7 ranked-feed-style injection: distinct advertisers + rows==units (C4/C6)
"""
import os, sys, uuid, time

os.chdir("/home/ubuntu/testlogon")
for line in open(".env.local"):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    os.environ.setdefault(k, v.strip())
sys.path.insert(0, "/home/ubuntu/testlogon")

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ad_serving import serve_ad, commit_ad_click
from app.services.ad_campaigns import list_campaigns_by_status
from app.services.ad_creatives import list_approved_creatives
from app.services.billing_shared import user_pk
from boto3.dynamodb.conditions import Key

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)

TAG = "adv3e3live_" + uuid.uuid4().hex[:8]
CLEANUP = []  # list of (table, Key) to delete at end


def scan_clicks_for_viewer(vsub):
    out, resp = [], T.ad_clicks.scan()
    out += [i for i in resp.get("Items", []) if i.get("viewer_sub") == vsub]
    while resp.get("LastEvaluatedKey"):
        resp = T.ad_clicks.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
        out += [i for i in resp.get("Items", []) if i.get("viewer_sub") == vsub]
    return out


print("\n=== L0: ADV3-6 live serving flags ===")
det = bool(getattr(S, "vod_ad_supported_deterministic", True))
bcast = bool(getattr(S, "broadcast_ads_billing_enabled", False))
spon = bool(getattr(S, "sponsored_posts_enabled", False))
check("L0a VOD_AD_SUPPORTED_DETERMINISTIC is OFF (live serve_ad preroll active)", det is False, f"value={det}")
check("L0b BROADCAST_ADS_BILLING_ENABLED is ON (live breaks charge)", bcast is True, f"value={bcast}")
check("L0c SPONSORED_POSTS_ENABLED is ON (feed injection active)", spon is True, f"value={spon}")

print("\n=== L1: live inventory ===")
active = list_campaigns_by_status("active")
servable = [c for c in active if list_approved_creatives(c["campaign_id"])]
paid_servable = [c for c in servable if not c.get("is_self_promo")]
check("L1 live inventory exists (>=1 active campaign w/ approved creative)", len(servable) >= 1,
      f"active={len(active)} servable={len(servable)} paid_servable={len(paid_servable)}")

print("\n=== L2: real fill diversity via exclusion (C4) ===")
V2 = "viewer_" + TAG + "_div"
def sstd(**kw):
    b = dict(surface="newsfeed", content_type="post", creator_id="platform",
             content_id="slot", slot_type="sponsored_post", user_id=V2,
             content_owner_id="", defer_ad_click=True)
    b.update(kw); return serve_ad(**b)
w1 = sstd(); c1 = w1.get("campaign_id")
w2 = sstd(exclude_campaign_ids={c1}); c2 = w2.get("campaign_id")
w3 = sstd(exclude_campaign_ids={c1, c2}); c3 = w3.get("campaign_id")
filled = [w for w in (w1, w2, w3) if w.get("filled") and not w.get("is_house_ad")]
distinct = {c for c in (c1, c2, c3) if c}
check("L2a real paid ads fill standalone slots", len(filled) >= 2, f"filled={len(filled)}")
check("L2b exclusion breaks single-advertiser monopoly (distinct winners)",
      len(distinct) >= min(3, len(paid_servable)) and c2 != c1, f"winners={c1},{c2},{c3}")

print("\n=== L3: deferred mint -> no orphan; commit writes one (C4) ===")
present_before = [w for w in (w1, w2, w3)
                  if T.ad_clicks.get_item(Key={"ad_click_id": w.get("ad_click_id", "_")}).get("Item")]
check("L3a deferred serves left ZERO AdClicks rows (no orphans)", len(present_before) == 0,
      f"unexpected_rows={len(present_before)}")
commit_ad_click(w1)
committed = T.ad_clicks.get_item(Key={"ad_click_id": w1["ad_click_id"]}).get("Item")
check("L3b commit persists exactly the kept row", bool(committed), "")
if committed:
    T.ad_clicks.delete_item(Key={"ad_click_id": w1["ad_click_id"]})  # cleanup

print("\n=== L4: ADV3-6 real paid PRE-ROLL fill (not placeholder) (C1) ===")
POSTER = "poster_" + TAG
V4 = "viewer_" + TAG + "_preroll"
pre = serve_ad(surface="preroll", content_type="vod", creator_id=POSTER,
               content_id="vid_" + TAG, slot_type="pre_roll", user_id=V4,
               content_owner_id=POSTER, defer_ad_click=True)
active_ids = {c["campaign_id"] for c in active}
check("L4 live serve_ad(preroll) returns a REAL paid fill (real campaign, ad_click minted)",
      pre.get("filled") and not pre.get("is_house_ad") and bool(pre.get("ad_click_id"))
      and pre.get("campaign_id") in active_ids,
      f"filled={pre.get('filled')} house={pre.get('is_house_ad')} camp={pre.get('campaign_id')}")

print("\n=== L5: ADV3-6 pre-roll completion charge + poster credit + idempotent ===")
AID = "adacct_" + TAG
CID = "camp_" + TAG
CRID = "cr_" + TAG
ACK = "ack_" + TAG
ts = now_ts()
T.ad_accounts.put_item(Item={"pk": f"ACCT#{AID}", "sk": "META", "account_id": AID,
    "owner_sub": "owner_" + TAG, "owner_type": "user", "status": "active",
    "balance_cents": 5000, "created_at": ts})
T.ad_campaigns.put_item(Item={"pk": f"ACCT#{AID}", "sk": f"CAMPAIGN#{CID}", "campaign_id": CID,
    "account_id": AID, "name": "synth", "objective": "awareness", "budget_cents": 5000,
    "budget_type": "lifetime", "daily_budget_cents": 0, "spent_today_cents": 0,
    "lifetime_spent_cents": 0, "status": "active", "category": "general",
    "bid_cpm_cents": 500, "bid_cpc_cents": 50, "bid_cpa_cents": 500, "is_self_promo": False,
    "created_at": ts, "updated_at": ts})
T.ad_clicks.put_item(Item={"ad_click_id": ACK, "viewer_sub": "viewer_" + TAG, "campaign_id": CID,
    "account_id": AID, "creative_id": CRID, "product_id": "", "content_owner_sub": POSTER,
    "surface": "preroll", "slot_type": "pre_roll", "content_id": "vid_" + TAG, "status": "served",
    "self_promo": False, "effective_price_cents": 500, "effective_cpm_cents": 500,
    "created_at": ts, "expires_at": ts + 604800})
from app.services.vod_ad_supported import _charge_preroll_completion
bal0 = int(T.ad_accounts.get_item(Key={"pk": f"ACCT#{AID}", "sk": "META"}).get("Item", {}).get("balance_cents", 0))
res1 = _charge_preroll_completion(target={"ad_click_id": ACK, "creative_id": CRID}, video_id="vid_" + TAG)
bal1 = int(T.ad_accounts.get_item(Key={"pk": f"ACCT#{AID}", "sk": "META"}).get("Item", {}).get("balance_cents", 0))
res2 = _charge_preroll_completion(target={"ad_click_id": ACK, "creative_id": CRID}, video_id="vid_" + TAG)  # idempotent
bal2 = int(T.ad_accounts.get_item(Key={"pk": f"ACCT#{AID}", "sk": "META"}).get("Item", {}).get("balance_cents", 0))
# find the settled ledger row -> creator_share proves the poster credit
ledger = T.ad_billing.query(
    KeyConditionExpression=Key("pk").eq(f"ACCT#{AID}"))
led_rows = ledger.get("Items", [])
settled = [r for r in led_rows if r.get("entry_type") == "impression_charge"]
creator_share = int(settled[0].get("meta", {}).get("creator_share_cents", 0)) if settled else -1
poster_credit_rows = T.billing.query(
    KeyConditionExpression=Key("pk").eq(user_pk(POSTER))).get("Items", [])
check("L5a advertiser balance DEBITED 500c on completion", bal0 - bal1 == 500, f"{bal0}->{bal1}")
check("L5b poster credited ~70% (creator_share_cents=350) in split", creator_share == 350, f"creator_share={creator_share}")
check("L5c poster has a settled ad-revenue CREDIT ledger row", len(poster_credit_rows) >= 1,
      f"rows={len(poster_credit_rows)}")
check("L5d completion is idempotent (no double-charge on replay)", bal2 == bal1, f"{bal1}->{bal2}")

# -- L5 cleanup: delete every synthetic/byproduct row --
for r in led_rows:
    T.ad_billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
for r in poster_credit_rows:
    T.billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
# platform-revenue byproduct row(s) for this synthetic campaign
prev = T.ad_billing.query(
    KeyConditionExpression=Key("pk").eq("PLATFORM#revenue")).get("Items", [])
for r in prev:
    if r.get("meta", {}).get("campaign_id") == CID or r.get("meta", {}).get("ad_click_id") == ACK:
        T.ad_billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
T.ad_clicks.delete_item(Key={"ad_click_id": ACK})
T.ad_campaigns.delete_item(Key={"pk": f"ACCT#{AID}", "sk": f"CAMPAIGN#{CID}"})
T.ad_accounts.delete_item(Key={"pk": f"ACCT#{AID}", "sk": "META"})

print("\n=== L6: shop 3-unit fetch <= 3 AdClicks rows (no orphan spins) (C4) ===")
V6 = "viewer_" + TAG + "_shop"
from app.services.shop_ads import serve_shop_sponsored
units = serve_shop_sponsored(viewer_id=V6, limit=3, surface="shop_search")
shop_rows = scan_clicks_for_viewer(V6)
ucamps = {u.get("campaign_id") for u in units if u.get("campaign_id")}
check("L6a shop returns <= 3 units", len(units) <= 3, f"units={len(units)}")
check("L6b committed rows == units (no 9-spin orphans)", len(shop_rows) == len(units),
      f"rows={len(shop_rows)} units={len(units)}")
if len(units) >= 2:
    check("L6c multi-unit shop shows distinct advertisers", len(ucamps) == len(units), f"camps={ucamps}")
else:
    check("L6c (n/a: <2 product units live) trivially distinct", True, f"units={len(units)}")
for r in shop_rows:
    T.ad_clicks.delete_item(Key={"ad_click_id": r["ad_click_id"]})  # cleanup

print("\n=== L7: feed injection: distinct advertisers + rows==units (C4/C6) ===")
V7 = "viewer_" + TAG + "_feed"
from app.routers.newsfeed import _inject_sponsored_posts
organic = [{"post_id": f"org_{TAG}_{i}", "allow_ads_near": True} for i in range(12)]
injected = _inject_sponsored_posts(list(organic), V7)
spons = [p for p in injected if p.get("is_sponsored")]
scamps = {p.get("campaign_id") for p in spons if p.get("campaign_id")}
feed_rows = scan_clicks_for_viewer(V7)
check("L7a ranked-style injection places sponsored slots", len(spons) >= 1, f"sponsored={len(spons)}")
check("L7b injected rows == injected units (no orphans)", len(feed_rows) == len(spons),
      f"rows={len(feed_rows)} sponsored={len(spons)}")
if len(spons) >= 2:
    check("L7c multi-slot page shows distinct advertisers", len(scamps) == len(spons), f"camps={scamps}")
else:
    check("L7c (n/a: single slot) trivially distinct", True, f"sponsored={len(spons)}")
for r in feed_rows:
    T.ad_clicks.delete_item(Key={"ad_click_id": r["ad_click_id"]})  # cleanup

print("\n=== RESIDUE CHECK ===")
leftover = (scan_clicks_for_viewer(V2) + scan_clicks_for_viewer(V4) + scan_clicks_for_viewer(V6)
            + scan_clicks_for_viewer(V7) + scan_clicks_for_viewer("viewer_" + TAG))
acct_left = T.ad_accounts.get_item(Key={"pk": f"ACCT#{AID}", "sk": "META"}).get("Item")
check("RESIDUE all synthetic AdClicks cleaned", len(leftover) == 0, f"leftover={len(leftover)}")
check("RESIDUE synthetic ad account removed", acct_left is None, "")

print("\n=== SUMMARY ===")
n_pass = sum(1 for _, ok, _ in RESULTS if ok); n = len(RESULTS)
print(f"{n_pass}/{n} PASS")
sys.exit(0 if n_pass == n else 1)
