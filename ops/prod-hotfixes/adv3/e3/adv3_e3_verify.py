"""ADV3 EPIC E3 (ADV3-7) verification — core serving mechanisms, moto in-process.

Deterministic, controlled inventory, ZERO prod-DDB residue (own moto DynamoDB,
discarded on exit). Proves the patched serve_ad code paths:
  T1 diversity/exclusion (C4)   T2 deferred mint + commit (C4/orphan)
  T3 non-defer regression       T4 reserved "platform" fill guard (C7)
  T5 daily-budget pacing (C5)
The live-inventory proofs (shop <=limit rows, ranked-feed injection, real
pre-roll fill + charge) run separately against prod DDB in adv3_e3_prod_live.py.
"""
import os, sys, uuid
from datetime import datetime, timezone

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
              {"name": "ByStatus", "pk": "status", "sk": "created_at"}], num_attrs={"created_at"})
mktable(S.ad_campaigns_table_name, "pk", "sk",
        gsis=[{"name": "ByStatusCreatedAt", "pk": "status", "sk": "created_at"},
              {"name": "ByCampaignId", "pk": "campaign_id", "sk": "created_at"}], num_attrs={"created_at"})
mktable(S.ad_creatives_table_name, "pk", "sk",
        gsis=[{"name": "ByCreativeId", "pk": "creative_id"},
              {"name": "ByStatus", "pk": "status"}])
mktable(S.ad_clicks_table_name, "ad_click_id")
mktable(S.ad_targeting_table_name, "pk", "sk")
mktable(S.ad_frequency_caps_table_name, "pk", "sk")
mktable(S.billing_table_name, "pk", "sk")

from app.core.tables import T
from app.core.time import now_ts
import app.services.ad_serving as ADS
from app.services.ad_serving import serve_ad, commit_ad_click, _passes_pacing

TAG = "adv3e3_" + uuid.uuid4().hex[:8]
VIEWER = "viewer_" + TAG


def mk_campaign(letter, bid_cpm, product=False, budget_type="lifetime", daily=0, spent_today=0):
    ts = now_ts()
    aid = f"adacct_{TAG}_{letter}"
    cid = f"camp_{TAG}_{letter}"
    crid = f"cr_{TAG}_{letter}"
    T.ad_accounts.put_item(Item={
        "pk": f"ACCT#{aid}", "sk": "META", "account_id": aid,
        "owner_sub": f"owner_{TAG}_{letter}", "owner_type": "user",
        "status": "active", "balance_cents": 100000, "created_at": ts,
    })
    camp = {
        "pk": f"ACCT#{aid}", "sk": f"CAMPAIGN#{cid}", "campaign_id": cid, "account_id": aid,
        "name": f"Synth {letter}", "objective": "awareness",
        "budget_cents": 100000, "budget_type": budget_type,
        "daily_budget_cents": daily, "spent_today_cents": spent_today,
        "lifetime_spent_cents": 0, "status": "active", "category": "general",
        "bid_cpm_cents": bid_cpm, "bid_cpc_cents": 50, "bid_cpa_cents": 500,
        "is_self_promo": False, "created_at": ts, "updated_at": ts,
    }
    T.ad_campaigns.put_item(Item=camp)
    cr = {
        "pk": f"CAMP#{cid}", "sk": f"CREATIVE#{crid}", "creative_id": crid,
        "campaign_id": cid, "account_id": aid, "format": "image" if product else "native_post",
        "title": f"Ad {letter}", "headline": f"Headline {letter}", "body_text": "body",
        "cta_text": "Go", "status": "approved", "rotation_weight": 50,
        "skip_after_seconds": 5, "created_at": ts, "updated_at": ts,
        "image_url": f"https://x/{letter}.png",
    }
    if product:
        cr["product_id"] = f"prod_{TAG}_{letter}"
        cr["ctas"] = [{"cta_type": "buy_product", "target_id": cr["product_id"], "label": "Shop"}]
    T.ad_creatives.put_item(Item=cr)
    return {"account_id": aid, "campaign_id": cid, "creative_id": crid}


# ── controlled inventory: A>B>C>D by CPM ──────────────────────────────
A = mk_campaign("A", 800); B = mk_campaign("B", 700)
C = mk_campaign("C", 600); D = mk_campaign("D", 500)


def std_serve(**kw):
    base = dict(surface="newsfeed", content_type="post", creator_id="platform",
                content_id="slot_x", slot_type="sponsored_post", user_id=VIEWER,
                content_owner_id="")
    base.update(kw)
    return serve_ad(**base)


print("\n=== T1: fill diversity / exclusion (C4) ===")
w1 = std_serve(defer_ad_click=True)
w2 = std_serve(defer_ad_click=True, exclude_campaign_ids={w1.get("campaign_id")})
w3 = std_serve(defer_ad_click=True, exclude_campaign_ids={w1.get("campaign_id"), w2.get("campaign_id")})
c1, c2, c3 = w1.get("campaign_id"), w2.get("campaign_id"), w3.get("campaign_id")
check("T1a top bidder wins first slot", c1 == A["campaign_id"], f"got {c1}")
check("T1b exclusion yields 2nd advertiser", c2 == B["campaign_id"] and c2 != c1, f"got {c2}")
check("T1c exclusion yields 3rd advertiser", c3 == C["campaign_id"] and c3 not in (c1, c2), f"got {c3}")
check("T1d no single-advertiser monopoly", len({c1, c2, c3}) == 3, f"{c1},{c2},{c3}")

print("\n=== T2: deferred mint + commit (C4 / no orphans) ===")
n_after_defer = len(T.ad_clicks.scan().get("Items", []))
check("T2a deferred serves minted ZERO AdClicks rows", n_after_defer == 0, f"rows={n_after_defer}")
check("T2b deferred response carries pending row", bool(w1.get("_pending_ad_click")), "")
commit_ad_click(w1)
row = T.ad_clicks.get_item(Key={"ad_click_id": w1["ad_click_id"]}).get("Item")
check("T2c commit writes exactly the kept row", bool(row) and row.get("campaign_id") == c1, "")
check("T2d only the committed row exists", len(T.ad_clicks.scan().get("Items", [])) == 1, "")

print("\n=== T3: non-defer regression (default mints immediately) ===")
w_reg = std_serve()  # defer defaults False
reg_row = T.ad_clicks.get_item(Key={"ad_click_id": w_reg["ad_click_id"]}).get("Item")
check("T3 default serve_ad still mints on serve", bool(reg_row), "")
# clean the two real rows so later scans are clean
T.ad_clicks.delete_item(Key={"ad_click_id": w1["ad_click_id"]})
T.ad_clicks.delete_item(Key={"ad_click_id": w_reg["ad_click_id"]})

print("\n=== T4: reserved 'platform' fill guard + disable mechanism (C7) ===")
# Force-suppress BOTH a normal creator and the reserved platform id.
T.billing.put_item(Item={"pk": "USER#platform", "sk": "AD_SETTINGS", "allow_ads": False})
NORMAL = f"creatorX_{TAG}"
T.billing.put_item(Item={"pk": f"USER#{NORMAL}", "sk": "AD_SETTINGS", "allow_ads": False})
plat = std_serve(defer_ad_click=True)  # creator_id="platform"
norm = std_serve(defer_ad_click=True, creator_id=NORMAL, content_owner_id=NORMAL)
check("T4a reserved 'platform' still fills despite allow_ads=False",
      plat.get("filled") and not plat.get("is_house_ad"), f"reason={plat.get('fill_reason')}")
check("T4b a normal creator's allow_ads=False DOES suppress (control)",
      (not norm.get("filled")) and norm.get("fill_reason") == "creator_ads_disabled",
      f"filled={norm.get('filled')} reason={norm.get('fill_reason')}")
T.billing.delete_item(Key={"pk": "USER#platform", "sk": "AD_SETTINGS"})
T.billing.delete_item(Key={"pk": f"USER#{NORMAL}", "sk": "AD_SETTINGS"})

print("\n=== T5: daily-budget pacing (C5) ===")
noon = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)   # 50% of day
early = datetime(2026, 7, 15, 6, 0, 0, tzinfo=timezone.utc)   # 25% of day
life = {"budget_type": "lifetime", "budget_cents": 1000, "spent_today_cents": 999}
check("T5a lifetime campaign never paced", all(_passes_pacing(life) for _ in range(50)), "")
onpace = {"budget_type": "daily", "daily_budget_cents": 1000, "spent_today_cents": 250}
check("T5b daily on-pace always serves", all(_passes_pacing(onpace, now=noon) for _ in range(50)), "")
ahead = {"budget_type": "daily", "daily_budget_cents": 1000, "spent_today_cents": 900}
hits = sum(1 for _ in range(400) if _passes_pacing(ahead, now=early))
rate = hits / 400.0
# expected ~ target/spent = (0.25*1.15)/0.9 = 0.319
check("T5c daily AHEAD-of-pace is throttled (not front-loaded)", 0.15 < rate < 0.55, f"serve_rate={rate:.3f}")
fresh = {"budget_type": "daily", "daily_budget_cents": 1000, "spent_today_cents": 0}
check("T5d fresh daily campaign serves", all(_passes_pacing(fresh, now=early) for _ in range(20)), "")

print("\n=== SUMMARY ===")
n_pass = sum(1 for _, ok, _ in RESULTS if ok)
n = len(RESULTS)
print(f"{n_pass}/{n} PASS")
_mock.stop()
sys.exit(0 if n_pass == n else 1)
