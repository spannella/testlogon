"""ADV3-9 D6/D5/D10 rollup verify: real per-surface/per-geo SPEND + complete/skip
counts in compute_hourly_rollup, and NO fabricated revenue_cents. Self-cleaning."""
import uuid
from datetime import datetime, timezone
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_billing
from app.services.ad_analytics import compute_hourly_rollup, get_breakdown

TAG = "adv3e4roll"
acct = f"{TAG}_{uuid.uuid4().hex[:8]}"
camp = f"{TAG}_c_{uuid.uuid4().hex[:8]}"
imp_created = []


def cleanup():
    try:
        for it in T.ad_billing.query(KeyConditionExpression=Key("pk").eq(f"ACCT#{acct}")).get("Items", []):
            T.ad_billing.delete_item(Key={"pk": it["pk"], "sk": it["sk"]})
    except Exception as e:
        print("cln ledger", e)
    try:
        for it in T.ad_analytics_rollups.query(KeyConditionExpression=Key("pk").eq(f"CAMP#{camp}")).get("Items", []):
            T.ad_analytics_rollups.delete_item(Key={"pk": it["pk"], "sk": it["sk"]})
    except Exception as e:
        print("cln rollup", e)
    try:
        T.ad_accounts.delete_item(Key={"pk": f"ACCT#{acct}", "sk": "META"})
        T.ad_campaigns.delete_item(Key={"pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}"})
    except Exception as e:
        print("cln acct", e)
    for pk, sk in imp_created:
        try:
            T.ad_impressions.delete_item(Key={"pk": pk, "sk": sk})
        except Exception as e:
            print("cln imp", e)


try:
    T.ad_accounts.put_item(Item={"pk": f"ACCT#{acct}", "sk": "META", "account_id": acct,
        "balance_cents": 1_000_000, "status": "active", "owner_sub": f"{TAG}_o"})
    T.ad_campaigns.put_item(Item={"pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}",
        "campaign_id": camp, "account_id": acct, "status": "active", "budget_cents": 0})

    for i in range(10):
        ad_billing.charge_impression(account_id=acct, campaign_id=camp, creative_id="cr1",
            creator_id="", content_id="v1", bid_cpm_cents=5000, idempotency_key=f"{TAG}i{i}",
            surface="newsfeed", slot_type="inline", geo_country="US")
    for i in range(4):
        ad_billing.charge_click(account_id=acct, campaign_id=camp, creative_id="cr1",
            creator_id="", content_id="v1", bid_cpc_cents=50, idempotency_key=f"{TAG}k{i}",
            surface="newsfeed", slot_type="inline", geo_country="US")

    ts = now_ts()
    for evt in ("complete", "impression"):
        for n in range(3):
            pk, sk = "AD_IMP#roll", f"VIDEO#v1#u{n}#{ts}#{evt}#{n}"
            T.ad_impressions.put_item(Item={"pk": pk, "sk": sk, "user_id": f"u{n}", "campaign_id": camp,
                "account_id": acct, "surface": "vod", "slot_type": "preroll", "geo_country": "US",
                "event_type": evt, "created_at": ts})
            imp_created.append((pk, sk))

    hour = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H")
    r = compute_hourly_rollup(camp, acct, hour)

    exp_spend = 10 * 5 + 4 * 50  # 250 (impr+click spend; conversions not in surface map)
    surf = r["by_surface"].get("newsfeed/inline", {})
    geo = r["by_targeting"].get("US", {})
    print("=== ROLLUP (hour) ===")
    print(f"spend_cents={r['spend_cents']} impressions={r['impressions']} clicks={r['clicks']}")
    print(f"by_surface[newsfeed/inline]={surf}")
    print(f"by_targeting[US]={geo}")
    print(f"completes={r['completes']} skips={r['skips']} unique_users={r['unique_users']}")
    print(f"has_revenue_cents={'revenue_cents' in r}")

    fails = []
    if surf.get("spend_cents") != exp_spend:
        fails.append(f"by_surface spend {surf.get('spend_cents')} != {exp_spend} (D6)")
    if geo.get("spend_cents") != exp_spend:
        fails.append(f"by_targeting spend {geo.get('spend_cents')} != {exp_spend} (D6)")
    if surf.get("impressions") != 10 or surf.get("clicks") != 4:
        fails.append("by_surface counts wrong")
    if r["completes"] != 3:
        fails.append(f"completes {r['completes']} != 3 (D5)")
    if r["unique_users"] != 3:
        fails.append(f"unique_users {r['unique_users']} != 3 (D11)")
    if "revenue_cents" in r:
        fails.append("fabricated revenue_cents present in rollup (D10)")

    print("=== RESULT ===")
    if fails:
        for f in fails:
            print("FAIL:", f)
        raise SystemExit(2)
    print("ROLLUP D5/D6/D10/D11 CHECKS PASSED")
finally:
    cleanup()
    rem = T.ad_billing.query(KeyConditionExpression=Key("pk").eq(f"ACCT#{acct}")).get("Items", [])
    rr = T.ad_analytics_rollups.query(KeyConditionExpression=Key("pk").eq(f"CAMP#{camp}")).get("Items", [])
    print(f"RESIDUE ledger={len(rem)} rollups={len(rr)}")
