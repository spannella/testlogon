"""ADV3-E4 deep-verify: ledger/summary/ROAS reconciliation + no fabricated metrics.
Seeds a synthetic advertiser, charges via the real money path, writes complete/skip
events, asserts get_summary reconciles with roas_report, then auto-cleans (0 residue).
"""
import uuid
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_billing
from app.services.ad_analytics import get_summary
from app.services.ad_roas import roas_report, ledger_metrics, calculate_campaign_roas

TAG = "adv3e4vfy"
acct = f"{TAG}_{uuid.uuid4().hex[:8]}"
camp = f"{TAG}_c_{uuid.uuid4().hex[:8]}"
created = []


def cleanup():
    try:
        r = T.ad_billing.query(KeyConditionExpression=Key("pk").eq(f"ACCT#{acct}"))
        for it in r.get("Items", []):
            T.ad_billing.delete_item(Key={"pk": it["pk"], "sk": it["sk"]})
    except Exception as e:
        print("cleanup ledger warn", e)
    try:
        T.ad_accounts.delete_item(Key={"pk": f"ACCT#{acct}", "sk": "META"})
        T.ad_campaigns.delete_item(Key={"pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}"})
    except Exception as e:
        print("cleanup acct warn", e)
    for pk, sk in created:
        try:
            T.ad_impressions.delete_item(Key={"pk": pk, "sk": sk})
        except Exception as e:
            print("cleanup imp warn", e)


try:
    T.ad_accounts.put_item(Item={"pk": f"ACCT#{acct}", "sk": "META", "account_id": acct,
        "balance_cents": 1_000_000, "status": "active", "owner_sub": f"{TAG}_owner"})
    T.ad_campaigns.put_item(Item={"pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}",
        "campaign_id": camp, "account_id": acct, "status": "active", "budget_cents": 0})

    N_IMP, N_CLK, N_CONV = 10, 4, 2
    CPM, CPC, CPA, CONV_VALUE = 5000, 50, 300, 4000
    for i in range(N_IMP):
        r = ad_billing.charge_impression(account_id=acct, campaign_id=camp, creative_id="cr1",
            creator_id="", content_id="v1", bid_cpm_cents=CPM, idempotency_key=f"{TAG}i{i}",
            surface="newsfeed", slot_type="inline", geo_country="US")
        assert r.get("ok"), r
    for i in range(N_CLK):
        r = ad_billing.charge_click(account_id=acct, campaign_id=camp, creative_id="cr1",
            creator_id="", content_id="v1", bid_cpc_cents=CPC, idempotency_key=f"{TAG}k{i}",
            surface="newsfeed", slot_type="inline", geo_country="US")
        assert r.get("ok"), r
    for i in range(N_CONV):
        r = ad_billing.charge_conversion(account_id=acct, campaign_id=camp, creative_id="cr1",
            creator_id="", content_id="v1", bid_cpa_cents=CPA, idempotency_key=f"{TAG}v{i}",
            conversion_value_cents=CONV_VALUE)
        assert r.get("ok"), r

    ts = now_ts()

    def imp_evt(evt, uid, n):
        pk = "AD_IMP#test"
        sk = f"VIDEO#v1#{uid}#{ts}#{evt}#{n}"
        T.ad_impressions.put_item(Item={"pk": pk, "sk": sk, "event_id": f"{TAG}{n}",
            "user_id": uid, "campaign_id": camp, "account_id": acct, "surface": "vod",
            "slot_type": "preroll", "geo_country": "US", "event_type": evt, "created_at": ts})
        created.append((pk, sk))

    for n in range(6):
        imp_evt("complete", f"u{n % 3}", n)      # 6 completes, 3 unique users
    for n in range(2):
        imp_evt("skip", f"u{n}", 100 + n)        # 2 skips
    for n in range(3):
        imp_evt("impression", f"u{n}", 200 + n)  # 3 impression reach events

    exp_spend = N_IMP * (CPM // 1000) + N_CLK * CPC + N_CONV * CPA  # 50 + 200 + 600 = 850
    s = get_summary(acct, None, days=30)
    rr = roas_report(acct, None, days=30)
    lm = ledger_metrics(acct, None, now_ts() - 30 * 86400)
    cr = calculate_campaign_roas(account_id=acct, campaign_id=camp, days=30)
    tot = rr["totals"]

    print("=== RECONCILE MATRIX (account, 30d) ===")
    print(f"expected spend_cents={exp_spend}")
    print(f"summary : imp={s['impressions']} clk={s['clicks']} spend={s['spend_cents']} conv={s['conversions']} value={s['conversion_revenue_cents']} roas={s['roas']} cpc={s['cpc_cents']} cpa={s['cpa_cents']}")
    print(f"roas_rpt: imp={tot['impressions']} clk={tot['clicks']} spend={tot['spend_cents']} conv={tot['conversions']} value={tot['conversion_value_cents']} roas={tot['roas']} cpa={tot['cpa_cents']}")
    print(f"ledger  : imp={lm['impressions']} clk={lm['clicks']} spend={lm['spend_cents']} conv={lm['conversions']} value={lm['conversion_value_cents']}")
    print(f"calc_roas(campaign): spend={cr['spend_cents']} conv_rev={cr['conversion_revenue_cents']} roas={cr['roas']} conv={cr['conversion_count']}")
    print(f"engagement: completes={s['completes']} skips={s['skips']} completion_rate={s['completion_rate_pct']} unique_users={s['unique_users']}")

    fails = []
    for k_s, k_r in [("impressions", "impressions"), ("clicks", "clicks"), ("spend_cents", "spend_cents"), ("conversions", "conversions"), ("conversion_revenue_cents", "conversion_value_cents")]:
        if s[k_s] != tot[k_r]:
            fails.append(f"summary.{k_s}({s[k_s]}) != roas_report.{k_r}({tot[k_r]})")
    if s["roas"] != tot["roas"]:
        fails.append(f"roas mismatch {s['roas']} vs {tot['roas']}")
    if s["spend_cents"] != exp_spend:
        fails.append(f"spend {s['spend_cents']} != expected {exp_spend}")
    if cr["conversion_revenue_cents"] != tot["conversion_value_cents"]:
        fails.append("calc_roas value != roas_report value (D7 engines disagree)")
    if cr["roas"] != tot["roas"]:
        fails.append(f"calc_roas roas {cr['roas']} != {tot['roas']} (D7)")
    if s["cpc_cents"] != round(exp_spend / N_CLK):
        fails.append(f"cpc {s['cpc_cents']} != round(spend/clicks)")
    if s["cpa_cents"] != round(exp_spend / N_CONV):
        fails.append(f"cpa {s['cpa_cents']} != round(spend/conversions)")
    if s["completes"] != 6 or s["skips"] != 2:
        fails.append(f"completes/skips wrong {s['completes']}/{s['skips']}")
    if s["completion_rate_pct"] != round(6 / 8 * 100, 2):
        fails.append(f"completion_rate wrong {s['completion_rate_pct']}")
    if s["unique_users"] != 3:
        fails.append(f"unique_users wrong {s['unique_users']}")
    s1 = get_summary(acct, None, days=1)
    if s1["spend_cents"] != exp_spend:
        fails.append(f"today(days=1) lost spend {s1['spend_cents']}")
    if "revenue_cents" in s:
        fails.append("fabricated revenue_cents present in summary")

    print("=== RESULT ===")
    if fails:
        for f in fails:
            print("FAIL:", f)
        raise SystemExit(2)
    print("ALL RECONCILE CHECKS PASSED")
finally:
    cleanup()
    rem = T.ad_billing.query(KeyConditionExpression=Key("pk").eq(f"ACCT#{acct}")).get("Items", [])
    meta = T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item")
    print(f"RESIDUE ledger_rows={len(rem)} acct_meta={'present' if meta else 'gone'}")
