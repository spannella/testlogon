#!/usr/bin/env python3
"""In-process money-path verification for the 3 backend features (run on prod)."""
import sys, time, uuid
from types import SimpleNamespace

from app.core.tables import T
from app.services.ad_serving import serve_ad, track_ad_event
from app.services.ad_accounts import get_ad_account

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + ("  | " + detail if detail else ""))

def acct_balance(account_id):
    it = T.ad_accounts.get_item(Key={"pk": "ACCT#%s" % account_id, "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0) or 0)

def billing_ledger_row(account_id, ad_click_id):
    from boto3.dynamodb.conditions import Key
    rows = T.ad_billing.query(
        KeyConditionExpression=Key("pk").eq("ACCT#%s" % account_id) & Key("sk").begins_with("LEDGER#")
    ).get("Items", [])
    for r in rows:
        if (r.get("meta") or {}).get("ad_click_id") == ad_click_id:
            return r
    return None

def creator_credits(user_sub, ad_click_id):
    from boto3.dynamodb.conditions import Key
    rows = T.billing.query(
        KeyConditionExpression=Key("pk").eq("USER#%s" % user_sub) & Key("sk").begins_with("LEDGER#")
    ).get("Items", [])
    return [r for r in rows if r.get("type") == "credit" and (r.get("meta") or {}).get("ad_click_id") == ad_click_id]

BROADCASTER = "bcast_verify_%s@testlogon.example" % uuid.uuid4().hex[:8]
VIEWER = "viewer_verify_%s@testlogon.example" % uuid.uuid4().hex[:8]
SESSION_ID = "bsess_verify_%s" % uuid.uuid4().hex[:10]

print("=" * 60)
print("FEATURE 1 - BROADCAST LIVE PRE-ROLL ADS")
print("broadcaster=%s viewer=%s session=%s" % (BROADCASTER, VIEWER, SESSION_ID))
print("=" * 60)

from app.services.broadcast_ads import build_pre_roll, record_ad_event

session = SimpleNamespace(
    id=SESSION_ID, created_by=BROADCASTER, pre_roll_enabled=True,
    mid_roll_skip_after_seconds=15, mid_roll_ad_break_duration_seconds=30,
    status="live", ad_break_active=False, total_ad_breaks=0,
)

res = build_pre_roll(session, VIEWER)
pre = res.get("pre_roll")
check("F1.serve returns creative", bool(pre) and pre.get("creative_id"), "creative=%s" % (pre or {}).get("creative_id"))
ad_click_id = (pre or {}).get("ad_click_id", "")
check("F1.pre_roll carries ad_click_id", bool(ad_click_id), "ad_click_id=%s" % ad_click_id)

click_row = T.ad_clicks.get_item(Key={"ad_click_id": ad_click_id}).get("Item") if ad_click_id else None
check("F1.AdClicks minted", bool(click_row))
if click_row:
    check("F1.surface=broadcast_preroll", click_row.get("surface") == "broadcast_preroll", "surface=%s" % click_row.get("surface"))
    check("F1.content_owner=broadcaster", click_row.get("content_owner_sub") == BROADCASTER, "owner=%s" % click_row.get("content_owner_sub"))
    account_id = click_row.get("account_id")
    effective = int(click_row.get("effective_price_cents", 0) or 0)
    owner = get_ad_account(account_id) or {}
    advertiser_owner = owner.get("owner_sub", "")
    print("  account_id=%s effective_price_cents=%s advertiser_owner=%s" % (account_id, effective, advertiser_owner))

    bal_before = acct_balance(account_id)
    r1 = record_ad_event(session_id=SESSION_ID, creative_id=pre["creative_id"], user_id=VIEWER,
                         event_type="complete", ad_click_id=ad_click_id, slot_type="broadcast_preroll")
    bal_after = acct_balance(account_id)
    debit = bal_before - bal_after
    check("F1.advertiser CHARGED (funds-guarded debit)", debit == effective and effective > 0,
          "debit=%s effective=%s bal %s->%s" % (debit, effective, bal_before, bal_after))

    row = billing_ledger_row(account_id, ad_click_id)
    check("F1.charge ledger row written", bool(row), "entry_type=%s amount=%s" % ((row or {}).get("entry_type"), (row or {}).get("amount_cents")))
    if row:
        meta = row.get("meta") or {}
        cshare = int(meta.get("creator_share_cents", 0) or 0)
        pshare = int(meta.get("platform_share_cents", 0) or 0)
        exp_c = (effective * 7000) // 10000
        check("F1.broadcaster credited 70pct", cshare == exp_c, "creator_share=%s expected=%s" % (cshare, exp_c))
        check("F1.platform 30pct", pshare == effective - exp_c, "platform_share=%s expected=%s" % (pshare, effective - exp_c))
        check("F1.credit creator_id=broadcaster", meta.get("creator_id") == BROADCASTER, "creator_id=%s" % meta.get("creator_id"))
        check("F1.surface tagged broadcast_preroll", meta.get("surface") == "broadcast_preroll")

    creds = creator_credits(BROADCASTER, ad_click_id)
    check("F1.broadcaster real credit row (type=credit)", len(creds) == 1 and int(creds[0].get("amount_cents", 0)) == (effective * 7000) // 10000,
          "rows=%d amt=%s" % (len(creds), creds[0].get("amount_cents") if creds else None))

    # Idempotency: a second completion must NOT charge again.
    bal_b2 = acct_balance(account_id)
    record_ad_event(session_id=SESSION_ID, creative_id=pre["creative_id"], user_id=VIEWER,
                    event_type="complete", ad_click_id=ad_click_id, slot_type="broadcast_preroll")
    # And an impression event on the same click must also be idempotent.
    record_ad_event(session_id=SESSION_ID, creative_id=pre["creative_id"], user_id=VIEWER,
                    event_type="impression", ad_click_id=ad_click_id, slot_type="broadcast_preroll")
    bal_a2 = acct_balance(account_id)
    check("F1.idempotent (repeat complete+impression = 0 extra debit)", bal_b2 == bal_a2, "bal %s->%s" % (bal_b2, bal_a2))
    check("F1.broadcaster credit still single row (no double credit)", len(creator_credits(BROADCASTER, ad_click_id)) == 1)

# Self-exclusion: broadcaster is never served their own pre-roll.
res_self = build_pre_roll(session, BROADCASTER)
check("F1.self-exclusion (broadcaster ad-free, no pre-roll)", res_self.get("pre_roll") is None and res_self.get("ad_free") is True,
      "pre_roll=%s ad_free=%s" % (res_self.get("pre_roll"), res_self.get("ad_free")))

print()
print("=" * 60)
print("FEATURE 2 - NO TIP ON SPONSORED POSTS (defensive reject)")
print("=" * 60)
from fastapi import HTTPException
from app.routers import newsfeed as nf
from app.routers.newsfeed import PostTipRequest, PostTipReactRequest

SPON_POST = "sponsored_verify_%s" % uuid.uuid4().hex[:10]
AUTHOR = "author_%s@testlogon.example" % uuid.uuid4().hex[:6]
TIPPER = "tipper_%s@testlogon.example" % uuid.uuid4().hex[:6]
nf.ddb_put_item({
    "pk": nf.pk_post(SPON_POST), "sk": nf.sk_post(), "post_id": SPON_POST,
    "user_id": AUTHOR, "text": "Sponsored ad post", "is_sponsored": True,
    "tip_total_cents": 0, "created_at": int(time.time()),
})

def expect_400(fn):
    try:
        fn()
        return (False, "no exception raised")
    except HTTPException as e:
        d = e.detail
        code = d.get("code") if isinstance(d, dict) else d
        return (e.status_code == 400 and code == "tip_not_allowed_on_ad", "status=%s code=%s" % (e.status_code, code))
    except Exception as e:
        return (False, "wrong exc %r" % e)

ok, det = expect_400(lambda: nf.tip_post(SPON_POST, PostTipRequest(amount_cents=500), TIPPER))
check("F2.tip on sponsored rejected 400 tip_not_allowed_on_ad", ok, det)
ok2, det2 = expect_400(lambda: nf.tip_react_to_post(SPON_POST, PostTipReactRequest(amount_cents=500, emoji="\U0001F4B8"), TIPPER))
check("F2.tip-react on sponsored rejected 400 tip_not_allowed_on_ad", ok2, det2)
# Confirm no ledger side-effect: sponsored post tip_total unchanged.
p = nf.ddb_get_item({"pk": nf.pk_post(SPON_POST), "sk": nf.sk_post()})
check("F2.no tip applied to sponsored post", int((p or {}).get("tip_total_cents", 0)) == 0)

print()
print("=" * 60)
print("FEATURE 3 - GROUP + SYNDICATE FEED ADS (standalone -> platform 100pct)")
print("=" * 60)
from app.services.sponsored_feed import inject_sponsored, inject_sponsored_syndicate
from app.models import SyndicatePostOut

def organic(n):
    return [{"post_id": "org_%d" % i, "user_id": "u%d" % i, "text": "post %d" % i,
             "created_at": int(time.time()), "allow_ads_near": True} for i in range(n)]

for surface_name, injector in (("group_feed", "group"), ("syndicate_feed", "synd")):
    gv = "gview_%s@testlogon.example" % uuid.uuid4().hex[:8]
    if injector == "group":
        out = inject_sponsored(organic(6), gv, surface="group_feed", content_prefix="group_TESTGID")
    else:
        out = inject_sponsored_syndicate(organic(6), gv, syndicate_id="TESTSID")
    spon = [p for p in out if p.get("is_sponsored")]
    check("F3.%s injects a sponsored unit" % surface_name, len(spon) >= 1, "count=%d total_items=%d" % (len(spon), len(out)))
    if not spon:
        continue
    unit = spon[0]
    acid = unit.get("ad_click_id", "")
    check("F3.%s unit is_sponsored+ad_click_id" % surface_name, bool(unit.get("is_sponsored")) and bool(acid), "ad_click_id=%s" % acid)
    crow = T.ad_clicks.get_item(Key={"ad_click_id": acid}).get("Item") if acid else None
    if crow:
        check("F3.%s surface tagged" % surface_name, crow.get("surface") == surface_name, "surface=%s" % crow.get("surface"))
        check("F3.%s standalone (content_owner empty)" % surface_name, str(crow.get("content_owner_sub", "") or "") == "", "owner=%r" % crow.get("content_owner_sub"))
        account_id = crow.get("account_id")
        # Money-path: charge via the real track endpoint -> platform 100pct.
        from boto3.dynamodb.conditions import Key as _K
        def _ledger_sks(aid):
            rs = T.ad_billing.query(KeyConditionExpression=_K("pk").eq("ACCT#%s" % aid) & _K("sk").begins_with("LEDGER#")).get("Items", [])
            return {r["sk"]: r for r in rs}
        before = _ledger_sks(account_id)
        bal_b = acct_balance(account_id)
        track_ad_event(event="impression", creative_id=unit.get("creative_id", ""),
                       campaign_id=crow.get("campaign_id", ""), account_id=account_id,
                       surface=surface_name, slot_type="sponsored_post",
                       content_id="feed_slot", creator_id="platform", ad_click_id=acid, user_id=gv)
        bal_a = acct_balance(account_id)
        debit = bal_b - bal_a
        after = _ledger_sks(account_id)
        new_rows = [after[sk] for sk in after if sk not in before]
        row = new_rows[0] if new_rows else None
        if row:
            meta = row.get("meta") or {}
            pshare = int(meta.get("platform_share_cents", 0) or 0)
            cshare = int(meta.get("creator_share_cents", 0) or 0)
            amt = int(row.get("amount_cents", 0) or 0)
            check("F3.%s advertiser charged on impression" % surface_name, debit == amt and amt > 0, "debit=%s amount=%s" % (debit, amt))
            check("F3.%s PLATFORM 100pct (no creator credit)" % surface_name, pshare == amt and cshare == 0, "platform=%s creator=%s" % (pshare, cshare))
        else:
            check("F3.%s charge ledger row" % surface_name, False, "no ledger row")
    if injector == "synd":
        try:
            SyndicatePostOut(**unit)
            check("F3.syndicate_feed unit serializes through SyndicatePostOut", True)
        except Exception as e:
            check("F3.syndicate_feed unit serializes through SyndicatePostOut", False, repr(e))

print()
print("=" * 60)
passed = sum(1 for _, ok, _ in RESULTS if ok)
total = len(RESULTS)
print("SUMMARY %d/%d PASS" % (passed, total))
print("OVERALL " + ("ALL_PASS" if passed == total else "FAILURES=%d" % (total - passed)))
