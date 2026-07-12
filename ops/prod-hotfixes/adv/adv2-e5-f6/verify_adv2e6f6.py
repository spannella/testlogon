"""ADV2-E5 (F6) advertiser direct mass-DM -- in-process money-path verify on prod DDB.

Self-seeds a funded advertiser account/campaign, 3 followers of the advertiser,
an opted-out follower, and a NON-follower (non-relationship). Exercises:
  * audience resolution -> only eligible non-opted-out FOLLOWERS (non-follower +
    opted-out follower EXCLUDED)
  * mass-DM sends AS the advertiser -> delivered 2c/recipient PLATFORM-100%
    (advertiser debited, NO creator credit -- no content owner)
  * open +5c / click +10c funnel-stack, idempotent repeats 0
  * the excluded users get 0 charge (no AdClicks row minted)
  * opt-out endpoint flips a user OUT (send-time re-gate drops them)
  * funds-guard: empty balance -> 0 delivered, balance never negative
Prints PASS/FAIL + OVERALL.
"""
import time
import uuid

from app.core.tables import T
from app.services import ad_messaging as am
from app.services import ad_dm_audience as addm
from app.services import social

R = []


def check(name, cond, extra=""):
    R.append(bool(cond))
    print(("PASS" if cond else "FAIL"), "|", name, ("| " + str(extra)) if extra else "")


sfx = uuid.uuid4().hex[:8]
adv = f"advf6_{sfx}"
r1 = f"r1f6_{sfx}"; r2 = f"r2f6_{sfx}"; r3 = f"r3f6_{sfx}"
r_opt = f"roptf6_{sfx}"; r_non = f"rnonf6_{sfx}"
acct = f"adacctf6_{sfx}"; camp = f"campf6_{sfx}"; creative = f"crf6_{sfx}"
START_BAL = 100000
now = int(time.time())

for u in (adv, r1, r2, r3, r_opt, r_non):
    T.profile.put_item(Item={"user_sub": u, "display_name": u, "created_at": now})

T.ad_accounts.put_item(Item={
    "pk": f"ACCT#{acct}", "sk": "META", "account_id": acct, "owner_sub": adv,
    "company_name": "Acme F6 Direct", "status": "active",
    "balance_cents": START_BAL, "lifetime_spend_cents": 0, "created_at": now})
T.ad_campaigns.put_item(Item={
    "pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}", "campaign_id": camp, "account_id": acct,
    "status": "active", "name": "F6 mass-dm", "bid_cpm_cents": 20000,
    "bid_cpc_cents": 50, "bid_cpa_cents": 500, "budget_cents": 100000000,
    "lifetime_spent_cents": 0, "spent_today_cents": 0, "created_at": now})


def bal():
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0))


def set_bal(v):
    T.ad_accounts.update_item(Key={"pk": f"ACCT#{acct}", "sk": "META"},
        UpdateExpression="SET balance_cents = :v", ExpressionAttributeValues={":v": v})


def advertiser_credit():
    # F6 is platform-100%: the advertiser (== account owner) must earn NOTHING as
    # a "credit" from their own send. Assert no creator-style credit rows exist.
    resp = T.billing.query(KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": f"USER#{adv}"})
    return sum(int(it.get("amount_cents", 0) or 0) for it in resp.get("Items", [])
               if str(it.get("sk", "")).startswith("LEDGER#") and str(it.get("type", "")) == "credit")


def platform_revenue(idem_key):
    # platform_revenue ledger row(s) for a given charge idempotency key.
    resp = T.ad_billing.query(KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": f"ACCT#{acct}"})
    tot = 0
    for it in resp.get("Items", []):
        if str((it.get("meta") or {}).get("ad_click_id", "")) == idem_key:
            tot += int(it.get("amount_cents", 0) or 0)
    return tot


# relationships: r1/r2/r3 + r_opt FOLLOW the advertiser; r_non does NOT
for u in (r1, r2, r3, r_opt):
    social.follow_user(u, adv)

print("== 0. per-user ad opt-out endpoint flips a user out ==")
before = am.user_accepts_ad_messages(r_opt)
am.set_ad_messages_optout(r_opt, False)
check("opt-out endpoint sets allow_ad_messages False", am.user_accepts_ad_messages(r_opt) is False,
      f"{before}->{am.user_accepts_ad_messages(r_opt)}")

print("== 1. audience resolution (relationship gate + opt-out exclusion) ==")
aud = addm.resolve_advertiser_audience(adv)
rec = set(aud["recipients"])
check("audience = the 3 eligible followers only", rec == {r1, r2, r3}, sorted(rec))
check("opted-out follower EXCLUDED", r_opt not in rec and r_opt in aud["excluded_optout"])
check("non-follower (non-relationship) EXCLUDED", r_non not in rec)
check("is_recipient_eligible False for non-follower", addm.is_recipient_eligible(adv, r_non) is False)
check("is_recipient_eligible False for opted-out follower", addm.is_recipient_eligible(adv, r_opt) is False)
check("is_recipient_eligible True for a plain follower", addm.is_recipient_eligible(adv, r1) is True)

print("== 2. advertiser mass-DM sends AS the advertiser, delivered PLATFORM-100% ==")
b0 = bal()
send = addm.send_mass_dm(advertiser_sub=adv, account_id=acct, campaign_id=camp,
    body="Flash sale for our followers -- 20% off today only!",
    cta_url="https://acme.example/sale", creative_id=creative, sponsor_label="Acme")
sid = send["send_id"]
check("F6 product tag", send["product"] == "F6", send["product"])
check("delivered to all 3 eligible recipients", send["delivered_count"] == 3, send["delivered_count"])
check("advertiser debited 3 x 2c = 6c on delivery", b0 - bal() == 6, f"{b0}->{bal()}")
check("NO creator/owner credit (platform 100%)", advertiser_credit() == 0, advertiser_credit())
# message sent AS the advertiser
first = send["results"][0]
from app.routers import messaging as M
mrow = M.tbl_msgs.get_item(Key={"conversation_id": first["conversation_id"],
                                "message_id": first["message_id"]}).get("Item") or {}
check("message sent AS advertiser (sender_id==advertiser)", str(mrow.get("sender_id")) == adv, mrow.get("sender_id"))
check("message content_owner_sub empty (no creator)", str(mrow.get("content_owner_sub") or "") == "")
check("message carries ad_click_id + cta_url", mrow.get("ad_click_id") == first["ad_click_id"] and bool(mrow.get("cta_url")))

print("== 3. EXCLUDED users got 0 charge (no delivery-state row minted) ==")
# deterministic click id for an excluded user under this send would be absent
excl_click = am._click_id(sid, r_non)
optout_click = am._click_id(sid, r_opt)
check("no AdClicks row for non-follower", am._get_click(excl_click) is None)
check("no AdClicks row for opted-out follower", am._get_click(optout_click) is None)

print("== 4. OPEN (+5c) then CLICK (+10c) funnel-stack + idempotent, platform-100% ==")
clicked = send["results"][0]
cid = clicked["ad_click_id"]
recipient = clicked["recipient_sub"]
b1 = bal()
o1 = am.record_open(ad_click_id=cid, actor_sub=recipient)
check("open charges +5c", b1 - bal() == 5, f"{b1}->{bal()} charge={o1.get('charge_cents')}")
check("open books platform-100% (no creator credit)", advertiser_credit() == 0)
b2 = bal()
o1b = am.record_open(ad_click_id=cid, actor_sub=recipient)
check("re-open idempotent (0 extra)", bal() == b2 and o1b.get("charge_cents") == 0, o1b.get("reason"))
b3 = bal()
c1 = am.record_click(ad_click_id=cid, actor_sub=recipient)
check("click charges +10c", b3 - bal() == 10, f"{b3}->{bal()} charge={c1.get('charge_cents')}")
b4 = bal()
c1b = am.record_click(ad_click_id=cid, actor_sub=recipient)
check("re-click idempotent (0 extra)", bal() == b4 and c1b.get("charge_cents") == 0, c1b.get("reason"))
check("clicked recipient funnel-stack = 2+5+10 = 17c", platform_revenue(cid) == 17, platform_revenue(cid))
check("total advertiser spend = 6 + 5 + 10 = 21c", START_BAL - bal() == 21, f"spent={START_BAL - bal()}")
check("advertiser earned NOTHING back (platform-100% throughout)", advertiser_credit() == 0, advertiser_credit())

print("== 5. send-time RE-GATE drops an opt-out that happens after resolve ==")
# r1 opts out AFTER being resolved into the audience; a fresh send must drop them.
am.set_ad_messages_optout(r1, False)
send2 = addm.send_mass_dm(advertiser_sub=adv, account_id=acct, campaign_id=camp,
    body="Second drop!", cta_url="https://acme.example/2")
rec2 = {r["recipient_sub"] for r in send2["results"] if r.get("state") == "sent"}
check("post-opt-out follower dropped from 2nd send", r1 not in rec2, sorted(rec2))
check("2nd send delivered to the remaining 2", send2["delivered_count"] == 2, send2["delivered_count"])
am.set_ad_messages_optout(r1, True)  # restore

print("== 6. list/detail contracts ==")
sends = addm.list_advertiser_sends(adv)
check("list_advertiser_sends returns this send", any(s.get("send_id") == sid for s in sends), len(sends))
det = addm.get_send(sid)
check("detail advertiser_sub == advertiser + creator_sub empty", str(det.get("advertiser_sub")) == adv and str(det.get("creator_sub") or "") == "")

print("== 7. insufficient balance STOPS sending (never negative) ==")
set_bal(1)  # < 2c delivered -> first charge fails
send3 = addm.send_mass_dm(advertiser_sub=adv, account_id=acct, campaign_id=camp,
    body="Third drop!", cta_url="https://acme.example/3")
check("insufficient funds -> 0 delivered", send3["delivered_count"] == 0, send3["delivered_count"])
check("send status paused_insufficient_funds", send3["status"] == "paused_insufficient_funds", send3["status"])
check("balance never negative (still 1)", bal() == 1, bal())

ok = sum(R)
tot = len(R)
print(f"\nOVERALL {'ALL_PASS' if ok == tot else 'FAIL'} {ok}/{tot}")
