"""ADV2-E5 (F5) in-process money-path verify on prod DDB.

Self-seeds a funded advertiser + campaign, a creator, 3 following recipients, an
opted-out follower, a non-follower (non-relationship), and a non-target user.
Exercises: audience resolution (opt-out + non-relationship EXCLUSION) -> offer ->
pending queue -> NON-TARGET approve 403 -> creator approve SENDS to the audience
AS the creator -> delivered billing 2c/recipient (advertiser debit) + creator 70%
credit -> open +5c -> click +10c -> idempotent repeats 0 -> clicked recipient
funnel-stack 17c -> double-approve 409 -> insufficient balance STOPS sending
(balance never negative). Prints PASS/FAIL + OVERALL.
"""
import time, uuid
from app.core.tables import T
from app.services import ad_messaging as am
from app.services import social

R = []
def check(name, cond, extra=""):
    R.append(bool(cond))
    print(("PASS" if cond else "FAIL"), "|", name, ("| " + str(extra)) if extra else "")

sfx = uuid.uuid4().hex[:8]
adv = f"adv_e5_{sfx}"; creator = f"creator_e5_{sfx}"
r1 = f"r1_e5_{sfx}"; r2 = f"r2_e5_{sfx}"; r3 = f"r3_e5_{sfx}"
r_opt = f"ropt_e5_{sfx}"; r_non = f"rnon_e5_{sfx}"; nontarget = f"nt_e5_{sfx}"
acct = f"adacct_e5_{sfx}"; camp = f"camp_e5_{sfx}"; creative = f"cr_e5_{sfx}"
START_BAL = 100000
now = int(time.time())

# profiles (follow_user requires the followed profile to exist)
for u in (adv, creator, r1, r2, r3, r_opt, r_non, nontarget):
    T.profile.put_item(Item={"user_sub": u, "display_name": u, "created_at": now})

# funded advertiser account + campaign
T.ad_accounts.put_item(Item={
    "pk": f"ACCT#{acct}", "sk": "META", "account_id": acct, "owner_sub": adv,
    "company_name": "Acme E5 Coffee", "status": "active",
    "balance_cents": START_BAL, "lifetime_spend_cents": 0, "created_at": now})
T.ad_campaigns.put_item(Item={
    "pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}", "campaign_id": camp, "account_id": acct,
    "status": "active", "name": "E5 campaign", "bid_cpm_cents": 20000,
    "bid_cpc_cents": 50, "bid_cpa_cents": 500, "budget_cents": 100000000,
    "lifetime_spent_cents": 0, "spent_today_cents": 0, "created_at": now})

def bal():
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0))

def set_bal(v):
    T.ad_accounts.update_item(Key={"pk": f"ACCT#{acct}", "sk": "META"},
        UpdateExpression="SET balance_cents = :v", ExpressionAttributeValues={":v": v})

def creator_credit():
    resp = T.billing.query(KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": f"USER#{creator}"})
    tot = 0
    for it in resp.get("Items", []):
        if str(it.get("sk", "")).startswith("LEDGER#") and str(it.get("type", "")) == "credit":
            tot += int(it.get("amount_cents", 0) or 0)
    return tot

def click_spend(ad_click_id):
    resp = T.ad_billing.query(KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": f"ACCT#{acct}"})
    tot = 0
    for it in resp.get("Items", []):
        if not str(it.get("sk", "")).startswith("LEDGER#"):
            continue
        if str((it.get("meta") or {}).get("ad_click_id", "")) == ad_click_id:
            tot += int(it.get("amount_cents", 0) or 0)
    return tot

# relationships: r1/r2/r3 + r_opt follow creator; r_non does NOT follow
for u in (r1, r2, r3, r_opt):
    social.follow_user(u, creator)
# r_opt opts out of ad messages
am.set_ad_messages_optout(r_opt, False)

print("== 1. audience resolution (opt-out + non-relationship exclusion) ==")
aud = am.resolve_creator_audience(creator)
rec = set(aud["recipients"])
check("audience = 3 following, non-opted-out recipients", rec == {r1, r2, r3}, sorted(rec))
check("opted-out follower EXCLUDED from audience", r_opt not in rec and r_opt in aud["excluded_optout"])
check("non-relationship (non-follower) EXCLUDED", r_non not in rec)
check("non-target user not in audience", nontarget not in rec)

print("== 2. advertiser offer -> creator pending queue ==")
offer = am.create_offer(advertiser_sub=adv, advertiser_account_id=acct, creator_sub=creator,
    body="Loving Acme cold brew this summer -- grab a bag, my code inside!",
    cta_url="https://acme.coffee/deal", campaign_id=camp, creative_id=creative,
    sponsor_account_id=acct, sponsor_label="Acme")
oid = offer["offer_id"]
check("offer status pending_creator", offer["status"] == "pending_creator")
pending = am.list_pending_for_creator(creator)
check("offer appears in creator inbox", any(o["offer_id"] == oid for o in pending))

print("== 3. NON-TARGET cannot approve ==")
try:
    am.approve_and_send(offer_id=oid, creator_sub=nontarget)
    check("non-target approve blocked 403", False, "no error raised")
except am.AdMessagingError as e:
    check("non-target approve blocked 403", e.status_code == 403, e.status_code)
still = am.get_offer(oid)
check("offer still pending after non-target attempt", still["status"] == "pending_creator")

print("== 4. creator approves -> SENDS to audience AS creator, delivered billing ==")
b0, cc0 = bal(), creator_credit()
send = am.approve_and_send(offer_id=oid, creator_sub=creator)
sid = send["send_id"]
check("delivered to all 3 recipients", send["delivered_count"] == 3, send["delivered_count"])
check("advertiser debited 3 x 2c = 6c on delivery", b0 - bal() == 6, f"{b0}->{bal()}")
check("creator credited 70% per delivery (3 x 1c = 3c, type:credit)", creator_credit() - cc0 == 3,
      creator_credit() - cc0)
# message actually sent AS the creator
first = send["results"][0]
from app.routers import messaging as M
mrow = M.tbl_msgs.get_item(Key={"conversation_id": first["conversation_id"],
                                "message_id": first["message_id"]}).get("Item") or {}
check("message sent AS creator (sender_id==creator)", str(mrow.get("sender_id")) == creator, mrow.get("sender_id"))
check("message carries ad_click_id + cta_url", mrow.get("ad_click_id") == first["ad_click_id"] and bool(mrow.get("cta_url")))
check("offer now approved + linked to send", am.get_offer(oid)["status"] == "approved" and am.get_offer(oid)["send_id"] == sid)

print("== 5. double-approve never double-sends (409) ==")
try:
    am.approve_and_send(offer_id=oid, creator_sub=creator)
    check("re-approve blocked 409", False, "no error")
except am.AdMessagingError as e:
    check("re-approve blocked 409", e.status_code == 409, e.status_code)

print("== 6. OPEN (+5c) then CLICK (+10c) funnel-stack + idempotent ==")
clicked = send["results"][0]
cid = clicked["ad_click_id"]
recipient = clicked["recipient_sub"]
# actor mismatch guard
other = r2 if recipient != r2 else r1
try:
    am.record_open(ad_click_id=cid, actor_sub=other)
    check("non-recipient open blocked 403", False, "no error")
except am.AdMessagingError as e:
    check("non-recipient open blocked 403", e.status_code == 403, e.status_code)

b1, cc1 = bal(), creator_credit()
o1 = am.record_open(ad_click_id=cid, actor_sub=recipient)
check("open charges +5c", b1 - bal() == 5, f"{b1}->{bal()} charge={o1.get('charge_cents')}")
check("open credits creator 70% (3c)", creator_credit() - cc1 == 3, creator_credit() - cc1)
b2 = bal()
o1b = am.record_open(ad_click_id=cid, actor_sub=recipient)
check("re-open idempotent (0 extra)", bal() == b2 and o1b.get("charge_cents") == 0, o1b.get("reason"))

b3, cc3 = bal(), creator_credit()
c1 = am.record_click(ad_click_id=cid, actor_sub=recipient)
check("click charges +10c", b3 - bal() == 10, f"{b3}->{bal()} charge={c1.get('charge_cents')}")
check("click credits creator 70% (7c)", creator_credit() - cc3 == 7, creator_credit() - cc3)
b4 = bal()
c1b = am.record_click(ad_click_id=cid, actor_sub=recipient)
check("re-click idempotent (0 extra)", bal() == b4 and c1b.get("charge_cents") == 0, c1b.get("reason"))

check("clicked recipient funnel-stack = 2+5+10 = 17c", click_spend(cid) == 17, click_spend(cid))
check("total advertiser spend = 6 + 5 + 10 = 21c", START_BAL - bal() == 21, f"spent={START_BAL - bal()}")
check("creator total credit = 3(deliv)+3(open)+7(click) = 13c", creator_credit() == 13, creator_credit())

print("== 7. insufficient balance STOPS sending (never negative) ==")
offer2 = am.create_offer(advertiser_sub=adv, advertiser_account_id=acct, creator_sub=creator,
    body="Second sponsored drop!", cta_url="https://acme.coffee/2", campaign_id=camp,
    creative_id=creative, sponsor_account_id=acct)
set_bal(1)  # < 2c delivered -> first charge fails
send2 = am.approve_and_send(offer_id=offer2["offer_id"], creator_sub=creator)
check("insufficient funds -> 0 delivered", send2["delivered_count"] == 0, send2["delivered_count"])
check("send status paused_insufficient_funds", send2["status"] == "paused_insufficient_funds", send2["status"])
check("balance never negative (still 1)", bal() == 1, bal())

ok = sum(R); tot = len(R)
print(f"\nOVERALL {'ALL_PASS' if ok == tot else 'FAIL'} {ok}/{tot}")
