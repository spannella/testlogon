"""SUBX-31 app-contract check: _post_to_dict emits subscriber_locked +
required_tier_level + required_tier_name for a tier-3 post viewed by a tier-1
subscriber (locked) vs a tier-3 subscriber (unlocked). Self-cleans."""
import time, uuid
from app.core.tables import T
from app.core.time import now_ts
from app.routers import newsfeed as NF

TAG = f"subx31w_{int(time.time())}_{uuid.uuid4().hex[:6]}"
CID = f"{TAG}_creator"
now = now_ts(); FUTURE = now + 30*86400
written = []
def put(it): T.subscriptions.put_item(Item=it); written.append((it["pk"], it["sk"]))
def mk_plan(pid, price):
    for pk, sk in ((f"PLAN#{pid}", "META"), (f"CREATOR#{CID}", f"PLAN#{pid}")):
        put({"pk": pk, "sk": sk, "plan_id": pid, "creator_id": CID, "name": f"Plan-{pid}",
             "price_cents": price, "currency": "usd", "interval": "month", "status": "active", "created_at": now})
def mk_sub(uid, pid):
    from app.services import subscription_access as SA
    subid = f"{TAG}_{uuid.uuid4().hex[:8]}"
    rec = {"subscription_id": subid, "plan_id": pid, "creator_id": CID, "subscriber_id": uid,
           "status": "active", "current_period_end": FUTURE, "tier_level": SA.get_plan_level(CID, pid), "created_at": now}
    for pk, sk in ((f"SUBSCRIBER#{uid}", f"SUB#{subid}"),):
        it = dict(rec); it.update({"pk": pk, "sk": sk}); put(it)

P1, P3 = f"{TAG}_p1", f"{TAG}_p3"
mk_plan(P1, 200); mk_plan(P3, 5000)   # L1 / L2 (dense rank of 2 plans -> 1,2). Use L2 as "high".
U1, U2, U0 = f"{TAG}_u1", f"{TAG}_u2", f"{TAG}_u0"
mk_sub(U1, P1)  # tier 1
mk_sub(U2, P3)  # tier 2 (highest here)

# a tier-2-required subscriber_only post authored by CID
post = {"post_id": f"{TAG}_post", "user_id": CID, "subscriber_only": True,
        "required_tier_level": 2, "body": "SECRET", "body_plain": "SECRET", "created_at": now}

def probe(viewer):
    d = NF._post_to_dict(dict(post), viewer_id=viewer)
    return d.get("subscriber_locked"), d.get("required_tier_level"), d.get("required_tier_name"), d.get("body")

res = []
def check(n, c): res.append((n, bool(c))); print(("PASS" if c else "FAIL"), n)

l1 = probe(U1)  # tier-1 viewer -> LOCKED, names the required tier
print(" tier1 viewer:", l1)
check("tier1 locked=True", l1[0] is True)
check("tier1 required_level=2", l1[1] == 2)
check("tier1 required_name=Plan-p3", l1[2] == f"Plan-{P3}")
check("tier1 body withheld", l1[3] == "[Locked content]")

l2 = probe(U2)  # tier-2 viewer -> UNLOCKED
print(" tier2 viewer:", l2)
check("tier2 locked=False", l2[0] is False)
check("tier2 body shown", l2[3] == "SECRET")

l0 = probe(U0)  # non-subscriber -> LOCKED
print(" non-sub viewer:", l0)
check("nonsub locked=True", l0[0] is True)
check("nonsub required_name set", l0[2] == f"Plan-{P3}")

# cleanup
dele = 0
for pk, sk in written:
    try: T.subscriptions.delete_item(Key={"pk": pk, "sk": sk}); dele += 1
    except Exception as e: print("DELWARN", e)
from boto3.dynamodb.conditions import Attr
resp = T.subscriptions.scan(FilterExpression=Attr("pk").contains(TAG) | Attr("sk").contains(TAG))
residue = len(resp.get("Items", []))
p = sum(1 for _, ok in res if ok)
print(f"\nRESULT {p}/{len(res)} passed; wrote={len(written)} deleted={dele} residue={residue}")
import sys; sys.exit(0 if p == len(res) and residue == 0 else 1)
