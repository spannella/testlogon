"""SUBX-30..33 live-DDB-direct verifier. Writes pattern-tagged synthetic rows to
the real subscriptions table, exercises the tier model + gate, then DELETES every
row it wrote and asserts 0 residue. No moto."""
import sys, time, uuid
from app.core.tables import T
from app.core.time import now_ts
from app.services import subscription_access as SA

TAG = f"subx30v_{int(time.time())}_{uuid.uuid4().hex[:6]}"
CID = f"{TAG}_creator"
CID2 = f"{TAG}_creator2"  # isolated creator for explicit-level / bridge probes
now = now_ts()
FUTURE = now + 30 * 86400
PAST = now - 86400

written = []  # (pk, sk)

def put(item):
    T.subscriptions.put_item(Item=item)
    written.append((item["pk"], item["sk"]))

def mk_plan(pid, price, interval="month", level=None, status="active", cid=CID):
    base = {"plan_id": pid, "creator_id": cid, "name": f"Plan-{pid}", "price_cents": price,
            "currency": "usd", "interval": interval, "status": status, "created_at": now}
    if level is not None:
        base["level"] = level
    meta = dict(base); meta.update({"pk": f"PLAN#{pid}", "sk": "META"})
    idx = dict(base); idx.update({"pk": f"CREATOR#{cid}", "sk": f"PLAN#{pid}"})
    put(meta); put(idx)

def mk_sub(sub_uid, pid, price, *, tier_level="__derive__", status="active", period_end=FUTURE, interval="month"):
    subid = f"{TAG}_{uuid.uuid4().hex[:8]}"
    rec = {"subscription_id": subid, "plan_id": pid, "creator_id": CID, "subscriber_id": sub_uid,
           "status": status, "current_period_end": period_end, "price_cents": price, "interval": interval,
           "currency": "usd", "created_at": now}
    if tier_level != "__derive__":
        if tier_level is not None:
            rec["tier_level"] = tier_level
    else:
        rec["tier_level"] = SA.get_plan_level(CID, pid)
    for pk, sk in ((f"SUBSCRIBER#{sub_uid}", f"SUB#{subid}"), (f"CREATOR#{CID}", f"SUB#{subid}"),
                   (f"SUBSCRIPTION#{subid}", "META")):
        it = dict(rec); it.update({"pk": pk, "sk": sk})
        put(it)
    return subid

results = []
def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL"), name)

# --- 3 plans: $2 (L1), $10 (L2), $50 (L3) by price rank ---
P1, P2, P3 = f"{TAG}_p1", f"{TAG}_p2", f"{TAG}_p3"
mk_plan(P1, 200); mk_plan(P2, 1000); mk_plan(P3, 5000)

# SUBX-30: derived dense price-rank levels
check("get_plan_level P1==1", SA.get_plan_level(CID, P1) == 1)
check("get_plan_level P2==2", SA.get_plan_level(CID, P2) == 2)
check("get_plan_level P3==3", SA.get_plan_level(CID, P3) == 3)

# explicit level on a plan overrides rank (isolated creator so it can't shift CID ranks)
PX = f"{TAG}_px"; mk_plan(PX, 300, level=7, cid=CID2)
check("get_plan_level explicit==7", SA.get_plan_level(CID2, PX) == 7)

# fan_club TIER# bridge -> level from TIER# (isolated creator)
PT = f"{TAG}_pt"; mk_plan(PT, 400, cid=CID2)
put({"pk": f"CREATOR#{CID2}", "sk": f"TIER#{TAG}_t", "plan_id": PT, "level": 5, "active": True, "name": "Bridged"})
check("get_plan_level fan_club bridge==5", SA.get_plan_level(CID2, PT) == 5)

# --- subscribers at each tier ---
U1, U2, U3, U0 = f"{TAG}_u1", f"{TAG}_u2", f"{TAG}_u3", f"{TAG}_u0"
mk_sub(U1, P1, 200)   # tier 1
mk_sub(U2, P2, 1000)  # tier 2
mk_sub(U3, P3, 5000)  # tier 3

# SUBX-30 AC: get_subscriber_tier_level returns a level for a real subscriber
check("subscriber_tier_level U1==1", SA.get_subscriber_tier_level(U1, CID) == 1)
check("subscriber_tier_level U2==2", SA.get_subscriber_tier_level(U2, CID) == 2)
check("subscriber_tier_level U3==3", SA.get_subscriber_tier_level(U3, CID) == 3)
check("subscriber_tier_level U0==None", SA.get_subscriber_tier_level(U0, CID) is None)

# SUBX-31 gate matrix: required_level 1/2/3 for each viewer.
# content_locked_for_viewer -> True means LOCKED.
def locked(viewer, lvl):
    return SA.content_locked_for_viewer(viewer, CID, subscriber_only=True, required_level=lvl)

# tier-1 sub: unlocks L1 only, locked at L2/L3
check("U1 unlocks L1", locked(U1, 1) is False)
check("U1 LOCKED at L2", locked(U1, 2) is True)
check("U1 LOCKED at L3", locked(U1, 3) is True)
# tier-2 sub: unlocks L1,L2; locked L3
check("U2 unlocks L1", locked(U2, 1) is False)
check("U2 unlocks L2", locked(U2, 2) is False)
check("U2 LOCKED at L3", locked(U2, 3) is True)
# tier-3 sub: unlocks all
check("U3 unlocks L1", locked(U3, 1) is False)
check("U3 unlocks L2", locked(U3, 2) is False)
check("U3 unlocks L3", locked(U3, 3) is False)
# non-subscriber locked everywhere (incl binary level 0)
check("U0 LOCKED binary(0)", locked(U0, 0) is True)
check("U0 LOCKED at L1", locked(U0, 1) is True)

# owner + binary preservation: creator bypass, and any-sub unlocks required_level<=0
check("owner bypass", locked(CID, 3) is False)
check("U1 binary(0) unlocks (grandfather)", locked(U1, 0) is False)

# --- SUBX-32 migration: legacy sub with NO tier_level resolves via fallback ---
ULEG = f"{TAG}_uleg"
mk_sub(ULEG, P2, 1000, tier_level=None)  # no tier_level field written
check("legacy(no tier_level) resolves L2 via fallback", SA.viewer_max_tier_level(ULEG, CID) == 2)
check("legacy unlocks L2", locked(ULEG, 2) is False)
check("legacy LOCKED at L3", locked(ULEG, 3) is True)

# --- SUBX-33 expiry re-lock per tier ---
UEXP = f"{TAG}_uexp"
mk_sub(UEXP, P3, 5000, period_end=PAST)  # tier-3 but expired
check("expired tier-3 -> level 0", SA.viewer_max_tier_level(UEXP, CID) == 0)
check("expired sub LOCKED at L1", locked(UEXP, 1) is True)

# --- SUBX-33 multi-sub / bundle-not-over-locked: viewer holds L1 AND L3 -> max=3 ---
UMULTI = f"{TAG}_umulti"
mk_sub(UMULTI, P1, 200)
mk_sub(UMULTI, P3, 5000)
check("multi-sub resolves max tier 3", SA.viewer_max_tier_level(UMULTI, CID) == 3)
check("multi-sub unlocks L3", locked(UMULTI, 3) is False)

# --- SUBX-33 downgrade schedules (keeps higher tier until applied) ---
# simulate: tier-3 sub with a persisted tier_level=3 still on record -> unlocks L3
UDOWN = f"{TAG}_udown"
mk_sub(UDOWN, P3, 5000, tier_level=3)
check("pending-downgrade holder still unlocks L3 pre-apply", locked(UDOWN, 3) is False)

# tier_label_for_level upsell target (cheapest plan >= level)
check("tier_label L2 = Plan-p2", SA.tier_label_for_level(CID, 2) == f"Plan-{P2}")
check("tier_label L3 = Plan-p3", SA.tier_label_for_level(CID, 3) == f"Plan-{P3}")

# ================= CLEANUP =================
deleted = 0
for pk, sk in written:
    try:
        T.subscriptions.delete_item(Key={"pk": pk, "sk": sk})
        deleted += 1
    except Exception as e:
        print("DELWARN", pk, sk, e)

# residue check: scan for any row whose pk/sk contains TAG
from boto3.dynamodb.conditions import Attr
residue = 0
try:
    resp = T.subscriptions.scan(FilterExpression=Attr("pk").contains(TAG) | Attr("sk").contains(TAG))
    residue = len(resp.get("Items", []))
    while resp.get("LastEvaluatedKey"):
        resp = T.subscriptions.scan(FilterExpression=Attr("pk").contains(TAG) | Attr("sk").contains(TAG),
                                    ExclusiveStartKey=resp["LastEvaluatedKey"])
        residue += len(resp.get("Items", []))
except Exception as e:
    print("SCANWARN", e)

print(f"\nWROTE={len(written)} DELETED={deleted} RESIDUE={residue}")
passed = sum(1 for _, ok in results if ok)
total = len(results)
print(f"RESULT {passed}/{total} checks passed; residue={residue}")
sys.exit(0 if passed == total and residue == 0 else 1)
