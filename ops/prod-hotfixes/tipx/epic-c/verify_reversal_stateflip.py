import uuid, traceback, boto3
TAG = "tipxr2_" + uuid.uuid4().hex[:8]
tipper = TAG + "_fan"; creator = TAG + "_creator"
results = []
def ok(n,c,e=""): results.append((n,bool(c),e)); print(("PASS" if c else "FAIL"),n,e)
from app.core.tables import T
from app.services.tips import reverse_tip
_rc = T.billing.meta.client
_bare = boto3.client("dynamodb", endpoint_url=_rc.meta.endpoint_url, region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test", aws_session_token="test")
_rc.transact_write_items = _bare.transact_write_items
def UL(uid): return T.billing.query(KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p":"USER#"+uid}).get("Items", [])
import asyncio
def run(c): return asyncio.new_event_loop().run_until_complete(c)
try:
    T.users.put_item(Item={"user_sub": creator, "username": creator})
    T.profile.put_item(Item={"user_sub": creator, "display_name": "R2", "discoverability_status": "active"})
    from app.routers.profile import tip_creator_profile, ProfileTipRequest
    resp = run(tip_creator_profile(identifier=creator, body=ProfileTipRequest(amount_cents=500, currency="usd", client_request_id="r2"), ctx={"user_sub": tipper}))
    cred = [r for r in UL(creator) if r.get("type")=="credit" and str(r.get("reason","")).startswith("Tip")][0]
    rev = reverse_tip(tipper_id=tipper, recipient_id=creator, gross_cents=500, net_cents=400, tip_payment_id=resp.get("tip_payment_id"), content_type="profile", content_id=creator, credit_entry_id=cred["entry_id"], credit_ts=int(cred["ts"]), reason="tipxr2")
    ok("reversal reachable", rev is not None)
    allc = UL(creator)
    flipped = [r for r in allc if r.get("entry_id")==cred["entry_id"] and r.get("state")=="reversed"]
    ok("original credit flipped to state:reversed", len(flipped)==1, str([r.get("state") for r in allc if r.get("entry_id")==cred["entry_id"]]))
    ok("reversal entry type!=credit", any(r.get("type")=="reversal" for r in allc))
    ok("tipper refund type!=credit", any(r.get("type")=="refund" for r in UL(tipper)))
except Exception as e:
    print("EXC", e); traceback.print_exc()
finally:
    for uid in (tipper, creator):
        for r in UL(uid):
            try: T.billing.delete_item(Key={"pk":r["pk"],"sk":r["sk"]})
            except Exception: pass
    try: T.billing.delete_item(Key={"pk":"USER#"+tipper,"sk":"TIPIDEMP#profiletip:"+creator+":r2"})
    except Exception: pass
    for uid in (tipper, creator):
        for tbl in (T.profile, T.users):
            try: tbl.delete_item(Key={"user_sub": uid})
            except Exception: pass
    resid = len(UL(tipper))+len(UL(creator))
    leftover = sum(1 for tbl in (T.profile,T.users) for uid in (tipper,creator) if tbl.get_item(Key={"user_sub":uid}).get("Item"))
    print("RESIDUE ledger=%d pu=%d" % (resid, leftover))
    npass = sum(1 for _,c,_ in results if c)
    print("SUMMARY %d/%d" % (npass, len(results)))
    print("ALLPASS" if npass==len(results) and resid==0 and leftover==0 else "HASFAIL")
