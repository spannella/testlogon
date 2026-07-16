import sys, uuid, json, traceback, boto3
TAG = "tipxc_" + uuid.uuid4().hex[:8]
tipper = TAG + "_fan"; creator = TAG + "_creator"
created = []; results = []
def ok(name, cond, extra=""):
    results.append((name, bool(cond), extra)); print(("PASS" if cond else "FAIL"), name, extra)
from app.core.tables import T
import app.services.tips as tips_mod
from app.services.tips import charge_tip, reverse_tip, TIP_CONTENT_TYPES
from app.services import tip_ledger
from botocore.exceptions import ClientError
from app.core.settings import S
import asyncio
_ep = T.billing.meta.client.meta.endpoint_url
_bare = boto3.client("dynamodb", endpoint_url=_ep, region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test", aws_session_token="test")
_orig = tips_mod._transact_tip_ledger
def _patched(**kw):
    m = tips_mod
    tn = S.billing_table_name
    tx = [{"Put": {"TableName": tn, "Item": m._av(kw["debit_item"])}}, {"Put": {"TableName": tn, "Item": m._av(kw["credit_item"])}}]
    if kw["idempotency_key"] and kw["receipt_item"] is not None:
        tx.append({"Put": {"TableName": tn, "Item": m._av(kw["receipt_item"]), "ConditionExpression": "attribute_not_exists(sk)"}})
    try:
        _bare.transact_write_items(TransactItems=tx); return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException": return False
        raise
tips_mod._transact_tip_ledger = _patched
def user_ledger(uid):
    return T.billing.query(KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": "USER#" + uid}).get("Items", [])
def track(uid):
    for r in user_ledger(uid): created.append((T.billing, {"pk": r["pk"], "sk": r["sk"]}))
def run(coro): return asyncio.new_event_loop().run_until_complete(coro)
try:
    T.users.put_item(Item={"user_sub": creator, "username": creator}); created.append((T.users, {"user_sub": creator}))
    T.users.put_item(Item={"user_sub": tipper, "username": tipper}); created.append((T.users, {"user_sub": tipper}))
    T.profile.put_item(Item={"user_sub": creator, "display_name": "TIPXC Creator", "discoverability_status": "active"}); created.append((T.profile, {"user_sub": creator}))
    T.profile.put_item(Item={"user_sub": tipper, "display_name": "TIPXC Fan", "discoverability_status": "active"}); created.append((T.profile, {"user_sub": tipper}))
    ok("profile in TIP_CONTENT_TYPES", "profile" in TIP_CONTENT_TYPES)
    ok("profile in ledger types", "profile" in tip_ledger._VALID_CONTENT_TYPES)
    ok("profile reason begins Tip", tip_ledger._reason_for_content_type("profile").startswith("Tip"), tip_ledger._reason_for_content_type("profile"))
    from app.routers.profile import tip_creator_profile, ProfileTipRequest
    ctx = {"user_sub": tipper}
    resp = run(tip_creator_profile(identifier=creator, body=ProfileTipRequest(amount_cents=1000, currency="usd", client_request_id="c1"), ctx=ctx))
    track(tipper); track(creator); created.append((T.billing, {"pk": "USER#"+tipper, "sk": "TIPIDEMP#profiletip:"+creator+":c1"}))
    ok("charged 1000", resp.get("charged_cents") == 1000, str(resp.get("charged_cents")))
    ok("net 800 20pct", resp.get("net_cents") == 800, str(resp.get("net_cents")))
    ok("recipient creator", resp.get("recipient_id") == creator)
    ok("profile total 1000", resp.get("tip_total_cents") == 1000, str(resp.get("tip_total_cents")))
    ok("not replay", resp.get("idempotent_replay") is False)
    cred = [r for r in user_ledger(creator) if r.get("type") == "credit" and str(r.get("reason","")).startswith("Tip")]
    deb = [r for r in user_ledger(tipper) if r.get("type") == "debit" and str(r.get("reason","")).startswith("Tip")]
    ok("one credit NET 800", len(cred) == 1 and int(cred[0]["amount_cents"]) == 800, str([int(c["amount_cents"]) for c in cred]))
    ok("credit content_type profile", bool(cred) and cred[0].get("meta",{}).get("content_type") == "profile")
    ok("one debit GROSS 1000", len(deb) == 1 and int(deb[0]["amount_cents"]) == 1000, str([int(d["amount_cents"]) for d in deb]))
    ok("profile.tip_total_cents 1000", int(T.profile.get_item(Key={"user_sub": creator}).get("Item", {}).get("tip_total_cents", 0)) == 1000)
    ok("TIPIDEMP receipt written", bool(T.billing.get_item(Key={"pk":"USER#"+tipper,"sk":"TIPIDEMP#profiletip:"+creator+":c1"}).get("Item")))
    resp2 = run(tip_creator_profile(identifier=creator, body=ProfileTipRequest(amount_cents=1000, currency="usd", client_request_id="c1"), ctx=ctx))
    ok("replay flagged", resp2.get("idempotent_replay") is True)
    ok("still ONE credit charged once", len([r for r in user_ledger(creator) if r.get("type")=="credit" and str(r.get("reason","")).startswith("Tip")]) == 1)
    ok("total NOT double-bumped", int(T.profile.get_item(Key={"user_sub": creator}).get("Item", {}).get("tip_total_cents", 0)) == 1000)
    resp3 = run(tip_creator_profile(identifier=creator, body=ProfileTipRequest(amount_cents=500, currency="usd", client_request_id="c2"), ctx=ctx))
    track(tipper); track(creator); created.append((T.billing, {"pk": "USER#"+tipper, "sk": "TIPIDEMP#profiletip:"+creator+":c2"}))
    ok("second tip total 1500", resp3.get("tip_total_cents") == 1500, str(resp3.get("tip_total_cents")))
    ok("second tip net 400", resp3.get("net_cents") == 400)
    from fastapi import HTTPException
    try:
        run(tip_creator_profile(identifier=creator, body=ProfileTipRequest(amount_cents=100), ctx={"user_sub": creator})); ok("self-tip rejected", False)
    except HTTPException as e:
        ok("self-tip 400", e.status_code == 400)
    try:
        run(tip_creator_profile(identifier=TAG+"_nobody", body=ProfileTipRequest(amount_cents=100), ctx=ctx)); ok("unknown rejected", False)
    except HTTPException as e:
        ok("unknown profile 404", e.status_code == 404)
    _pi = tips_mod._charge_tip_payment_intent
    def _decline(**kw):
        raise HTTPException(402, {"code": "payment_failed", "message": "declined"})
    tips_mod._charge_tip_payment_intent = _decline
    before_c = len(user_ledger(creator)); before_total = int(T.profile.get_item(Key={"user_sub": creator}).get("Item", {}).get("tip_total_cents", 0))
    try:
        run(tip_creator_profile(identifier=creator, body=ProfileTipRequest(amount_cents=999, currency="usd", client_request_id="c3decline"), ctx=ctx)); ok("402 raised on decline", False)
    except HTTPException as e:
        ok("402 on declined card", e.status_code == 402, str(e.status_code))
    tips_mod._charge_tip_payment_intent = _pi
    after_c = len(user_ledger(creator)); after_total = int(T.profile.get_item(Key={"user_sub": creator}).get("Item", {}).get("tip_total_cents", 0))
    ok("no ledger row on 402", after_c == before_c, str(before_c)+"-"+str(after_c))
    ok("no orphan total on 402", after_total == before_total, str(before_total)+"-"+str(after_total))
    ok("no receipt on 402", not T.billing.get_item(Key={"pk":"USER#"+tipper,"sk":"TIPIDEMP#profiletip:"+creator+":c3decline"}).get("Item"))
    tpid = resp3.get("tip_payment_id")
    try:
        rev = reverse_tip(tipper_id=tipper, tip_payment_id=tpid, amount_cents=500, recipient_id=creator, content_type="profile", content_id=creator, reason="tipxc-test")
        track(tipper); track(creator)
        allc = user_ledger(creator)
        rr = [r for r in allc if r.get("state") == "reversed"]
        re_ = [r for r in allc if r.get("type") == "reversal"]
        ok("reversal reachable", rev is not None)
        ok("original credit reversed", len(rr) >= 1, str(len(rr)))
        ok("reversal entry not credit", len(re_) >= 1 and all(r.get("type") != "credit" for r in re_), str([r.get("type") for r in re_]))
    except Exception as e:
        ok("reversal reachable", False, "raised "+repr(e)[:100])
except Exception as e:
    print("EXC", e); traceback.print_exc()
finally:
    tips_mod._transact_tip_ledger = _orig
    for uid in (tipper, creator):
        for r in user_ledger(uid):
            try: T.billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
            except Exception as ex: print("sweep-fail", ex)
    for crid in ("c1","c2","c3decline"):
        try: T.billing.delete_item(Key={"pk":"USER#"+tipper,"sk":"TIPIDEMP#profiletip:"+creator+":"+crid})
        except Exception: pass
    for tbl in (T.profile, T.users):
        for uid in (tipper, creator):
            try: tbl.delete_item(Key={"user_sub": uid})
            except Exception as ex: print("cleanup-fail", ex)
    resid = len(user_ledger(tipper)) + len(user_ledger(creator))
    leftover = sum(1 for tbl in (T.profile, T.users) for uid in (tipper, creator) if tbl.get_item(Key={"user_sub": uid}).get("Item"))
    print("RESIDUE ledger_rows=%d profiles_users_left=%d" % (resid, leftover))
    npass = sum(1 for _, c, _ in results if c)
    print("SUMMARY %d/%d passed" % (npass, len(results)))
    print("ALLPASS" if npass == len(results) and resid == 0 and leftover == 0 else "HASFAIL")
