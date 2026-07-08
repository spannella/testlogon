#!/usr/bin/env python3
"""TIP-B2 money-path verifier (in-process, real endpoints via TestClient with the
auth deps overridden to inject two identities A=tipper, B=author).

Checks:
  M1  A tip-reacts B's MESSAGE  -> 200; debit(gross) under A + credit(net,type=credit)
      under B with meta.content_type=message_react; money-reaction badge on the message.
  M2  self-tip on own message   -> 400 (no ledger).
  M3  failed charge (402)       -> endpoint 402; NO new credit row + NO new badge.
  P1  A tip-reacts B's POST     -> 200; credit(net,type=credit) under B post_react; badge on post.
  P2  self-tip on own post      -> 400.
  E1  classify_entry(message_react/post_react credit) -> "tips".
Prints VERIFY: lines + OVERALL PASS/FAIL.
"""
import uuid, sys, traceback
from fastapi import HTTPException
from fastapi.testclient import TestClient
from boto3.dynamodb.conditions import Key

import app.routers.messaging as msg_mod
import app.routers.newsfeed as nf_mod
import app.services.tips as tips_mod
from app.main import app
from app.core.tables import T

FIRE = "\U0001F525"
results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"VERIFY: {'PASS' if ok else 'FAIL'} {name} {detail}")

CUR = {"uid": None}
def _fake_msg_uid():
    return CUR["uid"]
async def _fake_nf_uid():
    return CUR["uid"]
app.dependency_overrides[msg_mod.get_messaging_user_id] = _fake_msg_uid
app.dependency_overrides[nf_mod._get_user_id] = _fake_nf_uid

client = TestClient(app)

A = "tipb2_tipper_" + uuid.uuid4().hex[:8]
B = "tipb2_author_" + uuid.uuid4().hex[:8]
print("USERS A(tipper)=", A, " B(author)=", B)

# --- seed minimal user rows so messaging can index/resolve them ---
for u in (A, B):
    try:
        msg_mod.tbl_users.put_item(Item={"user_id": u, "display_name": u, "handle": u})
    except Exception as e:
        print("warn seed user", u, e)
    for fn in ("_ensure_user_indexed",):
        try:
            getattr(msg_mod, fn)(u)
        except Exception:
            pass


def ledger_rows(uid):
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(f"USER#{uid}") & Key("sk").begins_with("LEDGER#"))
    return r.get("Items", [])

def credits_for(uid, content_type):
    out = []
    for it in ledger_rows(uid):
        if it.get("type") == "credit" and (it.get("meta") or {}).get("content_type") == content_type:
            out.append(it)
    return out

def debits_for(uid, content_type):
    out = []
    for it in ledger_rows(uid):
        if it.get("type") == "debit" and (it.get("meta") or {}).get("content_type") == content_type:
            out.append(it)
    return out


# ===================== MESSAGE FLOW =====================
CUR["uid"] = A
r = client.post("/messaging/conversations/dm/find-or-create", json={"user_id": B})
print("find-or-create", r.status_code, r.text[:300])
cj = r.json()
cid = cj.get("conversation_id") or cj.get("id")
assert cid, f"no conversation id: {r.text[:300]}"

CUR["uid"] = B
r = client.post(f"/messaging/conversations/{cid}/messages", json={"text": "hi from B (author)"})
print("send msg (B)", r.status_code, r.text[:200])
mj = r.json()
mid = mj.get("message_id")
assert mid, f"no message id: {r.text[:300]}"
assert mj.get("sender_id") == B

# M1: A tip-reacts B's message
CUR["uid"] = A
r = client.post(f"/messaging/conversations/{cid}/messages/{mid}/reactions/tip",
                json={"amount_cents": 500, "emoji": FIRE})
print("MSG tip-react (A)", r.status_code, r.text[:300])
m1_ok = r.status_code == 200
resp = r.json() if m1_ok else {}
cr = credits_for(B, "message_react")
dr = debits_for(A, "message_react")
cr_amt = int(cr[0]["amount_cents"]) if cr else -1
dr_amt = int(dr[0]["amount_cents"]) if dr else -1
badge = msg_mod.tbl_msgs.get_item(Key={"conversation_id": cid, "message_id": mid}).get("Item", {})
tip_reactions = badge.get("tip_reactions") or []
check("M1_message_tipreact_200_charge_credit_badge",
      m1_ok and cr_amt == 400 and dr_amt == 500 and len(tip_reactions) == 1 and cr[0]["type"] == "credit",
      f"resp={resp} debit(A)={dr_amt} credit(B,net)={cr_amt} type={cr[0]['type'] if cr else None} badge={tip_reactions}")

# M2: self-tip on own message
CUR["uid"] = B
r = client.post(f"/messaging/conversations/{cid}/messages/{mid}/reactions/tip", json={"amount_cents": 300})
check("M2_self_tip_message_400", r.status_code == 400, f"status={r.status_code} body={r.text[:160]}")

# M3: failed charge -> 402, no new ledger/badge
CUR["uid"] = A
credits_before = len(credits_for(B, "message_react"))
badges_before = len((msg_mod.tbl_msgs.get_item(Key={"conversation_id": cid, "message_id": mid}).get("Item", {}) or {}).get("tip_reactions") or [])
_orig = tips_mod._charge_tip_payment_intent
def _boom(**kw):
    raise HTTPException(402, {"code": "payment_failed", "message": "forced decline (verify)"})
tips_mod._charge_tip_payment_intent = _boom
try:
    r = client.post(f"/messaging/conversations/{cid}/messages/{mid}/reactions/tip", json={"amount_cents": 700, "emoji": FIRE})
finally:
    tips_mod._charge_tip_payment_intent = _orig
credits_after = len(credits_for(B, "message_react"))
badges_after = len((msg_mod.tbl_msgs.get_item(Key={"conversation_id": cid, "message_id": mid}).get("Item", {}) or {}).get("tip_reactions") or [])
check("M3_failed_charge_402_no_ledger_no_badge",
      r.status_code == 402 and credits_after == credits_before and badges_after == badges_before,
      f"status={r.status_code} credits {credits_before}->{credits_after} badges {badges_before}->{badges_after}")

# ===================== POST FLOW =====================
CUR["uid"] = B
r = client.post("/posts", json={"body": "tipb2 post by B", "visibility": "public"})
print("create post (B)", r.status_code, r.text[:250])
pj = r.json()
pid = pj.get("post_id") or pj.get("id")
assert pid, f"no post id: {r.text[:300]}"

# P1: A tip-reacts B's post
CUR["uid"] = A
r = client.post(f"/posts/{pid}/reactions/tip", json={"amount_cents": 800, "emoji": FIRE, "currency": "usd"})
print("POST tip-react (A)", r.status_code, r.text[:300])
p1_ok = r.status_code == 200
presp = r.json() if p1_ok else {}
pcr = credits_for(B, "post_react")
pdr = debits_for(A, "post_react")
pcr_amt = int(pcr[0]["amount_cents"]) if pcr else -1
pdr_amt = int(pdr[0]["amount_cents"]) if pdr else -1
post_item = nf_mod.ddb_get_item({"pk": nf_mod.pk_post(pid), "sk": nf_mod.sk_post()}) or {}
post_badges = post_item.get("tip_reactions") or []
check("P1_post_tipreact_200_charge_credit_badge",
      p1_ok and pcr_amt == 640 and pdr_amt == 800 and len(post_badges) == 1 and pcr[0]["type"] == "credit",
      f"resp={presp} debit(A)={pdr_amt} credit(B,net)={pcr_amt} badge={post_badges} tip_total={post_item.get('tip_total_cents')}")

# P2: self-tip on own post
CUR["uid"] = B
r = client.post(f"/posts/{pid}/reactions/tip", json={"amount_cents": 300})
check("P2_self_tip_post_400", r.status_code == 400, f"status={r.status_code} body={r.text[:160]}")

# ===================== EARNINGS CLASSIFY =====================
from app.services.creator_earnings import classify_entry
e_mr = classify_entry({"type": "credit", "reason": "Tip: message reaction", "meta": {"content_type": "message_react"}})
e_pr = classify_entry({"type": "credit", "reason": "Tip: post reaction", "meta": {"content_type": "post_react"}})
check("E1_classify_message_react_and_post_react_tips", e_mr == "tips" and e_pr == "tips", f"message_react={e_mr} post_react={e_pr}")

ok_all = all(ok for _, ok, _ in results)
print("OVERALL", "ALL_PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
