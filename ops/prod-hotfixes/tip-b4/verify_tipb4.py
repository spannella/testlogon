#!/usr/bin/env python3
"""TIP-B4 pay-to-message gate — in-process money-path verification (prod)."""
import time
from fastapi import HTTPException
from boto3.dynamodb.conditions import Key

import app.routers.messaging as m
from app.core.tables import T

TS = int(time.time())
R = f"tipb4_recip_{TS}"     # gated recipient
S = f"tipb4_send_{TS}"      # non-allowlisted sender
A = f"tipb4_allow_{TS}"     # allowlisted sender
S2 = f"tipb4_s2_{TS}"       # recipient-first counterpart

results = []
def rec(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS" if ok else "FAIL"), name, "|", detail)

def credit_rows(uid):
    resp = T.billing.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{uid}") & Key("sk").begins_with("LEDGER#")
    )
    return [i for i in resp.get("Items", []) if i.get("type") == "credit"]

# ---- TIP-401: privacy set/get + allowlist ----
m.update_message_privacy(m.MessagePrivacyUpdateIn(require_tip_to_message=True, min_tip_cents=500), user_id=R)
p = m.get_message_privacy(user_id=R)
rec("TIP-401 set/get require_tip+min500",
    p.require_tip_to_message is True and p.min_tip_cents == 500,
    f"require={p.require_tip_to_message} min={p.min_tip_cents}")

# ---- TIP-402: S opens DM to gated R with no tip -> 402 tip_required ----
open_cid = None
try:
    m.find_or_create_dm(m.FindOrCreateDmIn(user_id=R), req=None, user_id=S)
    rec("TIP-402 find_or_create_dm 402", False, "no exception raised")
except HTTPException as e:
    d = e.detail if isinstance(e.detail, dict) else {}
    open_cid = d.get("conversation_id")
    rec("TIP-402 open-DM 402 tip_required min500",
        e.status_code == 402 and d.get("code") == "tip_required" and d.get("min_tip_cents") == 500 and bool(open_cid),
        f"status={e.status_code} detail={d}")

# ---- TIP-402: S sends first message NO tip -> 402 ----
try:
    m.send_text_message(open_cid, m.SendTextMessageIn(text="hello"), req=None, user_id=S)
    rec("TIP-402 first-send no-tip 402", False, "delivered without tip")
except HTTPException as e:
    d = e.detail if isinstance(e.detail, dict) else {}
    rec("TIP-402 first-send no-tip 402 min500",
        e.status_code == 402 and d.get("code") == "tip_required" and d.get("min_tip_cents") == 500,
        f"status={e.status_code} detail={d}")

# ---- TIP-403: S sends first message WITH 500 tip -> delivered + R credited net ----
before = len(credit_rows(R))
try:
    msg = m.send_text_message(open_cid, m.SendTextMessageIn(text="hi, please reply", tip_amount_cents=500), req=None, user_id=S)
    after = credit_rows(R)
    new = [c for c in after if c.get("meta", {}).get("content_type") == "message"]
    net = int(new[0]["amount_cents"]) if new else -1
    rec("TIP-403 first-send +500tip delivered + R credited net400",
        len(after) == before + 1 and any(int(c["amount_cents"]) == 400 and c["type"] == "credit" for c in new),
        f"credit_rows {before}->{len(after)} net_cents={net} type=credit content_type=message")
except HTTPException as e:
    rec("TIP-403 first-send +500tip delivered", False, f"raised {e.status_code} {e.detail}")

# ---- existing-conversation bypass: S sends 2nd message no tip -> delivered ----
try:
    m.send_text_message(open_cid, m.SendTextMessageIn(text="second message"), req=None, user_id=S)
    rec("BYPASS existing-conversation (2nd msg no tip delivered)", True, "delivered")
except HTTPException as e:
    rec("BYPASS existing-conversation", False, f"raised {e.status_code} {e.detail}")

# ---- allowlist bypass: A added to R allowlist, opens+sends tip-free ----
m.add_message_privacy_allowlist(m.MessagePrivacyAllowlistEntryIn(user_id=A), user_id=R)
allow_cid = None
try:
    convo = m.find_or_create_dm(m.FindOrCreateDmIn(user_id=R), req=None, user_id=A)
    allow_cid = convo.conversation_id
    rec("BYPASS allowlist open-DM (no 402)", True, f"cid={allow_cid}")
except HTTPException as e:
    rec("BYPASS allowlist open-DM", False, f"raised {e.status_code} {e.detail}")
if allow_cid:
    try:
        m.send_text_message(allow_cid, m.SendTextMessageIn(text="tip-free hello"), req=None, user_id=A)
        rec("BYPASS allowlist first-send tip-free delivered", True, "delivered")
    except HTTPException as e:
        rec("BYPASS allowlist first-send", False, f"raised {e.status_code} {e.detail}")

# ---- recipient-messages-first bypass: R -> S2 first, then S2 replies no tip ----
try:
    convo = m.find_or_create_dm(m.FindOrCreateDmIn(user_id=S2), req=None, user_id=R)
    rf_cid = convo.conversation_id
    m.send_text_message(rf_cid, m.SendTextMessageIn(text="I reached out first"), req=None, user_id=R)
    # S2 must accept to become active, then reply with no tip
    try:
        m.accept_conversation(rf_cid, req=None, user_id=S2)
    except Exception:
        pass
    m.send_text_message(rf_cid, m.SendTextMessageIn(text="reply, no tip"), req=None, user_id=S2)
    rec("BYPASS recipient-messaged-first (S2 replies no tip delivered)", True, f"cid={rf_cid}")
except HTTPException as e:
    rec("BYPASS recipient-messaged-first", False, f"raised {e.status_code} {e.detail}")

# ---- allowlist remove ----
m.remove_message_privacy_allowlist(A, user_id=R)
p2 = m.get_message_privacy(user_id=R)
rec("TIP-401 allowlist add+remove", A not in p2.tip_free_allowlist, f"allowlist={p2.tip_free_allowlist}")

npass = sum(1 for _, ok, _ in results if ok)
print(f"\nSUMMARY {npass}/{len(results)} PASS", "ALL_PASS" if npass == len(results) else "SOME_FAIL")
