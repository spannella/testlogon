"""CONSOLIDATED content-moderation FULL state-machine verify — in-process on PROD DDB.

One script that exercises the ENTIRE report -> auto-hide -> case -> admin-triage ->
30d-hold -> poster-response -> final-call -> sweep backend + licensing->DMCA + ban,
against real prod DynamoDB with real seeded content rows. Non-destructive throughout.

Sections:
  R  MOD-A1..A3  report -> guarded auto-hide (severity), non-destructive, owner-aware, notify
  M  D-MESSAGE-HIDE  a reported message hides for everyone but the sender (owner-view), non-destructive
  A..H  MOD-A4..A6 + MOD-B1  dismiss/hold/respond/reinstate/close/sweep/endpoint-delete+ban/licensing/guards
"""
import os
import time

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.tables import T
from app.core.settings import S

import app.routers.moderation as M
import app.routers.newsfeed as NF
import app.routers.admin_moderation as ADMIN
import app.routers.messaging as MSG
from app.services import moderation_case as MC
from app.services import moderation_hide as MH
from app.services import moderation_lifecycle as LIFE
from app.services.moderation_policy_engine import is_user_currently_banned, apply_ban
from app.services.moderation_tickets_store import upsert_open_ticket_for_report
from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")
TS = int(time.time())
results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def seed_post(pid, owner, body, images=None):
    ddb.Table(APP_TABLE).put_item(Item={
        "pk": f"POST#{pid}", "sk": "META", "post_id": pid, "user_id": owner,
        "body": body, "content": body, "text": body,
        "status": "published", "visibility": "public", "privacy": "public",
        "created_at": int(time.time()), "updated_at": int(time.time()),
        "image_urls": images or [],
    })


def meta(pid):
    return ddb.Table(APP_TABLE).get_item(Key={"pk": f"POST#{pid}", "sk": "META"}).get("Item") or {}


def get_case(pid):
    return MC.get_case(MC.case_id_for("feed_post", pid))


def report(reporter, pid, topics, reason="This content violates the rules and should be reviewed."):
    tail = reporter[-1] if reporter and reporter[-1].isdigit() else "9"
    inp = M.CreateModerationReportIn(content_type="feed_post", content_id=pid, topics=topics, reason_text=reason)
    return M._create_report(inp, {"user_sub": reporter, "ip": f"10.0.0.{tail}"}, request=None)


def alerts(owner):
    try:
        r = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(owner), ScanIndexForward=False, Limit=40)
        return r.get("Items", [])
    except Exception as e:
        print("  (alerts query err:", e, ")")
        return []


def has_alert(owner, event):
    return any(a.get("event") == event for a in alerts(owner))


def enforcement_rows(uid, etype=None):
    r = T.user_enforcement_history.query(KeyConditionExpression=Key("user_id").eq(uid), ScanIndexForward=False, Limit=25)
    rows = [x for x in r.get("Items", []) if x.get("entity_type") == "user_enforcement"]
    if etype:
        rows = [x for x in rows if x.get("enforcement_type") == etype]
    return rows


def _get_post_status(pid, viewer):
    try:
        NF.get_post(pid, viewer)
        return 200
    except HTTPException as e:
        return e.status_code


def _perm_denied(case_id, other_uid):
    try:
        LIFE.poster_respond(case_id=case_id, owner_user_id=other_uid, statement="x")
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def _value_err(case_id, owner_uid):
    try:
        LIFE.poster_respond(case_id=case_id, owner_user_id=owner_uid, statement="x")
        return False
    except ValueError:
        return True
    except Exception:
        return False


# MODX-3: seed one shared TRUSTED reporter so the lifecycle scenarios still get a
# legitimate single-report auto-hide precondition under the new distinct/trust policy.
_AHT = f"ahtrust_{TS}"
T.account_state.put_item(Item={"user_sub": _AHT, "trusted_reporter": True, "updated_at": TS})


def autohide(pid, owner, body, cat="sexual"):
    seed_post(pid, owner, body)
    MC.on_report_filed(content_type="feed_post", content_id=pid, topics=[cat],
                       reporter_user_id=_AHT, metadata={}, ticket_id=None)
    return get_case(pid)


print("=== CONSOLIDATED MODERATION VERIFY ts=%d cases_table=%s ===" % (TS, getattr(S, "moderation_cases_table_name", "?")))

# ============================================================================
# SECTION R — REPORT -> GUARDED AUTO-HIDE (severity) — MOD-A1..A3
# ============================================================================
# R1 SEVERE (sexual) -> auto-hide on 1st report, non-destructive, owner-aware, notify
o1, p1 = f"ownR1_{TS}", f"pR1_{TS}"
seed_post(p1, o1, "ORIGINAL_SEVERE_%d" % TS)
report(_AHT, p1, ["sexual"])  # MODX-3: trusted single severe still auto-hides
c1, m1 = get_case(p1), meta(p1)
check("R1 SEVERE case under_review (auto-hide: trusted 1st report)", c1 and c1.get("state") == "under_review", str(c1 and c1.get("state")))
check("R1 meta moderation_hidden set", bool(m1.get("moderation_hidden")))
check("R1 case_id linked on meta", m1.get("moderation_case_id") == MC.case_id_for("feed_post", p1))
check("R1 NON-DESTRUCTIVE body intact", m1.get("body") == "ORIGINAL_SEVERE_%d" % TS, repr(m1.get("body")))
check("R1 non-owner get_post hidden (404)", _get_post_status(p1, f"stranger_{TS}") == 404)
check("R1 OWNER get_post can still see it (200)", _get_post_status(p1, o1) == 200)
check("R1 is_hidden_for_viewer(non-owner)=True", MH.is_hidden_for_viewer(m1, f"stranger_{TS}") is True)
check("R1 is_hidden_for_viewer(owner)=False", MH.is_hidden_for_viewer(m1, o1) is False)
check("R1 poster notified moderation_content_hidden", has_alert(o1, "moderation_content_hidden"))

# R2 LOWER (spam) once -> NOT hidden
o2, p2 = f"ownR2_{TS}", f"pR2_{TS}"
seed_post(p2, o2, "ORIGINAL_SPAM1")
report(f"repR2_{TS}", p2, ["spam"])
c2, m2 = get_case(p2), meta(p2)
check("R2 LOWER spam x1 stays visible", c2 and c2.get("state") == "visible", str(c2 and c2.get("state")))
check("R2 report_count=1", c2 and int(c2.get("report_count", 0)) == 1, str(c2 and c2.get("report_count")))
check("R2 NOT hidden", not m2.get("moderation_hidden"))
check("R2 non-owner can still see it", _get_post_status(p2, f"stranger_{TS}") == 200)

# R3 LOWER (spam) x3 distinct reporters -> hidden exactly at the 3rd
o3, p3 = f"ownR3_{TS}", f"pR3_{TS}"
seed_post(p3, o3, "ORIGINAL_SPAM3")
for _r in (f"repR3a_{TS}", f"repR3b_{TS}", f"repR3c_{TS}"):
    T.account_state.put_item(Item={"user_sub": _r, "established": True, "updated_at": TS})
report(f"repR3a_{TS}", p3, ["spam"]); a1 = get_case(p3)
report(f"repR3b_{TS}", p3, ["spam"]); a2 = get_case(p3)
report(f"repR3c_{TS}", p3, ["spam"]); c3 = get_case(p3)
check("R3 after 1 NOT hidden", a1 and not a1.get("hidden"))
check("R3 after 2 NOT hidden", a2 and not a2.get("hidden"))
check("R3 report_count=3", c3 and int(c3.get("report_count", 0)) == 3, str(c3 and c3.get("report_count")))
check("R3 hidden exactly at 3rd (under_review)", c3 and c3.get("state") == "under_review", str(c3 and c3.get("state")))
check("R3 body intact", meta(p3).get("body") == "ORIGINAL_SPAM3")

# R4 TRUSTED reporter, spam once -> hidden immediately
trusted = f"trust_{TS}"
T.account_state.put_item(Item={"user_sub": trusted, "trusted_reporter": True, "updated_at": TS})
o4, p4 = f"ownR4_{TS}", f"pR4_{TS}"
seed_post(p4, o4, "ORIGINAL_TRUSTED")
check("R4 is_trusted_reporter=True", MC.is_trusted_reporter(trusted))
report(trusted, p4, ["spam"])
c4 = get_case(p4)
check("R4 trusted reporter hides on 1 spam report", c4 and c4.get("state") == "under_review", str(c4 and c4.get("state")))
check("R4 report_count=1", c4 and int(c4.get("report_count", 0)) == 1, str(c4 and c4.get("report_count")))
check("R4 body intact", meta(p4).get("body") == "ORIGINAL_TRUSTED")

# R5 legacy category back-compat (racist -> hate severe -> hidden)
o5, p5 = f"ownR5_{TS}", f"pR5_{TS}"
seed_post(p5, o5, "ORIGINAL_LEGACY")
report(_AHT, p5, ["racist"])  # MODX-3: trusted
c5 = get_case(p5)
check("R5 legacy 'racist' -> 'hate' severe auto-hide", c5 and c5.get("state") == "under_review", str(c5 and c5.get("state")))
check("R5 categories normalized to hate", c5 and "hate" in set(c5.get("categories") or []), str(c5 and c5.get("categories")))

# R6 idempotent re-report on already-hidden severe post
r_again = MC.on_report_filed(content_type="feed_post", content_id=p1, topics=["sexual"],
                             reporter_user_id=f"repRX_{TS}", metadata={}, ticket_id=None)
check("R6 re-report idempotent (no new auto-hide)", r_again.get("auto_hidden_now") is False, str(r_again.get("auto_hidden_now")))

# ============================================================================
# SECTION M — D-MESSAGE-HIDE — a reported message hides for everyone but the sender
# ============================================================================
convM = f"convM_{TS}"
msgM = f"msgM_{TS}"
sender = f"sndM_{TS}"
other = f"othM_{TS}"
ddb.Table(MESSAGES_TABLE).put_item(Item={
    "conversation_id": convM, "message_id": msgM, "sender_id": sender,
    "kind": "text", "text": "ORIGINAL_SECRET_MESSAGE", "search_text": "ORIGINAL_SECRET_MESSAGE",
    "status": "sent", "created_at": TS,
})
owner_ret = MH.hide_content(content_type="message", content_id=msgM,
                            metadata={"conversation_id": convM}, case_id=f"case_msg_{TS}", state="under_review")
row = ddb.Table(MESSAGES_TABLE).get_item(Key={"conversation_id": convM, "message_id": msgM}).get("Item") or {}
check("M hide_content returns sender as owner", owner_ret == sender, str(owner_ret))
check("M message flagged moderation_hidden", bool(row.get("moderation_hidden")))
check("M NON-DESTRUCTIVE text intact", row.get("text") == "ORIGINAL_SECRET_MESSAGE", repr(row.get("text")))
check("M hidden for OTHER member (_filter_message_visible False)", MSG._filter_message_visible(row, other) is False)
check("M SENDER keeps owner-view (_filter_message_visible True)", MSG._filter_message_visible(row, sender) is True)
# unhide restores visibility for everyone (byte-for-byte)
MH.unhide_content(content_type="message", content_id=msgM, metadata={"conversation_id": convM}, case_id=f"case_msg_{TS}")
row2 = ddb.Table(MESSAGES_TABLE).get_item(Key={"conversation_id": convM, "message_id": msgM}).get("Item") or {}
check("M unhide restores visibility for OTHER member", MSG._filter_message_visible(row2, other) is True)
check("M unhide keeps text byte-for-byte", row2.get("text") == "ORIGINAL_SECRET_MESSAGE", repr(row2.get("text")))

# ============================================================================
# SCENARIO A — under_review -> admin DISMISS -> VISIBLE again
# ============================================================================
oA, pA = f"ownA_{TS}", f"pA_{TS}"
bodyA = f"ORIGINAL_A_{TS}"
cA = autohide(pA, oA, bodyA)
check("A precondition under_review+hidden", cA and cA.get("state") == "under_review" and meta(pA).get("moderation_hidden"))
resA = LIFE.admin_dismiss(case=get_case(pA), metadata={}, admin_user_id=f"admin_{TS}")
mA = meta(pA)
check("A state=dismissed", resA["state"] == "dismissed", resA["state"])
check("A content UN-HIDDEN (flags cleared)", not mA.get("moderation_hidden") and not mA.get("moderation_removed"))
check("A non-owner can SEE it again", _get_post_status(pA, f"stranger_{TS}") == 200)
check("A body still intact", mA.get("body") == bodyA, repr(mA.get("body")))

# ============================================================================
# SCENARIO B — confirm -> 30d hold -> respond -> awaiting_final -> reinstate (restore ORIGINAL)
# ============================================================================
oB, pB = f"ownB_{TS}", f"pB_{TS}"
bodyB = f"ORIGINAL_B_{TS}"
autohide(pB, oB, bodyB)
resB1 = LIFE.admin_confirm_hold(case=get_case(pB), metadata={}, admin_user_id=f"admin_{TS}")
cB = get_case(pB)
check("B state=hold", resB1["state"] == "hold", resB1["state"])
check("B hold_until ~= now+30d", 29 * 86400 <= (int(cB.get("hold_until", 0)) - TS) <= 31 * 86400, str(int(cB.get("hold_until", 0)) - TS))
check("B stays HIDDEN during hold", meta(pB).get("moderation_hidden") is True)
check("B poster notified violation_confirmed", has_alert(oB, "moderation_violation_confirmed"))
resB2 = LIFE.poster_respond(case_id=cB["case_id"], owner_user_id=oB, statement="This is my original work, please review.")
cB2 = get_case(pB)
check("B state=awaiting_final after response", resB2["state"] == "awaiting_final", resB2["state"])
check("B poster_response stored", "original work" in str(cB2.get("poster_response") or ""))
check("B non-owner cannot respond (403)", _perm_denied(cB["case_id"], f"stranger_{TS}"))
resB3 = LIFE.admin_final_reinstate(case=get_case(pB), metadata={}, admin_user_id=f"admin_{TS}")
mB = meta(pB)
check("B state=reinstated", resB3["state"] == "reinstated", resB3["state"])
check("B content restored VISIBLE", not mB.get("moderation_hidden") and _get_post_status(pB, f"stranger_{TS}") == 200)
check("B restored to ORIGINAL byte-for-byte", mB.get("body") == bodyB, repr(mB.get("body")))
check("B owner notified reinstated", has_alert(oB, "moderation_content_reinstated"))

# ============================================================================
# SCENARIO C — confirm -> poster CLOSES/withdraws -> immediately DELETED
# ============================================================================
oC, pC = f"ownC_{TS}", f"pC_{TS}"
autohide(pC, oC, f"ORIGINAL_C_{TS}")
LIFE.admin_confirm_hold(case=get_case(pC), metadata={}, admin_user_id=f"admin_{TS}")
resC = LIFE.poster_close(case_id=get_case(pC)["case_id"], owner_user_id=oC)
cC = get_case(pC)
check("C state=deleted after close", resC["state"] == "deleted" and cC.get("state") == "deleted", resC["state"])
check("C content ACTUALLY deleted (row gone)", meta(pC) == {})
check("C non-owner get_post -> 404", _get_post_status(pC, f"stranger_{TS}") == 404)
check("C poster_close records NO strike (MODX-4 poster-initiated removal)", len(enforcement_rows(oC, "content_violation")) == 0, str(len(enforcement_rows(oC, "content_violation"))))

# ============================================================================
# SCENARIO D — confirm -> 30d elapse -> SWEEP deletes; awaiting_final NOT swept
# ============================================================================
oD, pD = f"ownD_{TS}", f"pD_{TS}"
autohide(pD, oD, f"ORIGINAL_D_{TS}")
LIFE.admin_confirm_hold(case=get_case(pD), metadata={}, admin_user_id=f"admin_{TS}")
oD2, pD2 = f"ownD2_{TS}", f"pD2_{TS}"
autohide(pD2, oD2, f"ORIGINAL_D2_{TS}")
LIFE.admin_confirm_hold(case=get_case(pD2), metadata={}, admin_user_id=f"admin_{TS}")
LIFE.poster_respond(case_id=get_case(pD2)["case_id"], owner_user_id=oD2, statement="please keep this up")
past = TS - 86400
for pid in (pD, pD2):
    T.moderation_cases.update_item(Key={"case_id": MC.case_id_for("feed_post", pid)},
                                   UpdateExpression="SET hold_until = :h", ExpressionAttributeValues={":h": past})
swept = LIFE.sweep_expired_holds(now_ts=TS)
check("D sweep ESCALATED the un-answered hold (MODX-4 humane, not deleted)", MC.case_id_for("feed_post", pD) in swept["case_ids"], str(swept))
check("D escalated case -> awaiting_final", get_case(pD).get("state") == "awaiting_final", str(get_case(pD).get("state")))
check("D escalated content PRESERVED (not deleted)", meta(pD) != {})
check("D NO strike for pure no-response (MODX-4)", len(enforcement_rows(oD, "content_violation")) == 0, str(len(enforcement_rows(oD, "content_violation"))))
check("D already-responded case remains awaiting_final", get_case(pD2).get("state") == "awaiting_final")
check("D awaiting_final content still present", meta(pD2) != {})

# ============================================================================
# SCENARIO E — admin FINAL-CALL delete via REAL endpoint + violation + FIXED ban
# ============================================================================
root_admin = AuthenticatedUser(sub=f"rootadmin_{TS}", role=Role.ROOT)
oE, pE = f"ownE_{TS}", f"pE_{TS}"
seed_post(pE, oE, f"ORIGINAL_E_{TS}")
tkE = upsert_open_ticket_for_report(content_type="feed_post", content_id=pE, topics=["sexual"], now_ts=TS)
tkE_id = tkE["ticket_id"]
MC.on_report_filed(content_type="feed_post", content_id=pE, topics=["sexual"], reporter_user_id=f"repE_{TS}", metadata={}, ticket_id=tkE_id)
outE_confirm = ADMIN.confirm_moderation_case(tkE_id, admin=root_admin)
check("E endpoint confirm -> hold", outE_confirm.state == "hold" and outE_confirm.hold_until, str(outE_confirm.state))
finE = ADMIN._FinalCallIn(action="delete", note="severe violation", ban=True, ban_duration_days=7)
outE = ADMIN.final_call_moderation_case(tkE_id, finE, admin=root_admin)
check("E endpoint final-call delete -> deleted", outE.state == "deleted", str(outE.state))
check("E content hard-deleted (row gone)", meta(pE) == {})
check("E violation recorded", len(enforcement_rows(oE, "content_violation")) >= 1)
check("E FIXED ban recorded + enforced", len(enforcement_rows(oE, "ban")) >= 1 and is_user_currently_banned(oE))
tkE_row = T.moderation_tickets.get_item(Key={"ticket_id": tkE_id}).get("Item") or {}
check("E ticket closed content_removed", tkE_row.get("status") == "closed" and tkE_row.get("resolution") == "content_removed", str(tkE_row.get("status")))

# ============================================================================
# SCENARIO F — PERMANENT ban enforced (ban_until=0)
# ============================================================================
oF, pF = f"ownF_{TS}", f"pF_{TS}"
autohide(pF, oF, f"ORIGINAL_F_{TS}")
LIFE.admin_confirm_hold(case=get_case(pF), metadata={}, admin_user_id=f"admin_{TS}")
LIFE.admin_final_delete(case=get_case(pF), metadata={}, admin_user_id=f"admin_{TS}", source_ticket_id="", note="permanent")
apply_ban(offender_user_id=oF, ticket_id="", admin_user_id=f"admin_{TS}", note="permanent", duration_days=0, policy_category="content_violation")
stF = T.account_state.get_item(Key={"user_sub": oF}).get("Item") or {}
check("F PERMANENT ban enforced (ban_until=0, currently banned)", int(stF.get("ban_until", -1)) == 0 and is_user_currently_banned(oF), str(stF.get("ban_until")))

# ============================================================================
# SCENARIO G — LICENSING report -> DMCA auto-hide + notify + counter + admin final call
# ============================================================================
from app.services.dmca_claims import file_counter_notice, resolve_dmca_claim, get_claim
oG, pG = f"ownG_{TS}", f"pG_{TS}"
seed_post(pG, oG, f"ORIGINAL_G_{TS}")
inpG = M.CreateModerationReportIn(content_type="feed_post", content_id=pG, topics=["licensing_ip"],
                                  reason_text="This uses my copyrighted work without a license.")
outG = M._create_report(inpG, {"user_sub": f"claimant_{TS}", "ip": "10.0.0.7"}, request=None)
mG = meta(pG)
claimG = get_claim(outG.report_id)
check("G licensing report routed to DMCA (dmca_ id)", outG.report_id.startswith("dmca_"), outG.report_id)
check("G DMCA claim content_removed", claimG and claimG.get("status") == "content_removed", str(claimG and claimG.get("status")))
check("G content AUTO-HIDDEN on submit (dmca_hidden)", bool(mG.get("dmca_hidden")))
check("G poster notified dmca_claim_filed", has_alert(oG, "dmca_claim_filed"))
check("G strike incremented", int((claimG or {}).get("strike_number") or 0) >= 1, str((claimG or {}).get("strike_number")))
file_counter_notice(outG.report_id, {"counter_notice_text": "I own this", "counter_notice_signature": oG}, oG)
resolve_dmca_claim(outG.report_id, "restored", "counter upheld", f"admin_{TS}")
mG2 = meta(pG)
claimG2 = get_claim(outG.report_id)
check("G admin final call restores content", not mG2.get("dmca_hidden") and claimG2.get("status") == "resolved", str(claimG2.get("status")))

# ============================================================================
# SCENARIO H — state-machine guards / idempotency
# ============================================================================
oH, pH = f"ownH_{TS}", f"pH_{TS}"
seed_post(pH, oH, "orig_H")
MC.aggregate_report(content_type="feed_post", content_id=pH, categories=["spam"], owner_user_id=oH, ticket_id=None)
try:
    MC.transition(MC.case_id_for("feed_post", pH), "deleted"); guard1 = False
except ValueError:
    guard1 = True
check("H illegal skip visible->deleted rejected", guard1)
try:
    MC.transition(MC.case_id_for("feed_post", pC), "reinstated"); guard2 = False
except ValueError:
    guard2 = True
check("H terminal deleted->reinstated rejected", guard2)
try:
    MC.transition(MC.case_id_for("feed_post", p1), "deleted"); guard3 = False
except ValueError:
    guard3 = True
check("H under_review->deleted (skip hold) rejected", guard3)
r_again2 = LIFE.admin_dismiss(case=get_case(pA), metadata={}, admin_user_id=f"admin_{TS}")
check("H dismiss idempotent (still dismissed)", r_again2["state"] == "dismissed")
check("H respond on non-hold (dismissed) rejected", _value_err(get_case(pA)["case_id"], oA))

npass = sum(1 for ok, _, _ in results if ok)
ntot = len(results)
print("\n=== RESULT %d/%d ===" % (npass, ntot))
print("OVERALL", "ALL_PASS" if npass == ntot else "SOME_FAIL")
if npass != ntot:
    print("FAILURES:", [n for ok, n, _ in results if not ok])
