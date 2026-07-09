"""MOD-A4..A6 + MOD-B1 in-process verify on PROD DDB — full state-machine matrix.

Drives the moderation_lifecycle ops (which the admin/owner endpoints wrap) plus the
REAL admin endpoint functions + the REAL licensing->DMCA report path, all against
prod DynamoDB with real seeded content rows.
"""
import os
import time

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.tables import T

import app.routers.moderation as M
import app.routers.newsfeed as NF
import app.routers.admin_moderation as ADMIN
from app.services import moderation_case as MC
from app.services import moderation_hide as MH
from app.services import moderation_lifecycle as LIFE
from app.services.moderation_policy_engine import is_user_currently_banned
from app.services.moderation_tickets_store import upsert_open_ticket_for_report
from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
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


def autohide(pid, owner, body, cat="sexual"):
    """Seed a post + drive it to under_review via a severe report (auto-hide)."""
    seed_post(pid, owner, body)
    MC.on_report_filed(content_type="feed_post", content_id=pid, topics=[cat],
                       reporter_user_id=f"rep_{pid}", metadata={}, ticket_id=None)
    return get_case(pid)


print("=== MOD-A4..A6 + MOD-B1 VERIFY ts=%d ===" % TS)

# ============================================================================
# SCENARIO A — under_review -> admin DISMISS -> VISIBLE again
# ============================================================================
oA, pA = f"ownA_{TS}", f"pA_{TS}"
bodyA = f"ORIGINAL_A_{TS}"
cA = autohide(pA, oA, bodyA)
check("A precondition under_review+hidden", cA and cA.get("state") == "under_review" and meta(pA).get("moderation_hidden"), str(cA and cA.get("state")))
resA = LIFE.admin_dismiss(case=get_case(pA), metadata={}, admin_user_id=f"admin_{TS}")
mA = meta(pA)
check("A state=dismissed", resA["state"] == "dismissed", resA["state"])
check("A content UN-HIDDEN (meta flag cleared)", not mA.get("moderation_hidden") and not mA.get("moderation_removed"))
check("A non-owner can SEE it again", isinstance(NF.get_post(pA, f"stranger_{TS}"), dict))
check("A body still intact", mA.get("body") == bodyA, repr(mA.get("body")))

# ============================================================================
# SCENARIO B — confirm -> 30d hold -> poster responds -> awaiting_final -> reinstate (restore ORIGINAL)
# ============================================================================
oB, pB = f"ownB_{TS}", f"pB_{TS}"
bodyB = f"ORIGINAL_B_{TS}"
autohide(pB, oB, bodyB)
resB1 = LIFE.admin_confirm_hold(case=get_case(pB), metadata={}, admin_user_id=f"admin_{TS}")
cB = get_case(pB)
check("B state=hold", resB1["state"] == "hold", resB1["state"])
check("B hold_until ~= now+30d", 29 * 86400 <= (int(cB.get("hold_until", 0)) - TS) <= 31 * 86400, str(int(cB.get("hold_until", 0)) - TS))
check("B stays HIDDEN during hold", meta(pB).get("moderation_hidden") is True)
check("B poster notified (violation_confirmed)", has_alert(oB, "moderation_violation_confirmed"))
# poster responds
resB2 = LIFE.poster_respond(case_id=cB["case_id"], owner_user_id=oB, statement="This is my original work, please review.")
cB2 = get_case(pB)
check("B state=awaiting_final after response", resB2["state"] == "awaiting_final", resB2["state"])
check("B poster_response stored", "original work" in str(cB2.get("poster_response") or ""))
check("B non-owner NOT-owner cannot respond (403)", _perm_denied(cB["case_id"], f"stranger_{TS}"))
# admin final call: reinstate
resB3 = LIFE.admin_final_reinstate(case=get_case(pB), metadata={}, admin_user_id=f"admin_{TS}")
mB = meta(pB)
check("B state=reinstated", resB3["state"] == "reinstated", resB3["state"])
check("B content restored VISIBLE", not mB.get("moderation_hidden") and isinstance(NF.get_post(pB, f"stranger_{TS}"), dict))
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
check("C violation recorded on owner", len(enforcement_rows(oC, "content_violation")) >= 1)

# ============================================================================
# SCENARIO D — confirm -> simulate 30d elapse -> SWEEP deletes; awaiting_final NOT swept
# ============================================================================
oD, pD = f"ownD_{TS}", f"pD_{TS}"
autohide(pD, oD, f"ORIGINAL_D_{TS}")
LIFE.admin_confirm_hold(case=get_case(pD), metadata={}, admin_user_id=f"admin_{TS}")
# a second case that RESPONDED (awaiting_final) must be immune to the sweep
oD2, pD2 = f"ownD2_{TS}", f"pD2_{TS}"
autohide(pD2, oD2, f"ORIGINAL_D2_{TS}")
LIFE.admin_confirm_hold(case=get_case(pD2), metadata={}, admin_user_id=f"admin_{TS}")
LIFE.poster_respond(case_id=get_case(pD2)["case_id"], owner_user_id=oD2, statement="please keep this up")
# force both holds' hold_until into the past
past = TS - 86400
for pid in (pD, pD2):
    T.moderation_cases.update_item(Key={"case_id": MC.case_id_for("feed_post", pid)},
                                   UpdateExpression="SET hold_until = :h", ExpressionAttributeValues={":h": past})
swept = LIFE.sweep_expired_holds(now_ts=TS)
check("D sweep deleted the un-answered hold", MC.case_id_for("feed_post", pD) in swept["case_ids"], str(swept))
check("D swept content row gone", meta(pD) == {})
check("D swept violation recorded", len(enforcement_rows(oD, "content_violation")) >= 1)
check("D awaiting_final (responded) NOT swept", MC.case_id_for("feed_post", pD2) not in swept["case_ids"] and get_case(pD2).get("state") == "awaiting_final")
check("D awaiting_final content still present", meta(pD2) != {})

# ============================================================================
# SCENARIO E — admin FINAL-CALL delete via REAL endpoint + violation + FIXED ban; permanent ban enforced
# ============================================================================
root_admin = AuthenticatedUser(sub=f"rootadmin_{TS}", role=Role.ROOT)
oE, pE = f"ownE_{TS}", f"pE_{TS}"
seed_post(pE, oE, f"ORIGINAL_E_{TS}")
tkE = upsert_open_ticket_for_report(content_type="feed_post", content_id=pE, topics=["sexual"], now_ts=TS)
tkE_id = tkE["ticket_id"]
MC.on_report_filed(content_type="feed_post", content_id=pE, topics=["sexual"], reporter_user_id=f"repE_{TS}", metadata={}, ticket_id=tkE_id)
# admin confirm via REAL endpoint
outE_confirm = ADMIN.confirm_moderation_case(tkE_id, admin=root_admin)
check("E endpoint confirm -> hold", outE_confirm.state == "hold" and outE_confirm.hold_until, str(outE_confirm.state))
# admin final-call DELETE + fixed 7-day ban via REAL endpoint
finE = ADMIN._FinalCallIn(action="delete", note="severe violation", ban=True, ban_duration_days=7)
outE = ADMIN.final_call_moderation_case(tkE_id, finE, admin=root_admin)
check("E endpoint final-call delete -> deleted", outE.state == "deleted", str(outE.state))
check("E content hard-deleted (row gone)", meta(pE) == {})
check("E violation recorded", len(enforcement_rows(oE, "content_violation")) >= 1)
check("E FIXED ban recorded + enforced", len(enforcement_rows(oE, "ban")) >= 1 and is_user_currently_banned(oE))
tkE_row = T.moderation_tickets.get_item(Key={"ticket_id": tkE_id}).get("Item") or {}
check("E ticket closed content_removed", tkE_row.get("status") == "closed" and tkE_row.get("resolution") == "content_removed", str(tkE_row.get("status")))
# PERMANENT ban enforced (separate case, delete via lifecycle + apply_ban permanent)
from app.services.moderation_policy_engine import apply_ban
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
check("G licensing report routed to DMCA (claim id)", outG.report_id.startswith("dmca_"), outG.report_id)
check("G DMCA claim exists content_removed", claimG and claimG.get("status") == "content_removed", str(claimG and claimG.get("status")))
check("G content AUTO-HIDDEN on submit (dmca_hidden)", bool(mG.get("dmca_hidden")))
check("G poster notified (dmca_claim_filed)", has_alert(oG, "dmca_claim_filed"))
check("G strike incremented", int((claimG or {}).get("strike_number") or 0) >= 1, str((claimG or {}).get("strike_number")))
# counter-notice (poster response) then admin final call restore
file_counter_notice(outG.report_id, {"counter_notice_text": "I own this", "counter_notice_signature": oG}, oG)
resolve_dmca_claim(outG.report_id, "restored", "counter upheld", f"admin_{TS}")
mG2 = meta(pG)
claimG2 = get_claim(outG.report_id)
check("G admin final call restores content", not mG2.get("dmca_hidden") and claimG2.get("status") == "resolved", str(claimG2.get("status")))

# ============================================================================
# SCENARIO H — state-machine guards / idempotency
# ============================================================================
# cannot skip: visible -> deleted rejected
oH, pH = f"ownH_{TS}", f"pH_{TS}"
seed_post(pH, oH, "orig_H")
MC.aggregate_report(content_type="feed_post", content_id=pH, categories=["spam"], owner_user_id=oH, ticket_id=None)
try:
    MC.transition(MC.case_id_for("feed_post", pH), "deleted"); guard1 = False
except ValueError:
    guard1 = True
check("H illegal skip visible->deleted rejected", guard1)
# terminal cannot advance: deleted -> reinstated rejected (use pC which is deleted)
try:
    MC.transition(MC.case_id_for("feed_post", pC), "reinstated"); guard2 = False
except ValueError:
    guard2 = True
check("H terminal deleted->reinstated rejected", guard2)
# dismiss idempotent (re-dismiss pA is a no-op, stays dismissed)
r_again = LIFE.admin_dismiss(case=get_case(pA), metadata={}, admin_user_id=f"admin_{TS}")
check("H dismiss idempotent (still dismissed)", r_again["state"] == "dismissed")
# poster cannot respond to a non-hold (dismissed) case
check("H respond on non-hold rejected (409)", _value_err(get_case(pA)["case_id"], oA))

npass = sum(1 for ok, _, _ in results if ok)
ntot = len(results)
print("\n=== RESULT %d/%d ===" % (npass, ntot))
print("OVERALL", "ALL_PASS" if npass == ntot else "SOME_FAIL")
if npass != ntot:
    print("FAILURES:", [n for ok, n, _ in results if not ok])
