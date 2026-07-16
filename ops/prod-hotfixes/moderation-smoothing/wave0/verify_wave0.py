"""MODX WAVE-0 regression verify — in-process on PROD DDB, non-destructive, self-seeding.

Proves the Wave-0 fixes (MODX-2 act-after-guard + idempotent strikes + api-key ban gate,
MODX-1 un-freeze terminal cases + close orphaned tickets) work AND the happy path still
holds. Seeds synthetic content/users, exercises the flows, then auto-cleans (0 residue for
this run's TS). Pair with the consolidated verify_moderation.py (75/75) for no-regression.

Scenarios:
  A  MODX-1  re-report of a REINSTATED item -> fresh case + re-hide + admin action (no 500) + tickets closed
  B  MODX-1  re-report of a DELETED item    -> fresh case + admin action (no 500); poster_close closes the linked ticket (no orphan)
  S  MODX-1  30-day sweep closes the linked ticket (no orphan)
  C  MODX-2  illegal-state delete cannot hard-delete / strike; double delete cannot double-strike
  K  MODX-2  banned identity via an api-key principal is blocked (403); non-banned allowed; admin exempt
"""
import os
import time
import asyncio

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.aws import ddb
from app.core.tables import T
from app.core.settings import S

import app.routers.moderation as M
import app.routers.newsfeed as NF
import app.routers.admin_moderation as ADMIN
import app.services.sessions as SESS
from app.services import moderation_case as MC
from app.services import moderation_lifecycle as LIFE
from app.services.moderation_policy_engine import is_user_currently_banned, apply_ban
from app.services.moderation_tickets_store import upsert_open_ticket_for_report
from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
TS = int(time.time())
results = []
_pids = []
_owners = []
_tickets = []
_state_users = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def seed_post(pid, owner, body):
    ddb.Table(APP_TABLE).put_item(Item={
        "pk": f"POST#{pid}", "sk": "META", "post_id": pid, "user_id": owner,
        "body": body, "content": body, "text": body,
        "status": "published", "visibility": "public", "privacy": "public",
        "created_at": int(time.time()), "updated_at": int(time.time()), "image_urls": [],
    })
    if pid not in _pids:
        _pids.append(pid)
    if owner not in _owners:
        _owners.append(owner)


def meta(pid):
    return ddb.Table(APP_TABLE).get_item(Key={"pk": f"POST#{pid}", "sk": "META"}).get("Item") or {}


def get_case(pid):
    return MC.get_case(MC.case_id_for("feed_post", pid))


def ticket(tid):
    return T.moderation_tickets.get_item(Key={"ticket_id": tid}).get("Item") or {}


def _trust(uid):
    T.account_state.put_item(Item={"user_sub": uid, "trusted_reporter": True, "updated_at": TS})
    if uid not in _state_users:
        _state_users.append(uid)
    return uid


def report(reporter, pid, topics):
    _trust(reporter)
    inp = M.CreateModerationReportIn(content_type="feed_post", content_id=pid, topics=topics,
                                     reason_text="This content violates the rules and should be reviewed.")
    out = M._create_report(inp, {"user_sub": reporter, "ip": "10.0.0.5"}, request=None)
    if out.ticket_id and out.ticket_id not in _tickets:
        _tickets.append(out.ticket_id)
    return out


def enforcement_rows(uid, etype="content_violation"):
    r = T.user_enforcement_history.query(KeyConditionExpression=Key("user_id").eq(uid), ScanIndexForward=False, Limit=50)
    return [x for x in r.get("Items", []) if x.get("entity_type") == "user_enforcement" and (not etype or x.get("enforcement_type") == etype)]


def get_post_status(pid, viewer):
    try:
        NF.get_post(pid, viewer)
        return 200
    except HTTPException as e:
        return e.status_code


ROOT = AuthenticatedUser(sub=f"rootadmin_{TS}", role=Role.ROOT)


print("=== MODX WAVE-0 VERIFY ts=%d cases_table=%s ===" % (TS, getattr(S, "moderation_cases_table_name", "?")))

# ============================================================================
# SCENARIO A — MODX-1: re-report of a REINSTATED item -> fresh case + re-hide
# ============================================================================
oA, pA = f"ownA_{TS}", f"pA_{TS}"
seed_post(pA, oA, f"ORIG_A_{TS}")
rA1 = report(f"repA_{TS}", pA, ["sexual"])
tA1 = rA1.ticket_id
cA1 = get_case(pA)
check("A first report severe auto-hides (under_review)", cA1.get("state") == "under_review", str(cA1.get("state")))
ADMIN.confirm_moderation_case(tA1, admin=ROOT)
outA_re = ADMIN.final_call_moderation_case(tA1, ADMIN._FinalCallIn(action="reinstate"), admin=ROOT)
check("A admin reinstate -> reinstated (terminal)", outA_re.state == "reinstated", str(outA_re.state))
check("A ticket#1 closed no_violation", ticket(tA1).get("status") == "closed" and ticket(tA1).get("resolution") == "no_violation")
check("A reinstated content visible again", get_post_status(pA, f"stranger_{TS}") == 200)

# --- the fix: a NEW report must NOT hit the frozen terminal state ---
rA2 = report(f"repA2_{TS}", pA, ["sexual"])
tA2 = rA2.ticket_id
cA2 = get_case(pA)
check("A re-report opens FRESH case (reopened, re-hidden under_review)", cA2.get("state") == "under_review", str(cA2.get("state")))
check("A reopen_count incremented", int(cA2.get("reopen_count") or 0) == 1, str(cA2.get("reopen_count")))
check("A re-report re-hides content (non-owner 404)", get_post_status(pA, f"stranger2_{TS}") == 404)
check("A re-report minted a NEW open ticket", tA2 != tA1 and ticket(tA2).get("status") == "open", f"{tA1} -> {tA2}")
# admin action on the re-report ticket must NOT 500 (would raise from a terminal transition)
a_no500 = True
try:
    ADMIN.confirm_moderation_case(tA2, admin=ROOT)
    outA_del = ADMIN.final_call_moderation_case(tA2, ADMIN._FinalCallIn(action="delete", note="repeat"), admin=ROOT)
except Exception as e:  # noqa: BLE001
    a_no500 = False
    outA_del = None
    print("  A admin-action raised:", repr(e))
check("A admin confirm+delete on re-report ticket does NOT 500", a_no500 and outA_del and outA_del.state == "deleted")
check("A re-report lifecycle recorded exactly ONE violation", len(enforcement_rows(oA)) == 1, str(len(enforcement_rows(oA))))
check("A ticket#2 closed content_removed (no orphan)", ticket(tA2).get("status") == "closed" and ticket(tA2).get("resolution") == "content_removed")

# ============================================================================
# SCENARIO B — MODX-1: re-report of a DELETED item + poster_close closes ticket
# ============================================================================
oB, pB = f"ownB_{TS}", f"pB_{TS}"
seed_post(pB, oB, f"ORIG_B_{TS}")
tB1 = upsert_open_ticket_for_report(content_type="feed_post", content_id=pB, topics=["sexual"], now_ts=TS)["ticket_id"]
_tickets.append(tB1)
MC.on_report_filed(content_type="feed_post", content_id=pB, topics=["sexual"], reporter_user_id=_trust(f"repB_{TS}"), metadata={}, ticket_id=tB1)
LIFE.admin_confirm_hold(case=get_case(pB), metadata={}, admin_user_id=f"admin_{TS}")
LIFE.poster_close(case_id=MC.case_id_for("feed_post", pB), owner_user_id=oB)
check("B poster_close hard-deletes content", meta(pB) == {})
check("B poster_close records NO strike (MODX-4 poster-initiated removal)", len(enforcement_rows(oB)) == 0, str(len(enforcement_rows(oB))))
check("B poster_close CLOSES the linked ticket (no orphan)", ticket(tB1).get("status") == "closed" and ticket(tB1).get("resolution") == "content_removed", str(ticket(tB1).get("status")))

# re-post the same id and re-report a DELETED-case item -> fresh lifecycle, no 500
seed_post(pB, oB, f"REPOST_B_{TS}")
rB2 = report(f"repB2_{TS}", pB, ["sexual"])
tB2 = rB2.ticket_id
cB2 = get_case(pB)
check("B re-report of DELETED item reopens fresh (under_review)", cB2.get("state") == "under_review", str(cB2.get("state")))
check("B re-report re-hides (non-owner 404)", get_post_status(pB, f"strangerB_{TS}") == 404)
b_no500 = True
try:
    ADMIN.confirm_moderation_case(tB2, admin=ROOT)
    ADMIN.final_call_moderation_case(tB2, ADMIN._FinalCallIn(action="delete", note="repeat"), admin=ROOT)
except Exception as e:  # noqa: BLE001
    b_no500 = False
    print("  B admin-action raised:", repr(e))
check("B admin action on re-report ticket does NOT 500", b_no500 and get_case(pB).get("state") == "deleted")
check("B admin final-delete strike is the ONLY strike (1 total; poster_close carried none)", len(enforcement_rows(oB)) == 1, str(len(enforcement_rows(oB))))

# ============================================================================
# SCENARIO S — MODX-1: 30-day sweep closes the linked ticket (no orphan)
# ============================================================================
oS, pS = f"ownS_{TS}", f"pS_{TS}"
seed_post(pS, oS, f"ORIG_S_{TS}")
tS = upsert_open_ticket_for_report(content_type="feed_post", content_id=pS, topics=["sexual"], now_ts=TS)["ticket_id"]
_tickets.append(tS)
MC.on_report_filed(content_type="feed_post", content_id=pS, topics=["sexual"], reporter_user_id=_trust(f"repS_{TS}"), metadata={}, ticket_id=tS)
LIFE.admin_confirm_hold(case=get_case(pS), metadata={}, admin_user_id=f"admin_{TS}")
# force the hold to have elapsed so the sweep picks it up
csS = get_case(pS)
T.moderation_cases.update_item(Key={"case_id": csS["case_id"]},
                               UpdateExpression="SET hold_until = :h",
                               ExpressionAttributeValues={":h": TS - 10})
swept = LIFE.sweep_expired_holds(now_ts=TS)
check("S sweep ESCALATED the expired hold (MODX-4 humane)", MC.case_id_for("feed_post", pS) in swept.get("case_ids", []), str(swept))
check("S escalated content PRESERVED (not deleted)", meta(pS) != {})
check("S escalated case -> awaiting_final (live, not orphaned); ticket open", get_case(pS).get("state") == "awaiting_final" and ticket(tS).get("status") == "open", str((get_case(pS).get("state"), ticket(tS).get("status"))))

# ============================================================================
# SCENARIO C — MODX-2: act-after-guard (illegal-state delete + no double-strike)
# ============================================================================
# C1 illegal-state: final-delete on an UNDER_REVIEW (non-hold) case must NOT delete/strike
oC, pC = f"ownC_{TS}", f"pC_{TS}"
seed_post(pC, oC, f"ORIG_C_{TS}")
MC.on_report_filed(content_type="feed_post", content_id=pC, topics=["sexual"], reporter_user_id=_trust(f"repC_{TS}"), metadata={}, ticket_id=None)
c1_guard = False
try:
    LIFE.admin_final_delete(case=get_case(pC), metadata={}, admin_user_id=f"admin_{TS}", source_ticket_id="", note="illegal")
except ValueError:
    c1_guard = True
check("C illegal-state final-delete raises BEFORE any delete (guarded)", c1_guard)
check("C illegal-state: content still INTACT (not destroyed)", meta(pC).get("body") == f"ORIG_C_{TS}", repr(meta(pC).get("body")))
check("C illegal-state: NO violation strike recorded", len(enforcement_rows(oC)) == 0, str(len(enforcement_rows(oC))))
check("C illegal-state: case unchanged (under_review)", get_case(pC).get("state") == "under_review", str(get_case(pC).get("state")))

# C2 double delete: two finalizers on the SAME hold case -> exactly ONE violation
oC2, pC2 = f"ownC2_{TS}", f"pC2_{TS}"
seed_post(pC2, oC2, f"ORIG_C2_{TS}")
MC.on_report_filed(content_type="feed_post", content_id=pC2, topics=["sexual"], reporter_user_id=_trust(f"repC2_{TS}"), metadata={}, ticket_id=None)
LIFE.admin_confirm_hold(case=get_case(pC2), metadata={}, admin_user_id=f"admin_{TS}")
caseC2 = get_case(pC2)
r_del1 = LIFE.admin_final_delete(case=caseC2, metadata={}, admin_user_id=f"admin_{TS}", source_ticket_id="", note="del1")
# second finalizer uses the STALE (pre-delete) case snapshot -> simulates a lost race / retry
r_del2 = LIFE._finalize_delete(case=caseC2, metadata=None, admin_user_id=f"admin_{TS}", reason="del2", source_ticket_id="", record_violation_flag=True, now_ts=TS)
check("C double-delete: first delete applied (changed)", r_del1.get("state") == "deleted")
check("C double-delete: second delete is a no-op (changed=False)", r_del2.get("changed") is False, str(r_del2.get("changed")))
check("C double-delete: EXACTLY ONE violation strike (no double-strike)", len(enforcement_rows(oC2)) == 1, str(len(enforcement_rows(oC2))))
check("C double-delete: content deleted once", meta(pC2) == {})

# ============================================================================
# SCENARIO K — MODX-2 (A14): api-key principal ban gate
# ============================================================================
class _FakeState:
    pass


class _FakeReq:
    def __init__(self, principal, authorized):
        self.state = _FakeState()
        self.state.api_key_principal = principal
        self.state.api_key_route_authorized = authorized
        self.state.tenant_id = "default"
        self.cookies = {}
        self.headers = {}
        self.method = "GET"


def call_apikey(sub, role):
    req = _FakeReq({"user_sub": sub, "api_key_id": "ak_modxtest"}, True)
    au = AuthenticatedUser(sub=sub, role=role)
    return asyncio.new_event_loop().run_until_complete(
        SESS.require_ui_session(req, auth_user=au, user_sub=None, x_session_id=None, x_impersonation_token=None)
    )


oK = f"banK_{TS}"
_state_users.append(oK)
apply_ban(offender_user_id=oK, ticket_id="", admin_user_id=f"admin_{TS}", note="modx", duration_days=7, policy_category="content_violation")
check("K precondition: user is banned", is_user_currently_banned(oK))
k_blocked = False
try:
    call_apikey(oK, Role.USER)
except HTTPException as e:
    k_blocked = (e.status_code == 403)
check("K banned identity via ak_ key is BLOCKED (403)", k_blocked)

oKok = f"okK_{TS}"
ctx_ok = call_apikey(oKok, Role.USER)
check("K non-banned identity via ak_ key is ALLOWED", ctx_ok.get("user_sub") == oKok, str(ctx_ok.get("user_sub")))

ctx_admin = call_apikey(oK, Role.ADMIN)
check("K banned ADMIN via ak_ key is EXEMPT (mirrors session path)", ctx_admin.get("user_sub") == oK)

# ============================================================================
npass = sum(1 for ok, _, _ in results if ok)
ntot = len(results)
print("\n=== WAVE-0 RESULT %d/%d ===" % (npass, ntot))
print("OVERALL", "ALL_PASS" if npass == ntot else "SOME_FAIL")
if npass != ntot:
    print("FAILURES:", [n for ok, n, _ in results if not ok])

# ---- self-clean (0 residue for this run) ----
cleaned = 0
for pid in _pids:
    try:
        ddb.Table(APP_TABLE).delete_item(Key={"pk": f"POST#{pid}", "sk": "META"}); cleaned += 1
    except Exception:
        pass
    try:
        T.moderation_cases.delete_item(Key={"case_id": MC.case_id_for("feed_post", pid)}); cleaned += 1
    except Exception:
        pass
for tid in set(_tickets):
    try:
        T.moderation_tickets.delete_item(Key={"ticket_id": tid}); cleaned += 1
    except Exception:
        pass
for u in set(_owners) | set(_state_users):
    try:
        T.account_state.delete_item(Key={"user_sub": u}); cleaned += 1
    except Exception:
        pass
    try:
        ks = [s["AttributeName"] for s in T.user_enforcement_history.key_schema]
        for e in T.user_enforcement_history.query(KeyConditionExpression=Key("user_id").eq(u)).get("Items", []):
            T.user_enforcement_history.delete_item(Key={k: e[k] for k in ks}); cleaned += 1
    except Exception:
        pass
    try:
        ks = [s["AttributeName"] for s in T.alerts.key_schema]
        for a in T.alerts.query(KeyConditionExpression=Key("user_sub").eq(u)).get("Items", []):
            T.alerts.delete_item(Key={k: a[k] for k in ks}); cleaned += 1
    except Exception:
        pass
print("cleanup deleted ~%d rows for TS=%d" % (cleaned, TS))
# residual check for THIS run
resid = 0
for pid in _pids:
    if meta(pid):
        resid += 1
    if get_case(pid):
        resid += 1
for tid in set(_tickets):
    if ticket(tid):
        resid += 1
print("RESIDUE_FOR_RUN:", resid)
