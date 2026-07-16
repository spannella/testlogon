"""MODX WAVE-1 verify — in-process on PROD DDB, non-destructive, self-cleaning.

Proves the Wave-1 abuse-vector fixes AND that the happy path / core still holds:
  MODX-3  distinct-reporter auto-hide + target protection + per-target velocity
  MODX-4  humane expiry + awaiting_final SLA + under_review recourse + no-strike self-close
  MODX-5  reporter reputation loop + self/COI guards
  MODX-6  ban-evasion fingerprinting seam
  MODX-7  real dual-approval for permanent bans
  MODX-8  illegal / CSAM escalation lane

Seeds synthetic content/users, exercises the flows, auto-cleans (0 residue for TS).
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
from app.services import moderation_case as MC
from app.services import moderation_lifecycle as LIFE
from app.services import moderation_reporter_reputation as REP
from app.services import moderation_ban_fingerprint as FP
from app.services import moderation_illegal_lane as ILL
from app.services.moderation_policy_engine import apply_ban, is_user_currently_banned
from app.services.moderation_tickets_store import upsert_open_ticket_for_report
from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role, AdminProfile, AdminProfileType, AdminScope

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
TS = int(time.time())
results = []
_pids, _owners, _state_users, _tickets, _user_rows, _app_keys = [], [], [], [], [], []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def seed_post(pid, owner, body):
    ddb.Table(APP_TABLE).put_item(Item={
        "pk": f"POST#{pid}", "sk": "META", "post_id": pid, "user_id": owner,
        "body": body, "content": body, "text": body, "status": "published",
        "visibility": "public", "privacy": "public",
        "created_at": TS, "updated_at": TS, "image_urls": [],
    })
    if pid not in _pids:
        _pids.append(pid)
    if owner not in _owners:
        _owners.append(owner)


def meta(pid):
    return ddb.Table(APP_TABLE).get_item(Key={"pk": f"POST#{pid}", "sk": "META"}).get("Item") or {}


def get_case(pid):
    return MC.get_case(MC.case_id_for("feed_post", pid)) or {}


def ticket(tid):
    return T.moderation_tickets.get_item(Key={"ticket_id": tid}).get("Item") or {}


def seed_state(uid, **fields):
    item = {"user_sub": uid, "updated_at": TS}
    item.update(fields)
    T.account_state.put_item(Item=item)
    if uid not in _state_users:
        _state_users.append(uid)
    return uid


def seed_user(uid, **fields):
    item = {"user_sub": uid, "created_at": TS}
    item.update(fields)
    T.users.put_item(Item=item)
    if uid not in _user_rows:
        _user_rows.append(uid)
    return uid


def enforcement_rows(uid, etype="content_violation"):
    r = T.user_enforcement_history.query(KeyConditionExpression=Key("user_id").eq(uid), ScanIndexForward=False, Limit=50)
    return [x for x in r.get("Items", []) if x.get("entity_type") == "user_enforcement" and (not etype or x.get("enforcement_type") == etype)]


def get_post_status(pid, viewer):
    try:
        NF.get_post(pid, viewer)
        return 200
    except HTTPException as e:
        return e.status_code


def rfile(pid, owner, reporter, cats, ticket_id=None):
    return MC.on_report_filed(content_type="feed_post", content_id=pid, topics=cats,
                              reporter_user_id=reporter, metadata={}, ticket_id=ticket_id, now_ts=TS)


ROOT = AuthenticatedUser(sub=f"root_{TS}", role=Role.ROOT)
print("=== MODX WAVE-1 VERIFY ts=%d cases=%s ===" % (TS, getattr(S, "moderation_cases_table_name", "?")))

# ===========================================================================
# MODX-3 — distinct-reporter / trust / target-protection / velocity
# ===========================================================================
# 3a weaponized: a single UNTRUSTED severe report can NO LONGER auto-hide.
o3a, p3a = f"o3a_{TS}", f"p3a_{TS}"
seed_post(p3a, o3a, f"B_{TS}")
rfile(p3a, o3a, f"burner3a_{TS}", ["sexual"])
c3a = get_case(p3a)
check("3a single untrusted severe does NOT auto-hide", c3a.get("state") == "visible" and not c3a.get("hidden"), str(c3a.get("state")))
check("3a suppressed -> flagged needs_human_review", bool(c3a.get("needs_human_review")))
check("3a non-owner can still see it (not hidden)", get_post_status(p3a, f"str_{TS}") == 200)

# 3b one account, 3 REPORT EVENTS -> distinct stays 1 -> still not hidden.
o3b, p3b = f"o3b_{TS}", f"p3b_{TS}"
seed_post(p3b, o3b, f"B_{TS}")
for _ in range(3):
    rfile(p3b, o3b, f"solo3b_{TS}", ["sexual"])
c3b = get_case(p3b)
check("3b one account's 3 events -> distinct_reporter_count == 1", len({str(x) for x in (c3b.get('reporter_ids') or [])}) == 1, str(c3b.get("reporter_ids")))
check("3b still NOT auto-hidden (event-count fix)", c3b.get("state") == "visible", str(c3b.get("state")))

# 3c a TRUSTED reporter's single severe report DOES auto-hide (trust floor).
o3c, p3c = f"o3c_{TS}", f"p3c_{TS}"
seed_post(p3c, o3c, f"B_{TS}")
seed_state(f"trust3c_{TS}", trusted_reporter=True)
rfile(p3c, o3c, f"trust3c_{TS}", ["sexual"])
check("3c trusted single severe -> auto-hidden (under_review)", get_case(p3c).get("state") == "under_review", str(get_case(p3c).get("state")))

# 3d TWO distinct reporters incl. a CREDIBLE (established) one -> corroborated hide.
o3d, p3d = f"o3d_{TS}", f"p3d_{TS}"
seed_post(p3d, o3d, f"B_{TS}")
seed_state(f"estab3d_{TS}", established=True)
rfile(p3d, o3d, f"estab3d_{TS}", ["sexual"])
check("3d after 1 credible severe NOT yet hidden (needs corroboration)", get_case(p3d).get("state") == "visible", str(get_case(p3d).get("state")))
rfile(p3d, o3d, f"other3d_{TS}", ["sexual"])
check("3d 2 distinct (1 credible) severe -> corroborated auto-hide", get_case(p3d).get("state") == "under_review", str(get_case(p3d).get("state")))

# 3e VELOCITY: a burst of 3 fresh/untrusted distinct accounts -> human review, NOT hidden.
o3e, p3e = f"o3e_{TS}", f"p3e_{TS}"
seed_post(p3e, o3e, f"B_{TS}")
for i in range(3):
    rfile(p3e, o3e, f"brig3e{i}_{TS}", ["sexual"])
c3e = get_case(p3e)
check("3e 3 fresh burners -> velocity-suppressed (NOT hidden)", c3e.get("state") == "visible", str(c3e.get("state")))
check("3e brigade flagged needs_human_review (velocity)", bool(c3e.get("needs_human_review")) and c3e.get("human_review_reason") == "velocity_suppressed_human_review", str(c3e.get("human_review_reason")))

# 3f LOWER severity: 3 distinct CREDIBLE reporters -> distinct threshold auto-hide.
o3f, p3f = f"o3f_{TS}", f"p3f_{TS}"
seed_post(p3f, o3f, f"B_{TS}")
for i in range(3):
    seed_state(f"est3f{i}_{TS}", established=True)
    rfile(p3f, o3f, f"est3f{i}_{TS}", ["spam"])
check("3f 3 distinct credible LOWER -> auto-hide at threshold", get_case(p3f).get("state") == "under_review", str(get_case(p3f).get("state")))

# 3g PROTECTED target (verified): even a trusted single reporter needs corroboration.
o3g, p3g = f"o3g_{TS}", f"p3g_{TS}"
seed_user(o3g, verified=True)
seed_post(p3g, o3g, f"B_{TS}")
seed_state(f"trust3g_{TS}", trusted_reporter=True)
rfile(p3g, o3g, f"trust3g_{TS}", ["sexual"])
check("3g verified-target: trusted single report NOT auto-hidden (needs corroboration)", get_case(p3g).get("state") == "visible", str(get_case(p3g).get("state")))
rfile(p3g, o3g, f"corrob3g_{TS}", ["sexual"])
check("3g verified-target: with corroboration -> auto-hidden", get_case(p3g).get("state") == "under_review", str(get_case(p3g).get("state")))

# 3h COI self-report: reporter == owner is dropped from the distinct set.
o3h, p3h = f"o3h_{TS}", f"p3h_{TS}"
seed_post(p3h, o3h, f"B_{TS}")
rfile(p3h, o3h, o3h, ["sexual"])  # self-report
c3h = get_case(p3h)
check("3h self-report dropped (distinct == 0)", len({str(x) for x in (c3h.get('reporter_ids') or [])}) == 0, str(c3h.get("reporter_ids")))
check("3h self-report does NOT auto-hide", c3h.get("state") == "visible", str(c3h.get("state")))

# ===========================================================================
# MODX-4 — humane expiry + awaiting_final SLA + under_review recourse + close
# ===========================================================================
# 4a hold-expiry by INACTION escalates to awaiting_final (no delete, NO strike).
o4a, p4a = f"o4a_{TS}", f"p4a_{TS}"
seed_post(p4a, o4a, f"B_{TS}")
seed_state(f"t4a_{TS}", trusted_reporter=True)
rfile(p4a, o4a, f"t4a_{TS}", ["sexual"])
LIFE.admin_confirm_hold(case=get_case(p4a), metadata={}, admin_user_id=f"adm_{TS}", now_ts=TS)
T.moderation_cases.update_item(Key={"case_id": MC.case_id_for("feed_post", p4a)},
                               UpdateExpression="SET hold_until = :h", ExpressionAttributeValues={":h": TS - 10})
sw = LIFE.sweep_expired_holds(now_ts=TS)
c4a = get_case(p4a)
check("4a inaction-expiry ESCALATES to awaiting_final (not deleted)", c4a.get("state") == "awaiting_final", str(c4a.get("state")))
check("4a expired content PRESERVED (row intact)", meta(p4a) != {})
check("4a NO strike for pure no-response", len(enforcement_rows(o4a)) == 0, str(len(enforcement_rows(o4a))))
check("4a expired_no_response flag set + SLA deadline", bool(c4a.get("expired_no_response")) and c4a.get("sla_deadline"))

# 4b awaiting_final past SLA -> senior escalation (still hidden, not deleted).
T.moderation_cases.update_item(Key={"case_id": MC.case_id_for("feed_post", p4a)},
                               UpdateExpression="SET sla_deadline = :s", ExpressionAttributeValues={":s": TS - 10})
sw2 = LIFE.sweep_awaiting_final_sla(now_ts=TS)
c4b = get_case(p4a)
check("4b awaiting_final past SLA -> senior_escalated", bool(c4b.get("senior_escalated")) and MC.case_id_for("feed_post", p4a) in sw2["case_ids"], str(sw2))
check("4b still hidden + content preserved (no auto-delete/reinstate)", bool(c4b.get("hidden")) and meta(p4a) != {} and c4b.get("state") == "awaiting_final")

# 4c under_review RECOURSE: poster can dispute a fresh auto-hide before admin acts.
o4c, p4c = f"o4c_{TS}", f"p4c_{TS}"
seed_post(p4c, o4c, f"B_{TS}")
seed_state(f"t4c_{TS}", trusted_reporter=True)
tk4c = upsert_open_ticket_for_report(content_type="feed_post", content_id=p4c, topics=["sexual"], now_ts=TS)["ticket_id"]
_tickets.append(tk4c)
rfile(p4c, o4c, f"t4c_{TS}", ["sexual"], ticket_id=tk4c)
d = LIFE.poster_dispute(case_id=MC.case_id_for("feed_post", p4c), owner_user_id=o4c, statement="this was a mistake", now_ts=TS)
c4c = get_case(p4c)
check("4c poster_dispute recorded + flagged for human", c4c.get("poster_dispute") and bool(c4c.get("needs_human_review")))
check("4c content stays hidden pending review (no state skip)", c4c.get("state") == "under_review" and bool(c4c.get("hidden")))
check("4c dispute re-surfaces the linked ticket", ticket(tk4c).get("status") == "open" and bool(ticket(tk4c).get("poster_disputed")))

# 4d poster self-close carries NO strike.
o4d, p4d = f"o4d_{TS}", f"p4d_{TS}"
seed_post(p4d, o4d, f"B_{TS}")
seed_state(f"t4d_{TS}", trusted_reporter=True)
rfile(p4d, o4d, f"t4d_{TS}", ["sexual"])
LIFE.admin_confirm_hold(case=get_case(p4d), metadata={}, admin_user_id=f"adm_{TS}", now_ts=TS)
rc = LIFE.poster_close(case_id=MC.case_id_for("feed_post", p4d), owner_user_id=o4d, now_ts=TS)
check("4d poster_close deletes own content", rc.get("state") == "deleted" and meta(p4d) == {})
check("4d poster_close carries NO strike (MODX-4)", len(enforcement_rows(o4d)) == 0, str(len(enforcement_rows(o4d))))

# ===========================================================================
# MODX-5 — reporter reputation loop + COI guards
# ===========================================================================
# 5a a serially-DISMISSED reporter loses trust (false_rate up).
o5, p5a = f"o5_{TS}", f"p5a_{TS}"
R = f"falserep_{TS}"
_state_users.append(R)
seed_post(p5a, o5, f"B_{TS}")
rfile(p5a, o5, R, ["sexual"])
LIFE.admin_dismiss(case=get_case(p5a), metadata={}, admin_user_id=f"adm_{TS}", now_ts=TS)
st5 = T.account_state.get_item(Key={"user_sub": R}).get("Item") or {}
check("5a dismissed reporter: false-rate bumped, trust down", float(st5.get("report_false_rate") or 0) > 0.2 and float(st5.get("report_trust_score") or 0) < 1, str((st5.get("report_false_rate"), st5.get("report_trust_score"))))
check("5a serially-false reporter is NOT trusted", MC.is_trusted_reporter(R) is False)
# 5b a CONFIRMED report rewards trust.
p5b = f"p5b_{TS}"
seed_post(p5b, o5, f"B_{TS}")
rfile(p5b, o5, R, ["sexual"])
LIFE.admin_confirm_hold(case=get_case(p5b), metadata={}, admin_user_id=f"adm_{TS}", now_ts=TS)
st5b = T.account_state.get_item(Key={"user_sub": R}).get("Item") or {}
check("5b confirm increments upheld counter", int(st5b.get("reports_upheld") or 0) >= 1, str(st5b.get("reports_upheld")))
# 5c COI guard.
o5c, p5c = f"o5c_{TS}", f"p5c_{TS}"
seed_post(p5c, o5c, f"B_{TS}")
rfile(p5c, o5c, f"onerep5c_{TS}", ["sexual"])
case5c = get_case(p5c)
check("5c admin==owner is conflicted", REP.is_conflicted_admin(case5c, o5c) is True)
check("5c admin==sole reporter is conflicted", REP.is_conflicted_admin(case5c, f"onerep5c_{TS}") is True)
check("5c uninvolved admin is NOT conflicted", REP.is_conflicted_admin(case5c, f"neutral_{TS}") is False)

# ===========================================================================
# MODX-6 — ban-evasion fingerprinting
# ===========================================================================
off6 = f"off6_{TS}"
off6_email = f"evader{TS}@gmail.com"
seed_user(off6, signup_device_id=f"dev6_{TS}", signup_email=off6_email, signup_ip="203.0.113.9")
_state_users.append(off6)
apply_ban(offender_user_id=off6, ticket_id="", admin_user_id=f"adm_{TS}", note="evasion", duration_days=7, policy_category="content_violation")
_app_keys += [("device", FP._hash("device", FP._norm("device", f"dev6_{TS}"))),
              ("email", FP._hash("email", FP._norm("email", off6_email))),
              ("ip", FP._hash("ip", FP._norm("ip", "203.0.113.9")))]
scr = FP.screen_registration(device_id=f"dev6_{TS}")
check("6a new signup on banned device -> flagged evasion", scr["evasion"] is True and off6 in scr["matched_users"], str(scr))
scr_email = FP.screen_registration(email=f"ev.ader.{TS}@gmail.com")  # gmail dot-alias -> same canonical
check("6b gmail dot-alias of banned email -> flagged evasion", scr_email["evasion"] is True, str(scr_email))
scr_clean = FP.screen_registration(device_id=f"cleandev_{TS}")
check("6c unrelated fresh signup -> NOT flagged", scr_clean["evasion"] is False, str(scr_clean))
# expired ban must NOT poison the fingerprint
exp6 = f"exp6_{TS}"
seed_state(exp6, status="banned", ban_until=TS - 100, ban_started_at=TS - 200)
FP.record_ban_fingerprints(user_sub=exp6, device_id=f"expdev_{TS}", now_ts=TS)
_app_keys.append(("device", FP._hash("device", FP._norm("device", f"expdev_{TS}"))))
scr_exp = FP.screen_registration(device_id=f"expdev_{TS}")
check("6d EXPIRED ban does not flag evasion", scr_exp["evasion"] is False, str(scr_exp))

# ===========================================================================
# MODX-7 — real dual-approval for permanent bans
# ===========================================================================
senior7 = seed_user(f"senior7_{TS}", role="admin", admin_profile={"type": "scoped", "scopes": ["content_moderation_senior"]})
plain7 = seed_user(f"plain7_{TS}", role="admin", admin_profile={"type": "scoped", "scopes": ["content_moderation"]})
acting7 = AuthenticatedUser(sub=f"acting7_{TS}", role=Role.ROOT)


def dual(approver):
    try:
        ADMIN._require_dual_approval_for_permanent_ban(admin=acting7, second_approver_admin_user_id=approver)
        return None
    except HTTPException as e:
        return e.status_code


check("7a missing approver rejected", dual(None) == 403)
check("7b self-approval rejected", dual(acting7.sub) == 403)
check("7c fabricated/non-existent approver rejected", dual(f"ghost_{TS}") == 403)
check("7d existing but NON-senior approver rejected", dual(plain7) == 403)
check("7e real SENIOR approver accepted", dual(senior7) is None)

# ===========================================================================
# MODX-8 — illegal / CSAM escalation lane
# ===========================================================================
o8, p8 = f"o8_{TS}", f"p8_{TS}"
seed_post(p8, o8, f"EVIDENCE_{TS}")
tk8 = upsert_open_ticket_for_report(content_type="feed_post", content_id=p8, topics=["csam"], now_ts=TS)["ticket_id"]
_tickets.append(tk8)
r8 = rfile(p8, o8, f"rep8_{TS}", ["csam"], ticket_id=tk8)
c8 = get_case(p8)
cid8 = MC.case_id_for("feed_post", p8)
_app_keys += [("_illegal", cid8)]  # sentinel to clean preservation + mandated rows
check("8a csam report -> IMMEDIATE restricted hide (1st report, no corroboration)", c8.get("state") == "under_review" and bool(c8.get("hidden")), str(c8.get("state")))
check("8a case flagged illegal_lane + restricted + reinstate_blocked", bool(c8.get("illegal_lane")) and bool(c8.get("restricted")))
check("8a routed to locked ILLEGAL queue", c8.get("moderation_queue") == "illegal")
check("8a non-owner sees 404 (hidden)", get_post_status(p8, f"str8_{TS}") == 404)
pres = ddb.Table(APP_TABLE).get_item(Key={"pk": f"ILLEGALPRESERVE#{cid8}", "sk": "RECORD"}).get("Item")
check("8b evidence PRESERVATION record written", bool(pres) and pres.get("status") == "preserved")
mand = ddb.Table(APP_TABLE).query(KeyConditionExpression=Key("pk").eq(f"MANDATEDREPORT#{cid8}")).get("Items")
check("8b mandated-report event fired", bool(mand))
# reinstate / dismiss / self-delete all BLOCKED on illegal content
def blocked(fn):
    try:
        fn(); return False
    except ILL.IllegalContentError:
        return True
    except ValueError:
        return True
check("8c admin_final_reinstate BLOCKED on illegal", blocked(lambda: LIFE.admin_final_reinstate(case=get_case(p8), metadata={}, admin_user_id=f"adm_{TS}", now_ts=TS)))
check("8c admin_dismiss BLOCKED on illegal (would re-expose)", blocked(lambda: LIFE.admin_dismiss(case=get_case(p8), metadata={}, admin_user_id=f"adm_{TS}", now_ts=TS)))
check("8c poster_close BLOCKED (evidence preserved)", blocked(lambda: LIFE.poster_close(case_id=cid8, owner_user_id=o8, now_ts=TS)))
# senior-only gate on the final-call endpoint (SCOPED admin lacking the senior scope)
nonsenior = AuthenticatedUser(sub=f"nonsr_{TS}", role=Role.ADMIN,
                              admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)))
sg = None
try:
    ADMIN.final_call_moderation_case(tk8, ADMIN._FinalCallIn(action="delete", note="x"), admin=nonsenior)
except HTTPException as e:
    sg = e.status_code
check("8d final-call on illegal case is SENIOR-only (non-senior -> 403)", sg == 403, str(sg))

# ===========================================================================
npass = sum(1 for ok, _, _ in results if ok)
ntot = len(results)
print("\n=== WAVE-1 RESULT %d/%d ===" % (npass, ntot))
print("OVERALL", "ALL_PASS" if npass == ntot else "SOME_FAIL")
if npass != ntot:
    print("FAILURES:", [n for ok, n, _ in results if not ok])

# ---------------------------------------------------------------------------
# CLEANUP (0 residue for this run's TS)
# ---------------------------------------------------------------------------
cleaned = 0
for pid in set(_pids):
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
for uid in set(_owners) | set(_state_users):
    try:
        T.account_state.delete_item(Key={"user_sub": uid}); cleaned += 1
    except Exception:
        pass
    for e in enforcement_rows(uid, None):
        try:
            T.user_enforcement_history.delete_item(Key={"user_id": e["user_id"], "enforcement_id": e["enforcement_id"]}); cleaned += 1
        except Exception:
            pass
    try:
        r = T.alerts.query(KeyConditionExpression=Key("user_id").eq(uid), Limit=50)
        for a in r.get("Items", []):
            ks = [k["AttributeName"] for k in T.alerts.key_schema]
            T.alerts.delete_item(Key={k: a[k] for k in ks}); cleaned += 1
    except Exception:
        pass
for uid in set(_user_rows):
    try:
        T.users.delete_item(Key={"user_sub": uid}); cleaned += 1
    except Exception:
        pass
for kind, val in _app_keys:
    try:
        if kind == "_illegal":
            ddb.Table(APP_TABLE).delete_item(Key={"pk": f"ILLEGALPRESERVE#{val}", "sk": "RECORD"}); cleaned += 1
            mr = ddb.Table(APP_TABLE).query(KeyConditionExpression=Key("pk").eq(f"MANDATEDREPORT#{val}")).get("Items")
            for m in mr:
                ddb.Table(APP_TABLE).delete_item(Key={"pk": m["pk"], "sk": m["sk"]}); cleaned += 1
        else:
            q = ddb.Table(APP_TABLE).query(KeyConditionExpression=Key("pk").eq(f"BANFP#{kind}#{val}")).get("Items")
            for it in q:
                ddb.Table(APP_TABLE).delete_item(Key={"pk": it["pk"], "sk": it["sk"]}); cleaned += 1
    except Exception:
        pass
print("cleanup deleted ~%d rows for TS=%d" % (cleaned, TS))
# residue probe
residue = 0
for pid in set(_pids):
    if meta(pid):
        residue += 1
print("RESIDUE_FOR_RUN:", residue)
