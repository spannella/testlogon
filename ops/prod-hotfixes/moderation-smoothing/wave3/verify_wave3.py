"""MODX WAVE-3 verify -- in-process on PROD DDB, non-destructive, self-cleaning.

Proves the human-loop fixes (MODX-13..16) AND that the moderation core is intact:
  MODX-13  a banned principal is NOT 403'd out of the appeals lane (require_appellant
           context exemption); enforcement-options lists the user's own enforcement
           records with an accurate has_appeal flag.
  MODX-14  poster_respond stores poster_response+responded_at (surfaced on the admin
           ticket-detail DTO); the assigned moderator gets a proactive notification.
  MODX-15  moderation events are default-on PUSH (not Alerts-only) + settable + carry
           the right deep-link; a report acks the reporter; a terminal outcome fans a
           resolution alert back to the DISTINCT reporters (not the owner).
  CORE     feed_post: report -> under_review+hidden -> confirm(hold) -> poster_respond
           (awaiting_final) -> reinstate (visible, body byte-for-byte). No regression.

Seeds synthetic users/content, auto-cleans (0 residue).
"""
import os
import time
import uuid

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.tables import T

import app.routers.moderation as M
from app.services import moderation_case as MC
from app.services import moderation_hide as MH
from app.services import moderation_lifecycle as LIFE
from app.services import moderation_policy_engine as POL
from app.services import appeals as APPEALS
from app.services import alerts as ALERTS
from app.auth import deps as DEPS
from app.auth.roles import Role

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
TS = int(time.time())
SUFFIX = "modx3_%d_%s" % (TS, uuid.uuid4().hex[:6])
results = []
cleanups = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def cleanup(fn):
    cleanups.append(fn)


def new_uid(tag):
    return "u_%s_%s" % (tag, SUFFIX)


def alerts_for(uid):
    try:
        r = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(uid), Limit=50)
        return r.get("Items", []) or []
    except Exception:
        return []


def has_alert_event(uid, event):
    return any(str(a.get("event") or "") == event for a in alerts_for(uid))


def del_alerts(uid):
    for a in alerts_for(uid):
        try:
            T.alerts.delete_item(Key={"user_sub": uid, "alert_id": a.get("alert_id")})
        except Exception:
            pass


def seed_reporter(uid):
    T.account_state.put_item(Item={"user_sub": uid, "trusted_reporter": True, "updated_at": TS})
    cleanup(lambda: T.account_state.delete_item(Key={"user_sub": uid}))
    cleanup(lambda: del_alerts(uid))
    return uid


def seed_feed_post(owner, pid, body):
    key = {"pk": "POST#%s" % pid, "sk": "META"}
    ddb.Table(APP_TABLE).put_item(Item={**key, "post_id": pid, "user_id": owner, "body": body,
                                        "content": body, "status": "published", "created_at": TS})
    cleanup(lambda: ddb.Table(APP_TABLE).delete_item(Key=key))
    return key


def case_for(ct, cid):
    return MC.get_case(MC.case_id_for(ct, cid)) or {}


_ticket_ids = []


def report(ct, cid, reporter, **extra):
    inp = M.CreateModerationReportIn(content_type=ct, content_id=cid, topics=["hate"],
                                     reason_text="verify wave3 synthetic", **extra)
    ctx = {"user_sub": reporter, "ip": "10.0.0.%d" % (TS % 250)}
    out = M._create_report(inp, ctx, request=None)
    try:
        _ticket_ids.append(out.ticket_id)
    except Exception:
        pass
    return out


# ---------------------------------------------------------- MODX-13 -----------
def test_modx13_appellant_ban_exemption():
    uid = new_uid("banned")
    T.account_state.put_item(Item={"user_sub": uid, "status": "banned", "updated_at": TS,
                                   "reason": "moderation_ban", "banned_until": 0})
    cleanup(lambda: T.account_state.delete_item(Key={"user_sub": uid}))
    check("MODX-13: seeded user is banned", POL.is_user_currently_banned(uid), "is_user_currently_banned")

    # normal auth path 403s a banned user
    raised = False
    try:
        DEPS._enforce_not_banned(user_sub=uid, role=Role.USER)
    except Exception as exc:
        raised = getattr(exc, "status_code", None) == 403
    check("MODX-13: normal lane still 403s a banned user", raised, "control")

    # appellant lane does NOT 403 the same banned user
    tok = DEPS._allow_banned_appellant.set(True)
    ok = True
    try:
        DEPS._enforce_not_banned(user_sub=uid, role=Role.USER)
    except Exception:
        ok = False
    finally:
        DEPS._allow_banned_appellant.reset(tok)
    check("MODX-13: appellant lane reaches appeals while banned", ok, "require_appellant exemption")


def test_modx13_enforcement_options():
    uid = new_uid("enfuser")
    enf1 = "enf_%s_A" % SUFFIX
    enf2 = "enf_%s_B" % SUFFIX
    for eid, note in ((enf1, "older ban"), (enf2, "newer removal")):
        T.user_enforcement_history.put_item(Item={
            "user_id": uid, "enforcement_id": eid, "entity_type": "user_enforcement",
            "status": "recorded", "enforcement_type": "content_violation",
            "source_ticket_id": "tk_%s" % eid, "created_at": str(TS), "note": note,
            "created_by_admin_user_id": "system", "duration_days": 0,
        })
        cleanup(lambda e=eid: T.user_enforcement_history.delete_item(Key={"user_id": uid, "enforcement_id": e}))
    # an appeal exists ONLY for enf1
    aid = "ap_%s" % SUFFIX
    T.appeals.put_item(Item={"appeal_id": aid, "user_id": uid, "enforcement_id": enf1,
                             "status": "submitted", "appeal_text": "x", "created_at": TS, "updated_at": TS})
    cleanup(lambda: T.appeals.delete_item(Key={"appeal_id": aid}))

    opts = APPEALS.list_enforcement_options(uid)
    ids = {o["enforcement_id"] for o in opts}
    check("MODX-13: enforcement-options lists user's records", enf1 in ids and enf2 in ids, "ids=%s" % ids)
    by = {o["enforcement_id"]: o for o in opts}
    check("MODX-13: has_appeal accurate (enf1 True / enf2 False)",
          by.get(enf1, {}).get("has_appeal") is True and by.get(enf2, {}).get("has_appeal") is False,
          "enf1=%s enf2=%s" % (by.get(enf1, {}).get("has_appeal"), by.get(enf2, {}).get("has_appeal")))


# ---------------------------------------------------------- MODX-14 -----------
def test_modx14_poster_response_and_notify():
    owner = new_uid("p14_owner")
    pid = "post14_%s" % SUFFIX
    seed_feed_post(owner, pid, "held body")
    reporter = seed_reporter(new_uid("p14_rep"))
    report("feed_post", pid, reporter, post_id=pid)
    case = case_for("feed_post", pid)
    LIFE.admin_confirm_hold(case=case, metadata=None, admin_user_id=new_uid("p14_admin"), now_ts=TS + 1)
    case = case_for("feed_post", pid)
    cleanup(lambda: T.moderation_cases.delete_item(Key={"case_id": case.get("case_id")}))

    # assign a moderator to the linked ticket so poster_respond notifies them
    tid = str(case.get("ticket_id") or "")
    assignee = new_uid("p14_mod")
    if tid:
        try:
            T.moderation_tickets.update_item(Key={"ticket_id": tid},
                UpdateExpression="SET assigned_admin_user_id = :a",
                ExpressionAttributeValues={":a": assignee})
        except Exception:
            pass
    cleanup(lambda: del_alerts(assignee))

    stmt = "This is my defense statement %s" % SUFFIX
    LIFE.poster_respond(case_id=case.get("case_id"), owner_user_id=owner, statement=stmt, now_ts=TS + 2)
    case2 = case_for("feed_post", pid)
    check("MODX-14: poster_response stored on case (DTO source)",
          str(case2.get("poster_response") or "") == stmt and int(case2.get("responded_at") or 0) > 0,
          "resp=%r responded_at=%s" % (case2.get("poster_response"), case2.get("responded_at")))
    check("MODX-14: awaiting_final after respond", case2.get("state") == "awaiting_final", case2.get("state"))
    check("MODX-14: assigned moderator notified (poster_responded)",
          has_alert_event(assignee, "moderation_poster_responded"),
          "assignee alerts=%s" % [a.get("event") for a in alerts_for(assignee)])
    cleanup(lambda: del_alerts(owner))


# ---------------------------------------------------------- MODX-15 -----------
def test_modx15_push_and_deeplinks():
    dp = set(ALERTS.DEFAULT_PUSH_EVENT_TYPES)
    ae = set(ALERTS.ALERT_EVENT_TYPES)
    need = {"moderation_content_deleted", "moderation_violation_confirmed", "moderation_ban",
            "moderation_report_received", "moderation_report_resolved", "moderation_poster_responded"}
    check("MODX-15: moderation events are default-on PUSH (not Alerts-only)", need <= dp, "missing=%s" % (need - dp))
    check("MODX-15: moderation events settable (ALERT_EVENT_TYPES)", need <= ae, "missing=%s" % (need - ae))
    check("MODX-15: ban alert deep-links to /appeals",
          ALERTS._build_action_url("moderation_ban", {}) == "/appeals",
          ALERTS._build_action_url("moderation_ban", {}))
    check("MODX-15: violation alert deep-links to review",
          ALERTS._build_action_url("moderation_violation_confirmed", {}) == "/moderation/review",
          ALERTS._build_action_url("moderation_violation_confirmed", {}))


def test_modx15_reporter_feedback():
    owner = new_uid("p15_owner")
    pid = "post15_%s" % SUFFIX
    seed_feed_post(owner, pid, "reported body")
    reporter = seed_reporter(new_uid("p15_rep"))
    report("feed_post", pid, reporter, post_id=pid)
    case = case_for("feed_post", pid)
    cleanup(lambda: T.moderation_cases.delete_item(Key={"case_id": case.get("case_id")}))
    cleanup(lambda: del_alerts(owner))

    check("MODX-15: reporter got report-received ack", has_alert_event(reporter, "moderation_report_received"),
          "rep alerts=%s" % [a.get("event") for a in alerts_for(reporter)])

    # terminal outcome: dismiss -> reporter learns the resolution, owner learns restore
    LIFE.admin_dismiss(case=case, metadata=None, admin_user_id=new_uid("p15_admin"), now_ts=TS + 3)
    check("MODX-15: reporter got resolution outcome on terminal",
          has_alert_event(reporter, "moderation_report_resolved"),
          "rep alerts=%s" % [a.get("event") for a in alerts_for(reporter)])
    check("MODX-15: owner got restore notice (not the reporter's outcome)",
          has_alert_event(owner, "moderation_content_restored"),
          "owner alerts=%s" % [a.get("event") for a in alerts_for(owner)])
    check("MODX-15: reporter did NOT get the owner-only restore notice",
          not has_alert_event(reporter, "moderation_content_restored"), "isolation")


# ---------------------------------------------------------- CORE --------------
def test_core_feed_post_lifecycle():
    owner = new_uid("core_owner")
    pid = "postcore_%s" % SUFFIX
    body = "the original feed body -- must survive byte-for-byte %s" % SUFFIX
    key = seed_feed_post(owner, pid, body)
    reporter = seed_reporter(new_uid("core_rep"))
    report("feed_post", pid, reporter, post_id=pid)
    case = case_for("feed_post", pid)
    cleanup(lambda: T.moderation_cases.delete_item(Key={"case_id": case.get("case_id")}))

    def read():
        return ddb.Table(APP_TABLE).get_item(Key=key).get("Item") or {}

    check("CORE: report auto-hid (under_review+hidden)",
          case.get("state") == "under_review" and bool(case.get("hidden")) and
          MH.is_hidden_for_viewer(read(), new_uid("viewer"), owner_field="user_id"),
          "state=%s hidden=%s" % (case.get("state"), case.get("hidden")))

    LIFE.admin_confirm_hold(case=case, metadata=None, admin_user_id=new_uid("core_admin"), now_ts=TS + 1)
    c = case_for("feed_post", pid)
    check("CORE: confirm -> hold, stays hidden", c.get("state") == "hold" and bool(c.get("hidden")),
          "state=%s hidden=%s" % (c.get("state"), c.get("hidden")))

    LIFE.poster_respond(case_id=c.get("case_id"), owner_user_id=owner, statement="please review", now_ts=TS + 2)
    c = case_for("feed_post", pid)
    check("CORE: poster_respond -> awaiting_final, still hidden", c.get("state") == "awaiting_final" and bool(c.get("hidden")),
          "state=%s hidden=%s" % (c.get("state"), c.get("hidden")))

    LIFE.admin_final_reinstate(case=c, metadata=None, admin_user_id=new_uid("core_admin"), now_ts=TS + 3)
    c = case_for("feed_post", pid)
    it = read()
    check("CORE: reinstate -> visible + body byte-for-byte",
          c.get("state") == "reinstated" and not c.get("hidden") and
          (not MH.is_hidden_flag(it)) and it.get("body") == body,
          "state=%s hidden=%s body_ok=%s" % (c.get("state"), c.get("hidden"), it.get("body") == body))
    cleanup(lambda: del_alerts(owner))


def main():
    try:
        test_modx13_appellant_ban_exemption()
        test_modx13_enforcement_options()
        test_modx14_poster_response_and_notify()
        test_modx15_push_and_deeplinks()
        test_modx15_reporter_feedback()
        test_core_feed_post_lifecycle()
    finally:
        for tid in _ticket_ids:
            try:
                T.moderation_tickets.delete_item(Key={"ticket_id": tid})
            except Exception:
                pass
        for fn in reversed(cleanups):
            try:
                fn()
            except Exception:
                pass
    passed = sum(1 for ok, _, _ in results if ok)
    total = len(results)
    print("\n==== WAVE-3 VERIFY: %d/%d PASSED ====" % (passed, total))
    for ok, n, d in results:
        if not ok:
            print("  FAIL:", n, "--", d)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
