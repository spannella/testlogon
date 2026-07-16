"""MODX WAVE-4 verify -- in-process on DDB, non-destructive, self-cleaning.

Proves the admin-tooling-at-scale fixes (MODX-17..22 backend) AND that the
moderation core is intact:
  MODX-18  compute_moderation_kpis excludes parked holds (hold/awaiting_final) from
           open/backlog/oldest sets and surfaces them as on_hold_count; the ticket
           list filters by any LIVE category (+ legacy synonym) and real status.
  MODX-19  the ban roster lists an active ban; lift restores account_state=active,
           closes the enforcement row, and drops it from the active roster.
  MODX-20  the ticket/actor audit trail reads back written events; a fresh claim is
           exclusive (steal required), same-claimer passes, a TTL-stale claim frees.
  MODX-22  bulk dismiss returns a per-item result for every ticket (good + bogus).
  CORE     feed_post: report -> under_review+hidden -> confirm(hold) -> poster_respond
           (awaiting_final) -> reinstate (visible, body byte-for-byte). No regression.

Seeds synthetic users/content/tickets, auto-cleans (0 residue).
Run: set -a && source .env.local && set +a && \
     AWS_ENDPOINT_URL=http://localhost:8001 PYTHONPATH=. ./.venv/bin/python \
     ops/prod-hotfixes/moderation-smoothing/wave4/verify_wave4.py
"""
import os
import time
import uuid

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.tables import T

import app.routers.moderation as M
import app.routers.admin_moderation as AM
from app.services import moderation_case as MC
from app.services import moderation_hide as MH
from app.services import moderation_lifecycle as LIFE
from app.services import moderation_policy_engine as POL
from app.services.moderation_audit_log import write_moderation_audit_event
from app.auth.deps import AuthenticatedUser
from app.auth.roles import Role

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
TS = int(time.time())
SUFFIX = "modx4_%d_%s" % (TS, uuid.uuid4().hex[:6])
results = []
cleanups = []
ROOT = AuthenticatedUser(sub="rootadmin_%s" % SUFFIX, role=Role.ROOT)


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))
    print(("PASS" if cond else "FAIL"), name, "--", detail)


def cleanup(fn):
    cleanups.append(fn)


def nid(tag):
    return "u_%s_%s" % (tag, SUFFIX)


# ── topic sentinels (the create_content_report transaction requires TOPIC# rows) ──
def seed_topics():
    for topic in ("hate", "harassment", "spam", "sexual", "violence_threats", "other",
                  "illegal", "extortion", "criminal", "racist", "csam"):
        try:
            T.content_reports.put_item(
                Item={"report_id": "TOPIC#%s" % topic, "entity_type": "content_report_topic", "topic": topic},
                ConditionExpression="attribute_not_exists(report_id)",
            )
        except Exception:
            pass


def seed_reporter(uid):
    T.account_state.put_item(Item={"user_sub": uid, "trusted_reporter": True, "updated_at": TS})
    cleanup(lambda: T.account_state.delete_item(Key={"user_sub": uid}))
    return uid


def seed_feed_post(owner, pid, body):
    key = {"pk": "POST#%s" % pid, "sk": "META"}
    ddb.Table(APP_TABLE).put_item(Item={**key, "post_id": pid, "user_id": owner, "body": body,
                                        "content": body, "status": "published", "created_at": TS})
    cleanup(lambda: ddb.Table(APP_TABLE).delete_item(Key=key))
    return key


def case_for(ct, cid):
    return MC.get_case_for_content(ct, cid) or {}


def put_ticket(tid, **fields):
    item = {
        "ticket_id": tid,
        "entity_type": "moderation_ticket",
        "status": "open",
        "priority": "medium",
        "queue": "general",
        "latest_report_scope": "ALL",
        "latest_report_at": str(TS),
        "created_at": str(TS),
        "updated_at": str(TS),
        "content_type": "feed_post",
        "content_id": "c_%s" % tid,
        "aggregated_topics": [],
    }
    item.update(fields)
    T.moderation_tickets.put_item(Item=item)
    cleanup(lambda: T.moderation_tickets.delete_item(Key={"ticket_id": tid}))
    return tid


def report(ct, cid, reporter, topics, **extra):
    inp = M.CreateModerationReportIn(content_type=ct, content_id=cid, topics=topics,
                                     reason_text="verify wave4 synthetic", **extra)
    ctx = {"user_sub": reporter, "ip": "10.0.1.%d" % (TS % 250)}
    return M._create_report(inp, ctx, request=None)


# ─────────────────────────────── MODX-18: KPI exclude holds ───────────────────
def test_kpi_excludes_holds():
    before = AM.compute_moderation_kpis()
    ids = {
        "open": put_ticket("tk_%s_open" % SUFFIX, status="open"),
        "crit": put_ticket("tk_%s_crit" % SUFFIX, status="open", priority="critical"),
        "hold": put_ticket("tk_%s_hold" % SUFFIX, status="open", moderation_case_state="hold"),
        "await": put_ticket("tk_%s_await" % SUFFIX, status="open", moderation_case_state="awaiting_final"),
    }
    after = AM.compute_moderation_kpis()
    d_open = after["open_ticket_count"] - before["open_ticket_count"]
    d_hold = after["on_hold_count"] - before.get("on_hold_count", 0)
    d_crit = after["critical_backlog"] - before["critical_backlog"]
    check("MODX-18: parked holds excluded from open backlog (delta==2 non-hold)", d_open == 2, "delta_open=%d" % d_open)
    check("MODX-18: on_hold_count surfaces the 2 parked holds", d_hold == 2, "delta_on_hold=%d" % d_hold)
    check("MODX-18: critical_backlog counts only the non-hold critical", d_crit == 1, "delta_crit=%d" % d_crit)
    check("MODX-18: on_hold_count present in KPI payload", "on_hold_count" in after, "keys ok")


# ─────────────────────────────── MODX-18: real filters ───────────────────────
def test_live_category_filters():
    ta = put_ticket("tk_%s_har" % SUFFIX, aggregated_topics=["harassment"])
    tb = put_ticket("tk_%s_hate" % SUFFIX, aggregated_topics=["hate"])
    tc = put_ticket("tk_%s_spam" % SUFFIX, aggregated_topics=["spam"])
    td = put_ticket("tk_%s_closed" % SUFFIX, status="closed", aggregated_topics=["harassment"])

    def ids_for(status=None, queue=None, topic=None, assignee=None):
        out = AM.list_moderation_tickets(status=status, queue=queue, topic=topic,
                                         assignee=assignee, limit=100, cursor=None, _admin=ROOT)
        return {i.ticket_id for i in out.items}

    har = ids_for(topic="harassment")
    check("MODX-18: filter topic=harassment returns harassment ticket", ta in har and tb not in har and tc not in har, "har=%s" % (ta in har))
    ext = ids_for(topic="extortion")  # legacy synonym -> harassment
    check("MODX-18: legacy synonym extortion matches harassment", ta in ext, "ta in extortion=%s" % (ta in ext))
    hate = ids_for(topic="hate")
    check("MODX-18: filter topic=hate returns hate ticket only", tb in hate and ta not in hate, "tb=%s" % (tb in hate))
    racist = ids_for(topic="racist")  # legacy synonym -> hate
    check("MODX-18: legacy synonym racist matches hate", tb in racist, "tb in racist=%s" % (tb in racist))
    closed = ids_for(status="closed")
    op = ids_for(status="open")
    check("MODX-18: status=closed surfaces closed ticket (real status set)", td in closed and td not in op, "td closed=%s open=%s" % (td in closed, td in op))


# ─────────────────────────────── MODX-20: audit read ─────────────────────────
def test_audit_read():
    tid = "tk_%s_audit" % SUFFIX
    actor = nid("auditor")
    aids = []
    for act in ("ticket_assigned", "content_violation_confirmed", "content_case_reinstated"):
        aid = write_moderation_audit_event(action=act, actor_user_id=actor, ticket_id=tid,
                                           content_type="feed_post", content_id="c1", metadata={"k": act})
        aids.append(aid)
        cleanup(lambda a=aid: T.moderation_audit_log.delete_item(Key={"audit_id": a}))
    trail = AM.get_ticket_audit_trail(tid, limit=100, _admin=ROOT)
    got_actions = [e.action for e in trail.items]
    check("MODX-20: ticket audit trail reads all 3 events", len([e for e in trail.items if e.ticket_id == tid]) >= 3, "actions=%s" % got_actions)
    by_actor = AM.get_audit_by_actor(actor=actor, limit=100, _admin=ROOT)
    check("MODX-20: actor audit filter returns this actor's events", len([e for e in by_actor.items if e.actor_user_id == actor]) >= 3, "n=%d" % len(by_actor.items))


# ─────────────────────────────── MODX-20: claim exclusivity ──────────────────
def test_claim_exclusive():
    tid = put_ticket("tk_%s_claim" % SUFFIX, status="open")
    a = nid("modA")
    b = nid("modB")
    claimed = AM.claim_moderation_ticket(tid, admin=AuthenticatedUser(sub=a, role=Role.ROOT))
    item = T.moderation_tickets.get_item(Key={"ticket_id": tid}).get("Item") or {}
    check("MODX-20: claim records assignee", str(item.get("assigned_admin_user_id")) == a, "assignee=%s" % item.get("assigned_admin_user_id"))
    check("MODX-20: claim records assigned_at (TTL basis)", AM._parse_int(item.get("assigned_at"), 0) > 0, "assigned_at=%s" % item.get("assigned_at"))

    # another moderator without steal -> 409 ticket_claimed_by_other
    blocked = False
    try:
        AM._enforce_claim(item, AuthenticatedUser(sub=b, role=Role.ROOT), steal=False)
    except Exception as exc:
        blocked = getattr(exc, "status_code", None) == 409
    check("MODX-20: a fresh claim blocks another moderator (409)", blocked, "steal=False")

    # same claimer passes
    ok_self = True
    try:
        AM._enforce_claim(item, AuthenticatedUser(sub=a, role=Role.ROOT), steal=False)
    except Exception:
        ok_self = False
    check("MODX-20: the claim owner is not blocked", ok_self, "self")

    # steal=true passes + records an audit steal
    ok_steal = True
    try:
        AM._enforce_claim(item, AuthenticatedUser(sub=b, role=Role.ROOT), steal=True)
    except Exception:
        ok_steal = False
    steal_audit = AM._query_audit("ByTicketCreatedAt", "ticket_id", tid, 10)
    cleanup(lambda: [T.moderation_audit_log.delete_item(Key={"audit_id": r.get("audit_id")}) for r in steal_audit])
    check("MODX-20: steal=true overrides + audits the takeover", ok_steal and any(r.get("action") == "ticket_claim_stolen" for r in steal_audit), "steal ok")

    # TTL-stale claim is free to act on
    stale = dict(item)
    stale["assigned_at"] = TS - AM.CLAIM_TTL_SECONDS - 60
    ok_stale = True
    try:
        AM._enforce_claim(stale, AuthenticatedUser(sub=b, role=Role.ROOT), steal=False)
    except Exception:
        ok_stale = False
    check("MODX-20: a TTL-stale claim auto-releases", ok_stale, "stale")


# ─────────────────────────────── MODX-19: ban roster + lift ──────────────────
def test_ban_management():
    uid = nid("banned")
    enf_id = "enf_%s_ban" % SUFFIX
    T.user_enforcement_history.put_item(Item={
        "user_id": uid, "enforcement_id": enf_id, "entity_type": "user_enforcement",
        "status": "active", "enforcement_type": "ban", "source_ticket_id": "tk_%s" % SUFFIX,
        "created_at": str(TS), "created_by_admin_user_id": "system", "duration_days": 0, "note": "verify ban",
    })
    cleanup(lambda: T.user_enforcement_history.delete_item(Key={"user_id": uid, "enforcement_id": enf_id}))
    POL.apply_ban(offender_user_id=uid, ticket_id="tk_%s" % SUFFIX, admin_user_id="system",
                  note="verify ban", duration_days=0)
    cleanup(lambda: T.account_state.delete_item(Key={"user_sub": uid}))
    cleanup(lambda: [T.alerts.delete_item(Key={"user_sub": uid, "alert_id": a.get("alert_id")})
                     for a in (T.alerts.query(KeyConditionExpression=Key("user_sub").eq(uid)).get("Items", []) if hasattr(T, "alerts") else [])])

    check("MODX-19: user is banned before lift", POL.is_user_currently_banned(uid), "pre-lift")
    roster = AM.list_moderation_bans(user=None, include_inactive=False, _admin=ROOT)
    entry = next((e for e in roster.items if e.user_id == uid), None)
    check("MODX-19: active ban appears on the roster", entry is not None and entry.active, "found=%s" % (entry is not None))
    check("MODX-19: roster marks a 0-day ban as permanent", entry is not None and entry.permanent, "permanent")

    out = AM.lift_moderation_ban(uid, AM.BanLiftIn(note="wrongful, appeal upheld"), admin=ROOT)
    check("MODX-19: lift closes the enforcement row", enf_id in out.lifted_enforcement_ids, "lifted=%s" % out.lifted_enforcement_ids)
    check("MODX-19: lift restores account to active (ban gate re-admits)", not POL.is_user_currently_banned(uid), "post-lift")
    enf_after = T.user_enforcement_history.get_item(Key={"user_id": uid, "enforcement_id": enf_id}).get("Item") or {}
    check("MODX-19: enforcement row status == lifted", str(enf_after.get("status")) == "lifted", "status=%s" % enf_after.get("status"))
    roster2 = AM.list_moderation_bans(user=None, include_inactive=False, _admin=ROOT)
    check("MODX-19: lifted ban drops from the active roster", not any(e.user_id == uid and e.active for e in roster2.items), "gone")
    lift_audit = AM.get_audit_by_actor(actor=ROOT.sub, limit=100, _admin=ROOT)
    check("MODX-19: lift writes a ban_lifted audit event", any(e.action == "ban_lifted" and e.target_user_id == uid for e in lift_audit.items), "audited")
    cleanup(lambda: [T.moderation_audit_log.delete_item(Key={"audit_id": e.audit_id}) for e in lift_audit.items if e.action == "ban_lifted"])


# ─────────────────────────────── MODX-22: bulk actions ───────────────────────
def test_bulk_actions():
    tids = []
    for i in range(3):
        owner = seed_reporter(nid("bulk_owner_%d" % i))
        pid = "postbulk_%d_%s" % (i, SUFFIX)
        seed_feed_post(owner, pid, "bulk body %d" % i)
        rep = seed_reporter(nid("bulk_rep_%d" % i))
        out = report("feed_post", pid, rep, ["spam"], post_id=pid)
        tids.append(out.ticket_id)
        c = case_for("feed_post", pid)
        cleanup(lambda cid=c.get("case_id"): T.moderation_cases.delete_item(Key={"case_id": cid}))
        cleanup(lambda t=out.ticket_id: T.moderation_tickets.delete_item(Key={"ticket_id": t}))
    bogus = "tk_%s_bogus" % SUFFIX
    res = AM.bulk_moderation_action(AM.BulkModerationIn(ticket_ids=tids + [bogus], action="dismiss", note="brigade sweep"), admin=ROOT)
    check("MODX-22: bulk returns a result per unique ticket", res.total == 4, "total=%d" % res.total)
    for r in res.results:
        if not r.ok:
            print("   bulk item", r.ticket_id, "code=%s err=%s" % (r.error_code, r.error))
    check("MODX-22: all 3 real tickets dismissed", res.succeeded == 3, "succeeded=%d" % res.succeeded)
    check("MODX-22: the bogus ticket fails with a per-item error (not fatal)",
          res.failed == 1 and any((not r.ok) and r.ticket_id == bogus for r in res.results), "failed=%d" % res.failed)
    dismissed_ok = all(any(r.ticket_id == t and r.ok for r in res.results) for t in tids)
    check("MODX-22: per-item outcomes carry the resulting state", dismissed_ok and all(r.state for r in res.results if r.ok), "states ok")


# ─────────────────────────────── CORE regression ─────────────────────────────
def test_core_lifecycle():
    owner = nid("core_owner")
    pid = "postcore_%s" % SUFFIX
    body = "core hold body %s" % SUFFIX
    seed_feed_post(owner, pid, body)
    rep = seed_reporter(nid("core_rep"))
    report("feed_post", pid, rep, ["hate"], post_id=pid)
    case = case_for("feed_post", pid)
    cleanup(lambda: T.moderation_cases.delete_item(Key={"case_id": case.get("case_id")}))
    check("CORE: report opens case under_review", str(case.get("state")) == "under_review", "state=%s" % case.get("state"))
    post = ddb.Table(APP_TABLE).get_item(Key={"pk": "POST#%s" % pid, "sk": "META"}).get("Item") or {}
    check("CORE: reported content is hidden", MH.is_hidden_flag(post), "hidden_after_report")

    LIFE.admin_confirm_hold(case=case, metadata=None, admin_user_id=nid("core_admin"), now_ts=TS + 1)
    case = case_for("feed_post", pid)
    check("CORE: confirm -> 30-day hold", str(case.get("state")) == "hold", "state=%s" % case.get("state"))

    LIFE.poster_respond(case_id=case.get("case_id"), owner_user_id=owner,
                        statement="please review, this is fine", now_ts=TS + 2)
    case = case_for("feed_post", pid)
    check("CORE: poster_respond -> awaiting_final", str(case.get("state")) == "awaiting_final", "state=%s" % case.get("state"))

    LIFE.admin_final_reinstate(case=case, metadata=None, admin_user_id=nid("core_admin"), now_ts=TS + 3)
    case = case_for("feed_post", pid)
    post = ddb.Table(APP_TABLE).get_item(Key={"pk": "POST#%s" % pid, "sk": "META"}).get("Item") or {}
    check("CORE: reinstate -> reinstated", str(case.get("state")) == "reinstated", "state=%s" % case.get("state"))
    check("CORE: reinstated content visible again", not MH.is_hidden_flag(post), "unhidden")
    check("CORE: body byte-for-byte intact", str(post.get("body")) == body, "body match")


def main():
    seed_topics()
    for fn in (test_kpi_excludes_holds, test_live_category_filters, test_audit_read,
               test_claim_exclusive, test_ban_management, test_bulk_actions, test_core_lifecycle):
        try:
            fn()
        except Exception as exc:
            check("%s raised" % fn.__name__, False, repr(exc))
    for fn in reversed(cleanups):
        try:
            fn()
        except Exception:
            pass
    passed = sum(1 for ok, _, _ in results if ok)
    total = len(results)
    print("\n==== WAVE-4 VERIFY: %d/%d PASSED ====" % (passed, total))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
