#!/usr/bin/env python3
"""MODX WAVE-4 backend re-apply helper (admin tooling at scale).

Idempotent, anchor-based in-place edits. Mirrors the dev-clone android-impl edits
byte-for-byte. Run from a testlogon checkout root (default ".") or pass a root:
    python3 apply_wave4.py [ROOT]

Every transform is guarded (marker check) so re-running is a no-op, and asserts its
anchor so a dry-run on a divergent tree fails loudly instead of silently skipping.

Tickets (backend portions):
  MODX-18  KPI trust (exclude parked holds from open/backlog/oldest sets, add
           on_hold_count) + real live-category ticket filter + reporting kill-switch
           for video/syndicate + read-only auto-hide-rules panel.
  MODX-19  ban management: GET /bans roster + POST /bans/{user}/lift.
  MODX-20  decision audit-trail read (GET /tickets/{id}/audit, GET /audit?actor=)
           + claim enforcement (assignee==caller or steal) + TTL auto-release +
           POST /tickets/{id}/unclaim (+ reassign).
  MODX-22  bulk triage: POST /tickets/bulk (per-item results).

Files patched:
  app/services/moderation_kpis.py       exclude parked holds; on_hold_count
  app/routers/admin_moderation.py       DTO + live-category filter + claim/audit/ban/bulk
  app/services/moderation_flags.py       video/syndicate reporting kill-switch
"""
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


def rf(p):
    with open(os.path.join(ROOT, p)) as f:
        return f.read()


def wf(p, s):
    with open(os.path.join(ROOT, p), "w") as f:
        f.write(s)


def sub(s, old, new, count=1):
    assert old in s, "ANCHOR MISSING: " + repr(old[:90])
    return s.replace(old, new, count)


NEW_ENDPOINTS = '''# ── MODX-19: ban management (active-enforcement roster + lift) ────────────────
class BanRosterEntryOut(BaseModel):
    user_id: str
    enforcement_id: str
    source_ticket_id: str = ""
    created_at: int = 0
    created_by_admin_user_id: str | None = None
    duration_days: int = 0
    ban_until: int = 0
    permanent: bool = False
    note: str = ""
    account_status: str = ""
    active: bool = True


class BanRosterOut(BaseModel):
    items: list[BanRosterEntryOut]
    next_cursor: str | None = None


def _active_ban_enforcements() -> list[dict[str, Any]]:
    """All active ban enforcement rows. Prefers the ByStatusCreatedAt GSI
    (status HASH) and falls back to a bounded scan if the index is unavailable."""
    rows: list[dict[str, Any]] = []
    esk = None
    try:
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": "ByStatusCreatedAt",
                "KeyConditionExpression": Key("status").eq("active"),
                "ScanIndexForward": False,
            }
            if esk:
                kwargs["ExclusiveStartKey"] = esk
            resp = T.user_enforcement_history.query(**kwargs)
            rows.extend(resp.get("Items", []))
            esk = resp.get("LastEvaluatedKey")
            if not esk:
                break
    except ClientError:
        rows = []
        esk = None
        for _ in range(20):
            kwargs = {"FilterExpression": Attr("status").eq("active")}
            if esk:
                kwargs["ExclusiveStartKey"] = esk
            resp = T.user_enforcement_history.scan(**kwargs)
            rows.extend(resp.get("Items", []))
            esk = resp.get("LastEvaluatedKey")
            if not esk:
                break
    return [
        r for r in rows
        if r.get("entity_type") == "user_enforcement" and str(r.get("enforcement_type")) == "ban"
    ]


def _ban_roster_entry(r: dict[str, Any], *, now: int) -> BanRosterEntryOut:
    uid = str(r.get("user_id") or "")
    acct: dict[str, Any] = {}
    try:
        acct = T.account_state.get_item(Key={"user_sub": uid}).get("Item") or {}
    except Exception:
        acct = {}
    acct_status = str(acct.get("status") or "")
    ban_until = _parse_int(acct.get("ban_until"), 0)
    currently_banned = acct_status in ("banned", "suspended") and (ban_until == 0 or now < ban_until)
    active = str(r.get("status") or "") == "active" and currently_banned
    return BanRosterEntryOut(
        user_id=uid,
        enforcement_id=str(r.get("enforcement_id") or ""),
        source_ticket_id=str(r.get("source_ticket_id") or ""),
        created_at=_parse_int(r.get("created_at"), 0),
        created_by_admin_user_id=str(r.get("created_by_admin_user_id") or "") or None,
        duration_days=_parse_int(r.get("duration_days"), 0),
        ban_until=ban_until,
        permanent=bool(acct_status in ("banned", "suspended") and ban_until == 0),
        note=str(r.get("note") or acct.get("ban_note") or ""),
        account_status=acct_status,
        active=active,
    )


@router.get("/bans", response_model=BanRosterOut)
def list_moderation_bans(
    user: str | None = Query(default=None),
    include_inactive: bool = Query(default=False),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> BanRosterOut:
    """MODX-19 (D4): active-ban roster. ``?user=`` returns that user's full ban
    history (active + lifted/expired); the default roster returns only currently
    active bans."""
    ensure_admin_board_enabled(_admin)
    now = int(time.time())
    if user:
        rows = [
            r for r in _query_enforcement_history_by_offender(str(user))
            if str(r.get("enforcement_type")) == "ban"
        ]
    else:
        rows = _active_ban_enforcements()
    entries = [_ban_roster_entry(r, now=now) for r in rows]
    if not user and not include_inactive:
        entries = [e for e in entries if e.active]
    entries.sort(key=lambda e: e.created_at, reverse=True)
    return BanRosterOut(items=entries, next_cursor=None)


class BanLiftIn(BaseModel):
    note: str | None = Field(default=None, max_length=2000)
    enforcement_id: str | None = Field(default=None, max_length=128)


class BanLiftOut(BaseModel):
    ok: bool
    user_id: str
    account_status: str
    lifted_enforcement_ids: list[str] = Field(default_factory=list)


@router.post("/bans/{user_id}/lift", response_model=BanLiftOut)
def lift_moderation_ban(
    user_id: str,
    inp: BanLiftIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> BanLiftOut:
    """MODX-19 (D4): reverse a wrongful/permanent ban. Sets account_state back to
    ``active`` (fail-closed ban gate re-admits the user), closes the matching active
    ban enforcement row(s) as ``lifted``, writes an audit event, notifies the user.
    Idempotent."""
    ensure_admin_actions_enabled(admin)
    uid = str(user_id or "").strip()
    if not uid:
        raise HTTPException(status_code=400, detail="user_id required")
    now = str(int(time.time()))
    acct: dict[str, Any] = {}
    try:
        acct = T.account_state.get_item(Key={"user_sub": uid}).get("Item") or {}
    except Exception:
        acct = {}
    T.account_state.put_item(
        Item={
            "user_sub": uid,
            "status": "active",
            "updated_at": int(time.time()),
            "reason": "moderation_ban_lifted",
            "requested_by": admin.sub,
            "ban_until": 0,
            "lifted_at": int(time.time()),
            "lifted_by_admin_user_id": admin.sub,
            "ban_note": str(inp.note or acct.get("ban_note") or "")[:500],
        }
    )
    rows = [
        r for r in _query_enforcement_history_by_offender(uid)
        if str(r.get("enforcement_type")) == "ban" and str(r.get("status")) == "active"
    ]
    if inp.enforcement_id:
        rows = [r for r in rows if str(r.get("enforcement_id")) == str(inp.enforcement_id)]
    lifted: list[str] = []
    for r in rows:
        enf_id = str(r.get("enforcement_id") or "")
        if not enf_id:
            continue
        try:
            T.user_enforcement_history.update_item(
                Key={"user_id": uid, "enforcement_id": enf_id},
                UpdateExpression="SET #s = :lifted, #la = :now, #lb = :admin",
                ExpressionAttributeNames={"#s": "status", "#la": "lifted_at", "#lb": "lifted_by_admin_user_id"},
                ExpressionAttributeValues={":lifted": "lifted", ":now": now, ":admin": admin.sub},
            )
            lifted.append(enf_id)
        except Exception:
            pass
    write_moderation_audit_event(
        action="ban_lifted",
        actor_user_id=admin.sub,
        target_user_id=uid,
        metadata={"lifted_enforcement_ids": lifted, "note": str(inp.note or "")[:500]},
    )
    try:
        from app.services.alerts import write_alert
        write_alert(
            uid,
            event="moderation_ban_lifted",
            outcome="resolved",
            title="Account restriction lifted",
            details={"action": "ban_lifted", "note": str(inp.note or "")[:500]},
        )
    except Exception:
        pass
    return BanLiftOut(ok=True, user_id=uid, account_status="active", lifted_enforcement_ids=lifted)


# ── MODX-20: decision audit-trail read ───────────────────────────────────────
class AuditEventOut(BaseModel):
    audit_id: str
    action: str
    actor_user_id: str
    ticket_id: str = ""
    content_type: str = ""
    content_id: str = ""
    target_user_id: str = ""
    created_at: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditTrailOut(BaseModel):
    items: list[AuditEventOut]


def _project_audit(row: dict[str, Any]) -> AuditEventOut:
    return AuditEventOut(
        audit_id=str(row.get("audit_id") or ""),
        action=str(row.get("action") or ""),
        actor_user_id=str(row.get("actor_user_id") or ""),
        ticket_id=str(row.get("ticket_id") or ""),
        content_type=str(row.get("content_type") or ""),
        content_id=str(row.get("content_id") or ""),
        target_user_id=str(row.get("target_user_id") or ""),
        created_at=_parse_int(row.get("created_at"), 0),
        metadata=(row.get("metadata") if isinstance(row.get("metadata"), dict) else {}),
    )


def _query_audit(index_name: str, key_attr: str, key_val: str, limit: int) -> list[dict[str, Any]]:
    try:
        resp = T.moderation_audit_log.query(
            IndexName=index_name,
            KeyConditionExpression=Key(key_attr).eq(key_val),
            ScanIndexForward=False,
            Limit=limit,
        )
        rows = resp.get("Items", [])
    except ClientError:
        rows = []
    rows.sort(key=lambda r: _parse_int(r.get("created_at"), 0), reverse=True)
    return rows[:limit]


@router.get("/tickets/{ticket_id}/audit", response_model=AuditTrailOut)
def get_ticket_audit_trail(
    ticket_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> AuditTrailOut:
    """MODX-20 (D6): who/when/why decision timeline for one ticket."""
    ensure_admin_board_enabled(_admin)
    rows = _query_audit("ByTicketCreatedAt", "ticket_id", ticket_id, limit)
    return AuditTrailOut(items=[_project_audit(r) for r in rows])


@router.get("/audit", response_model=AuditTrailOut)
def get_audit_by_actor(
    actor: str = Query(...),
    limit: int = Query(default=100, ge=1, le=200),
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> AuditTrailOut:
    """MODX-20 (D6): every moderation action taken by one moderator."""
    ensure_admin_board_enabled(_admin)
    rows = _query_audit("ByActorCreatedAt", "actor_user_id", actor, limit)
    return AuditTrailOut(items=[_project_audit(r) for r in rows])


# ── MODX-20: unclaim / reassign ──────────────────────────────────────────────
@router.post("/tickets/{ticket_id}/unclaim", response_model=ModerationTicketOut)
def unclaim_moderation_ticket(
    ticket_id: str,
    reassign_to: str | None = Query(default=None),
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> ModerationTicketOut:
    """MODX-20 (D8): release a claim (or hand it to another moderator) so an
    abandoned claim never wedges the assignee filter."""
    ensure_admin_actions_enabled(admin)
    ticket_item = _get_ticket_or_404(ticket_id)
    assignee = str(ticket_item.get("assigned_admin_user_id") or "")
    new_assignee = str(reassign_to or "").strip()
    now = int(time.time())
    if new_assignee:
        T.moderation_tickets.update_item(
            Key={"ticket_id": ticket_id},
            UpdateExpression="SET assigned_admin_user_id = :a, assigned_at = :now, updated_at = :nows",
            ExpressionAttributeValues={":a": new_assignee, ":now": now, ":nows": str(now)},
        )
        action, meta = "ticket_reassigned", {"from": assignee, "to": new_assignee}
    else:
        T.moderation_tickets.update_item(
            Key={"ticket_id": ticket_id},
            UpdateExpression="REMOVE assigned_admin_user_id, assigned_at SET updated_at = :nows",
            ExpressionAttributeValues={":nows": str(now)},
        )
        action, meta = "ticket_unassigned", {"from": assignee}
    write_moderation_audit_event(action=action, actor_user_id=admin.sub, ticket_id=ticket_id, metadata=meta)
    return _to_ticket_out(_get_ticket_or_404(ticket_id))


# ── MODX-22: bulk triage actions ─────────────────────────────────────────────
class BulkModerationIn(BaseModel):
    ticket_ids: list[str] = Field(default_factory=list, max_length=100)
    action: Literal["dismiss", "confirm", "reinstate", "delete"]
    note: str | None = Field(default=None, max_length=2000)
    steal: bool = False


class BulkItemResultOut(BaseModel):
    ticket_id: str
    ok: bool
    state: str | None = None
    error_code: str | None = None
    error: str | None = None


class BulkModerationOut(BaseModel):
    action: str
    total: int
    succeeded: int
    failed: int
    results: list[BulkItemResultOut]


@router.post("/tickets/bulk", response_model=BulkModerationOut)
def bulk_moderation_action(
    inp: BulkModerationIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> BulkModerationOut:
    """MODX-22 (D11): apply one triage action to many tickets, returning a per-item
    outcome. Each item runs the SAME guarded state-machine path as the single-ticket
    endpoints, so a brigade wave can be cleared in one call without losing per-item
    correctness (illegal-state / claimed / conflict errors are reported, not fatal)."""
    ensure_admin_actions_enabled(admin)
    seen: set[str] = set()
    uniq: list[str] = []
    for t in (inp.ticket_ids or []):
        tid = str(t).strip()
        if tid and tid not in seen:
            seen.add(tid)
            uniq.append(tid)
    results: list[BulkItemResultOut] = []
    for tid in uniq:
        try:
            if inp.action == "dismiss":
                r = dismiss_moderation_case(tid, steal=inp.steal, admin=admin)
            elif inp.action == "confirm":
                r = confirm_moderation_case(tid, steal=inp.steal, admin=admin)
            elif inp.action == "reinstate":
                r = final_call_moderation_case(tid, _FinalCallIn(action="reinstate", note=inp.note), steal=inp.steal, admin=admin)
            else:  # delete
                r = final_call_moderation_case(tid, _FinalCallIn(action="delete", note=inp.note), steal=inp.steal, admin=admin)
            results.append(BulkItemResultOut(ticket_id=tid, ok=True, state=getattr(r, "state", None)))
        except HTTPException as exc:
            code = None
            detail = exc.detail
            if isinstance(detail, dict):
                code = str(detail.get("code") or "") or None
                msg = str(detail.get("message") or detail)
            else:
                msg = str(detail)
            results.append(BulkItemResultOut(ticket_id=tid, ok=False, error_code=code, error=msg))
        except Exception as exc:  # noqa: BLE001
            results.append(BulkItemResultOut(ticket_id=tid, ok=False, error=str(exc)))
    succeeded = sum(1 for r in results if r.ok)
    return BulkModerationOut(
        action=inp.action,
        total=len(uniq),
        succeeded=succeeded,
        failed=len(uniq) - succeeded,
        results=results,
    )


# ── MODX-18 (D16): read-only auto-hide rules panel ───────────────────────────
class AutoHideRulesOut(BaseModel):
    severe_categories: list[str]
    lower_categories: list[str]
    illegal_categories: list[str]
    lower_hide_distinct_reporter_threshold: int
    severe_distinct_reporter_floor: int
    velocity_burst_min: int
    new_account_age_seconds: int
    protected_account_age_seconds: int
    hold_window_seconds: int


@router.get("/auto-hide-rules", response_model=AutoHideRulesOut)
def get_auto_hide_rules(
    _admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> AutoHideRulesOut:
    """MODX-18 (D16): surface the (currently hardcoded) auto-hide thresholds so an
    operator can see WHY content auto-hid instead of guessing."""
    ensure_admin_board_enabled(_admin)
    from app.services import moderation_case as _mc
    return AutoHideRulesOut(
        severe_categories=sorted(_mc.SEVERE_CATEGORIES),
        lower_categories=sorted(_mc.LOWER_CATEGORIES),
        illegal_categories=sorted(_mc.ILLEGAL_CATEGORIES),
        lower_hide_distinct_reporter_threshold=int(_mc.LOWER_HIDE_THRESHOLD),
        severe_distinct_reporter_floor=int(_mc.SEVERE_DISTINCT_FLOOR),
        velocity_burst_min=int(_mc.VELOCITY_BURST_MIN),
        new_account_age_seconds=int(_mc.NEW_ACCOUNT_AGE_SECONDS),
        protected_account_age_seconds=int(_mc.PROTECTED_ACCOUNT_AGE_SECONDS),
        hold_window_seconds=int(_mc.HOLD_WINDOW_SECONDS),
    )
'''


# ────────────────────────────────────────────────────────────────────────────
# 1) moderation_kpis.py — MODX-18 (D3): parked holds are not un-triaged backlog.
# ────────────────────────────────────────────────────────────────────────────
KPI = "app/services/moderation_kpis.py"
k = rf(KPI)
if "_PARKED_CASE_STATES" not in k:
    k = sub(
        k,
        '    open_tickets = [row for row in tickets if str(row.get("status") or "") == "open"]\n'
        '    critical_open = [row for row in open_tickets if str(row.get("priority") or "").lower() == "critical"]\n',
        '    # MODX-18 (D3): a confirmed 30-day hold (and awaiting_final) keeps the ticket\n'
        '    # status="open" so the poster hold clock keeps ticking, but it is PARKED work,\n'
        '    # not un-triaged backlog. Excluding those case-states from the open/backlog/\n'
        '    # oldest-age KPI sets stops parked holds paging on-call and drowning real SLA\n'
        '    # breaches; they are surfaced separately as on_hold_count.\n'
        '    _PARKED_CASE_STATES = {"hold", "awaiting_final"}\n'
        '    raw_open_tickets = [row for row in tickets if str(row.get("status") or "") == "open"]\n'
        '    on_hold_tickets = [\n'
        '        row for row in raw_open_tickets\n'
        '        if str(row.get("moderation_case_state") or "").lower() in _PARKED_CASE_STATES\n'
        '    ]\n'
        '    open_tickets = [\n'
        '        row for row in raw_open_tickets\n'
        '        if str(row.get("moderation_case_state") or "").lower() not in _PARKED_CASE_STATES\n'
        '    ]\n'
        '    critical_open = [row for row in open_tickets if str(row.get("priority") or "").lower() == "critical"]\n',
    )
    k = sub(
        k,
        '        "oldest_open_age_minutes": oldest_open_age_minutes,\n'
        '        "extortion_criminal_reports_window_count": len(surge_reports),\n',
        '        "oldest_open_age_minutes": oldest_open_age_minutes,\n'
        '        "on_hold_count": len(on_hold_tickets),\n'
        '        "extortion_criminal_reports_window_count": len(surge_reports),\n',
    )
    wf(KPI, k)
    print("patched", KPI)
else:
    print("skip (already patched)", KPI)


# ────────────────────────────────────────────────────────────────────────────
# 2) moderation_flags.py — MODX-18 (D15): video/syndicate reporting kill-switch.
# ────────────────────────────────────────────────────────────────────────────
FLAGS = "app/services/moderation_flags.py"
f = rf(FLAGS)
if "report_video_enabled" not in f:
    f = sub(
        f,
        '    if ctype in ("story", "clip") and not bool(flags.get("report_ephemeral_enabled", True)):\n'
        '        raise HTTPException(status_code=403, detail="ephemeral reporting is disabled")\n',
        '    if ctype in ("story", "clip") and not bool(flags.get("report_ephemeral_enabled", True)):\n'
        '        raise HTTPException(status_code=403, detail="ephemeral reporting is disabled")\n'
        '    # MODX-18 (D15): the remaining content classes get their own incident kill-switch.\n'
        '    if ctype in ("video", "video_comment") and not bool(flags.get("report_video_enabled", True)):\n'
        '        raise HTTPException(status_code=403, detail="video reporting is disabled")\n'
        '    if ctype == "syndicate_post" and not bool(flags.get("report_syndicate_enabled", True)):\n'
        '        raise HTTPException(status_code=403, detail="syndicate reporting is disabled")\n',
    )
    wf(FLAGS, f)
    print("patched", FLAGS)
else:
    print("skip (already patched)", FLAGS)


# ────────────────────────────────────────────────────────────────────────────
# 3) admin_moderation.py
# ────────────────────────────────────────────────────────────────────────────
AM = "app/routers/admin_moderation.py"
a = rf(AM)

# 3a) MODX-18: on_hold_count on the KPI DTO.
if "on_hold_count: int = 0" not in a:
    a = sub(
        a,
        "    open_ticket_count: int\n"
        "    critical_backlog: int\n"
        "    oldest_open_age_minutes: int\n"
        "    extortion_criminal_reports_window_count: int\n",
        "    open_ticket_count: int\n"
        "    critical_backlog: int\n"
        "    oldest_open_age_minutes: int\n"
        "    on_hold_count: int = 0\n"
        "    extortion_criminal_reports_window_count: int\n",
    )

# 3b) MODX-18 (D5): live-category synonym map + helper (module scope, after POLICY_CATEGORY_RANK).
if "_CATEGORY_SYNONYMS" not in a:
    a = sub(
        a,
        'POLICY_CATEGORY_RANK = {"spam": 1, "sexual": 2, "racist": 2, "criminal": 3, "extortion": 4}\n',
        'POLICY_CATEGORY_RANK = {"spam": 1, "sexual": 2, "racist": 2, "criminal": 3, "extortion": 4}\n'
        '\n'
        '# MODX-18 (D5): live 6-category taxonomy (+ illegal lane) with the legacy report\n'
        '# topics accepted as server-side synonyms, so filtering by either the new\n'
        '# canonical category or the historical topic returns the same tickets.\n'
        '_CATEGORY_SYNONYMS: dict[str, set[str]] = {\n'
        '    "sexual": {"sexual"},\n'
        '    "violence_threats": {"violence_threats", "criminal"},\n'
        '    "hate": {"hate", "racist"},\n'
        '    "harassment": {"harassment", "extortion"},\n'
        '    "spam": {"spam"},\n'
        '    "other": {"other"},\n'
        '    "illegal": {"illegal", "csam"},\n'
        '    "criminal": {"violence_threats", "criminal"},\n'
        '    "racist": {"hate", "racist"},\n'
        '    "extortion": {"harassment", "extortion"},\n'
        '    "csam": {"illegal", "csam"},\n'
        '}\n'
        '\n'
        '\n'
        'def _topic_match_set(topic: str | None) -> set[str]:\n'
        '    if not topic:\n'
        '        return set()\n'
        '    return _CATEGORY_SYNONYMS.get(topic, {topic})\n'
        '\n'
        '\n'
        'CLAIM_TTL_SECONDS = 30 * 60  # MODX-20 (D8): stale claims auto-release after 30 min.\n',
    )

# 3c) MODX-18: widen the topic Literal to the live set + legacy synonyms.
if 'topic: Literal[\n' not in a:
    a = sub(
        a,
        '    topic: Literal["sexual", "extortion", "criminal", "spam", "racist"] | None = Query(default=None),\n',
        '    topic: Literal[\n'
        '        "sexual", "violence_threats", "hate", "spam", "harassment", "other", "illegal",\n'
        '        "extortion", "criminal", "racist", "csam",\n'
        '    ] | None = Query(default=None),\n',
    )

# 3d) MODX-18: filter by the live-category synonym set (drops the dead single-value contains()).
if "_topic_match_set(topic)" not in a:
    a = sub(
        a,
        '        if topic and index_name != "ByLatestReportAt":\n'
        '            query_kwargs["FilterExpression"] = Attr("aggregated_topics").contains(topic)\n'
        '\n'
        '        resp = T.moderation_tickets.query(**query_kwargs)\n'
        '        items = [i for i in resp.get("Items", []) if i.get("entity_type") == "moderation_ticket"]\n'
        '\n'
        '        if topic and index_name == "ByLatestReportAt":\n'
        '            items = [i for i in items if topic in set(i.get("aggregated_topics") or [])]\n',
        '        resp = T.moderation_tickets.query(**query_kwargs)\n'
        '        items = [i for i in resp.get("Items", []) if i.get("entity_type") == "moderation_ticket"]\n'
        '\n'
        '        # MODX-18 (D5): match against the live category AND its legacy synonyms.\n'
        '        if topic:\n'
        '            _match = _topic_match_set(topic)\n'
        '            items = [\n'
        '                i for i in items\n'
        '                if _match & {str(v) for v in (i.get("aggregated_topics") or [])}\n'
        '            ]\n',
    )

# 3e) MODX-20: claim enforcement helpers (after _get_ticket_or_404).
if "_enforce_claim" not in a:
    a = sub(
        a,
        '    if not item or item.get("entity_type") != "moderation_ticket":\n'
        '        raise HTTPException(status_code=404, detail="ticket not found")\n'
        '    return item\n',
        '    if not item or item.get("entity_type") != "moderation_ticket":\n'
        '        raise HTTPException(status_code=404, detail="ticket not found")\n'
        '    return item\n'
        '\n'
        '\n'
        'def _claim_is_active(ticket_item: Dict[str, Any], *, now: int | None = None) -> bool:\n'
        '    """A ticket is EXCLUSIVELY claimed only when a moderator claimed it through\n'
        '    the claim endpoint (which stamps assigned_at). A bare assigned_admin_user_id\n'
        '    with no claim timestamp (auto/legacy triage assignment) is NOT an exclusive\n'
        '    claim, and a claim older than the TTL auto-releases."""\n'
        '    assignee = str(ticket_item.get("assigned_admin_user_id") or "")\n'
        '    if not assignee:\n'
        '        return False\n'
        '    assigned_at = _parse_int(ticket_item.get("assigned_at"), 0)\n'
        '    if assigned_at <= 0:\n'
        '        return False  # MODX-20 (D8): assignment without a claim stamp is not a lock.\n'
        '    now = int(now or time.time())\n'
        '    if (now - assigned_at) > CLAIM_TTL_SECONDS:\n'
        '        return False  # MODX-20 (D8): stale claim -> treated as released.\n'
        '    return True\n'
        '\n'
        '\n'
        'def _enforce_claim(ticket_item: Dict[str, Any], admin: AuthenticatedUser, *, steal: bool = False) -> None:\n'
        '    """MODX-20 (D8): a fresh claim reserves the ticket for its assignee. Another\n'
        '    moderator must pass steal=true to act on it (recorded as an audit steal). An\n'
        '    unassigned or TTL-expired (stale) claim is free to act on."""\n'
        '    assignee = str(ticket_item.get("assigned_admin_user_id") or "")\n'
        '    if not _claim_is_active(ticket_item):\n'
        '        return\n'
        '    if assignee == admin.sub:\n'
        '        return\n'
        '    if steal:\n'
        '        write_moderation_audit_event(\n'
        '            action="ticket_claim_stolen",\n'
        '            actor_user_id=admin.sub,\n'
        '            ticket_id=str(ticket_item.get("ticket_id") or ""),\n'
        '            metadata={"previous_assignee": assignee},\n'
        '        )\n'
        '        return\n'
        '    raise HTTPException(\n'
        '        status_code=409,\n'
        '        detail={\n'
        '            "code": "ticket_claimed_by_other",\n'
        '            "assigned_admin_user_id": assignee,\n'
        '            "message": "ticket is claimed by another moderator; retry with steal=true to take it over",\n'
        '        },\n'
        '    )\n',
    )

# 3f) MODX-20: record assigned_at on claim so the TTL can measure staleness.
if '"#assigned_at": "assigned_at"' not in a:
    a = sub(
        a,
        '        UpdateExpression="SET #assigned_admin_user_id = :admin_sub, #updated_at = :updated_at",\n'
        '        ExpressionAttributeNames={\n'
        '            "#status": "status",\n'
        '            "#assigned_admin_user_id": "assigned_admin_user_id",\n'
        '            "#updated_at": "updated_at",\n'
        '        },\n'
        '        ExpressionAttributeValues={\n'
        '            ":open": "open",\n'
        '            ":admin_sub": admin.sub,\n'
        '            ":updated_at": str(int(time.time())),\n'
        '        },\n',
        '        UpdateExpression="SET #assigned_admin_user_id = :admin_sub, #assigned_at = :now, #updated_at = :now",\n'
        '        ExpressionAttributeNames={\n'
        '            "#status": "status",\n'
        '            "#assigned_admin_user_id": "assigned_admin_user_id",\n'
        '            "#assigned_at": "assigned_at",\n'
        '            "#updated_at": "updated_at",\n'
        '        },\n'
        '        ExpressionAttributeValues={\n'
        '            ":open": "open",\n'
        '            ":admin_sub": admin.sub,\n'
        '            ":now": int(time.time()),\n'
        '        },\n',
    )

# 3g) MODX-20: thread steal + claim enforcement into the state-machine action endpoints.
if "def dismiss_moderation_case(\n    ticket_id: str,\n    admin:" in a:
    a = sub(
        a,
        'def dismiss_moderation_case(\n'
        '    ticket_id: str,\n'
        '    admin: AuthenticatedUser = Depends(require_content_moderation_admin),\n'
        ') -> _CaseActionOut:\n'
        '    ensure_admin_actions_enabled(admin)\n'
        '    from app.services import moderation_lifecycle as _life\n'
        '    ticket, case, meta = _modab_case_and_meta(ticket_id)\n',
        'def dismiss_moderation_case(\n'
        '    ticket_id: str,\n'
        '    steal: bool = Query(default=False),\n'
        '    admin: AuthenticatedUser = Depends(require_content_moderation_admin),\n'
        ') -> _CaseActionOut:\n'
        '    ensure_admin_actions_enabled(admin)\n'
        '    from app.services import moderation_lifecycle as _life\n'
        '    ticket, case, meta = _modab_case_and_meta(ticket_id)\n'
        '    _enforce_claim(ticket, admin, steal=steal)\n',
    )
if "def confirm_moderation_case(\n    ticket_id: str,\n    admin:" in a:
    a = sub(
        a,
        'def confirm_moderation_case(\n'
        '    ticket_id: str,\n'
        '    admin: AuthenticatedUser = Depends(require_content_moderation_admin),\n'
        ') -> _CaseActionOut:\n'
        '    ensure_admin_actions_enabled(admin)\n'
        '    from app.services import moderation_lifecycle as _life\n'
        '    ticket, case, meta = _modab_case_and_meta(ticket_id)\n',
        'def confirm_moderation_case(\n'
        '    ticket_id: str,\n'
        '    steal: bool = Query(default=False),\n'
        '    admin: AuthenticatedUser = Depends(require_content_moderation_admin),\n'
        ') -> _CaseActionOut:\n'
        '    ensure_admin_actions_enabled(admin)\n'
        '    from app.services import moderation_lifecycle as _life\n'
        '    ticket, case, meta = _modab_case_and_meta(ticket_id)\n'
        '    _enforce_claim(ticket, admin, steal=steal)\n',
    )
if "    inp: _FinalCallIn,\n    admin: AuthenticatedUser = Depends(require_content_moderation_admin),\n) -> _CaseActionOut:" in a:
    a = sub(
        a,
        '    inp: _FinalCallIn,\n'
        '    admin: AuthenticatedUser = Depends(require_content_moderation_admin),\n'
        ') -> _CaseActionOut:\n'
        '    ensure_admin_actions_enabled(admin)\n'
        '    from app.services import moderation_lifecycle as _life\n'
        '    from app.services import moderation_reporter_reputation as _rep\n'
        '    from app.services import moderation_case as _mc\n'
        '    ticket, case, meta = _modab_case_and_meta(ticket_id)\n',
        '    inp: _FinalCallIn,\n'
        '    steal: bool = Query(default=False),\n'
        '    admin: AuthenticatedUser = Depends(require_content_moderation_admin),\n'
        ') -> _CaseActionOut:\n'
        '    ensure_admin_actions_enabled(admin)\n'
        '    from app.services import moderation_lifecycle as _life\n'
        '    from app.services import moderation_reporter_reputation as _rep\n'
        '    from app.services import moderation_case as _mc\n'
        '    ticket, case, meta = _modab_case_and_meta(ticket_id)\n'
        '    _enforce_claim(ticket, admin, steal=steal)\n',
    )

# 3h) NEW endpoints appended at end of file (ban mgmt / audit / unclaim / bulk / rules).
if "MODX-19: ban management" not in a:
    a = a.rstrip() + "\n\n\n" + NEW_ENDPOINTS

wf(AM, a)
print("patched", AM)
print("WAVE-4 backend apply complete.")
