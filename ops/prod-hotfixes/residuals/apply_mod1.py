#!/usr/bin/env python3
"""MOD-1: OFFENDER GSI (ByOffenderCreatedAt = user_id HASH + created_at RANGE) on
user_enforcement_history. The index hashes on the EXISTING user_id attribute (the
offender), so every row auto-indexes -- no new attribute, no backfill, and enforcement
writes never touch a not-yet-ACTIVE index key. Patches admin_moderation.py: add the
complete GSI query fn (GSI-preferred, complete base-table fallback), rewire the offender
summary / prior-history / admin endpoint to it, + total_enforcements. Idempotent, anchored.
Run: python apply_mod1.py [ROOT]
"""
import sys, os
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()


def patch(path, edits):
    fp = os.path.join(ROOT, path)
    src = open(fp, encoding="utf-8").read()
    orig = src
    for tag, old, new in edits:
        if new in src and old not in src:
            print("  SKIP %s (already applied)" % tag)
            continue
        if old not in src:
            print("  !! ANCHOR MISSING %s" % tag)
            raise SystemExit(2)
        cnt = src.count(old)
        if cnt != 1:
            print("  !! ANCHOR NOT UNIQUE (%d) %s" % (cnt, tag))
            raise SystemExit(2)
        src = src.replace(old, new)
        print("  OK   %s" % tag)
    if src != orig:
        open(fp, "w", encoding="utf-8").write(src)
        print("WROTE %s" % path)
    else:
        print("NOCHG %s" % path)


AM = "app/routers/admin_moderation.py"

AM_MODEL_OLD = '''class OffenderHistorySummaryOut(BaseModel):
    offender_user_id: str | None = None
    total_tickets: int = 0
    open_tickets: int = 0
    total_reports: int = 0'''
AM_MODEL_NEW = AM_MODEL_OLD + '''
    total_enforcements: int = 0  # MOD-1: precise count of ALL enforcement records'''

AM_FN_OLD = '''    out.sort(key=lambda i: (int(i.get("created_at") or 0), str(i.get("enforcement_id") or "")), reverse=True)
    return out[:limit]


def _prior_enforcement_history(offender_user_id: str | None) -> list[dict[str, Any]]:
    if not offender_user_id:
        return []
    return _query_enforcement_history(offender_user_id, limit=25)'''
AM_FN_NEW = '''    out.sort(key=lambda i: (int(i.get("created_at") or 0), str(i.get("enforcement_id") or "")), reverse=True)
    return out[:limit]


def _project_enforcement_row(row: dict[str, Any], fallback_user_id: str) -> dict[str, Any]:
    return {
        "user_id": str(row.get("user_id") or fallback_user_id),
        "enforcement_id": str(row.get("enforcement_id") or ""),
        "enforcement_type": str(row.get("enforcement_type") or ""),
        "status": str(row.get("status") or ""),
        "source_ticket_id": str(row.get("source_ticket_id") or ""),
        "created_at": _parse_int(row.get("created_at"), 0),
        "created_by_admin_user_id": str(row.get("created_by_admin_user_id") or "") or None,
        "duration_days": _parse_int(row.get("duration_days"), 0),
        "note": str(row.get("note") or ""),
    }


def _query_enforcement_history_by_offender(offender_user_id: str, *, cap: int | None = None) -> list[dict[str, Any]]:
    """MOD-1: COMPLETE query of ALL enforcement records for an offender. Prefers the
    ByOffenderCreatedAt GSI (user_id HASH -- the offender -- + created_at RANGE, so the
    DB returns them newest-first); falls back to a COMPLETE paginated base-table Query
    (also keyed on user_id) whenever the index is not queryable, so the admin offender
    summary counts are ALWAYS precise -- never Limit-truncated like the old bounded
    query, and never dependent on index availability."""
    if not offender_user_id:
        return []
    raw_rows: list[dict[str, Any]] = []
    try:
        exclusive_start_key: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": "ByOffenderCreatedAt",
                "KeyConditionExpression": Key("user_id").eq(offender_user_id),
                "ScanIndexForward": False,
            }
            if exclusive_start_key:
                kwargs["ExclusiveStartKey"] = exclusive_start_key
            resp = T.user_enforcement_history.query(**kwargs)
            raw_rows.extend(resp.get("Items", []))
            exclusive_start_key = resp.get("LastEvaluatedKey")
            if not exclusive_start_key:
                break
    except ClientError:
        # Index missing / not ACTIVE -> COMPLETE base-table query (user_id is the HASH
        # key, so this returns every enforcement record for the offender).
        raw_rows = []
        exclusive_start_key = None
        while True:
            kwargs = {"KeyConditionExpression": Key("user_id").eq(offender_user_id)}
            if exclusive_start_key:
                kwargs["ExclusiveStartKey"] = exclusive_start_key
            resp = T.user_enforcement_history.query(**kwargs)
            raw_rows.extend(resp.get("Items", []))
            exclusive_start_key = resp.get("LastEvaluatedKey")
            if not exclusive_start_key:
                break
    out: list[dict[str, Any]] = [
        _project_enforcement_row(row, offender_user_id)
        for row in raw_rows
        if row.get("entity_type") == "user_enforcement"
    ]
    out.sort(key=lambda i: (int(i.get("created_at") or 0), str(i.get("enforcement_id") or "")), reverse=True)
    return out[:cap] if cap else out


def _prior_enforcement_history(offender_user_id: str | None) -> list[dict[str, Any]]:
    if not offender_user_id:
        return []
    return _query_enforcement_history_by_offender(offender_user_id, cap=25)'''

AM_SUM_OLD = '''    # MOD-F1: replaced the unbounded full-table moderation_tickets scan with a
    # bounded Key query on user_enforcement_history (keyed by user_id). The
    # offender's prior tickets are the distinct source tickets that produced an
    # enforcement record; "open" counts currently-active enforcements.
    history = _query_enforcement_history(offender_user_id, limit=100)
    distinct_tickets = {str(h.get("source_ticket_id") or "") for h in history if h.get("source_ticket_id")}
    active_enforcements = sum(
        1 for h in history if str(h.get("status") or "").lower() in ("active", "banned", "open")
    )

    return OffenderHistorySummaryOut(
        offender_user_id=offender_user_id,
        total_tickets=len(distinct_tickets),
        open_tickets=active_enforcements,
        total_reports=len(reports),
    )'''
AM_SUM_NEW = '''    # MOD-1: COMPLETE indexed query over the ByOffenderCreatedAt GSI -- EVERY
    # enforcement record for the offender, not a Limit-bounded base-table page --
    # so total_tickets (distinct source tickets), open_tickets (active
    # enforcements) and total_enforcements are PRECISE counts.
    history = _query_enforcement_history_by_offender(offender_user_id)
    distinct_tickets = {str(h.get("source_ticket_id") or "") for h in history if h.get("source_ticket_id")}
    active_enforcements = sum(
        1 for h in history if str(h.get("status") or "").lower() in ("active", "banned", "open")
    )

    return OffenderHistorySummaryOut(
        offender_user_id=offender_user_id,
        total_tickets=len(distinct_tickets),
        open_tickets=active_enforcements,
        total_reports=len(reports),
        total_enforcements=len(history),
    )'''

AM_EP_OLD = '''    ensure_admin_board_enabled(_admin)
    items = _query_enforcement_history(user_id, limit=limit)
    return UserEnforcementHistoryListOut(items=[UserEnforcementHistoryOut(**row) for row in items])'''
AM_EP_NEW = '''    ensure_admin_board_enabled(_admin)
    items = _query_enforcement_history_by_offender(user_id, cap=limit)
    return UserEnforcementHistoryListOut(items=[UserEnforcementHistoryOut(**row) for row in items])'''

patch(AM, [
    ("model.total_enforcements", AM_MODEL_OLD, AM_MODEL_NEW),
    ("gsi_query_fn", AM_FN_OLD, AM_FN_NEW),
    ("summary.rewire", AM_SUM_OLD, AM_SUM_NEW),
    ("endpoint.rewire", AM_EP_OLD, AM_EP_NEW),
])
# NOTE: the ByOffenderCreatedAt GSI hashes on the EXISTING ``user_id`` attribute (the
# offender) -- no new attribute is written on enforcement rows, so nothing has to be
# backfilled and enforcement writes never touch a not-yet-ACTIVE index's key.
print("MOD-1 apply complete.")
