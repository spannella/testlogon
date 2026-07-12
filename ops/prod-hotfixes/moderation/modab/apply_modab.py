#!/usr/bin/env python3
"""MOD-A4..A6 + MOD-B1 idempotent anchor-based patcher (dev + prod forms).

Usage: python apply_modab.py /path/to/repo_root
Patches (all idempotent; re-runnable):
  1) app/services/moderation_case.py  -> allow visible->dismissed transition
  2) app/routers/admin_moderation.py  -> dismiss / confirm / final-call endpoints
  3) app/routers/moderation.py        -> licensing_ip topic + DMCA route + poster respond/close
  4) app/core/settings.py             -> hold-sweep flags
  5) app/main.py                      -> register start_hold_sweep_task
"""
import io
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


def _read(p):
    with io.open(os.path.join(ROOT, p), "r", encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with io.open(os.path.join(ROOT, p), "w", encoding="utf-8") as f:
        f.write(s)


def patch(path, marker, transform):
    src = _read(path)
    if marker in src:
        print("  SKIP (already applied):", path, "//", marker)
        return False
    new = transform(src)
    if new == src or marker not in new:
        print("  FAIL (anchor not found):", path, "//", marker)
        raise SystemExit(2)
    _write(path, new)
    print("  OK:", path, "//", marker)
    return True


# ---------------------------------------------------------------------------
# 1) moderation_case.py: allow visible -> dismissed
# ---------------------------------------------------------------------------
def p_case(src):
    anchor = '    STATE_VISIBLE: {STATE_UNDER_REVIEW},'
    repl = '    STATE_VISIBLE: {STATE_UNDER_REVIEW, STATE_DISMISSED},  # MODAB: dismiss a not-yet-hidden report'
    return src.replace(anchor, repl, 1)


# ---------------------------------------------------------------------------
# 2) admin_moderation.py: append triage endpoints at EOF
# ---------------------------------------------------------------------------
ADMIN_BLOCK = '''

# ── MODAB (MOD-A4): moderation_case triage — dismiss / confirm-30d-hold / final-call ──
class _CaseActionOut(BaseModel):
    ok: bool
    ticket_id: str
    case_id: str
    state: str
    hidden: bool = False
    hold_until: int | None = None
    owner_user_id: str | None = None
    enforcement_id: str | None = None


class _FinalCallIn(BaseModel):
    action: Literal["reinstate", "delete"]
    note: str | None = Field(default=None, max_length=2000)
    ban: bool = False
    ban_duration_days: int | None = Field(default=None, ge=0, le=3650)
    second_approver_admin_user_id: str | None = Field(default=None, max_length=256)


def _modab_case_and_meta(ticket_id: str):
    from app.services import moderation_case as _mc
    ticket = _get_ticket_or_404(ticket_id)
    reports = _linked_reports(ticket_id)
    snapshot = _content_snapshot(ticket, reports)
    ct = str(ticket.get("content_type") or "")
    cid = str(ticket.get("content_id") or "")
    meta = (reports[0].get("metadata") if reports else {}) or {}
    case = _mc.get_case_for_content(ct, cid)
    if not case:
        owner = _infer_offender_user_id(ticket, snapshot)
        case = _mc.aggregate_report(
            content_type=ct,
            content_id=cid,
            categories=_to_topic_list(ticket.get("aggregated_topics")),
            owner_user_id=owner,
            ticket_id=ticket_id,
            metadata=meta,
        )
    return ticket, case, meta


def _modab_tag_ticket(ticket_id: str, *, status: str, admin_sub: str, case_state: str, resolution: str | None = None, hold_until: int | None = None) -> None:
    now = str(int(time.time()))
    names = {"#s": "status", "#ua": "updated_at", "#cs": "moderation_case_state"}
    vals: dict[str, Any] = {":s": status, ":ua": now, ":cs": case_state}
    sets = ["#s = :s", "#ua = :ua", "#cs = :cs"]
    if resolution is not None:
        names["#r"] = "resolution"; vals[":r"] = resolution; sets.append("#r = :r")
        names["#ra"] = "resolved_at"; vals[":ra"] = now; sets.append("#ra = :ra")
        names["#rb"] = "resolved_by_admin_user_id"; vals[":rb"] = admin_sub; sets.append("#rb = :rb")
    if hold_until is not None:
        names["#hu"] = "hold_until"; vals[":hu"] = hold_until; sets.append("#hu = :hu")
    T.moderation_tickets.update_item(
        Key={"ticket_id": ticket_id},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=vals,
    )


@router.post("/tickets/{ticket_id}/dismiss", response_model=_CaseActionOut)
def dismiss_moderation_case(
    ticket_id: str,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> _CaseActionOut:
    ensure_admin_actions_enabled(admin)
    from app.services import moderation_lifecycle as _life
    ticket, case, meta = _modab_case_and_meta(ticket_id)
    res = _life.admin_dismiss(case=case, metadata=meta, admin_user_id=admin.sub)
    _modab_tag_ticket(ticket_id, status="closed", admin_sub=admin.sub, case_state=res["state"], resolution="no_violation")
    write_moderation_audit_event(
        action="content_case_dismissed",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket.get("content_type") or ""),
        content_id=str(ticket.get("content_id") or ""),
        target_user_id=str(res.get("owner_user_id") or ""),
        metadata={"case_id": case["case_id"], "state": res["state"]},
    )
    return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=False, owner_user_id=res.get("owner_user_id"))


@router.post("/tickets/{ticket_id}/confirm", response_model=_CaseActionOut)
def confirm_moderation_case(
    ticket_id: str,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> _CaseActionOut:
    ensure_admin_actions_enabled(admin)
    from app.services import moderation_lifecycle as _life
    ticket, case, meta = _modab_case_and_meta(ticket_id)
    res = _life.admin_confirm_hold(case=case, metadata=meta, admin_user_id=admin.sub)
    _modab_tag_ticket(ticket_id, status="open", admin_sub=admin.sub, case_state=res["state"], hold_until=res.get("hold_until"))
    write_moderation_audit_event(
        action="content_violation_confirmed",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket.get("content_type") or ""),
        content_id=str(ticket.get("content_id") or ""),
        target_user_id=str(res.get("owner_user_id") or ""),
        metadata={"case_id": case["case_id"], "hold_until": res.get("hold_until")},
    )
    return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=True, hold_until=res.get("hold_until"), owner_user_id=res.get("owner_user_id"))


@router.post("/tickets/{ticket_id}/final-call", response_model=_CaseActionOut)
def final_call_moderation_case(
    ticket_id: str,
    inp: _FinalCallIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
) -> _CaseActionOut:
    ensure_admin_actions_enabled(admin)
    from app.services import moderation_lifecycle as _life
    ticket, case, meta = _modab_case_and_meta(ticket_id)
    note = str(inp.note or "").strip()

    if inp.action == "reinstate":
        res = _life.admin_final_reinstate(case=case, metadata=meta, admin_user_id=admin.sub)
        _modab_tag_ticket(ticket_id, status="closed", admin_sub=admin.sub, case_state=res["state"], resolution="no_violation")
        write_moderation_audit_event(
            action="content_case_reinstated",
            actor_user_id=admin.sub,
            ticket_id=ticket_id,
            content_type=str(ticket.get("content_type") or ""),
            content_id=str(ticket.get("content_id") or ""),
            target_user_id=str(res.get("owner_user_id") or ""),
            metadata={"case_id": case["case_id"]},
        )
        return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=False, owner_user_id=res.get("owner_user_id"))

    # action == "delete"
    permanent = bool(inp.ban) and int(inp.ban_duration_days or 0) <= 0
    if permanent:
        _require_senior_moderation_for_permanent_ban(admin=admin)
        ensure_permanent_ban_scope_rollout(admin)
        _require_dual_approval_for_permanent_ban(admin=admin, second_approver_admin_user_id=inp.second_approver_admin_user_id)

    res = _life.admin_final_delete(case=case, metadata=meta, admin_user_id=admin.sub, source_ticket_id=ticket_id, note=note or "admin_final_delete")
    owner = str(res.get("owner_user_id") or "")

    if inp.ban and owner:
        ban_enf_id = f"enf_{uuid.uuid4().hex[:20]}"
        now = str(int(time.time()))
        T.user_enforcement_history.put_item(
            Item={
                "user_id": owner,
                "enforcement_id": ban_enf_id,
                "entity_type": "user_enforcement",
                "status": "active",
                "enforcement_type": "ban",
                "source_ticket_id": ticket_id,
                "created_at": now,
                "created_by_admin_user_id": admin.sub,
                "note": note,
                "duration_days": int(inp.ban_duration_days or 0),
            }
        )
        apply_ban(
            offender_user_id=owner,
            ticket_id=ticket_id,
            admin_user_id=admin.sub,
            note=note,
            duration_days=inp.ban_duration_days,
            policy_category="content_violation",
            enforcement_id=ban_enf_id,
        )
        write_moderation_audit_event(
            action="enforcement_banned",
            actor_user_id=admin.sub,
            ticket_id=ticket_id,
            target_user_id=owner,
            metadata={"duration_days": int(inp.ban_duration_days or 0), "permanent": permanent},
        )

    _modab_tag_ticket(ticket_id, status="closed", admin_sub=admin.sub, case_state=res["state"], resolution="content_removed")
    write_moderation_audit_event(
        action="content_case_deleted",
        actor_user_id=admin.sub,
        ticket_id=ticket_id,
        content_type=str(ticket.get("content_type") or ""),
        content_id=str(ticket.get("content_id") or ""),
        target_user_id=owner,
        metadata={"case_id": case["case_id"], "enforcement_id": res.get("enforcement_id"), "banned": bool(inp.ban)},
    )
    return _CaseActionOut(ok=True, ticket_id=ticket_id, case_id=case["case_id"], state=res["state"], hidden=True, owner_user_id=owner, enforcement_id=res.get("enforcement_id"))
'''


def p_admin(src):
    return src + ADMIN_BLOCK


# ---------------------------------------------------------------------------
# 3) moderation.py: licensing_ip topic + DMCA route + poster respond/close
# ---------------------------------------------------------------------------
MOD_OWNER_BLOCK = '''

# ── MODAB (MOD-B1): route a licensing/IP report to the DMCA auto-hide pipeline ──
def _route_licensing_report_to_dmca(inp: "CreateModerationReportIn", reporter_user_id: str, now_ts: int) -> "CreateModerationReportOut":
    from app.services.dmca_claims import file_dmca_claim

    ct = inp.content_type
    dmca_ct = ct
    content_id = inp.content_id
    if ct in ("feed_media", "feed_post"):
        dmca_ct = "feed_post"
        content_id = (getattr(inp, "post_id", None) or inp.content_id) if ct == "feed_media" else inp.content_id
    elif ct in ("message", "message_media"):
        dmca_ct = "message_media"

    claim_input = {
        "claimant_name": reporter_user_id,
        "claimant_email": f"{reporter_user_id}@reporter.testlogon",
        "content_type": dmca_ct,
        "content_id": content_id,
        "original_work_description": inp.reason_text,
        "sworn_statement": True,
        "good_faith_belief": True,
        "signature": reporter_user_id,
    }
    result = file_dmca_claim(claim_input, reporter_user_id)
    claim_id = str(result.get("claim_id") or "")
    write_moderation_audit_event(
        action="report_routed_to_dmca",
        actor_user_id=reporter_user_id,
        ticket_id=claim_id,
        content_type=inp.content_type,
        content_id=inp.content_id,
        metadata={"claim_id": claim_id, "strike_number": result.get("strike_number")},
    )
    write_alert(
        reporter_user_id,
        event="moderation_report_received",
        outcome="success",
        title="Report received",
        details={"report_id": claim_id, "ticket_id": claim_id, "status": "submitted", "routed": "dmca_licensing"},
    )
    return CreateModerationReportOut(ok=True, report_id=claim_id, ticket_id=claim_id, status="submitted", created_at=now_ts)


# ── MODAB (MOD-A5): poster response to a 30-day content hold ──
class HoldRespondIn(BaseModel):
    statement: str = Field(min_length=1, max_length=2000)


class HoldActionOut(BaseModel):
    ok: bool
    case_id: str
    state: str


def _hold_respond(case_id: str, ctx: Dict[str, str], inp: HoldRespondIn) -> HoldActionOut:
    uid = str(ctx.get("user_sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from app.services import moderation_lifecycle as _life
    try:
        res = _life.poster_respond(case_id=case_id, owner_user_id=uid, statement=inp.statement)
    except PermissionError:
        raise HTTPException(status_code=403, detail="not the content owner")
    except ValueError as exc:
        msg = str(exc)
        if msg == "case_not_found":
            raise HTTPException(status_code=404, detail="case not found") from exc
        raise HTTPException(status_code=409, detail=msg) from exc
    return HoldActionOut(ok=True, case_id=case_id, state=str(res.get("state") or ""))


def _hold_close(case_id: str, ctx: Dict[str, str]) -> HoldActionOut:
    uid = str(ctx.get("user_sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from app.services import moderation_lifecycle as _life
    try:
        res = _life.poster_close(case_id=case_id, owner_user_id=uid)
    except PermissionError:
        raise HTTPException(status_code=403, detail="not the content owner")
    except ValueError as exc:
        msg = str(exc)
        if msg == "case_not_found":
            raise HTTPException(status_code=404, detail="case not found") from exc
        raise HTTPException(status_code=409, detail=msg) from exc
    return HoldActionOut(ok=True, case_id=case_id, state=str(res.get("state") or ""))


@router.post("/holds/{case_id}/respond", response_model=HoldActionOut)
def hold_respond(case_id: str, inp: HoldRespondIn, ctx=Depends(require_ui_session)):
    return _hold_respond(case_id, ctx, inp)


@compat_router.post("/holds/{case_id}/respond", response_model=HoldActionOut)
def hold_respond_compat(case_id: str, inp: HoldRespondIn, ctx=Depends(require_ui_session)):
    return _hold_respond(case_id, ctx, inp)


@router.post("/holds/{case_id}/close", response_model=HoldActionOut)
def hold_close(case_id: str, ctx=Depends(require_ui_session)):
    return _hold_close(case_id, ctx)


@compat_router.post("/holds/{case_id}/close", response_model=HoldActionOut)
def hold_close_compat(case_id: str, ctx=Depends(require_ui_session)):
    return _hold_close(case_id, ctx)
'''


def p_moderation(src):
    # 3a) add licensing_ip to ALLOWED_TOPICS
    a_topics = '"violence_threats", "other"}'
    if a_topics not in src:
        print("  FAIL: ALLOWED_TOPICS anchor missing in moderation.py")
        raise SystemExit(2)
    src = src.replace(a_topics, '"violence_threats", "other", "licensing_ip"}', 1)
    # 3b) ensure write_moderation_audit_event imported (already imported in both forms)
    if "from app.services.moderation_audit_log import write_moderation_audit_event" not in src:
        src = src.replace(
            "from app.services.alerts import audit_event, write_alert",
            "from app.services.alerts import audit_event, write_alert\nfrom app.services.moderation_audit_log import write_moderation_audit_event",
            1,
        )
    # 3c) insert the licensing routing branch after the anti-spam call inside _create_report
    anchor = "    _run_anti_spam_heuristics(reporter_user_id=reporter_user_id, inp=inp, request=request)"
    if anchor not in src:
        print("  FAIL: anti-spam anchor missing in moderation.py")
        raise SystemExit(2)
    branch = (
        anchor
        + "\n\n    # MODAB (MOD-B1): licensing/IP reports go to the DMCA auto-hide pipeline, not a general ticket.\n"
        + '    if "licensing_ip" in inp.topics:\n'
        + "        return _route_licensing_report_to_dmca(inp, reporter_user_id, now_ts)"
    )
    src = src.replace(anchor, branch, 1)
    # 3d) append owner endpoints + helpers
    return src + MOD_OWNER_BLOCK


# ---------------------------------------------------------------------------
# 4) settings.py: hold-sweep flags (insert right after dmca_timer_interval_seconds block)
# ---------------------------------------------------------------------------
def p_settings(src):
    anchor = '''    dmca_timer_interval_seconds: int = int(
        os.environ.get("DMCA_TIMER_INTERVAL_SECONDS", "3600")
    )'''
    if anchor not in src:
        print("  FAIL: dmca_timer_interval anchor missing in settings.py")
        raise SystemExit(2)
    add = anchor + '''
    # MODAB (MOD-A6): precise scheduled 30-day content-hold expiry sweep.
    moderation_hold_sweep_enabled: bool = os.environ.get(
        "MODERATION_HOLD_SWEEP_ENABLED", "1"
    ) not in ("0", "false", "False")
    moderation_hold_sweep_interval_seconds: int = int(
        os.environ.get("MODERATION_HOLD_SWEEP_INTERVAL_SECONDS", "900")
    )'''
    return src.replace(anchor, add, 1)


# ---------------------------------------------------------------------------
# 5) main.py: register start_hold_sweep_task
# ---------------------------------------------------------------------------
def p_main(src):
    imp_anchor = "from app.services.dmca_claims import start_dmca_timer_task"
    if imp_anchor not in src:
        print("  FAIL: dmca import anchor missing in main.py")
        raise SystemExit(2)
    src = src.replace(
        imp_anchor,
        imp_anchor + "\nfrom app.services.moderation_lifecycle import start_hold_sweep_task",
        1,
    )
    reg_anchor = '    app.add_event_handler("startup", start_dmca_timer_task)'
    if reg_anchor not in src:
        print("  FAIL: dmca startup anchor missing in main.py")
        raise SystemExit(2)
    src = src.replace(
        reg_anchor,
        reg_anchor + '\n    app.add_event_handler("startup", start_hold_sweep_task)  # MODAB MOD-A6',
        1,
    )
    return src


def main():
    print("=== apply_modab.py ROOT=%s ===" % ROOT)
    patch("app/services/moderation_case.py", "MODAB: dismiss a not-yet-hidden report", p_case)
    patch("app/routers/admin_moderation.py", "MODAB (MOD-A4): moderation_case triage", p_admin)
    patch("app/routers/moderation.py", "MODAB (MOD-A5): poster response", p_moderation)
    patch("app/core/settings.py", "moderation_hold_sweep_enabled", p_settings)
    patch("app/main.py", "start_hold_sweep_task", p_main)
    print("=== done ===")


if __name__ == "__main__":
    main()
