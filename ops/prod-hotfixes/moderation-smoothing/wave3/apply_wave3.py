#!/usr/bin/env python3
"""MODX WAVE-3 re-apply helper (human loops: reachable appeals, un-blind admin final
call, notifications + reporter feedback, error legibility).

Idempotent, anchor-based in-place edits. Mirrors the dev-clone android-impl edits
byte-for-byte. Run from a testlogon checkout root (default ".") or pass a root:
    python3 apply_wave3.py [ROOT]

Every transform is guarded (marker check) so re-running is a no-op, and asserts its
anchor so a dry-run on a divergent tree fails loudly instead of silently skipping.

Files patched (MODX-13..16):
  app/auth/deps.py                    require_appellant dep (banned users reach appeals)
  app/routers/appeals.py              require_appellant on the surface + enforcement-options endpoint
  app/services/appeals.py             list_enforcement_options (dropdown source)
  app/models.py                       EnforcementOption(s)Out
  app/routers/admin_moderation.py     poster_response/responded_at on the ticket-detail DTO
  app/services/moderation_lifecycle.py  push in _notify + reporter outcome fanout + poster-response->mod notify
  app/services/alerts.py              moderation events: category + settable + default-on push + deep-links
  app/routers/moderation.py           reporter report-received push + expanded copy + reports/mine
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
    assert old in s, "ANCHOR MISSING: " + repr(old[:80])
    return s.replace(old, new, count)


results = []


def done(name, changed):
    results.append((name, "changed" if changed else "already"))


# ------------------------------------------------------------------ deps.py ----
def patch_deps():
    p = "app/auth/deps.py"
    s = rf(p)
    orig = s
    if "_allow_banned_appellant" in s:
        return done(p, False)
    s = sub(s, "import time\n", "import time\nimport contextvars\n")
    old = (
        "def _enforce_not_banned(*, user_sub: str, role: Role) -> None:\n"
        "    if role in {Role.ROOT, Role.ADMIN}:\n"
        "        return\n"
        "    if is_user_currently_banned(user_sub):\n"
        "        raise HTTPException(status_code=403, detail=\"account is banned\")\n"
    )
    new = (
        "# MODX-13: appeals must be reachable BY the very users an enforcement concerns\n"
        "# (banned/suspended). This context flag lets an explicit appeals dependency\n"
        "# (``require_appellant``) authenticate a banned principal WITHOUT the global\n"
        "# ban gate 403ing them out of their own due-process channel. It is set only for\n"
        "# the narrow appeals surface and always reset in a finally, so no other route\n"
        "# can ever admit a banned user.\n"
        "_allow_banned_appellant: contextvars.ContextVar[bool] = contextvars.ContextVar(\n"
        "    \"allow_banned_appellant\", default=False\n"
        ")\n\n\n"
        "def _enforce_not_banned(*, user_sub: str, role: Role) -> None:\n"
        "    if role in {Role.ROOT, Role.ADMIN}:\n"
        "        return\n"
        "    if _allow_banned_appellant.get():\n"
        "        # MODX-13: appellant lane -- do not 403 a banned user out of appeals.\n"
        "        return\n"
        "    if is_user_currently_banned(user_sub):\n"
        "        raise HTTPException(status_code=403, detail=\"account is banned\")\n\n\n"
        "async def require_appellant(request: Request) -> \"AuthenticatedUser\":\n"
        "    \"\"\"MODX-13: authenticate the caller for the APPEALS surface only, exempting\n"
        "    them from the ban gate so a banned/suspended user can reach + submit an appeal\n"
        "    (and read their own enforcement history to fill the form). Identity resolution\n"
        "    is otherwise identical to ``get_authenticated_user``; the exemption is scoped to\n"
        "    this call via a context flag that is always reset.\"\"\"\n"
        "    token = _allow_banned_appellant.set(True)\n"
        "    try:\n"
        "        return await get_authenticated_user(request)\n"
        "    finally:\n"
        "        _allow_banned_appellant.reset(token)\n"
    )
    s = sub(s, old, new)
    wf(p, s)
    done(p, s != orig)


# --------------------------------------------------------- appeals service ----
def patch_appeals_service():
    p = "app/services/appeals.py"
    s = rf(p)
    orig = s
    if "def list_enforcement_options" in s:
        return done(p, False)
    fn = (
        "def list_enforcement_options(user_id: str, limit: int = 25) -> List[Dict[str, Any]]:\n"
        "    \"\"\"MODX-13: the appellant-facing enforcement picker source. Returns the user own\n"
        "    enforcement records (most-recent first), each flagged with whether an appeal already\n"
        "    exists, so the app can render a SELECTABLE dropdown instead of a hand-typed id that\n"
        "    the user has no way of knowing.\"\"\"\n"
        "    rows = _list_user_enforcements(user_id, limit=max(1, min(limit, 100)))\n"
        "    out: List[Dict[str, Any]] = []\n"
        "    for r in rows:\n"
        "        if str(r.get(\"entity_type\") or \"user_enforcement\") != \"user_enforcement\":\n"
        "            continue\n"
        "        eid = str(r.get(\"enforcement_id\") or \"\")\n"
        "        if not eid:\n"
        "            continue\n"
        "        has_appeal = False\n"
        "        try:\n"
        "            resp = T.appeals.query(\n"
        "                IndexName=\"ByEnforcementId\",\n"
        "                KeyConditionExpression=Key(\"enforcement_id\").eq(eid),\n"
        "                Limit=1,\n"
        "            )\n"
        "            has_appeal = bool(resp.get(\"Items\"))\n"
        "        except Exception:\n"
        "            has_appeal = False\n"
        "        out.append({\n"
        "            \"enforcement_id\": eid,\n"
        "            \"enforcement_type\": str(r.get(\"enforcement_type\") or \"\"),\n"
        "            \"status\": str(r.get(\"status\") or \"\"),\n"
        "            \"source_ticket_id\": str(r.get(\"source_ticket_id\") or \"\") or None,\n"
        "            \"created_at\": _coerce_int(r.get(\"created_at\"), 0),\n"
        "            \"duration_days\": _coerce_int(r.get(\"duration_days\"), 0),\n"
        "            \"note\": str(r.get(\"note\") or \"\")[:280],\n"
        "            \"has_appeal\": has_appeal,\n"
        "        })\n"
        "    return out\n\n\n"
    )
    anchor = "def file_appeal(user_id: str, enforcement_id: str, appeal_text: str) -> Dict[str, Any]:"
    s = sub(s, anchor, fn + anchor)
    wf(p, s)
    done(p, s != orig)


# ----------------------------------------------------------------- models ------
def patch_models():
    p = "app/models.py"
    s = rf(p)
    orig = s
    if "class EnforcementOptionOut" in s:
        return done(p, False)
    block = (
        "class EnforcementOptionOut(BaseModel):\n"
        "    \"\"\"MODX-13: one selectable enforcement in the appeal picker (the user never types\n"
        "    an opaque enforcement id by hand).\"\"\"\n"
        "    enforcement_id: str\n"
        "    enforcement_type: str = \"\"\n"
        "    status: str = \"\"\n"
        "    source_ticket_id: Optional[str] = None\n"
        "    created_at: int = 0\n"
        "    duration_days: int = 0\n"
        "    note: str = \"\"\n"
        "    has_appeal: bool = False\n\n\n"
        "class EnforcementOptionsOut(BaseModel):\n"
        "    items: List[EnforcementOptionOut] = Field(default_factory=list)\n\n\n"
    )
    anchor = "class AppealCreateOut(BaseModel):"
    s = sub(s, anchor, block + anchor)
    wf(p, s)
    done(p, s != orig)


# ------------------------------------------------------------ appeals router ---
def patch_appeals_router():
    p = "app/routers/appeals.py"
    s = rf(p)
    orig = s
    if "require_appellant" in s:
        return done(p, False)
    s = sub(s,
            "from app.auth.deps import AuthenticatedUser, get_authenticated_user",
            "from app.auth.deps import AuthenticatedUser, get_authenticated_user, require_appellant")
    s = sub(s,
            "    AppealWithdrawOut,\n)",
            "    AppealWithdrawOut,\n    EnforcementOptionOut,\n    EnforcementOptionsOut,\n)")
    s = sub(s,
            "from app.services.appeals import (\n    file_appeal,",
            "from app.services.appeals import (\n    file_appeal,\n    list_enforcement_options,")
    s = s.replace("user: AuthenticatedUser = Depends(get_authenticated_user),",
                  "user: AuthenticatedUser = Depends(require_appellant),")
    endpoint = (
        "@router.get(\"/enforcement-options\", response_model=EnforcementOptionsOut)\n"
        "async def list_my_enforcement_options(\n"
        "    user: AuthenticatedUser = Depends(require_appellant),\n"
        "):\n"
        "    \"\"\"MODX-13: the appellant enforcement picker. Returns THIS user own enforcement\n"
        "    records so the appeal form offers a selectable list instead of a hand-typed id.\n"
        "    Reachable while banned (``require_appellant``).\"\"\"\n"
        "    rows = list_enforcement_options(user.sub)\n"
        "    return EnforcementOptionsOut(items=[EnforcementOptionOut(**r) for r in rows])\n\n\n"
    )
    anchor = "@router.post(\"\", response_model=AppealCreateOut, status_code=201)"
    s = sub(s, anchor, endpoint + anchor)
    wf(p, s)
    done(p, s != orig)


# ----------------------------------------------------- admin_moderation DTO ----
def patch_admin_dto():
    p = "app/routers/admin_moderation.py"
    s = rf(p)
    orig = s
    if "poster_response: str | None = None" in s:
        return done(p, False)
    s = sub(s,
            "    illegal_lane: bool = False\n    sla_deadline: int | None = None\n\n\nclass ModerationDecisionIn",
            "    illegal_lane: bool = False\n    sla_deadline: int | None = None\n"
            "    # MODX-14 (C3): surface the poster hold-response so the admin final call is not made blind.\n"
            "    poster_response: str | None = None\n    responded_at: int | None = None\n\n\nclass ModerationDecisionIn")
    s = sub(s,
            "        sla_deadline=(_parse_int(_case.get(\"sla_deadline\"), 0) or None),\n",
            "        sla_deadline=(_parse_int(_case.get(\"sla_deadline\"), 0) or None),\n"
            "        poster_response=(str(_case.get(\"poster_response\")) if _case.get(\"poster_response\") else None),\n"
            "        responded_at=(_parse_int(_case.get(\"responded_at\"), 0) or None),\n")
    wf(p, s)
    done(p, s != orig)


# --------------------------------------------------------------- lifecycle -----
def patch_lifecycle():
    p = "app/services/moderation_lifecycle.py"
    s = rf(p)
    orig = s
    # A) push import + _notify rewrite + _notify_reporters
    if "_notify_reporters" not in s:
        s = sub(s,
                "from app.services.alerts import write_alert\n",
                "from app.services.alerts import write_alert\n"
                "from app.services.push import send_push_for_alert\n")
        old_notify = (
            "def _notify(owner_user_id: Optional[str], *, event: str, title: str, message: str, case_id: str, state: str, extra: Optional[Dict[str, Any]] = None) -> None:\n"
            "    if not owner_user_id:\n"
            "        return\n"
            "    details = {\"case_id\": case_id, \"state\": state, \"message\": message}\n"
            "    if extra:\n"
            "        details.update({k: v for k, v in extra.items() if v is not None})\n"
            "    try:\n"
            "        try:\n"
            "            write_alert(owner_user_id, event=event, outcome=\"warning\", title=title, details=details, push_event_types=[event])\n"
            "        except TypeError:\n"
            "            write_alert(owner_user_id, event=event, outcome=\"warning\", title=title, details=details)\n"
            "    except Exception:\n"
            "        logger.exception(\"moderation_lifecycle._notify failed for %s\", owner_user_id)\n"
        )
        new_notify = (
            "def _notify(owner_user_id: Optional[str], *, event: str, title: str, message: str, case_id: str, state: str, outcome: str = \"warning\", extra: Optional[Dict[str, Any]] = None) -> None:\n"
            "    if not owner_user_id:\n"
            "        return\n"
            "    details = {\"case_id\": case_id, \"state\": state, \"message\": message, \"alert_type\": event}\n"
            "    if extra:\n"
            "        details.update({k: v for k, v in extra.items() if v is not None})\n"
            "    try:\n"
            "        wr = write_alert(owner_user_id, event=event, outcome=outcome, title=title, details=details)\n"
            "        # MODX-15 (C8): moderation events are time-sensitive + consequential -> deliver a real\n"
            "        # PUSH, not Alerts-only. The alert row (with its auto-derived deep-link) already\n"
            "        # persisted above; send_push_for_alert reads that action_url off the row. Best-effort.\n"
            "        try:\n"
            "            alert_id = (wr or {}).get(\"alert_id\", \"\") if isinstance(wr, dict) else \"\"\n"
            "            send_push_for_alert(owner_user_id, event, title, message, alert_id)\n"
            "        except Exception:\n"
            "            logger.exception(\"moderation_lifecycle._notify push failed for %s\", owner_user_id)\n"
            "    except Exception:\n"
            "        logger.exception(\"moderation_lifecycle._notify failed for %s\", owner_user_id)\n\n\n"
            "def _notify_reporters(case: Dict[str, Any], *, event: str, title: str, message: str, state: str, exclude: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> None:\n"
            "    \"\"\"MODX-15 (C7): close the reporter feedback loop. When a case reaches a terminal\n"
            "    outcome, tell the people who reported it what happened (action taken / dismissed) so\n"
            "    reporting is not fire-and-forget. Fan out to the DISTINCT reporter set (never the owner),\n"
            "    best-effort + de-duplicated.\"\"\"\n"
            "    case_id = str(case.get(\"case_id\") or \"\")\n"
            "    rids = case.get(\"reporter_ids\")\n"
            "    if not isinstance(rids, (set, frozenset, list, tuple)):\n"
            "        return\n"
            "    owner = str(case.get(\"owner_user_id\") or \"\")\n"
            "    seen = set()\n"
            "    for rid in rids:\n"
            "        rid = str(rid or \"\").strip()\n"
            "        if not rid or rid in seen or rid == owner or rid == exclude:\n"
            "            continue\n"
            "        seen.add(rid)\n"
            "        _notify(rid, event=event, title=title, message=message, case_id=case_id, state=state, outcome=\"info\", extra=extra)\n"
        )
        s = sub(s, old_notify, new_notify)

    # B) terminal reporter fanout - delete
    if "moderation_report_resolved" not in s:
        anchor_del = (
            "    _notify(\n"
            "        resolved_owner,\n"
            "        event=\"moderation_content_deleted\",\n"
            "        title=\"Your content was removed\",\n"
            "        message=f\"After review, your {_label(content_type)} has been permanently removed.\",\n"
            "        case_id=case_id,\n"
            "        state=mc.STATE_DELETED,\n"
            "        extra={\"content_type\": content_type, \"reason\": reason, \"enforcement_id\": enforcement_id},\n"
            "    )\n"
        )
        s = sub(s, anchor_del, anchor_del + (
            "    # MODX-15 (C7): tell the reporters their report led to action.\n"
            "    _notify_reporters(\n"
            "        case,\n"
            "        event=\"moderation_report_resolved\",\n"
            "        title=\"Action taken on content you reported\",\n"
            "        message=f\"Thanks for reporting. The {_label(content_type)} you reported was reviewed and removed.\",\n"
            "        state=mc.STATE_DELETED,\n"
            "        exclude=resolved_owner,\n"
            "        extra={\"outcome\": \"content_removed\"},\n"
            "    )\n"
        ))
        anchor_dis = (
            "    _notify(\n"
            "        owner,\n"
            "        event=\"moderation_content_restored\",\n"
            "        title=\"Report dismissed\",\n"
            "        message=f\"A report against your {_label(content_type)} was reviewed and dismissed. Your content is visible again.\",\n"
            "        case_id=case_id,\n"
            "        state=mc.STATE_DISMISSED,\n"
            "        extra={\"content_type\": content_type},\n"
            "    )\n"
        )
        s = sub(s, anchor_dis, anchor_dis + (
            "    # MODX-15 (C7): close the loop for reporters even on a no-violation outcome.\n"
            "    _notify_reporters(\n"
            "        updated or case,\n"
            "        event=\"moderation_report_resolved\",\n"
            "        title=\"Report reviewed\",\n"
            "        message=f\"Thanks for reporting. The {_label(content_type)} you reported was reviewed; no violation was found.\",\n"
            "        state=mc.STATE_DISMISSED,\n"
            "        exclude=owner,\n"
            "        extra={\"outcome\": \"no_violation\"},\n"
            "    )\n"
        ))
        anchor_rei = (
            "    _notify(\n"
            "        owner,\n"
            "        event=\"moderation_content_reinstated\",\n"
            "        title=\"Your content was reinstated\",\n"
            "        message=f\"After review, your {_label(content_type)} has been restored and is visible again.\",\n"
            "        case_id=case_id,\n"
            "        state=mc.STATE_REINSTATED,\n"
            "        extra={\"content_type\": content_type},\n"
            "    )\n"
        )
        s = sub(s, anchor_rei, anchor_rei + (
            "    # MODX-15 (C7): reporters learn the final call went the other way.\n"
            "    _notify_reporters(\n"
            "        updated or case,\n"
            "        event=\"moderation_report_resolved\",\n"
            "        title=\"Report reviewed\",\n"
            "        message=f\"Thanks for reporting. After a final review the {_label(content_type)} was restored; no violation was found.\",\n"
            "        state=mc.STATE_REINSTATED,\n"
            "        exclude=owner,\n"
            "        extra={\"outcome\": \"reinstated\"},\n"
            "    )\n"
        ))

    # C) poster_respond -> notify assigned moderator
    if "_notify_assigned_moderator_poster_responded" not in s:
        anchor = (
            "        except Exception:\n"
            "            logger.exception(\"poster_respond ticket reopen failed for %s\", ticket_id)\n"
            "    return {\"state\": mc.STATE_AWAITING_FINAL, \"case\": updated}\n"
        )
        repl = (
            "        except Exception:\n"
            "            logger.exception(\"poster_respond ticket reopen failed for %s\", ticket_id)\n"
            "    # MODX-14 (C4): a poster response must not sit unseen until someone happens to browse\n"
            "    # the board. Proactively notify the assigned moderator (if any) that awaiting_final now\n"
            "    # carries a fresh defense to weigh. Un-assigned tickets already re-surface on the board\n"
            "    # (status=open) as the board-badge path. Best-effort.\n"
            "    _notify_assigned_moderator_poster_responded(ticket_id=ticket_id, case=case, case_id=case_id)\n"
            "    return {\"state\": mc.STATE_AWAITING_FINAL, \"case\": updated}\n\n\n"
            "def _notify_assigned_moderator_poster_responded(*, ticket_id: str, case: Dict[str, Any], case_id: str) -> None:\n"
            "    \"\"\"MODX-14 (C4): ping the ticket assignee that the poster has responded so the final\n"
            "    call is made promptly. Best-effort; never breaks the poster_respond write.\"\"\"\n"
            "    if not ticket_id:\n"
            "        return\n"
            "    try:\n"
            "        tk = T.moderation_tickets.get_item(Key={\"ticket_id\": ticket_id}).get(\"Item\") or {}\n"
            "    except Exception:\n"
            "        tk = {}\n"
            "    assignee = str(tk.get(\"assigned_admin_user_id\") or \"\").strip()\n"
            "    if not assignee:\n"
            "        return\n"
            "    ctype = str(case.get(\"content_type\") or \"\")\n"
            "    _notify(\n"
            "        assignee,\n"
            "        event=\"moderation_poster_responded\",\n"
            "        title=\"Poster responded -- final call needed\",\n"
            "        message=f\"The poster of a held {_label(ctype)} submitted a response. It is awaiting your final decision.\",\n"
            "        case_id=case_id,\n"
            "        state=mc.STATE_AWAITING_FINAL,\n"
            "        outcome=\"info\",\n"
            "        extra={\"ticket_id\": ticket_id, \"content_type\": ctype},\n"
            "    )\n"
        )
        s = sub(s, anchor, repl)
    wf(p, s)
    done(p, s != orig)


# ----------------------------------------------------------------- alerts ------
MOD_EVENTS = [
    "moderation_content_deleted", "moderation_content_removed", "moderation_content_hidden",
    "moderation_content_reinstated", "moderation_content_restored", "moderation_violation_confirmed",
    "moderation_hold_escalated", "moderation_report_received", "moderation_report_resolved",
    "moderation_poster_responded", "moderation_warning", "moderation_ban", "moderation_sla_breach",
    "moderation_extortion_criminal_surge",
    "dmca_claim_filed", "dmca_content_restored", "dmca_counter_notice_received", "dmca_repeat_infringer_ban",
]


def patch_alerts():
    p = "app/services/alerts.py"
    s = rf(p)
    orig = s
    if "\"moderation\":" not in s:
        lst = ", ".join('"%s"' % e for e in MOD_EVENTS)
        s = sub(s,
                "    \"commerce\": {\"cart.abandoned\", \"order_shipped\", \"order_out_for_delivery\", \"order_delivered\"},\n}",
                "    \"commerce\": {\"cart.abandoned\", \"order_shipped\", \"order_out_for_delivery\", \"order_delivered\"},\n"
                "    # MODX-15: moderation / DMCA lifecycle notifications get their own category + push.\n"
                "    \"moderation\": {" + lst + "},\n}")
    if "moderation_content_deleted" not in s.split("ALERT_EVENT_TYPES: List[str] = [")[1].split("]")[0]:
        lst2 = ",".join('"%s"' % e for e in MOD_EVENTS)
        s = sub(s,
                "    \"order_out_for_delivery\",\n    \"order_delivered\",\n]",
                "    \"order_out_for_delivery\",\n    \"order_delivered\",\n"
                "    # MODX-15: moderation / DMCA lifecycle events (push default-on transactional).\n"
                "    " + lst2 + ",\n]")
    if "moderation_content_deleted" not in s.split("DEFAULT_PUSH_EVENT_TYPES: List[str] = [")[1].split("]")[0]:
        lst3 = ",".join('"%s"' % e for e in MOD_EVENTS)
        s = sub(s,
                "    \"subscription_gifted\",          # SUB-E5: a gift subscription\n]",
                "    \"subscription_gifted\",          # SUB-E5: a gift subscription\n"
                "    # MODX-15: moderation/DMCA events are consequential + time-sensitive -> default-on push.\n"
                "    " + lst3 + ",\n]")
    if "moderation_ban" not in s.split("def _build_action_url")[1].split("return url_map.get")[0]:
        s = sub(s,
                "        \"ticket_status_changed\": f\"/tickets/{ticket_id}\" if ticket_id else \"/tickets\",\n    }\n    return url_map.get(alert_type)",
                "        \"ticket_status_changed\": f\"/tickets/{ticket_id}\" if ticket_id else \"/tickets\",\n"
                "        # MODX-15/C6: enforcement outcomes deep-link to the appeal channel, not the (empty)\n"
                "        # open-cases list; poster review events land on the content-review screen.\n"
                "        \"moderation_ban\": \"/appeals\",\n"
                "        \"moderation_content_deleted\": \"/appeals\",\n"
                "        \"moderation_content_removed\": \"/appeals\",\n"
                "        \"moderation_violation_confirmed\": \"/moderation/review\",\n"
                "        \"moderation_hold_escalated\": \"/moderation/review\",\n"
                "        \"moderation_content_hidden\": \"/moderation/review\",\n"
                "        \"moderation_content_reinstated\": \"/moderation/review\",\n"
                "        \"moderation_content_restored\": \"/moderation/review\",\n"
                "    }\n    return url_map.get(alert_type)")
    wf(p, s)
    done(p, s != orig)


# ------------------------------------------------------------ moderation rt ----
def patch_moderation_router():
    p = "app/routers/moderation.py"
    s = rf(p)
    orig = s
    if "send_push_for_alert" not in s:
        s = sub(s,
                "from app.services.alerts import audit_event, write_alert",
                "from app.services.alerts import audit_event, write_alert\nfrom app.services.push import send_push_for_alert")
        s = sub(s,
                "        write_alert(\n"
                "            reporter_user_id,\n"
                "            event=\"moderation_report_received\",\n"
                "            outcome=\"success\",\n"
                "            title=\"Report received\",\n"
                "            details={\"report_id\": report_id, \"ticket_id\": ticket_id, \"status\": \"deduplicated\"},\n"
                "        )\n",
                "        _wr = write_alert(\n"
                "            reporter_user_id,\n"
                "            event=\"moderation_report_received\",\n"
                "            outcome=\"success\",\n"
                "            title=\"Report received\",\n"
                "            details={\"report_id\": report_id, \"ticket_id\": ticket_id, \"status\": \"deduplicated\", \"alert_type\": \"moderation_report_received\"},\n"
                "        )\n"
                "        try:\n"
                "            send_push_for_alert(reporter_user_id, \"moderation_report_received\", \"Report received\", \"We already have your report and it is being reviewed.\", (_wr or {}).get(\"alert_id\", \"\"))\n"
                "        except Exception:\n"
                "            logger.exception(\"report_received push failed\")\n")
        s = sub(s,
                "    write_alert(\n"
                "        reporter_user_id,\n"
                "        event=\"moderation_report_received\",\n"
                "        outcome=\"success\",\n"
                "        title=\"Report received\",\n"
                "        details={\"report_id\": report_id, \"ticket_id\": ticket_id, \"status\": \"submitted\"},\n"
                "    )\n",
                "    _wr = write_alert(\n"
                "        reporter_user_id,\n"
                "        event=\"moderation_report_received\",\n"
                "        outcome=\"success\",\n"
                "        title=\"Report received\",\n"
                "        details={\"report_id\": report_id, \"ticket_id\": ticket_id, \"status\": \"submitted\", \"alert_type\": \"moderation_report_received\"},\n"
                "    )\n"
                "    # MODX-15 (C7/C8): confirm receipt with a real push + set the what-happens-next expectation.\n"
                "    try:\n"
                "        send_push_for_alert(reporter_user_id, \"moderation_report_received\", \"Report received\", \"Thanks for reporting. Our team will review it and you will be told the outcome.\", (_wr or {}).get(\"alert_id\", \"\"))\n"
                "    except Exception:\n"
                "        logger.exception(\"report_received push failed\")\n")
    if "class MyFiledReportOut" not in s:
        anchor = "@router.get(\"/cases/mine\", response_model=MyModerationCasesOut)"
        block = (
            "# -- MODX-15 (C7): reporter feedback -- the reports THIS user filed + their outcome --\n"
            "class MyFiledReportOut(BaseModel):\n"
            "    report_id: str = \"\"\n"
            "    content_type: str = \"\"\n"
            "    content_id: str = \"\"\n"
            "    topics: List[str] = []\n"
            "    ticket_id: str = \"\"\n"
            "    created_at: int = 0\n"
            "    outcome: str = \"pending\"\n"
            "    outcome_state: str = \"\"\n\n\n"
            "class MyFiledReportsOut(BaseModel):\n"
            "    reports: List[MyFiledReportOut]\n\n\n"
            "_REPORT_OUTCOME = {\n"
            "    \"deleted\": \"action_taken\",\n"
            "    \"hold\": \"action_taken\",\n"
            "    \"awaiting_final\": \"action_taken\",\n"
            "    \"dismissed\": \"no_violation\",\n"
            "    \"reinstated\": \"no_violation\",\n"
            "    \"visible\": \"pending\",\n"
            "    \"under_review\": \"pending\",\n"
            "}\n\n\n"
            "def _list_my_filed_reports(ctx: Dict[str, str]) -> \"MyFiledReportsOut\":\n"
            "    uid = str(ctx.get(\"user_sub\") or \"\").strip()\n"
            "    if not uid:\n"
            "        raise HTTPException(status_code=401, detail=\"Unauthorized\")\n"
            "    out: List[MyFiledReportOut] = []\n"
            "    try:\n"
            "        resp = T.content_reports.query(\n"
            "            IndexName=\"ByReporterCreatedAt\",\n"
            "            KeyConditionExpression=Key(\"reporter_user_id\").eq(uid),\n"
            "            ScanIndexForward=False,\n"
            "            Limit=50,\n"
            "        )\n"
            "    except ClientError:\n"
            "        logger.exception(\"moderation._list_my_filed_reports query failed for %s\", uid)\n"
            "        raise HTTPException(status_code=503, detail=\"unavailable\")\n"
            "    from app.services import moderation_case as _mc\n"
            "    for it in resp.get(\"Items\", []) or []:\n"
            "        if it.get(\"entity_type\") != \"content_report\":\n"
            "            continue\n"
            "        ctype = str(it.get(\"content_type\") or \"\")\n"
            "        cid = str(it.get(\"content_id\") or \"\")\n"
            "        state = \"\"\n"
            "        try:\n"
            "            _case = _mc.get_case_for_content(ctype, cid) or {}\n"
            "            state = str(_case.get(\"state\") or \"\")\n"
            "        except Exception:\n"
            "            state = \"\"\n"
            "        topics_raw = it.get(\"topics\") or []\n"
            "        topics = [str(t) for t in topics_raw] if isinstance(topics_raw, (list, tuple)) else []\n"
            "        out.append(MyFiledReportOut(\n"
            "            report_id=str(it.get(\"report_id\") or \"\"),\n"
            "            content_type=ctype,\n"
            "            content_id=cid,\n"
            "            topics=topics,\n"
            "            ticket_id=str(it.get(\"linked_ticket_id\") or \"\"),\n"
            "            created_at=_mod_coerce_int(it.get(\"created_at\")) or 0,\n"
            "            outcome=_REPORT_OUTCOME.get(state, \"pending\"),\n"
            "            outcome_state=state,\n"
            "        ))\n"
            "    return MyFiledReportsOut(reports=out)\n\n\n"
            "@router.get(\"/reports/mine\", response_model=MyFiledReportsOut)\n"
            "def list_my_filed_reports(ctx=Depends(require_ui_session)):\n"
            "    return _list_my_filed_reports(ctx)\n\n\n"
            "@compat_router.get(\"/reports/mine\", response_model=MyFiledReportsOut)\n"
            "def list_my_filed_reports_compat(ctx=Depends(require_ui_session)):\n"
            "    return _list_my_filed_reports(ctx)\n\n\n"
        )
        s = sub(s, anchor, block + anchor)
    wf(p, s)
    done(p, s != orig)


def main():
    patch_deps()
    patch_appeals_service()
    patch_models()
    patch_appeals_router()
    patch_admin_dto()
    patch_lifecycle()
    patch_alerts()
    patch_moderation_router()
    import ast
    for _p in ["app/auth/deps.py", "app/routers/appeals.py", "app/services/appeals.py",
               "app/models.py", "app/routers/admin_moderation.py",
               "app/services/moderation_lifecycle.py", "app/services/alerts.py",
               "app/routers/moderation.py"]:
        ast.parse(rf(_p))
    for name, st in results:
        print("%-45s %s" % (name, st))
    print("SYNTAX OK (all 8 files parse)")


if __name__ == "__main__":
    main()
