import io, sys
p = "app/routers/admin_moderation.py"
s = open(p, encoding="utf-8").read()
orig = s
changes = []

# 1) Extend ModerationTicketDetailOut with case_state + hold_until + owner_user_id
a1 = "class ModerationTicketDetailOut(BaseModel):\n    ticket: ModerationTicketOut\n    content_snapshot: dict[str, Any] = Field(default_factory=dict)\n    linked_reports: list[LinkedReportOut] = Field(default_factory=list)\n    offender_history_summary: OffenderHistorySummaryOut\n    prior_enforcement_history: list[dict[str, Any]] = Field(default_factory=list)"
b1 = a1 + "\n    case_state: str = \"\"\n    hold_until: int | None = None\n    owner_user_id: str | None = None"
if b1 in s:
    changes.append("D1_detail_out ALREADY")
elif a1 in s:
    s = s.replace(a1, b1, 1); changes.append("D1_detail_out OK")
else:
    print("MISSING D1"); sys.exit(2)

# 2) syndicate_post branch in _content_snapshot (insert before final return)
a2 = "        return {\n            \"kind\": content_type,\n            \"exists\": bool((profile.get(\"profile\") or {}).get(\"profile_photo_url\")),\n            \"user_id\": content_id,\n            \"author_user_id\": content_id,\n            \"profile_photo_url\": str((profile.get(\"profile\") or {}).get(\"profile_photo_url\") or \"\") or None,\n        }\n\n    return {\"kind\": content_type, \"exists\": False}"
b2 = ("        return {\n            \"kind\": content_type,\n            \"exists\": bool((profile.get(\"profile\") or {}).get(\"profile_photo_url\")),\n            \"user_id\": content_id,\n            \"author_user_id\": content_id,\n            \"profile_photo_url\": str((profile.get(\"profile\") or {}).get(\"profile_photo_url\") or \"\") or None,\n        }\n\n"
      "    if content_type == \"syndicate_post\":\n"
      "        from app.services import syndicate_feed as _sf\n"
      "        syndicate_id = str(meta.get(\"syndicate_id\") or \"\")\n"
      "        post = (_sf._get_post(syndicate_id, content_id) if syndicate_id else None) or {}\n"
      "        return {\n"
      "            \"kind\": content_type,\n"
      "            \"exists\": bool(post),\n"
      "            \"post_id\": content_id,\n"
      "            \"syndicate_id\": syndicate_id,\n"
      "            \"author_user_id\": str(post.get(\"author_id\") or \"\") or None,\n"
      "            \"text\": str(post.get(\"text\") or \"\"),\n"
      "            \"created_at\": _parse_int(post.get(\"created_at\"), 0),\n"
      "        }\n\n"
      "    return {\"kind\": content_type, \"exists\": False}")
if "if content_type == \"syndicate_post\":" in s:
    changes.append("D2_snapshot ALREADY")
elif a2 in s:
    s = s.replace(a2, b2, 1); changes.append("D2_snapshot OK")
else:
    print("MISSING D2"); sys.exit(2)

# 3) populate case_state/hold_until/owner in get_moderation_ticket_detail
a3 = "    offender_user_id = _infer_offender_user_id(ticket_item, snapshot)\n\n    return ModerationTicketDetailOut(\n        ticket=_to_ticket_out(ticket_item),\n        content_snapshot=snapshot,"
b3 = ("    offender_user_id = _infer_offender_user_id(ticket_item, snapshot)\n\n"
      "    from app.services import moderation_case as _mc\n"
      "    _case = _mc.get_case_for_content(str(ticket_item.get(\"content_type\") or \"\"), str(ticket_item.get(\"content_id\") or \"\")) or {}\n"
      "    _case_state = str(_case.get(\"state\") or ticket_item.get(\"moderation_case_state\") or \"\")\n"
      "    _hold_until_raw = _case.get(\"hold_until\") if _case.get(\"hold_until\") is not None else ticket_item.get(\"hold_until\")\n"
      "    _hold_until = _parse_int(_hold_until_raw, 0) or None\n"
      "    _owner = str(_case.get(\"owner_user_id\") or offender_user_id or \"\") or None\n\n"
      "    return ModerationTicketDetailOut(\n"
      "        ticket=_to_ticket_out(ticket_item),\n"
      "        content_snapshot=snapshot,\n"
      "        case_state=_case_state,\n"
      "        hold_until=_hold_until,\n"
      "        owner_user_id=_owner,")
if "case_state=_case_state," in s:
    changes.append("D3_detail_ep ALREADY")
elif a3 in s:
    s = s.replace(a3, b3, 1); changes.append("D3_detail_ep OK")
else:
    print("MISSING D3"); sys.exit(2)

open(p, "w", encoding="utf-8").write(s)
import py_compile
py_compile.compile(p, doraise=True)
print("PATCHED", changes)
