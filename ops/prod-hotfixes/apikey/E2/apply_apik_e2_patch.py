#!/usr/bin/env python3
"""APIK EPIC E2 (#118) - messaging parity patch (registry-only).

Idempotent, region-scoped patch of app/services/api_key_route_scope_registry.py.
Usage: python apply_apik_e2_patch.py /path/to/repo/app/services/api_key_route_scope_registry.py

Registers the messaging capabilities that were unmapped/exempt (== 403 under GA) so an
API key can bootstrap a thread, rich-send (incl. image via presign->send), react, read
receipts, poll realtime, organize (pins/forward/search), manage the conversation and
scheduled sends, and run mass-message campaigns (messager:manage + entitlement).

Scope model (messager:manage >= messager:write >= messager:read):
  read   -> reads / realtime poll / search / gallery / receipts view
  write  -> conversation bootstrap, all rich sends + image presign, reactions, read
            receipts, calls, pins/forward, privacy allowlist
  manage -> participant/lifecycle admin, scheduled-send cancel/edit, helpdesk transfer,
            mass-message campaigns (E2-5, + entitlement)

Intentional blocks stay exempt (drafts / mute / compliance+moderation / chat-delegate /
admin-upsert / health). Money routes (tip / unlock / lottery / paid-attachment
grant+consume) stay fail-closed exempt: there is no messager money scope, so they remain
403 until a distinct high-priv money scope is modeled (never a coarse messager:write).
"""
import sys, io

READ = [
    "GET:/messaging/config",
    "GET:/messaging/contacts/search",
    "GET:/messaging/conversations",
    "GET:/messaging/conversations/{conversation_id}",
    "GET:/messaging/conversations/{conversation_id}/gallery",
    "GET:/messaging/conversations/{conversation_id}/messages",
    "GET:/messaging/conversations/{conversation_id}/messages/scheduled",
    "GET:/messaging/conversations/{conversation_id}/messages/search",
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment",
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/edits",
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions/details",
    "GET:/messaging/conversations/{conversation_id}/messages/{message_id}/views",
    "GET:/messaging/conversations/{conversation_id}/participants",
    "GET:/messaging/conversations/{conversation_id}/pins",
    "GET:/messaging/conversations/{conversation_id}/polls/{poll_id}",
    "GET:/messaging/conversations/{conversation_id}/routing-events",
    "GET:/messaging/conversations/{conversation_id}/typing",
    "GET:/messaging/events",
    "GET:/messaging/events/poll",
    "GET:/messaging/events/stream",
    "GET:/messaging/helpdesk/availability",
    "GET:/messaging/helpdesk/groups/{group_id}/agents",
    "GET:/messaging/helpdesk/queue",
    "GET:/messaging/messages/calls/{call_id}/billing",
    "GET:/messaging/messages/find-datetime/{poll_id}",
    "GET:/messaging/messages/search",
    "GET:/messaging/presence",
    "GET:/messaging/privacy/message",
    "GET:/messaging/threads/{thread_id}/messages",
]
WRITE = [
    "POST:/messaging/conversations",
    "POST:/messaging/conversations/dm/find-or-create",
    "POST:/messaging/conversations/group",
    "POST:/messaging/conversations/{conversation_id}/accept",
    "POST:/messaging/conversations/{conversation_id}/images/presign",
    "POST:/messaging/conversations/{conversation_id}/leave",
    "POST:/messaging/conversations/{conversation_id}/messages",
    "POST:/messaging/conversations/{conversation_id}/messages/calendar-event",
    "POST:/messaging/conversations/{conversation_id}/messages/calendar-share",
    "POST:/messaging/conversations/{conversation_id}/messages/countdown",
    "POST:/messaging/conversations/{conversation_id}/messages/file",
    "POST:/messaging/conversations/{conversation_id}/messages/file-share",
    "POST:/messaging/conversations/{conversation_id}/messages/find-datetime",
    "POST:/messaging/conversations/{conversation_id}/messages/gallery",
    "POST:/messaging/conversations/{conversation_id}/messages/gif",
    "POST:/messaging/conversations/{conversation_id}/messages/image",
    "POST:/messaging/conversations/{conversation_id}/messages/meeting-poll",
    "POST:/messaging/conversations/{conversation_id}/messages/sticker",
    "POST:/messaging/conversations/{conversation_id}/messages/video-share",
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/pin",
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/pin",
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions",
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/transcribe",
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/translate",
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/view",
    "POST:/messaging/conversations/{conversation_id}/polls/{poll_id}/confirm",
    "POST:/messaging/conversations/{conversation_id}/polls/{poll_id}/vote",
    "POST:/messaging/conversations/{conversation_id}/read",
    "POST:/messaging/conversations/{conversation_id}/tts-voice-message",
    "POST:/messaging/conversations/{conversation_id}/typing",
    "POST:/messaging/conversations/{conversation_id}/voice-message",
    "POST:/messaging/conversations/{conversation_id}/voice-message/presign",
    "POST:/messaging/conversations/{conversation_id}/voicemail",
    "POST:/messaging/conversations/{conversation_id}/voicemail/presign",
    "POST:/messaging/conversations/{target_conversation_id}/messages/forward",
    "POST:/messaging/helpdesk/conversations/{conversation_id}/claim",
    "POST:/messaging/messages/calls/invite",
    "POST:/messaging/messages/calls/{call_id}/accept",
    "POST:/messaging/messages/calls/{call_id}/decline",
    "POST:/messaging/messages/calls/{call_id}/end",
    "PATCH:/messaging/messages/calls/{call_id}/heartbeat",
    "POST:/messaging/messages/calls/{call_id}/signal",
    "POST:/messaging/messages/calls/{call_id}/timeout",
    "POST:/messaging/messages/calls/{call_id}/turn-credentials",
    "POST:/messaging/messages/find-datetime/{poll_id}/availability",
    "POST:/messaging/messages/find-datetime/{poll_id}/close",
    "POST:/messaging/presence/heartbeat",
    "PUT:/messaging/privacy/message",
    "POST:/messaging/privacy/message/allowlist",
    "DELETE:/messaging/privacy/message/allowlist/{allow_user_id}",
]
MANAGE = [
    "PATCH:/messaging/conversations/{conversation_id}",
    "DELETE:/messaging/conversations/{conversation_id}",
    "POST:/messaging/conversations/{conversation_id}/participants",
    "PATCH:/messaging/conversations/{conversation_id}/participants/{participant_id}",
    "DELETE:/messaging/conversations/{conversation_id}/participants/{participant_id}",
    "PATCH:/messaging/conversations/{conversation_id}/messages/{message_id}",
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}",
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/revoke",
    "PATCH:/messaging/conversations/{conversation_id}/messages/{message_id}/schedule",
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/schedule",
    "POST:/messaging/helpdesk/conversations/{conversation_id}/transfer",
]
# APIK-E2-5: mass-message campaigns are broadcast/admin -> distinct high-priv messager:manage + entitlement.
MASS = [
    "GET:/messaging/mass-messages",
    "POST:/messaging/mass-messages",
    "GET:/messaging/mass-messages/{campaign_id}",
    "POST:/messaging/mass-messages/{campaign_id}/cancel",
]

_INT = "INTENTIONAL: session/admin-only, not exposed to API keys (APIK-E2 intentional block)"
_MONEY = ("MONEY route fail-closed: no messager money scope exists; stays 403 until a distinct "
          "high-priv money scope is modeled (never coarse messager:write) (APIK-E2)")
EXEMPT = {
    # drafts (intentional)
    "GET:/messaging/conversations/{conversation_id}/drafts": _INT,
    "POST:/messaging/conversations/{conversation_id}/drafts": _INT,
    "GET:/messaging/conversations/{conversation_id}/drafts/{draft_id}": _INT,
    "PATCH:/messaging/conversations/{conversation_id}/drafts/{draft_id}": _INT,
    "DELETE:/messaging/conversations/{conversation_id}/drafts/{draft_id}": _INT,
    # mute (intentional)
    "POST:/messaging/conversations/{conversation_id}/mute": _INT,
    # compliance + moderation (intentional)
    "GET:/messaging/compliance/archive/events": _INT,
    "GET:/messaging/compliance/archive/exports": _INT,
    "POST:/messaging/compliance/archive/exports": _INT,
    "GET:/messaging/compliance/archive/exports/{export_id}": _INT,
    "GET:/messaging/compliance/archive/exports/{export_id}/manifest": _INT,
    "GET:/messaging/compliance/archive/exports/{export_id}/records": _INT,
    "GET:/messaging/conversations/{conversation_id}/hidden-messages": _INT,
    "GET:/messaging/conversations/{conversation_id}/legal-holds": _INT,
    "POST:/messaging/conversations/{conversation_id}/legal-holds": _INT,
    "POST:/messaging/conversations/{conversation_id}/legal-holds/{hold_id}/release": _INT,
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/hide": _INT,
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/hide": _INT,
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/report": _INT,
    "PATCH:/messaging/conversations/{conversation_id}/reports/{report_id}/status": _INT,
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/moderate-revoke": _INT,
    # chat-delegate acts-as-creator surface (dak_ delegation only) - intentional
    "GET:/messaging/delegate/{creator_id}/audit": _INT,
    "GET:/messaging/delegate/{creator_id}/conversations": _INT,
    "GET:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages": _INT,
    "POST:/messaging/delegate/{creator_id}/conversations/{conversation_id}/messages": _INT,
    # admin + health (intentional / no product traffic)
    "POST:/messaging/admin/users/upsert": _INT,
    "GET:/messaging/healthz": "health probe, no API-key product traffic (APIK-E2)",
    # money (deferred, fail-closed)
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/tip": _MONEY,
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/reactions/tip": _MONEY,
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/unlock": _MONEY,
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment/grant": _MONEY,
    "POST:/messaging/conversations/{conversation_id}/messages/{message_id}/attachment/consume": _MONEY,
    "POST:/messaging/messages/lottery": _MONEY,
    "POST:/messaging/messages/{message_id}/lottery/unlock": _MONEY,
    "GET:/messaging/messages/{message_id}/lottery": _MONEY,
}


def reg_row(rid, scope):
    return ('    "%s": {"product": "messager", "required_scopes": ["%s"], "entitlement_required": True},'
            % (rid, scope))


def build_reg_block():
    L = ["    # Messager -- APIK-E2 (#118): full messaging parity. messager:manage>=write>=read.",
         "    # read=reads/realtime/search/receipts-view; write=bootstrap+rich-sends(incl image presign)+",
         "    # reactions+read-receipts+calls+pins/forward+privacy; manage=participant/lifecycle admin+",
         "    # scheduled-send cancel/edit+helpdesk transfer. Money & intentional blocks stay exempt below."]
    L.append("    # E2 read")
    for r in READ:
        L.append(reg_row(r, "messager:read"))
    L.append("    # E2 write (bootstrap / rich sends / image presign->send / reactions / receipts / calls / organize)")
    for r in WRITE:
        L.append(reg_row(r, "messager:write"))
    L.append("    # E2 manage (participant + conversation lifecycle, scheduled-send cancel/edit, helpdesk transfer)")
    for r in MANAGE:
        L.append(reg_row(r, "messager:manage"))
    L.append("    # APIK-E2-5: mass-message campaigns require messager:manage (+entitlement) - distinct high-priv broadcast.")
    for r in MASS:
        L.append(reg_row(r, "messager:manage"))
    return "\n".join(L)


# Exact old messager registry block (9 rows under "# Messager"), replaced wholesale.
OLD_REG_BLOCK = (
    '    # Messager\n'
    '    "GET:/messaging/conversations": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},\n'
    '    "GET:/messaging/conversations/{conversation_id}": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},\n'
    '    "GET:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},\n'
    '    "POST:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},\n'
    '    "POST:/messaging/conversations/{conversation_id}/messages/image": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},\n'
    '    "POST:/messaging/conversations/{conversation_id}/messages/file": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},\n'
    '    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},\n'
    '    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/revoke": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},\n'
    '    "PATCH:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},\n'
)


def main():
    path = sys.argv[1]
    with io.open(path, "r", encoding="utf-8") as f:
        src = f.read()

    if "APIK-E2 (#118)" in src:
        print("ALREADY_PATCHED", path)
        return

    # 1) Registry: replace the 9-row messager block with the full E2 block.
    assert OLD_REG_BLOCK in src, "old messager registry block anchor not found"
    src = src.replace(OLD_REG_BLOCK, build_reg_block() + "\n")

    # 2) Exemptions: region-scoped rewrite of messaging exemption rows.
    ex_marker = "API_KEY_ROUTE_EXEMPTIONS: Dict[str, RouteExemption] = {\n"
    end_marker = "\nAPI_KEY_INITIAL_ROLLOUT_PATH_PREFIXES"
    i = src.index(ex_marker)
    head = src[:i]
    tail_all = src[i:]
    j = tail_all.index(end_marker)
    ex_block = tail_all[:j]
    rest = tail_all[j:]

    # drop existing messaging exemption lines, keep everything else verbatim
    kept = []
    dropped_n = 0
    for line in ex_block.split("\n"):
        s = line.strip()
        if s.startswith('"'):
            key = s.split('"')[1]
            if ":" in key and key.split(":", 1)[1].startswith("/messaging"):
                dropped_n += 1
                continue
        kept.append(line)
    ex_block = "\n".join(kept)
    print("dropped_old_messaging_exemptions=%d" % dropped_n)

    # insert canonical messaging exemption block right after the dict-open line
    new_ex = ["    # Messager -- APIK-E2 (#118): intentional blocks + money routes stay fail-closed (== 403 under GA)."]
    for rid, reason in EXEMPT.items():
        new_ex.append('    "%s": {"reason": "%s"},' % (rid, reason))
    open_line = ex_marker  # includes trailing newline
    assert ex_block.startswith(ex_marker.rstrip("\n"))
    ex_block = ex_block.replace(ex_marker.rstrip("\n") + "\n",
                                ex_marker.rstrip("\n") + "\n" + "\n".join(new_ex) + "\n", 1)

    src = head + ex_block + rest

    with io.open(path, "w", encoding="utf-8") as f:
        f.write(src)
    print("PATCHED", path)


if __name__ == "__main__":
    main()
