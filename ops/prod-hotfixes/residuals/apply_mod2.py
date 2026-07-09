#!/usr/bin/env python3
"""MOD-2 / D-MESSAGE-HIDE: a reported (moderation-hidden) message shows a VISIBLE
"under review" placeholder to non-sender members instead of vanishing; the SENDER
keeps owner-view; on unhide the real content returns byte-for-byte.

Idempotent. Anchored exact-string edits + indentation-agnostic regex for the two
thread-listing loops (dev + prod indentation differ). Run: python apply_mod2.py [ROOT]
"""
import sys, os, re
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
FP = os.path.join(ROOT, "app/routers/messaging.py")
src = open(FP, encoding="utf-8").read()
orig = src

# (1) MessageOut: add under_review flag after revoked_by
MODEL_OLD = "    revoked_by: Optional[str] = None\n"
MODEL_NEW = ("    revoked_by: Optional[str] = None\n"
             "    under_review: Optional[bool] = None  # MOD-2: True on the moderation \"under review\" placeholder\n")
if "under_review: Optional[bool] = None" in src:
    print("  SKIP model.under_review")
else:
    assert src.count(MODEL_OLD) == 1, "revoked_by anchor not unique/found"
    src = src.replace(MODEL_OLD, MODEL_NEW)
    print("  OK   model.under_review")

# (2) helpers + choke-point guard on _message_out_from_item
DEF_OLD = ("def _message_out_from_item(message_item: dict, viewer_user_id: str) -> MessageOut:\n"
           "    merged_item = _merge_consumption_state(message_item, viewer_user_id)\n")
HELPERS = '''def _under_review_placeholder_message_out(message_item: dict, viewer_user_id: str) -> MessageOut:
    """MOD-2: the stripped "under review" placeholder shown to non-sender members
    for a moderation-hidden message (media / reactions / tips / ad payload all
    omitted -- nothing leaks)."""
    conversation_id = str(message_item.get("conversation_id") or "")
    projected_sender_id = _project_message_sender_id(
        message_item=message_item,
        viewer_user_id=viewer_user_id,
        conversation_id=conversation_id,
    )
    return MessageOut(
        conversation_id=conversation_id,
        message_id=str(message_item.get("message_id") or ""),
        sender_id=projected_sender_id,
        created_at=int(message_item.get("created_at") or 0),
        kind="text",
        text="Message under review",
        reply_to_message_id=message_item.get(MESSAGE_FIELD_REPLY_TO_ID),
        parent_message_id=message_item.get(MESSAGE_FIELD_PARENT_ID),
        thread_id=message_item.get(MESSAGE_FIELD_THREAD_ID),
        thread_root_message_id=message_item.get(MESSAGE_FIELD_THREAD_ROOT_ID),
        under_review=True,
    )


def _should_render_under_review_placeholder(message_item: dict, user_id: str) -> bool:
    """MOD-2: True iff _filter_message_visible rejected this message SOLELY because
    it is moderation-hidden for a non-sender -> the thread keeps it as a visible
    "under review" placeholder instead of dropping the row. Revoked / scheduled /
    deleted-for-viewer messages stay filtered out."""
    if not (message_item.get("moderation_hidden") or message_item.get("moderation_removed_at")):
        return False
    if message_item.get("sender_id") == user_id:
        return False
    if message_item.get("revoked_at"):
        return False
    if message_item.get("status") == "scheduled":
        return False
    if user_id in set(message_item.get("deleted_for", []) or []):
        return False
    return True


'''
DEF_NEW = (HELPERS +
           "def _message_out_from_item(message_item: dict, viewer_user_id: str) -> MessageOut:\n"
           "    # MOD-2 / D-MESSAGE-HIDE: a moderation-hidden message is shown to NON-SENDER\n"
           "    # members as a VISIBLE \"under review\" placeholder (real text / media / reactions\n"
           "    # stripped); the SENDER keeps owner-view (real content). On unhide the moderation\n"
           "    # flags clear (non-destructive) so the real content returns byte-for-byte.\n"
           "    if (message_item.get(\"moderation_hidden\") or message_item.get(\"moderation_removed_at\")) \\\n"
           "            and message_item.get(\"sender_id\") != viewer_user_id:\n"
           "        return _under_review_placeholder_message_out(message_item, viewer_user_id)\n"
           "    merged_item = _merge_consumption_state(message_item, viewer_user_id)\n")
if "_under_review_placeholder_message_out(message_item, viewer_user_id)\n    merged_item" in src or "def _under_review_placeholder_message_out" in src:
    print("  SKIP helpers+chokepoint")
else:
    assert src.count(DEF_OLD) == 1, "_message_out_from_item anchor not unique/found"
    src = src.replace(DEF_OLD, DEF_NEW)
    print("  OK   helpers+chokepoint")

# (3) the two thread-listing loops -> keep hidden messages as a placeholder
for var in ("m", "raw"):
    if "_should_render_under_review_placeholder(%s, user_id)" % var in src:
        print("  SKIP loop[%s]" % var)
        continue
    pat = re.compile(
        r"^(?P<ind>[ \t]+)if not _filter_message_visible\(" + var + r", user_id\):\n"
        r"(?P=ind)    continue\n"
        r"(?P=ind)msg = _message_out_from_item\(" + var + r", user_id\)",
        re.M,
    )
    repl = (
        r"\g<ind>if not _filter_message_visible(" + var + r", user_id):\n"
        r"\g<ind>    if not _should_render_under_review_placeholder(" + var + r", user_id):\n"
        r"\g<ind>        continue\n"
        r"\g<ind>msg = _message_out_from_item(" + var + r", user_id)"
    )
    src, n = pat.subn(repl, src)
    if n != 1:
        print("  !! loop[%s] matched %d times (expected 1)" % (var, n))
        raise SystemExit(2)
    print("  OK   loop[%s]" % var)

if src != orig:
    open(FP, "w", encoding="utf-8").write(src)
    print("WROTE app/routers/messaging.py")
else:
    print("NOCHG app/routers/messaging.py")
print("MOD-2 apply complete.")
