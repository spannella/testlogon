"""TIP-B5 prod surgical patcher: messaging gate extension + social_alerts ttl fix.

Idempotent: re-running is a no-op (guards on already-applied markers).
"""
import ast
import sys

MSG = "app/routers/messaging.py"
SOC = "app/services/social_alerts.py"

GATE = [
    "",
    "    # TIP-B5 pay-to-message gate extension (TIP-402/403): the FIRST image/gallery",
    "    # message to a gated DM recipient must carry a tip >= min_tip_cents, matching",
    "    # the text send path. Bypassed for allowlist / mutual-follow / established",
    "    # conversation. A gated recipient cannot be first-contacted with an un-tipped image.",
    '    if convo.get("type") == "dm":',
    "        _gate_tip_recipient = _resolve_tip_recipient(conversation_id, user_id)",
    "        if _gate_tip_recipient:",
    "            _gate_min_c = _dm_tip_gate_required(user_id, _gate_tip_recipient, conversation_id, inp.tip_amount_cents)",
    "            if _gate_min_c is not None:",
    '                raise HTTPException(402, {"code": "tip_required", "min_tip_cents": _gate_min_c, "recipient": _gate_tip_recipient})',
]


def patch_messaging():
    src = open(MSG, encoding="utf-8").read()
    if "_gate_tip_recipient" in src:
        print("  messaging: already patched (skip)")
        return False
    lines = src.split("\n")

    def insert_after(def_name, needle):
        for i, ln in enumerate(lines):
            if ln.startswith(f"def {def_name}("):
                for j in range(i, min(i + 60, len(lines))):
                    if needle in lines[j]:
                        for k, b in enumerate(GATE):
                            lines.insert(j + 1 + k, b)
                        print(f"  messaging: inserted gate after L{j+1} in {def_name}")
                        return True
                raise SystemExit(f"anchor {needle!r} not found in {def_name}")
        raise SystemExit(f"def {def_name} not found")

    insert_after("create_image_message", "_validate_reply_target(conversation_id, inp.reply_to_message_id)")
    # re-scan for gallery (list mutated)
    insert_after("create_gallery_message", "_enforce_message_send_quota_precheck(user_id=user_id, conversation_id=conversation_id, req=req)")
    out = "\n".join(lines)
    ast.parse(out)
    open(MSG, "w", encoding="utf-8").write(out)
    return True


def patch_social():
    s = open(SOC, encoding="utf-8").read()
    if '"#ttl": "ttl"' in s or '"#ttl = :ttl"' in s:
        print("  social_alerts: already patched (skip)")
        return False
    if '"ttl = :ttl"' not in s:
        raise SystemExit("social_alerts: ttl anchor missing")
    s = s.replace('"ttl = :ttl"', '"#ttl = :ttl"')
    old = 'expr_names: Dict[str, str] = {"#read": "read", "#evt": "event"}'
    new = 'expr_names: Dict[str, str] = {"#read": "read", "#evt": "event", "#ttl": "ttl"}'
    if old not in s:
        raise SystemExit("social_alerts: expr_names anchor missing")
    s = s.replace(old, new)
    ast.parse(s)
    open(SOC, "w", encoding="utf-8").write(s)
    print("  social_alerts: ttl reserved-keyword fixed (ExpressionAttributeNames)")
    return True


if __name__ == "__main__":
    patch_messaging()
    patch_social()
    print("PATCHER_DONE")
