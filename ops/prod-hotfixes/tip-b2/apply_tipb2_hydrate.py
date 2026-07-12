#!/usr/bin/env python3
"""TIP-B2 author-side chip hydration: surface stored `tip_reactions` badges in the
message serializer + MessageOut model and both newsfeed post serializers.
Anchor-count-guarded (each anchor must appear exactly once), Decimal-safe, py_compile-checked.
Idempotent: skips if the tip_reactions key/field already present at the site."""
import sys, py_compile

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
MSG = ROOT + "/app/routers/messaging.py"
NF  = ROOT + "/app/routers/newsfeed.py"

def patch(path, edits):
    src = open(path, encoding="utf-8").read()
    orig = src
    for name, anchor, insert, guard in edits:
        if guard in src:
            print("SKIP %s: already patched" % name); continue
        n = src.count(anchor)
        if n != 1:
            print("FAIL %s: anchor count=%d (want 1)" % (name, n)); sys.exit(3)
        src = src.replace(anchor, anchor + insert)
        print("OK %s" % name)
    if src != orig:
        open(path, "w", encoding="utf-8").write(src)
        py_compile.compile(path, doraise=True)
        print("COMPILED %s" % path)
    else:
        print("NOCHANGE %s" % path)

# --- messaging.py ---
msg_model_anchor = (
    "    # Tips / money\n"
    "    tip_amount_cents: Optional[int] = None\n"
    "    tip_currency: Optional[str] = None\n"
    "    tip_payment_id: Optional[str] = None\n")
msg_model_insert = "    tip_reactions: list = []  # TIP-B2: money-reaction badges (author-side chip hydration)\n"

msg_ser_anchor = (
    '        tip_currency=merged_item.get("tip_currency"),\n'
    '        tip_payment_id=merged_item.get("tip_payment_id"),\n')
msg_ser_insert = (
    "        tip_reactions=[\n"
    '            {"tipper_id": _r.get("tipper_id"), "emoji": _r.get("emoji"),\n'
    '             "amount_cents": int(_r.get("amount_cents") or 0),\n'
    '             "tip_payment_id": _r.get("tip_payment_id"),\n'
    '             "created_at": int(_r["created_at"]) if _r.get("created_at") is not None else None}\n'
    '            for _r in (merged_item.get("tip_reactions") or [])\n'
    "        ],\n")

patch(MSG, [
    ("msg_model", msg_model_anchor, msg_model_insert, "tip_reactions: list = []  # TIP-B2"),
    ("msg_serializer", msg_ser_anchor, msg_ser_insert, 'for _r in (merged_item.get("tip_reactions")'),
])

# --- newsfeed.py (two serializers: single-post uses post.get, feed-item uses it.get) ---
def nf_insert(var):
    return (
        '        "tip_reactions": [\n'
        '            {"tipper_id": _r.get("tipper_id"), "emoji": _r.get("emoji"),\n'
        '             "amount_cents": int(_r.get("amount_cents") or 0),\n'
        '             "tip_payment_id": _r.get("tip_payment_id"),\n'
        '             "created_at": _r.get("created_at")}\n'
        '            for _r in (%s.get("tip_reactions") or [])\n'
        "        ],\n") % var

patch(NF, [
    ("nf_single_post", '        "tip_total_cents": int(post.get("tip_total_cents", 0)),\n', nf_insert("post"), 'for _r in (post.get("tip_reactions")'),
    ("nf_feed_item",   '        "tip_total_cents": int(it.get("tip_total_cents", 0)),\n',   nf_insert("it"),   'for _r in (it.get("tip_reactions")'),
])
print("ALL_DONE")
