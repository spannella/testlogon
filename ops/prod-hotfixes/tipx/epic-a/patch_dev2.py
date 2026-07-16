#!/usr/bin/env python3
"""TIPX-A1 (orphan-total) dev-clone patcher. Run from repo root."""
import io, sys

def read(p):
    with io.open(p, encoding="utf-8") as f: return f.read()
def write(p, s):
    with io.open(p, "w", encoding="utf-8") as f: f.write(s)

def sub_once(path, old, new, label):
    s = read(path)
    if new in s and old not in s:
        print(f"  [skip] {label}"); return
    n = s.count(old)
    if n != 1:
        print(f"  [FAIL] {label}: found {n} anchors"); sys.exit(2)
    write(path, s.replace(old, new, 1))
    print(f"  [ok]   {label}")

NF = "app/routers/newsfeed.py"
# A1 tip_post: move the tip_total bump AFTER a successful charge (into the
# post_author block). A 402 now leaves NO tip_total_cents mutation + no ledger.
sub_once(NF,
    "    # TIP-007: the mock PaymentProvider stub is replaced by the centralized\n"
    "    # charge_tip seam (called below, after the tip_total bump). The stub always\n"
    "    # \"succeeded\", so removing it changes no behavior.\n"
    "    updated = ddb_update_item(\n"
    "        key={\"pk\": pk_post(post_id), \"sk\": sk_post()},\n"
    "        update_expr=\"SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt\",\n"
    "        expr_vals={\":z\": 0, \":amt\": req.amount_cents},\n"
    "    )\n"
    "\n"
    "    # Write billing ledger debit + credit entries via the centralized charge_tip seam.\n"
    "    post_author = post.get(\"user_id\")\n"
    "    _tip_txn_id = \"\"\n"
    "    if post_author and post_author != user_id:\n"
    "        from app.services.tips import charge_tip\n"
    "        _tp = charge_tip(\n",
    "    # TIPX-A1: charge FIRST, bump the public tip_total AFTER a successful charge\n"
    "    # so a declined charge (402) leaves NO inflated total + no ledger row.\n"
    "    updated: dict = {}\n"
    "    post_author = post.get(\"user_id\")\n"
    "    _tip_txn_id = \"\"\n"
    "    if post_author and post_author != user_id:\n"
    "        from app.services.tips import charge_tip\n"
    "        _tp = charge_tip(\n",
    "A1: tip_post remove pre-charge bump")

# Insert the bump right after charge_tip returns (before the social hook).
sub_once(NF,
    "        _tip_txn_id = _tp.tip_payment_id\n"
    "        try:\n"
    "            from app.services.activity_feed import record_social_interaction\n"
    "            record_social_interaction(recipient_id=post_author, actor_id=user_id, kind=\"tip\", target_type=\"post\", target_id=post_id, extra={\"amount_cents\": req.amount_cents, \"currency\": req.currency})\n",
    "        _tip_txn_id = _tp.tip_payment_id\n"
    "        # TIPX-A1: bump the public tip total ONLY now that the charge succeeded.\n"
    "        updated = ddb_update_item(\n"
    "            key={\"pk\": pk_post(post_id), \"sk\": sk_post()},\n"
    "            update_expr=\"SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt\",\n"
    "            expr_vals={\":z\": 0, \":amt\": req.amount_cents},\n"
    "        )\n"
    "        try:\n"
    "            from app.services.activity_feed import record_social_interaction\n"
    "            record_social_interaction(recipient_id=post_author, actor_id=user_id, kind=\"tip\", target_type=\"post\", target_id=post_id, extra={\"amount_cents\": req.amount_cents, \"currency\": req.currency})\n",
    "A1: tip_post bump after charge")

# ---------------------------------------------------------------------------
# A1 post-hoc send_message_tip: charge BEFORE the row stamp.
# ---------------------------------------------------------------------------
MSG = "app/routers/messaging.py"
sub_once(MSG,
    "    # Mock payment in dev mode; real payment processor in production\n"
    "    tip_payment_id = \"tip_\" + new_id()\n"
    "    ts = now_ts()\n"
    "\n"
    "    update_expr = (\n"
    "        \"SET tip_amount_cents = if_not_exists(tip_amount_cents, :zero) + :amt, \"\n"
    "        \"tip_currency = :cur, tip_payment_id = :pid, tip_updated_at = :ts\"\n"
    "    )\n"
    "    expr_values: dict = {\n"
    "        \":zero\": 0,\n"
    "        \":amt\": inp.amount_cents,\n"
    "        \":cur\": inp.currency,\n"
    "        \":pid\": tip_payment_id,\n"
    "        \":ts\": ts,\n"
    "    }\n"
    "    if inp.payment_method_id:\n"
    "        update_expr += \", tip_payment_method_id = :pmid\"\n"
    "        expr_values[\":pmid\"] = inp.payment_method_id\n"
    "\n"
    "    tbl_msgs.update_item(\n"
    "        Key={\"conversation_id\": conversation_id, \"message_id\": message_id},\n"
    "        UpdateExpression=update_expr,\n"
    "        ExpressionAttributeValues=expr_values,\n"
    "    )\n"
    "\n"
    "    # Write billing ledger debit + credit entries for the tip\n"
    "    msg_author = msg.get(\"sender_id\")\n"
    "    if msg_author and msg_author != user_id:\n"
    "        from app.services.tips import charge_tip\n"
    "        charge_tip(\n",
    "    # Mock payment in dev mode; real payment processor in production\n"
    "    tip_payment_id = \"tip_\" + new_id()\n"
    "    ts = now_ts()\n"
    "\n"
    "    # TIPX-A1: CHARGE FIRST -- a declined charge (402) must leave NO tip_amount_cents\n"
    "    # bump / tip_payment_id stamp (no phantom tip badge on a message that was\n"
    "    # never paid). The row is stamped only after charge_tip returns successfully.\n"
    "    msg_author = msg.get(\"sender_id\")\n"
    "    if msg_author and msg_author != user_id:\n"
    "        from app.services.tips import charge_tip\n"
    "        charge_tip(\n",
    "A1: post-hoc msgtip charge-first (remove pre-charge stamp)")

# After the charge_tip(...) call block for post-hoc msgtip, stamp the row.
# Anchor: the create_invoice_safe follows; we insert the update_item right after
# the closing of charge_tip( ... ) i.e. before the invoice block.
sub_once(MSG,
    "            idempotency_key=(f\"msgtip:{message_id}:{inp.client_request_id}\" if getattr(inp, \"client_request_id\", None) else f\"msgtip:{message_id}\"),  # TIPX-A3\n"
    "            tip_payment_id=tip_payment_id,\n"
    "        )\n"
    "        # FIN-001: generate an invoice for the tip (best-effort)\n",
    "            idempotency_key=(f\"msgtip:{message_id}:{inp.client_request_id}\" if getattr(inp, \"client_request_id\", None) else f\"msgtip:{message_id}\"),  # TIPX-A3\n"
    "            tip_payment_id=tip_payment_id,\n"
    "        )\n"
    "        # TIPX-A1: stamp the message row ONLY after the charge succeeded.\n"
    "        _phmt_expr = (\n"
    "            \"SET tip_amount_cents = if_not_exists(tip_amount_cents, :zero) + :amt, \"\n"
    "            \"tip_currency = :cur, tip_payment_id = :pid, tip_updated_at = :ts\"\n"
    "        )\n"
    "        _phmt_vals: dict = {\":zero\": 0, \":amt\": inp.amount_cents, \":cur\": inp.currency, \":pid\": tip_payment_id, \":ts\": ts}\n"
    "        if inp.payment_method_id:\n"
    "            _phmt_expr += \", tip_payment_method_id = :pmid\"\n"
    "            _phmt_vals[\":pmid\"] = inp.payment_method_id\n"
    "        tbl_msgs.update_item(\n"
    "            Key={\"conversation_id\": conversation_id, \"message_id\": message_id},\n"
    "            UpdateExpression=_phmt_expr,\n"
    "            ExpressionAttributeValues=_phmt_vals,\n"
    "        )\n"
    "        # FIN-001: generate an invoice for the tip (best-effort)\n",
    "A1: post-hoc msgtip stamp-after-charge")

print("done")
