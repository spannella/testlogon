#!/usr/bin/env python3
"""TIPX-E1: wire notify_tip into charge_tip (both return paths) + notify_tip_reversed into reverse_tip."""
import io, sys, time

PATH = "app/services/tips.py"
src = io.open(PATH, encoding="utf-8").read()
orig = src
ts = int(time.time())

# --- 1. collab-split return path: emit notify_tip before storing receipt+return ---
anchor_collab = """        _store_idempotent_receipt(tipper_id, idempotency_key, result)
        return result"""
repl_collab = """        _store_idempotent_receipt(tipper_id, idempotency_key, result)
        # TIPX-E1: single-choke-point tip notification (recipient alert + tipper receipt).
        _notify_tip_best_effort(entry, result)
        return result"""
assert src.count(anchor_collab) == 1, f"collab anchor count={src.count(anchor_collab)}"
src = src.replace(anchor_collab, repl_collab)

# --- 2. normal path: after publish_tip_dashboard_sse(entry) / return result ---
anchor_norm = """    # 7. Notify the recipient's dashboard stream (best-effort).
    publish_tip_dashboard_sse(entry)
    return result"""
repl_norm = """    # 7. Notify the recipient's dashboard stream (best-effort).
    publish_tip_dashboard_sse(entry)
    # TIPX-E1: single-choke-point tip notification (recipient alert + tipper receipt).
    _notify_tip_best_effort(entry, result)
    return result"""
assert src.count(anchor_norm) == 1, f"norm anchor count={src.count(anchor_norm)}"
src = src.replace(anchor_norm, repl_norm)

# --- 3. define _notify_tip_best_effort helper just before `def charge_tip(` ---
helper = '''def _notify_tip_best_effort(entry: "TipLedgerEntry", result: "TipResult") -> None:
    """TIPX-E1: fire the recipient alert + tipper receipt for a committed tip.

    Best-effort: a notification failure must never break a charge/credit that
    already committed. Routes EVERY surface through the one choke point so no
    surface can be silent (comment/video/message-react/attached) or dead-link.
    """
    try:
        from app.services.tip_notifications import notify_tip

        notify_tip(
            tipper_id=entry.tipper_user_id,
            recipient_id=entry.recipient_user_id,
            amount_cents=result.charged_cents,
            net_cents=result.net_cents,
            fee_cents=result.fee_cents,
            currency=entry.currency,
            content_type=entry.content_type,
            content_id=entry.content_id,
            tip_payment_id=result.tip_payment_id,
            meta=getattr(entry, "extra_meta", None) or {},
        )
    except Exception:
        logger.warning("notify_tip failed tip=%s", result.tip_payment_id, exc_info=True)


def charge_tip('''
anchor_def = "def charge_tip("
assert src.count(anchor_def) == 1, f"charge_tip def count={src.count(anchor_def)}"
src = src.replace(anchor_def, helper, 1)

# --- 4. reverse_tip: emit notify_tip_reversed on the FIRST reversal (after adjuncts, before `return receipt`) ---
# The tail of reverse_tip ends with the stripe refund block then `\n    return receipt`.
anchor_rev = """            logger.warning("stripe refund skipped for tip=%s", tip_payment_id, exc_info=True)

    return receipt"""
repl_rev = """            logger.warning("stripe refund skipped for tip=%s", tip_payment_id, exc_info=True)

    # TIPX-E3 (N8): notify BOTH parties on the first reversal (best-effort).
    try:
        from app.services.tip_notifications import notify_tip_reversed

        notify_tip_reversed(
            tipper_id=tipper_id,
            recipient_id=recipient_id,
            gross_cents=gross_cents,
            net_cents=net_cents,
            currency=currency,
            content_type=content_type,
            content_id=content_id,
            tip_payment_id=tip_payment_id,
            reason=reason,
        )
    except Exception:
        logger.warning("notify_tip_reversed failed tip=%s", tip_payment_id, exc_info=True)

    return receipt"""
assert src.count(anchor_rev) == 1, f"reverse anchor count={src.count(anchor_rev)}"
src = src.replace(anchor_rev, repl_rev)

if src == orig:
    print("NO CHANGE"); sys.exit(1)
io.open(PATH + f".bak_tipx_{ts}", "w", encoding="utf-8").write(orig)
io.open(PATH, "w", encoding="utf-8").write(src)
print(f"PATCHED tips.py; bak=.bak_tipx_{ts}")
