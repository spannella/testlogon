p = "app/services/ad_attribution.py"
s = open(p, encoding="utf-8").read()
orig = s

# capture prior status before the atomic claim
old_resolve = '''    resolved_click_id = str(row.get("ad_click_id"))

    # Atomic last-click claim'''
new_resolve = '''    resolved_click_id = str(row.get("ad_click_id"))
    # ADV3-2/A5: remember the pre-claim status so an insufficient-funds /
    # budget-exceeded conversion can be UN-consumed (reverted) and retried later.
    _prev_status = str(row.get("status", "") or "clicked")

    # Atomic last-click claim'''
assert old_resolve in s, "resolve anchor not found"
s = s.replace(old_resolve, new_resolve, 1)

# after the charge block, before the final logger.info, add the revert-on-underfund
old_tail = '''    else:
        result["charge"] = {"ok": True, "reason": "no_cpa_bid", "charge_cents": 0}
    logger.info(
        "ad_conversion_attributed click=%s type=%s owner=%s cpa=%s",
        resolved_click_id, conversion_type, content_owner_sub or "-", bid_cpa_cents,
    )
    return result'''
new_tail = '''    else:
        result["charge"] = {"ok": True, "reason": "no_cpa_bid", "charge_cents": 0}

    # ADV3-2/A5: an insufficient-funds (or budget-exceeded) conversion must NOT
    # consume the click. Revert the atomic claim so a later retry -- after the
    # advertiser refunds/refills -- can re-attribute + charge EXACTLY once. The
    # _process_charge idempotency marker is released on insufficient funds /
    # budget-exceeded, so the retry is clean (no double-charge).
    _charge = result.get("charge") or {}
    if (not _charge.get("ok")) and str(_charge.get("reason", "")) in (
        "insufficient_funds", "budget_exceeded"
    ):
        try:
            T.ad_clicks.update_item(
                Key={"ad_click_id": resolved_click_id},
                UpdateExpression=(
                    "SET #s = :prev REMOVE converted_at, conversion_type, "
                    "conversion_value_cents"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":prev": _prev_status},
            )
        except Exception:
            logger.warning("ad_conversion_claim_revert_failed click=%s", resolved_click_id)
        logger.info(
            "ad_conversion_deferred click=%s reason=%s (claim reverted for retry)",
            resolved_click_id, _charge.get("reason", ""),
        )
        result["attributed"] = False
        result["reason"] = "charge_deferred"
        return result

    logger.info(
        "ad_conversion_attributed click=%s type=%s owner=%s cpa=%s",
        resolved_click_id, conversion_type, content_owner_sub or "-", bid_cpa_cents,
    )
    return result'''
assert old_tail in s, "attribution tail not found"
s = s.replace(old_tail, new_tail, 1)

assert s != orig
open(p, "w", encoding="utf-8").write(s)
print("ad_attribution.py patched OK; delta bytes:", len(s) - len(orig))
