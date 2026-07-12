#!/usr/bin/env python3
"""ADV2 residuals R1 (syndicate-aware reversal) + R2 (AdClicks.charged_cents).

Idempotent, anchor-matched (not line#) so it runs on the dev clone AND prod even
where they diverge. Re-run = ALREADY_APPLIED per patch. Usage:
    python apply_adv2res.py [ROOT]   (default ROOT=.)
"""
import io
import os
import sys
import py_compile

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


def _read(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)


PATCHES = []  # (relpath, sentinel, old, new)


def add(relpath, sentinel, old, new):
    PATCHES.append((relpath, sentinel, old, new))


# ---------------------------------------------------------------------------
# R1a: syndicate_treasury.debit_placement_earning (reverse of credit_...)
# ---------------------------------------------------------------------------
add(
    "app/services/syndicate_treasury.py",
    "def debit_placement_earning(",
    "def refund_advertising(",
    '''def debit_placement_earning(
    *,
    syndicate_id: str,
    amount_cents: int,
    member_user_id: str = "",
    account_id: str = "",
    campaign_id: str = "",
    reversal_of: str = "",
) -> Dict[str, Any]:
    """ADV2-RES R1: reverse a syndicate ad-placement treasury credit. When the
    underlying syndicate-owned ad charge is reversed, debit the treasury the share
    it was credited by credit_placement_earning (balance SUBTRACT + one 'debit'
    treasury ledger row). Sign-flipped mirror of credit_placement_earning. No-op
    for a non-positive amount."""
    if amount_cents <= 0:
        return {"ok": True, "amount_cents": 0, "ledger_entry_id": ""}
    pk_treasury = _treasury_pk(syndicate_id)
    ts = now_ts()
    T.syndicate_treasury.update_item(
        Key={"pk": pk_treasury, "sk": BALANCE_SK},
        UpdateExpression=(
            "SET balance_cents = if_not_exists(balance_cents, :z) - :amt, "
            "total_ad_earnings_cents = if_not_exists(total_ad_earnings_cents, :z) - :amt, "
            "updated_at = :t, syndicate_id = :sid"
        ),
        ExpressionAttributeValues={
            ":z": 0, ":amt": int(amount_cents), ":t": ts, ":sid": syndicate_id,
        },
    )
    entry_id = _gen_id()
    T.syndicate_treasury.put_item(Item={
        "pk": pk_treasury,
        "sk": ledger_sk(ts, entry_id),
        "entry_id": entry_id,
        "ts": ts,
        "direction": "debit",
        "type": "debit",
        "amount_cents": int(amount_cents),
        "reason": "Syndicate ad placement reversal",
        "actor_user_id": "",
        "counterparty_user_id": member_user_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "source_type": "ad_placement_reversal",
        "reversal_of": reversal_of,
        "currency": "usd",
        "created_at": ts,
    })
    balance = get_treasury_balance(syndicate_id)
    return {
        "ok": True,
        "amount_cents": int(amount_cents),
        "ledger_entry_id": entry_id,
        "new_treasury_balance_cents": balance["balance_cents"],
    }


def refund_advertising(''',
)

# ---------------------------------------------------------------------------
# R1b: ad_billing.reverse_ad_charge -> syndicate 3-way aware
# ---------------------------------------------------------------------------
# (i) meta reads: add syndicate pointers + member_clawback + treasury_debited
add(
    "app/services/ad_billing.py",
    "member_clawback = member_share if is_syndicate_split else creator_share",
    '''    creator_credit_sk = str(emeta.get("creator_credit_sk", "") or "")
    platform_entry_sk = str(emeta.get("platform_entry_sk", "") or "")''',
    '''    creator_credit_sk = str(emeta.get("creator_credit_sk", "") or "")
    platform_entry_sk = str(emeta.get("platform_entry_sk", "") or "")
    # ADV2-RES R1: syndicate 3-way reversal pointers. In a syndicate split the
    # member credit row holds member_share_cents (the treasury took the
    # remainder), so the member clawback == member_share; a non-syndicate
    # reversal keeps clawing the full creator_share UNCHANGED.
    is_syndicate_split = bool(emeta.get("is_syndicate_split"))
    member_share = int(emeta.get("member_share_cents", 0) or 0)
    treasury_share = int(emeta.get("syndicate_treasury_share_cents", 0) or 0)
    split_syndicate_id = str(emeta.get("syndicate_id", "") or "")
    member_clawback = member_share if is_syndicate_split else creator_share
    treasury_debit_planned = treasury_share if is_syndicate_split else 0
    treasury_debited = 0''',
)

# (ii) _receipt
add(
    "app/services/ad_billing.py",
    '"treasury_debit_cents": treasury_debited,',
    '''            "campaign_id": campaign_id, "refunded_cents": amount_cents,
            "creator_clawback_cents": creator_share if creator_id else 0,
            "platform_reversal_cents": platform_share,
            "idempotent_replay": replay,
        }''',
    '''            "campaign_id": campaign_id, "refunded_cents": amount_cents,
            "creator_clawback_cents": member_clawback if creator_id else 0,
            "platform_reversal_cents": platform_share,
            "treasury_debit_cents": treasury_debited,
            "is_syndicate_split": is_syndicate_split,
            "syndicate_id": split_syndicate_id,
            "idempotent_replay": replay,
        }''',
)

# (iii) marker item
add(
    "app/services/ad_billing.py",
    '"treasury_debit_cents": treasury_debit_planned,',
    '''                "reversal_entry_id": reversal_entry_id, "amount_cents": amount_cents,
                "creator_clawback_cents": creator_share if creator_id else 0,
                "platform_reversal_cents": platform_share, "campaign_id": campaign_id,
                "created_at": ts,''',
    '''                "reversal_entry_id": reversal_entry_id, "amount_cents": amount_cents,
                "creator_clawback_cents": member_clawback if creator_id else 0,
                "platform_reversal_cents": platform_share, "campaign_id": campaign_id,
                "treasury_debit_cents": treasury_debit_planned,
                "is_syndicate_split": is_syndicate_split, "syndicate_id": split_syndicate_id,
                "created_at": ts,''',
)

# (iv) duplicate-replay receipt
add(
    "app/services/ad_billing.py",
    '"treasury_debit_cents": int(prior.get("treasury_debit_cents", 0) or 0),',
    '''                "refunded_cents": int(prior.get("amount_cents", 0) or 0),
                "creator_clawback_cents": int(prior.get("creator_clawback_cents", 0) or 0),
                "platform_reversal_cents": int(prior.get("platform_reversal_cents", 0) or 0),
                "idempotent_replay": True,''',
    '''                "refunded_cents": int(prior.get("amount_cents", 0) or 0),
                "creator_clawback_cents": int(prior.get("creator_clawback_cents", 0) or 0),
                "platform_reversal_cents": int(prior.get("platform_reversal_cents", 0) or 0),
                "treasury_debit_cents": int(prior.get("treasury_debit_cents", 0) or 0),
                "is_syndicate_split": bool(prior.get("is_syndicate_split")),
                "syndicate_id": str(prior.get("syndicate_id", "") or ""),
                "idempotent_replay": True,''',
)

# (v) clawback amount -> member_clawback
add(
    "app/services/ad_billing.py",
    "    if creator_id and member_clawback > 0:",
    '''    if creator_id and creator_share > 0:
        try:
            _sk, clawback_item = new_ledger_entry(
                key_name="pk", key_value=user_pk(creator_id),
                entry_type="ad_revenue_reversal",  # != "credit"
                amount_cents=creator_share, state="settled",''',
    '''    if creator_id and member_clawback > 0:
        try:
            _sk, clawback_item = new_ledger_entry(
                key_name="pk", key_value=user_pk(creator_id),
                entry_type="ad_revenue_reversal",  # != "credit"
                amount_cents=member_clawback, state="settled",''',
)

# (vi) new step 7: debit treasury back, before the final logger
add(
    "app/services/ad_billing.py",
    "# 7. ADV2-RES R1: syndicate 3-way -> debit the treasury the placement share",
    '''    logger.info(
        "ad_charge_reversed account=%s entry=%s amount=%s creator=%s clawback=%s",
        account_id, entry_id, amount_cents, creator_id or "-", creator_share,
    )
    return _receipt(False)''',
    '''    # 7. ADV2-RES R1: syndicate 3-way -> debit the treasury the placement share
    #    it was credited at charge time (mirrors credit_placement_earning, sign
    #    flipped). Non-syndicate reversals never touch a treasury.
    if is_syndicate_split and treasury_share > 0 and split_syndicate_id:
        try:
            from app.services import syndicate_treasury as _tres_rev
            _tres_rev.debit_placement_earning(
                syndicate_id=split_syndicate_id, amount_cents=treasury_share,
                member_user_id=creator_id, account_id=account_id,
                campaign_id=campaign_id, reversal_of=entry_id,
            )
            treasury_debited = treasury_share
        except Exception:
            logger.warning(
                "ad_reversal_treasury_debit_failed syndicate=%s", split_syndicate_id
            )

    logger.info(
        "ad_charge_reversed account=%s entry=%s amount=%s creator=%s "
        "member_clawback=%s treasury_debit=%s",
        account_id, entry_id, amount_cents, creator_id or "-",
        member_clawback, treasury_debited,
    )
    return _receipt(False)''',
)

# ---------------------------------------------------------------------------
# R2: AdClicks.charged_cents == the real charge, across all surfaces
# ---------------------------------------------------------------------------
# (a) newsfeed impression/click (track_ad_event)
add(
    "app/services/ad_serving.py",
    'UpdateExpression="SET #s = :s, "\n                            "charged_cents = if_not_exists(charged_cents, :z) + :cc",',
    '''                    T.ad_clicks.update_item(
                        Key={"ad_click_id": ad_click_id},
                        UpdateExpression="SET #s = :s",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={
                            ":s": "clicked" if event == "click" else "impressed"
                        },
                    )''',
    '''                    T.ad_clicks.update_item(
                        Key={"ad_click_id": ad_click_id},
                        UpdateExpression="SET #s = :s, "
                            "charged_cents = if_not_exists(charged_cents, :z) + :cc",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={
                            ":s": "clicked" if event == "click" else "impressed",
                            ":z": 0, ":cc": charge_cents,
                        },
                    )''',
)

# (b) CTA tap (record_cta_click) -> stamp charged_cents after charge
add(
    "app/services/ad_serving.py",
    "# ADV2-RES R2: stamp the real charged amount on the AdClicks row (CTA)",
    '''            charge_cents = int(res.get("charge_cents", 0) or 0)
            reason = str(res.get("reason", "") or "")
        except Exception:
            logger.warning("cta_click_charge_failed click=%s cta=%s", ad_click_id, cta_type)
            reason = "charge_error"

    return {''',
    '''            charge_cents = int(res.get("charge_cents", 0) or 0)
            reason = str(res.get("reason", "") or "")
        except Exception:
            logger.warning("cta_click_charge_failed click=%s cta=%s", ad_click_id, cta_type)
            reason = "charge_error"

    # ADV2-RES R2: stamp the real charged amount on the AdClicks row (CTA).
    # Accumulate; a duplicate CTA charge returns 0 so it never double-counts.
    if charge_cents > 0:
        try:
            T.ad_clicks.update_item(
                Key={"ad_click_id": ad_click_id},
                UpdateExpression="SET charged_cents = if_not_exists(charged_cents, :z) + :cc",
                ExpressionAttributeValues={":z": 0, ":cc": charge_cents},
            )
        except Exception:
            logger.warning("cta_click_charged_cents_stamp_failed click=%s", ad_click_id)

    return {''',
)

# (c) VOD pre-roll completion -> don't clobber charged_cents to 0 on duplicate
add(
    "app/services/vod_ad_supported.py",
    '_upd = "SET #s = :s, completed_at = :t"',
    '''        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression="SET #s = :s, charged_cents = :c, completed_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "completed",
                ":c": int(result.get("charge_cents", 0)) if result.get("ok") else 0,
                ":t": now_ts(),
            },
        )''',
    '''        # ADV2-RES R2: only write charged_cents on a REAL charge (>0); a
        # duplicate completion returns charge_cents=0 and must NOT clobber the
        # already-stamped real amount back to 0.
        _cc = int(result.get("charge_cents", 0) or 0) if result.get("ok") else 0
        _upd = "SET #s = :s, completed_at = :t"
        _vals = {":s": "completed", ":t": now_ts()}
        if _cc > 0:
            _upd += ", charged_cents = if_not_exists(charged_cents, :z) + :cc"
            _vals[":z"] = 0
            _vals[":cc"] = _cc
        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression=_upd,
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=_vals,
        )''',
)

# (d) broadcast pre/mid-roll completion -> same clobber fix
add(
    "app/services/broadcast_ads.py",
    '_upd = "SET #s = :s, completed_at = :t"',
    '''        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression="SET #s = :s, charged_cents = :c, completed_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "completed",
                ":c": int(result.get("charge_cents", 0)) if result.get("ok") else 0,
                ":t": now_ts(),
            },
        )''',
    '''        # ADV2-RES R2: only write charged_cents on a REAL charge (>0); a
        # duplicate completion returns charge_cents=0 and must NOT clobber the
        # already-stamped real amount back to 0.
        _cc = int(result.get("charge_cents", 0) or 0) if result.get("ok") else 0
        _upd = "SET #s = :s, completed_at = :t"
        _vals = {":s": "completed", ":t": now_ts()}
        if _cc > 0:
            _upd += ", charged_cents = if_not_exists(charged_cents, :z) + :cc"
            _vals[":z"] = 0
            _vals[":cc"] = _cc
        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression=_upd,
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=_vals,
        )''',
)

# (e) conversion (attribute_conversion) -> stamp charged_cents after CPA charge
add(
    "app/services/ad_attribution.py",
    "# ADV2-RES R2: stamp the real CPA charge on the AdClicks row.",
    '''            result["charge"] = charge
        except Exception:
            logger.warning("ad_conversion_charge_failed click=%s", resolved_click_id, exc_info=True)''',
    '''            result["charge"] = charge
            # ADV2-RES R2: stamp the real CPA charge on the AdClicks row.
            _cc = int(charge.get("charge_cents", 0) or 0) if charge.get("ok") else 0
            if _cc > 0:
                try:
                    T.ad_clicks.update_item(
                        Key={"ad_click_id": resolved_click_id},
                        UpdateExpression="SET charged_cents = if_not_exists(charged_cents, :z) + :cc",
                        ExpressionAttributeValues={":z": 0, ":cc": _cc},
                    )
                except Exception:
                    logger.warning(
                        "ad_conversion_charged_cents_stamp_failed click=%s",
                        resolved_click_id,
                    )
        except Exception:
            logger.warning("ad_conversion_charge_failed click=%s", resolved_click_id, exc_info=True)''',
)


def main():
    touched = {}
    results = []
    for relpath, sentinel, old, new in PATCHES:
        p = os.path.join(ROOT, relpath)
        text = touched.get(p) or _read(p)
        if sentinel in text:
            results.append("ALREADY_APPLIED %s :: %s" % (relpath, sentinel[:48]))
            touched[p] = text
            continue
        cnt = text.count(old)
        if cnt != 1:
            print("ERROR anchor count=%d (need 1) in %s :: %s" % (cnt, relpath, sentinel[:48]))
            sys.exit(2)
        text = text.replace(old, new, 1)
        touched[p] = text
        results.append("PATCHED %s :: %s" % (relpath, sentinel[:48]))

    for p, text in touched.items():
        _write(p, text)

    for p in sorted(touched):
        py_compile.compile(p, doraise=True)

    for r in results:
        print(r)
    print("PY_COMPILE_OK files=%d" % len(touched))
    print("APPLY_DONE")


if __name__ == "__main__":
    main()
