#!/usr/bin/env python3
"""ADV-B5 apply script (ADV-501 ROAS + ADV-502 reversal + ADV-504 test seam).

Idempotent, anchor-based text edits so it runs identically on the dev clone and
prod (the only dev/prod divergence in these files is comments; every anchor
below is a stable code line). Usage: python apply_advb5.py <repo_root>
"""
import io
import sys

ROOT = sys.argv[1].rstrip("/")


def _read(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)


def patch(path, edits, sentinel):
    p = "%s/%s" % (ROOT, path)
    s = _read(p)
    if sentinel in s:
        print("SKIP (already applied):", path)
        return
    for old, new in edits:
        n = s.count(old)
        if n != 1:
            raise SystemExit("ANCHOR NOT UNIQUE (%d) in %s:\n%s" % (n, path, old[:160]))
        s = s.replace(old, new)
    _write(p, s)
    print("PATCHED:", path)


# ---------------------------------------------------------------------------
# 1) app/services/ad_billing.py
# ---------------------------------------------------------------------------
AB = []

# 1a. charge_conversion gains conversion_value_cents (ADV-501: attributed value
#     recorded on the conversion_charge ledger row so ROAS reads one source).
AB.append((
'''def charge_conversion(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpa_cents: int,
    idempotency_key: str = "",
) -> dict:
    """Charge advertiser for one conversion (CPA model)."""
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="conversion_charge", charge_cents=bid_cpa_cents,
        creator_id=creator_id, reason="Ad conversion",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpa"},
        idempotency_key=idempotency_key,
    )''',
'''def charge_conversion(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpa_cents: int,
    idempotency_key: str = "", conversion_value_cents: int = 0,
) -> dict:
    """Charge advertiser for one conversion (CPA model).

    ADV-501: conversion_value_cents (the revenue the conversion drove -- e.g. the
    subscription/purchase price) is recorded on the ledger meta so the ROAS
    report can aggregate attributed value straight from the money path.
    """
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="conversion_charge", charge_cents=bid_cpa_cents,
        creator_id=creator_id, reason="Ad conversion",
        meta={
            "creative_id": creative_id, "content_id": content_id, "model": "cpa",
            "conversion_value_cents": int(conversion_value_cents or 0),
        },
        idempotency_key=idempotency_key,
    )'''))

# 1b. _process_charge: reorder (campaign bump + split BEFORE the ledger write) and
#     denormalize the split detail onto the charge row so ADV-502 reversal is exact.
AB.append((
'''    # 2. Write charge to ad_billing ledger (only after a successful debit)
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "entry_type": entry_type,
        "amount_cents": charge_cents,
        "state": "settled",
        "reason": reason,
        "meta": meta,
        "month_key": month_key,
        "created_at": ts,
    })

    # 3. Increment campaign spend
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                         "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
    )

    # 4. Revenue split
    _split_revenue(
        charge_cents=charge_cents, creator_id=creator_id,
        account_id=account_id, meta=meta, ts=ts,
    )

    # 5. Budget check + spending alerts
    _check_budget_and_alert(account_id, campaign_id)

    return {"ok": True, "entry_id": entry_id, "charge_cents": charge_cents}''',
'''    # 2. Increment campaign spend
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                         "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
    )

    # 3. Revenue split. Returns the split detail (per-party shares + credit-row
    #    pointers) so it can be denormalized onto the charge ledger row -> the
    #    ADV-502 reversal can back the split out precisely + self-contained.
    split = _split_revenue(
        charge_cents=charge_cents, creator_id=creator_id,
        account_id=account_id, meta=meta, ts=ts,
    ) or {}

    # 4. Write charge to ad_billing ledger (only after a successful debit).
    ledger_meta = {
        **meta,
        "creator_id": creator_id,
        "creator_share_cents": int(split.get("creator_share_cents", 0)),
        "platform_share_cents": int(split.get("platform_share_cents", 0)),
        "creator_credit_sk": split.get("creator_credit_sk", ""),
        "creator_credit_ts": int(split.get("creator_credit_ts", 0)),
        "platform_entry_sk": split.get("platform_entry_sk", ""),
    }
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "entry_type": entry_type,
        "amount_cents": charge_cents,
        "state": "settled",
        "reason": reason,
        "meta": ledger_meta,
        "month_key": month_key,
        "created_at": ts,
    })

    # 5. Budget check + spending alerts
    _check_budget_and_alert(account_id, campaign_id)

    return {"ok": True, "entry_id": entry_id, "charge_cents": charge_cents}'''))

# 1c. _split_revenue -> return the split detail.
AB.append((
'''def _split_revenue(
    *, charge_cents: int, creator_id: str, meta: dict, ts: int, account_id: str = "",
) -> None:''',
'''def _split_revenue(
    *, charge_cents: int, creator_id: str, meta: dict, ts: int, account_id: str = "",
) -> dict:'''))

AB.append((
'''    platform_share_pct = (
        (platform_share * 100) // charge_cents if charge_cents > 0 else PLATFORM_REVENUE_SHARE_PCT
    )

    # Credit creator via existing billing ledger''',
'''    platform_share_pct = (
        (platform_share * 100) // charge_cents if charge_cents > 0 else PLATFORM_REVENUE_SHARE_PCT
    )

    # ADV-502: capture the credit-row pointers so a later reversal can back them
    # out precisely (creator clawback + platform reversal).
    creator_credit_sk = ""
    creator_credit_ts = 0
    platform_entry_sk = ""

    # Credit creator via existing billing ledger'''))

AB.append((
'''            T.billing.put_item(Item=credit_item)
        except Exception:
            logger.warning("ad_revenue_creator_credit_failed", extra={"creator_id": creator_id})''',
'''            T.billing.put_item(Item=credit_item)
            creator_credit_sk = _sk
            creator_credit_ts = int(credit_item.get("ts", ts))
        except Exception:
            logger.warning("ad_revenue_creator_credit_failed", extra={"creator_id": creator_id})'''))

AB.append((
'''            entry_id = f"rev_{uuid.uuid4().hex[:12]}"
            month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
            T.ad_billing.put_item(Item={
                "pk": "PLATFORM#revenue",
                "sk": f"LEDGER#{ts}#{entry_id}",''',
'''            entry_id = f"rev_{uuid.uuid4().hex[:12]}"
            month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
            platform_entry_sk = f"LEDGER#{ts}#{entry_id}"
            T.ad_billing.put_item(Item={
                "pk": "PLATFORM#revenue",
                "sk": platform_entry_sk,'''))

AB.append((
'''            logger.warning("ad_revenue_platform_credit_failed", extra={"charge_cents": charge_cents})


def _check_budget_and_alert(account_id: str, campaign_id: str) -> None:''',
'''            logger.warning("ad_revenue_platform_credit_failed", extra={"charge_cents": charge_cents})

    return {
        "creator_id": creator_id,
        "creator_share_cents": creator_share,
        "platform_share_cents": platform_share,
        "creator_credit_sk": creator_credit_sk,
        "creator_credit_ts": creator_credit_ts,
        "platform_entry_sk": platform_entry_sk,
        "revenue_share_bps": creator_bps,
    }


def _check_budget_and_alert(account_id: str, campaign_id: str) -> None:'''))

# 1d. Append reverse_ad_charge + _find_charge_entry at the very end.
AB.append((
'''def _get_balance(account_id: str) -> int:
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    item = resp.get("Item")
    return int(item.get("balance_cents", 0)) if item else 0''',
'''def _get_balance(account_id: str) -> int:
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    item = resp.get("Item")
    return int(item.get("balance_cents", 0)) if item else 0


# ---------------------------------------------------------------------------
# ADV-502 -- ad-charge refund / reversal (fraud clawback / dispute).
# ---------------------------------------------------------------------------
_REVERSIBLE_ENTRY_TYPES = ("impression_charge", "click_charge", "conversion_charge")


def _find_charge_entry(account_id: str, entry_id: str) -> Optional[dict]:
    """Locate a settled charge ledger row by entry_id under an account (paginated)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"ACCT#{account_id}") & Key("sk").begins_with("LEDGER#")
        ),
        "FilterExpression": Attr("entry_id").eq(entry_id),
    }
    while True:
        resp = T.ad_billing.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            return items[0]
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            return None
        kwargs["ExclusiveStartKey"] = lek


def reverse_ad_charge(
    *, account_id: str, entry_id: str, reason: str = "admin_reversal",
    actor: str = "", entry: Optional[dict] = None,
) -> dict:
    """ADV-502: idempotently reverse a settled ad charge.

    Refunds the advertiser balance, backs the charge out of campaign spend, writes
    a ``charge_reversal`` row to the ad_billing ledger, and reverses the revenue
    split: the creator credit is clawed back with entry_type != "credit" (so it can
    NEVER inflate creator earnings -- creator_earnings only sums type=="credit") and
    the original credit row is flipped to state="reversed"; the platform revenue
    record is reversed too. A ``REVERSAL#{entry_id}`` marker (claimed with
    attribute_not_exists) makes it idempotent + guards double-reversal: a second
    call is a no-op returning the stored receipt. Mirrors the TIP-502 pattern.
    """
    from fastapi import HTTPException

    entry = entry or _find_charge_entry(account_id, entry_id)
    if not entry:
        raise HTTPException(404, {"code": "charge_not_found",
                                  "message": f"No ad charge {entry_id} on account {account_id}."})
    etype = str(entry.get("entry_type", ""))
    if etype not in _REVERSIBLE_ENTRY_TYPES:
        raise HTTPException(400, {"code": "not_reversible",
                                  "message": f"Entry {entry_id} ({etype}) is not a reversible charge."})

    amount_cents = int(entry.get("amount_cents", 0) or 0)
    campaign_id = str(entry.get("campaign_id", "") or "")
    emeta = entry.get("meta", {}) or {}
    creator_id = str(emeta.get("creator_id", "") or "")
    creator_share = int(emeta.get("creator_share_cents", 0) or 0)
    platform_share = int(emeta.get("platform_share_cents", 0) or 0)
    creator_credit_sk = str(emeta.get("creator_credit_sk", "") or "")
    platform_entry_sk = str(emeta.get("platform_entry_sk", "") or "")

    ts = now_ts()
    reversal_entry_id = f"rev_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    def _receipt(replay: bool) -> dict:
        return {
            "ok": True, "reversed": True, "entry_id": entry_id,
            "reversal_entry_id": reversal_entry_id, "account_id": account_id,
            "campaign_id": campaign_id, "refunded_cents": amount_cents,
            "creator_clawback_cents": creator_share if creator_id else 0,
            "platform_reversal_cents": platform_share,
            "idempotent_replay": replay,
        }

    # 1. Claim the reversal marker FIRST -> idempotency + double-reversal guard
    #    (kept out of the LEDGER# history query; mirrors the IDEMP# marker).
    try:
        T.ad_billing.put_item(
            Item={
                "pk": f"ACCT#{account_id}", "sk": f"REVERSAL#{entry_id}",
                "entry_type": "charge_reversal_marker", "reversal_of": entry_id,
                "reversal_entry_id": reversal_entry_id, "amount_cents": amount_cents,
                "creator_clawback_cents": creator_share if creator_id else 0,
                "platform_reversal_cents": platform_share, "campaign_id": campaign_id,
                "created_at": ts,
            },
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            prior = T.ad_billing.get_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"REVERSAL#{entry_id}"}
            ).get("Item", {}) or {}
            logger.info("ad_charge_reversal_duplicate account=%s entry=%s", account_id, entry_id)
            return {
                "ok": True, "reversed": True, "entry_id": entry_id,
                "reversal_entry_id": str(prior.get("reversal_entry_id", "")),
                "account_id": account_id, "campaign_id": str(prior.get("campaign_id", "")),
                "refunded_cents": int(prior.get("amount_cents", 0) or 0),
                "creator_clawback_cents": int(prior.get("creator_clawback_cents", 0) or 0),
                "platform_reversal_cents": int(prior.get("platform_reversal_cents", 0) or 0),
                "idempotent_replay": True,
            }
        raise

    # 2. Refund the advertiser balance + back the charge out of lifetime spend.
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
                             "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) - :amt",
            ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
        )
    except ClientError:
        try:
            T.ad_billing.delete_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"REVERSAL#{entry_id}"}
            )
        except Exception:
            pass
        raise

    # 3. Back the charge out of campaign spend (best-effort).
    if campaign_id:
        try:
            T.ad_campaigns.update_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
                UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) - :amt, "
                                 "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) - :amt",
                ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
            )
        except Exception:
            logger.warning("ad_reversal_campaign_backout_failed campaign=%s", campaign_id)

    # 4. Write the reversal row to the ad_billing ledger (audit/history).
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}", "sk": f"LEDGER#{ts}#{reversal_entry_id}",
        "entry_id": reversal_entry_id, "account_id": account_id,
        "campaign_id": campaign_id, "entry_type": "charge_reversal",
        "amount_cents": amount_cents, "state": "settled",
        "reason": f"Charge reversal ({reason})",
        "meta": {
            "reversal_of": entry_id, "reversal_reason": reason, "reversal_actor": actor,
            "original_entry_type": etype, "creator_id": creator_id,
            "creator_clawback_cents": creator_share if creator_id else 0,
            "platform_reversal_cents": platform_share,
        },
        "month_key": month_key, "created_at": ts,
    })

    # 5. Claw back the creator revenue credit WITHOUT inflating earnings:
    #    entry_type != "credit" (creator_earnings only sums type=="credit"), and
    #    flip the original credit row to state="reversed".
    if creator_id and creator_share > 0:
        try:
            _sk, clawback_item = new_ledger_entry(
                key_name="pk", key_value=user_pk(creator_id),
                entry_type="ad_revenue_reversal",  # != "credit"
                amount_cents=creator_share, state="settled",
                reason="Ad revenue reversal",
                meta={"reversal_of": entry_id, "reversal_reason": reason,
                      "account_id": account_id, "campaign_id": campaign_id},
            )
            T.billing.put_item(Item=clawback_item)
        except Exception:
            logger.warning("ad_reversal_creator_clawback_failed creator=%s", creator_id)
        if creator_credit_sk:
            try:
                T.billing.update_item(
                    Key={"pk": user_pk(creator_id), "sk": creator_credit_sk},
                    UpdateExpression="SET #s = :r",
                    ConditionExpression="attribute_exists(sk)",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":r": "reversed"},
                )
            except Exception:
                logger.warning("ad_reversal_credit_flip_failed creator=%s", creator_id)

    # 6. Reverse the platform revenue record (audit symmetry).
    if platform_share > 0:
        try:
            prev_id = f"rev_{uuid.uuid4().hex[:12]}"
            T.ad_billing.put_item(Item={
                "pk": "PLATFORM#revenue", "sk": f"LEDGER#{ts}#{prev_id}",
                "entry_id": prev_id, "entry_type": "platform_revenue_reversal",
                "amount_cents": platform_share, "state": "settled",
                "reason": f"Platform ad revenue reversal ({reason})",
                "meta": {"reversal_of": entry_id, "account_id": account_id,
                         "campaign_id": campaign_id},
                "month_key": month_key, "created_at": ts,
            })
        except Exception:
            logger.warning("ad_reversal_platform_backout_failed")
        if platform_entry_sk:
            try:
                T.ad_billing.update_item(
                    Key={"pk": "PLATFORM#revenue", "sk": platform_entry_sk},
                    UpdateExpression="SET #s = :r",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":r": "reversed"},
                )
            except Exception:
                pass

    logger.info(
        "ad_charge_reversed account=%s entry=%s amount=%s creator=%s clawback=%s",
        account_id, entry_id, amount_cents, creator_id or "-", creator_share,
    )
    return _receipt(False)'''))

patch("app/services/ad_billing.py", AB, sentinel="def reverse_ad_charge(")


# ---------------------------------------------------------------------------
# 2) app/services/ad_attribution.py -- pass conversion_value_cents through.
# ---------------------------------------------------------------------------
AT = [(
'''            charge = ad_billing.charge_conversion(
                account_id=str(row.get("account_id", "") or ""),
                campaign_id=str(row.get("campaign_id", "") or ""),
                creative_id=str(row.get("creative_id", "") or ""),
                creator_id=content_owner_sub,
                content_id=str(row.get("content_id", "") or ""),
                bid_cpa_cents=bid_cpa_cents,
                idempotency_key="%s#conversion" % resolved_click_id,
            )''',
'''            charge = ad_billing.charge_conversion(
                account_id=str(row.get("account_id", "") or ""),
                campaign_id=str(row.get("campaign_id", "") or ""),
                creative_id=str(row.get("creative_id", "") or ""),
                creator_id=content_owner_sub,
                content_id=str(row.get("content_id", "") or ""),
                bid_cpa_cents=bid_cpa_cents,
                conversion_value_cents=int(conversion_value_cents or 0),
                idempotency_key="%s#conversion" % resolved_click_id,
            )''')]
patch("app/services/ad_attribution.py", AT, sentinel="conversion_value_cents=int(conversion_value_cents or 0),")


# ---------------------------------------------------------------------------
# 3) app/services/ad_serving.py -- extract the 2nd-price clearing helper (ADV-504).
# ---------------------------------------------------------------------------
AS = []
AS.append((
'''def serve_ad(''',
'''# ADV-302/504: reserve floor for a lone-bidder second-price clear.
_CPM_FLOOR = 50


def clear_second_price(win_cpm, runner_up_cpm, floor=_CPM_FLOOR):
    """Second-price clearing: the winner pays the runner-up bid + 1c, capped at
    its own bid; a lone bidder (runner_up_cpm is None) clears at the reserve
    floor. Always >= 1c and never above the winner's own bid. Behaviour-identical
    to the prior inline logic -- extracted so ADV-504 can assert it directly."""
    if runner_up_cpm is None:
        cleared = floor
    else:
        cleared = min(int(win_cpm), int(runner_up_cpm) + 1)
    return max(1, min(cleared, int(win_cpm)))


def serve_ad('''))

AS.append((
'''    _CPM_FLOOR = 50
    _CPM_DEF, _CPC_DEF, _CPA_DEF = 500, 50, 500
    win_cpm = int(winner["campaign"].get("bid_cpm_cents", _CPM_DEF) or _CPM_DEF)
    if len(candidates) > 1:
        runner_up_cpm = int(round(candidates[1]["score"]))
        cleared_cpm = min(win_cpm, runner_up_cpm + 1)
    else:
        cleared_cpm = _CPM_FLOOR
    cleared_cpm = max(1, min(cleared_cpm, win_cpm))''',
'''    _CPM_DEF, _CPC_DEF, _CPA_DEF = 500, 50, 500
    win_cpm = int(winner["campaign"].get("bid_cpm_cents", _CPM_DEF) or _CPM_DEF)
    runner_up_cpm = int(round(candidates[1]["score"])) if len(candidates) > 1 else None
    cleared_cpm = clear_second_price(win_cpm, runner_up_cpm, _CPM_FLOOR)'''))
patch("app/services/ad_serving.py", AS, sentinel="def clear_second_price(")


# ---------------------------------------------------------------------------
# 4) app/services/ad_roas.py -- ADV-501 per-account/per-campaign ROAS report.
# ---------------------------------------------------------------------------
ROAS_FUNC = '''

def roas_report(account_id, campaign_id=None, days: int = 30):
    """ADV-501: per-account + per-campaign ROAS report sourced from the ad_billing
    ledger (the single money-path source of truth).

    Aggregates impression/click/conversion CHARGES (spend) and the attributed
    conversion VALUE (recorded on conversion_charge rows as
    meta.conversion_value_cents) then derives impressions, clicks, CTR,
    conversions, CPA and ROAS (= conversion value / spend). When campaign_id is
    given the report is scoped to that campaign; otherwise the account total plus
    a per-campaign breakdown is returned. Returns:
        {account_id, campaign_id, days, computed_at, totals:{...}, campaigns:[...]}
    """
    from boto3.dynamodb.conditions import Key as _Key

    since_ts = now_ts() - days * 86400
    buckets: Dict[str, Dict[str, int]] = {}

    def _bucket(cid: str) -> Dict[str, int]:
        return buckets.setdefault(cid, {
            "impressions": 0, "clicks": 0, "conversions": 0,
            "spend_cents": 0, "conversion_value_cents": 0,
        })

    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            _Key("pk").eq(f"ACCT#{account_id}") & _Key("sk").begins_with("LEDGER#")
        ),
    }
    while True:
        resp = T.ad_billing.query(**kwargs)
        for it in resp.get("Items", []):
            if int(it.get("created_at", 0) or 0) < since_ts:
                continue
            et = it.get("entry_type", "")
            if et not in ("impression_charge", "click_charge", "conversion_charge"):
                continue
            cid = str(it.get("campaign_id", "") or "unknown")
            if campaign_id and cid != campaign_id:
                continue
            b = _bucket(cid)
            b["spend_cents"] += int(it.get("amount_cents", 0) or 0)
            if et == "impression_charge":
                b["impressions"] += 1
            elif et == "click_charge":
                b["clicks"] += 1
            elif et == "conversion_charge":
                b["conversions"] += 1
                b["conversion_value_cents"] += int(
                    (it.get("meta", {}) or {}).get("conversion_value_cents", 0) or 0
                )
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    def _derive(cid, b: Dict[str, int]) -> Dict[str, Any]:
        imp, clk, conv = b["impressions"], b["clicks"], b["conversions"]
        spend, value = b["spend_cents"], b["conversion_value_cents"]
        row = {
            "impressions": imp, "clicks": clk, "conversions": conv,
            "spend_cents": spend, "conversion_value_cents": value,
            "ctr_pct": round(clk / imp * 100, 2) if imp > 0 else 0.0,
            "cpa_cents": round(spend / conv, 2) if conv > 0 else 0.0,
            "roas": round(value / spend, 4) if spend > 0 else 0.0,
        }
        if cid is not None:
            row = {"campaign_id": cid, **row}
        return row

    per_campaign = [_derive(cid, b) for cid, b in sorted(buckets.items())]
    tot = {"impressions": 0, "clicks": 0, "conversions": 0,
           "spend_cents": 0, "conversion_value_cents": 0}
    for b in buckets.values():
        for k in tot:
            tot[k] += b[k]

    return {
        "account_id": account_id,
        "campaign_id": campaign_id,
        "days": days,
        "computed_at": now_ts(),
        "totals": _derive(None, tot),
        "campaigns": per_campaign,
    }
'''

def patch_roas():
    p = "%s/app/services/ad_roas.py" % ROOT
    s = _read(p)
    if "def roas_report(" in s:
        print("SKIP (already applied): app/services/ad_roas.py")
        return
    s = s.rstrip() + "\n" + ROAS_FUNC
    _write(p, s)
    print("PATCHED: app/services/ad_roas.py")

patch_roas()


# ---------------------------------------------------------------------------
# 5) app/routers/ads.py -- ROAS endpoint + admin reversal endpoint.
# ---------------------------------------------------------------------------
ADS = []
ADS.append((
'''@router.get("/analytics/timeseries")''',
'''@router.get("/roas")
async def roas_report_endpoint(
    account_id: str = Query(...),
    campaign_id: str | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    ctx=Depends(require_ui_session),
):
    """ADV-501: per-account + per-campaign ROAS (spend / impressions / clicks /
    CTR / conversions / CPA / ROAS) sourced from the ad_billing ledger."""
    from app.services.ad_roas import roas_report
    _require_account_owner(account_id, ctx["user_sub"])
    return roas_report(account_id, campaign_id, days)


@router.get("/analytics/timeseries")'''))

ADS.append((
'''# ── Ad Analytics (ADS-008) ''',
'''@admin_router.post("/charges/reverse")
async def internal_reverse_charge(
    body: dict,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """ADV-502: idempotently reverse an ad charge (fraud clawback / dispute)."""
    from app.services.ad_billing import reverse_ad_charge
    actor = getattr(user, "sub", "") or getattr(user, "user_id", "") or ""
    return reverse_ad_charge(
        account_id=body["account_id"],
        entry_id=body["entry_id"],
        reason=body.get("reason", "admin_reversal"),
        actor=actor,
    )


# ── Ad Analytics (ADS-008) '''))
patch("app/routers/ads.py", ADS, sentinel='@router.get("/roas")')

print("ALL_APPLIED_OK")
