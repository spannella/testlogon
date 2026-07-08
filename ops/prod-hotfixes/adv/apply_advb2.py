#!/usr/bin/env python3
"""ADV-B2 (ADV-201 + ADV-203) surgical hotfix patcher.

Applies identical edits to app/services/vod_ad_supported.py and
app/services/ad_billing.py under the target repo root (argv[1], default cwd).
Idempotent: re-running is a no-op. Verifies each anchor matches exactly once.
"""
import sys, io, os, py_compile

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

def patch(path, edits, sentinel):
    with io.open(path, "r", encoding="utf-8") as f:
        src = f.read()
    if sentinel in src:
        print("SKIP (already patched):", path)
        return
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise SystemExit("ANCHOR MATCH=%d (expected 1) in %s for:\n%s" % (n, path, old[:200]))
        src = src.replace(old, new)
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    py_compile.compile(path, doraise=True)
    print("PATCHED:", path)


# ---------------- vod_ad_supported.py ----------------
VOD = os.path.join(ROOT, "app/services/vod_ad_supported.py")

vod_edits = []

vod_edits.append((
'''    deterministic = bool(getattr(S, "vod_ad_supported_deterministic", True)) or S.dev_mode
''',
'''    # ADV-201: decouple the pre-roll gate from dev_mode. The platform runs
    # DEV_MODE=1 (moto S3 / stripe-mock) everywhere, so ORing dev_mode forced
    # the deterministic placeholder forever. Gate on the flag ONLY, so setting
    # vod_ad_supported_deterministic=false enables the LIVE serve_ad path.
    deterministic = bool(getattr(S, "vod_ad_supported_deterministic", True))
'''))

vod_edits.append((
'''        if not deterministic:
            # Wire the live ad engine for actual creative selection.
            try:
                from app.services.ad_serving import serve_ad

                served = serve_ad(
                    surface="vod",
                    content_type="vod",
                    creator_id=video.owner_user_id,
                    content_id=video.video_id,
                    slot_type=slot.get("type", "pre_roll"),
                    user_id=user_id,
                )
                if served.get("filled"):
                    creative_id = served.get("creative_id", creative_id) or creative_id
                    creative_url = (
                        served.get("video_url")
                        or served.get("image_url")
                        or creative_url
                    )
            except Exception:
                logger.warning(
                    "vod_ad_supported_serve_failed video=%s user=%s",
                    video.video_id,
                    user_id,
                )

        schedule.append(
            {
                "break_id": f"adbrk_{uuid.uuid4().hex[:12]}",
                "slot_type": slot.get("type", "pre_roll"),
                "position_seconds": int(slot.get("timestamp_seconds", 0)),
                "duration_seconds": int(slot.get("duration_seconds", 15)),
                "creative_id": creative_id,
                "creative_url": creative_url,
                "creative_type": creative_type,
                "skip_after_seconds": int(slot.get("skip_after_seconds", 5)),
                "slot_index": int(slot.get("slot_index", 0)),
                "completed": False,
            }
        )
''',
'''        ad_click_id = ""

        if not deterministic:
            # ADV-201: wire the LIVE ad engine for pre-roll creative selection.
            # surface="preroll" so the minted AdClicks row carries the pre-roll
            # surface and content_owner_sub = the VIDEO creator (the poster);
            # ADV-203 reads that row on completion to charge the advertiser and
            # credit the poster. A house/unfilled response falls back to the
            # deterministic placeholder so a no-fill never blocks playback.
            try:
                from app.services.ad_serving import serve_ad

                served = serve_ad(
                    surface="preroll",
                    content_type="vod",
                    creator_id=video.owner_user_id,
                    content_id=video.video_id,
                    slot_type=slot.get("type", "pre_roll"),
                    user_id=user_id,
                    content_owner_id=video.owner_user_id,
                )
                if served.get("filled") and not served.get("is_house_ad"):
                    creative_id = served.get("creative_id", creative_id) or creative_id
                    if served.get("video_url"):
                        creative_url = served.get("video_url")
                        creative_type = "video"
                    elif served.get("image_url"):
                        creative_url = served.get("image_url")
                        creative_type = "image"
                    ad_click_id = served.get("ad_click_id", "") or ""
            except Exception:
                logger.warning(
                    "vod_ad_supported_serve_failed video=%s user=%s",
                    video.video_id,
                    user_id,
                )

        schedule.append(
            {
                "break_id": f"adbrk_{uuid.uuid4().hex[:12]}",
                "slot_type": slot.get("type", "pre_roll"),
                "position_seconds": int(slot.get("timestamp_seconds", 0)),
                "duration_seconds": int(slot.get("duration_seconds", 15)),
                "creative_id": creative_id,
                "creative_url": creative_url,
                "creative_type": creative_type,
                "skip_after_seconds": int(slot.get("skip_after_seconds", 5)),
                "slot_index": int(slot.get("slot_index", 0)),
                "ad_click_id": ad_click_id,
                "completed": False,
            }
        )
'''))

vod_edits.append((
'''def report_break(
    *,
    user_id: str,
    video_id: str,
''',
'''def _charge_preroll_completion(
    *, target: Dict[str, Any], video_id: str
) -> Optional[Dict[str, Any]]:
    """ADV-203: charge the advertiser for a completed paid pre-roll + credit poster.

    Reads the AdClicks row minted at serve time (authoritative account /
    campaign / content-owner / cleared price) and runs the funds-guarded
    ``ad_billing._process_charge``, which debits the advertiser balance and,
    via ``_split_revenue``, credits the video's ORIGINAL POSTER
    (``content_owner_sub``) their share (~70%) plus the platform (~30%).

    Idempotent per ``ad_click_id`` (``_process_charge`` idempotency marker), so
    a duplicate completion never double-charges. Returns the charge result, or
    None when there is nothing to charge (no ad_click_id / missing click row).
    """
    ad_click_id = target.get("ad_click_id", "")
    if not ad_click_id:
        return None
    try:
        row = T.ad_clicks.get_item(Key={"ad_click_id": ad_click_id}).get("Item")
    except Exception:
        logger.warning("vod_ad_preroll_click_read_failed ad_click_id=%s", ad_click_id)
        return None
    if not row:
        logger.warning("vod_ad_preroll_click_missing ad_click_id=%s", ad_click_id)
        return None

    account_id = row.get("account_id", "")
    campaign_id = row.get("campaign_id", "")
    if not account_id or not campaign_id:
        return None
    creative_id = row.get("creative_id", "") or target.get("creative_id", "")
    content_owner = row.get("content_owner_sub", "")
    charge_cents = int(row.get("effective_price_cents", 0) or 0)
    if charge_cents <= 0:
        charge_cents = int(getattr(S, "vod_ad_cpm_cents", 500) or 500)

    from app.services.ad_billing import _process_charge

    result = _process_charge(
        account_id=account_id,
        campaign_id=campaign_id,
        entry_type="impression_charge",
        charge_cents=charge_cents,
        creator_id=content_owner,
        reason="VOD pre-roll impression",
        meta={
            "creative_id": creative_id,
            "content_id": video_id,
            "model": "cpm",
            "surface": "preroll",
            "ad_click_id": ad_click_id,
        },
        idempotency_key=f"preroll:{ad_click_id}",
    )

    # Best-effort audit stamp on the AdClicks row.
    try:
        T.ad_clicks.update_item(
            Key={"ad_click_id": ad_click_id},
            UpdateExpression="SET #s = :s, charged_cents = :c, completed_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "completed",
                ":c": int(result.get("charge_cents", 0)) if result.get("ok") else 0,
                ":t": now_ts(),
            },
        )
    except Exception:
        pass

    logger.info(
        "vod_ad_preroll_charged ad_click_id=%s account=%s campaign=%s result=%s",
        ad_click_id, account_id, campaign_id, result,
    )
    return result


def report_break(
    *,
    user_id: str,
    video_id: str,
'''))

vod_edits.append((
'''    if event_type == EVENT_COMPLETE:
        target["completed"] = True
''',
'''    was_completed = bool(target.get("completed", False))
    if event_type == EVENT_COMPLETE:
        target["completed"] = True
'''))

vod_edits.append((
'''    except Exception:
        logger.warning(
            "vod_ad_supported_track_failed video=%s break=%s", video_id, break_id
        )

    return {
        "ok": True,
        "session_id": item.get("session_id", ""),
''',
'''    except Exception:
        logger.warning(
            "vod_ad_supported_track_failed video=%s break=%s", video_id, break_id
        )

    # ADV-203: on a completed PAID pre-roll, charge the advertiser (CPM, funds-
    # guarded) and credit the video POSTER their share via _split_revenue. Only
    # fires on the completion transition (not a re-report) and only when the
    # break carries an ad_click_id (a real paid fill, not the placeholder).
    if event_type == EVENT_COMPLETE and not was_completed and target.get("ad_click_id"):
        try:
            _charge_preroll_completion(target=target, video_id=video_id)
        except Exception:
            logger.warning(
                "vod_ad_preroll_charge_failed video=%s break=%s", video_id, break_id
            )

    return {
        "ok": True,
        "session_id": item.get("session_id", ""),
'''))

patch(VOD, vod_edits, sentinel="_charge_preroll_completion")


# ---------------- ad_billing.py ----------------
BILL = os.path.join(ROOT, "app/services/ad_billing.py")

bill_edits = []

bill_edits.append((
'''def charge_impression(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpm_cents: int,
) -> dict:
    """Charge advertiser for one impression (CPM model)."""
    charge_cents = max(1, bid_cpm_cents // 1000)
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="impression_charge", charge_cents=charge_cents,
        creator_id=creator_id, reason="Ad impression",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpm"},
    )
''',
'''def charge_impression(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpm_cents: int,
    idempotency_key: str = "",
) -> dict:
    """Charge advertiser for one impression (CPM model)."""
    charge_cents = max(1, bid_cpm_cents // 1000)
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="impression_charge", charge_cents=charge_cents,
        creator_id=creator_id, reason="Ad impression",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpm"},
        idempotency_key=idempotency_key,
    )
'''))

bill_edits.append((
'''def _process_charge(
    *, account_id: str, campaign_id: str, entry_type: str,
    charge_cents: int, creator_id: str, reason: str, meta: dict,
) -> dict:
''',
'''def _process_charge(
    *, account_id: str, campaign_id: str, entry_type: str,
    charge_cents: int, creator_id: str, reason: str, meta: dict,
    idempotency_key: str = "",
) -> dict:
'''))

bill_edits.append((
'''    ts = now_ts()
    entry_id = f"chg_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # 1. Debit advertiser balance FIRST, funds-guarded so it can never go negative.
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression="SET balance_cents = balance_cents - :amt, "
                             "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) + :amt",
            ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt",
            ExpressionAttributeValues={":amt": charge_cents, ":z": 0},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info(
                "ad_charge_insufficient_funds account=%s campaign=%s amount=%s",
                account_id, campaign_id, charge_cents,
            )
            return {"ok": False, "reason": "insufficient_funds", "charge_cents": charge_cents}
        raise
''',
'''    ts = now_ts()
    entry_id = f"chg_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # ADV-203: idempotency guard. When an idempotency_key is supplied (e.g. a VOD
    # pre-roll completion keyed on ad_click_id) claim a marker BEFORE the debit so
    # a duplicate completion never double-charges. The marker omits campaign_id /
    # month_key so it stays out of the sparse ByCampaign/ByMonth GSIs and the
    # LEDGER# history query. On insufficient funds it is released so a later retry
    # (after the account is funded) can still charge exactly once.
    if idempotency_key:
        try:
            T.ad_billing.put_item(
                Item={
                    "pk": f"ACCT#{account_id}",
                    "sk": f"IDEMP#{idempotency_key}",
                    "entry_type": "charge_idempotency",
                    "created_at": ts,
                },
                ConditionExpression="attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logger.info(
                    "ad_charge_duplicate account=%s key=%s", account_id, idempotency_key
                )
                return {"ok": True, "reason": "duplicate", "charge_cents": 0}
            raise

    # 1. Debit advertiser balance FIRST, funds-guarded so it can never go negative.
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression="SET balance_cents = balance_cents - :amt, "
                             "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) + :amt",
            ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt",
            ExpressionAttributeValues={":amt": charge_cents, ":z": 0},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info(
                "ad_charge_insufficient_funds account=%s campaign=%s amount=%s",
                account_id, campaign_id, charge_cents,
            )
            if idempotency_key:
                try:
                    T.ad_billing.delete_item(
                        Key={"pk": f"ACCT#{account_id}", "sk": f"IDEMP#{idempotency_key}"}
                    )
                except Exception:
                    pass
            return {"ok": False, "reason": "insufficient_funds", "charge_cents": charge_cents}
        raise
'''))

patch(BILL, bill_edits, sentinel="ADV-203: idempotency guard")

print("ALL_PATCHES_OK")
