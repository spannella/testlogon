"""Broadcast ad breaks service (ADS-006).

Provides:
  * pre-roll / mid-roll ad *selection* (stubbed inline — ADS-002 video creatives
    and ADS-004 ad serving engine do not exist yet, so this returns a deterministic
    house creative)
  * subscriber ad-free resolution
  * ad-break state transitions on the broadcast session
  * ad event tracking (impression / skip / complete / click)

The integration point is the existing broadcast system. Ad-break state lives on the
``broadcast_sessions`` row (fields added by ADS-006); ad events are written to the
``broadcast_ad_events`` table.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from uuid import uuid4

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_store import get_session, update_session_fields
from app.services.broadcast_sse import broadcast_sse_publish

# Allowed mid-roll break durations (seconds)
ALLOWED_MIDROLL_DURATIONS = (15, 30, 60)

# Pre-roll skip is fixed at 5s per ADS-006 spec
PRE_ROLL_SKIP_AFTER_SECONDS = 5


# ─── Subscriber ad-free ─────────────────────────────────────────────


def is_ad_free(viewer_id: str, creator_id: str) -> bool:
    """Return True if the viewer should not see ads on this creator's broadcast.

    The broadcaster themself is always ad-free. Active subscribers of the creator
    are ad-free (subscriber benefit). The check is server-authoritative.
    """
    if viewer_id == creator_id:
        return True
    try:
        from app.services.subscription_access import has_active_subscription

        return has_active_subscription(viewer_id, creator_id)
    except Exception:  # pragma: no cover - never block playback on a check failure
        return False


# ─── Inline ad selection (stub for ADS-004) ─────────────────────────


def serve_broadcast_ad(
    *,
    surface: str,
    creator_id: str,
    content_id: str,
    slot_type: str,
    user_id: str,
) -> Dict[str, Any]:
    """Select an ad for a broadcast surface via the ADS-004 serving engine.

    Delegates to ``app.services.ad_serving.serve_ad`` for targeting, frequency
    caps, and budget enforcement. Falls back to the deterministic house creative
    when the engine raises (e.g. DDB error) or returns an unfilled result, so a
    transient engine failure or empty inventory never breaks broadcast playback.

    Returns a dict with ``filled`` plus creative metadata + tracking URLs.
    """
    try:
        from app.services.ad_serving import serve_ad

        result = serve_ad(
            surface=surface,
            content_type="broadcast",
            creator_id=creator_id,
            content_id=content_id,
            slot_type=slot_type,
            user_id=user_id,
            content_owner_id=creator_id,
        )
        if result.get("filled"):
            return result
    except Exception:  # graceful degradation — never break playback on engine error
        import logging

        logging.getLogger(__name__).warning(
            "serve_broadcast_ad: engine failed, falling back to house creative "
            "(creator=%s content=%s slot=%s)",
            creator_id,
            content_id,
            slot_type,
            exc_info=True,
        )

    # Fallback: deterministic house creative (engine unfilled or errored).
    creative_id = f"bcast_house_{slot_type}"
    return {
        "filled": True,
        "creative_id": creative_id,
        "format": "video",
        "video_url": f"/mock/s3/ad-creatives/{creative_id}.mp4",
        "image_url": None,
        "cta_url": None,
        "impression_url": f"/broadcast/sessions/{content_id}/ads/{creative_id}/track?event=impression",
        "click_url": f"/broadcast/sessions/{content_id}/ads/{creative_id}/track?event=click",
        "skip_url": f"/broadcast/sessions/{content_id}/ads/{creative_id}/track?event=skip",
    }


def build_pre_roll(session, viewer_id: str) -> Dict[str, Any]:
    """Build the pre-roll payload for a viewer joining ``session``.

    Returns ``{"pre_roll": <obj|None>, "ad_free": bool}``.
    """
    # Ad-free subscribers (and the broadcaster) skip pre-roll entirely.
    if is_ad_free(viewer_id, session.created_by):
        return {"pre_roll": None, "ad_free": True}

    # Global platform kill-switch for pre-roll (BROADCAST_PREROLL_ENABLED).
    if not S.broadcast_preroll_enabled:
        return {"pre_roll": None, "ad_free": True}

    if not session.pre_roll_enabled:
        return {"pre_roll": None, "ad_free": True}

    ad = serve_broadcast_ad(
        surface="broadcast_preroll",
        creator_id=session.created_by,
        content_id=session.id,
        slot_type="broadcast_preroll",
        user_id=viewer_id,
    )
    if not ad.get("filled"):
        # No ad available → play stream immediately. ad_free stays False so the
        # client still knows ads *could* have shown (matches VOD semantics).
        return {"pre_roll": None, "ad_free": False}

    # The ADS-004 serving engine returns tracking URLs for real campaign fills,
    # but the house-ad fallback (no paid inventory) does not. Synthesize the
    # broadcast tracking URLs in that case so the pre-roll payload is always
    # complete (matches the deterministic house-creative path above).
    creative_id = ad["creative_id"]
    impression_url = ad.get("impression_url") or (
        f"/broadcast/sessions/{session.id}/ads/{creative_id}/track?event=impression"
    )
    click_url = ad.get("click_url") or (
        f"/broadcast/sessions/{session.id}/ads/{creative_id}/track?event=click"
    )
    skip_url = ad.get("skip_url") or (
        f"/broadcast/sessions/{session.id}/ads/{creative_id}/track?event=skip"
    )

    pre_roll = {
        "creative_id": creative_id,
        "format": ad["format"],
        "video_url": ad.get("video_url"),
        "image_url": ad.get("image_url"),
        "cta_url": ad.get("cta_url"),
        "skip_after_seconds": PRE_ROLL_SKIP_AFTER_SECONDS,
        "ad_click_id": ad.get("ad_click_id", ""),
        "ctas": ad.get("ctas") or [],
        "impression_url": impression_url,
        "click_url": click_url,
        "skip_url": skip_url,
    }
    return {"pre_roll": pre_roll, "ad_free": False}


def _break_remaining_seconds(session) -> int:
    """Seconds left in the active ad break (0 when not active)."""
    if not session.ad_break_active or not session.ad_break_started_at:
        return 0
    duration = int(session.mid_roll_ad_break_duration_seconds)
    elapsed = now_ts() - int(session.ad_break_started_at)
    return max(0, duration - elapsed)


def build_mid_roll(session, viewer_id: str) -> Dict[str, Any]:
    """Per-viewer mid-roll payload during an active ad break (ADV2-101).

    Mirrors ``build_pre_roll`` but surface/slot ``broadcast_midroll``. Returns
    ``{"mid_roll": <obj|None>, "ad_free": bool, "remaining_seconds": int}``. An
    ad NEVER blocks the live stream: disabled / no-fill / ad-free all return
    ``mid_roll=None`` so the viewer keeps watching live.
    """
    remaining = _break_remaining_seconds(session)

    # Global platform kill-switch for mid-roll.
    if not S.broadcast_midroll_enabled:
        return {"mid_roll": None, "ad_free": True, "remaining_seconds": remaining}

    # Only serve while a break is actually active.
    if not session.ad_break_active:
        return {"mid_roll": None, "ad_free": False, "remaining_seconds": 0}

    # Ad-free subscribers (and the broadcaster themself) are never interrupted.
    if is_ad_free(viewer_id, session.created_by):
        return {"mid_roll": None, "ad_free": True, "remaining_seconds": remaining}

    ad = serve_broadcast_ad(
        surface="broadcast_midroll",
        creator_id=session.created_by,
        content_id=session.id,
        slot_type="broadcast_midroll",
        user_id=viewer_id,
    )
    if not ad.get("filled"):
        # No-fill -> stay live (ad_free stays False; an ad could have shown).
        return {"mid_roll": None, "ad_free": False, "remaining_seconds": remaining}

    mid_roll = {
        "creative_id": ad["creative_id"],
        "format": ad["format"],
        "video_url": ad.get("video_url"),
        "image_url": ad.get("image_url"),
        "cta_url": ad.get("cta_url"),
        "skip_after_seconds": int(session.mid_roll_skip_after_seconds),
        "ad_click_id": ad.get("ad_click_id", ""),
        "ctas": ad.get("ctas") or [],
        "impression_url": ad["impression_url"],
        "click_url": ad["click_url"],
        "skip_url": ad["skip_url"],
        "remaining_seconds": remaining,
    }
    return {"mid_roll": mid_roll, "ad_free": False, "remaining_seconds": remaining}



# ─── Ad-break state ─────────────────────────────────────────────────


def start_ad_break(session) -> Dict[str, Any]:
    """Mark an ad break active on the session and publish the SSE start event.

    Caller is responsible for authorization + state validation. Returns the
    broadcast payload (duration / skip / started_at).
    """
    ts = now_ts()
    duration = int(session.mid_roll_ad_break_duration_seconds)
    skip_after = int(session.mid_roll_skip_after_seconds)

    update_session_fields(
        session.id,
        {
            "ad_break_active": True,
            "ad_break_started_at": ts,
            "total_ad_breaks": int(session.total_ad_breaks) + 1,
            "last_ad_break_at": ts,
        },
    )

    payload = {
        "duration_seconds": duration,
        "skip_after_seconds": skip_after,
        "started_at": ts,
    }
    broadcast_sse_publish(session.id, {"_type": "ad_break:start", **payload})
    return payload


def end_ad_break(session_id: str, *, ended_by: str = "auto") -> None:
    """Clear the ad-break flag and publish the SSE end event (idempotent)."""
    update_session_fields(
        session_id,
        {"ad_break_active": False, "ad_break_started_at": None},
    )
    broadcast_sse_publish(session_id, {"_type": "ad_break:end", "ended_by": ended_by})


async def schedule_ad_break_end(session_id: str, duration: int) -> None:
    """Background task: auto-end an ad break after ``duration`` seconds.

    Re-reads the session before ending so a manual early-end is not clobbered.
    """
    import asyncio

    await asyncio.sleep(max(1, int(duration)))
    try:
        session = get_session(session_id)
    except Exception:
        return
    if session and session.ad_break_active:
        end_ad_break(session_id, ended_by="auto")


# ─── Ad event tracking ──────────────────────────────────────────────

_VALID_EVENTS = {"impression", "skip", "complete", "click"}


def _charge_broadcast_completion(*, ad_click_id, session_id, surface="broadcast_preroll"):
    # Charge advertiser for a completed broadcast pre-roll + credit the
    # BROADCASTER 70/30 via ad_billing._process_charge. Reads the AdClicks row
    # minted at serve time (content_owner_sub=broadcaster). Funds-guarded +
    # idempotent per ad_click_id. Returns the charge result or None.
    if not ad_click_id:
        return None
    try:
        row = T.ad_clicks.get_item(Key={"ad_click_id": ad_click_id}).get("Item")
    except Exception:
        return None
    if not row:
        return None
    # ADV2-303 (F3): free self-promo -> no advertiser charge, no ledger, no
    # broadcaster credit. Short-circuit BEFORE the 500c completion floor.
    if row.get("self_promo"):
        return {"ok": True, "reason": "self_promo", "charge_cents": 0}
    account_id = row.get("account_id", "")
    campaign_id = row.get("campaign_id", "")
    if not account_id or not campaign_id:
        return None
    creative_id = row.get("creative_id", "")
    content_owner = row.get("content_owner_sub", "")
    # ADV2-102: authoritative surface = the one minted at serve time (falls
    # back to the caller hint) so pre-roll and mid-roll bill under distinct
    # idempotency namespaces (broadcast_preroll:{id} vs broadcast_midroll:{id}).
    surface = str(row.get("surface", "") or "") or surface
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
        reason="Broadcast %s impression"
        % ("mid-roll" if surface == "broadcast_midroll" else "pre-roll"),
        meta={
            "creative_id": creative_id,
            "content_id": session_id,
            "model": "cpm",
            "surface": surface,
            "ad_click_id": ad_click_id,
        },
        idempotency_key="%s:%s" % (surface, ad_click_id),
    )
    try:
        # ADV2-RES R2: only write charged_cents on a REAL charge (>0); a
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
        )
    except Exception:
        pass
    return result


# Backward-compatible alias: the row's own surface is authoritative, so this
# name keeps charging correctly for both pre-roll and mid-roll click rows.
_charge_broadcast_preroll_completion = _charge_broadcast_completion


def record_ad_event(
    *,
    session_id: str,
    creative_id: str,
    user_id: str,
    event_type: str,
    slot_type: str = "",
    # Billing context — required for charge_impression when billing is enabled.
    account_id: str = "",
    campaign_id: str = "",
    creator_id: str = "",
    bid_cpm_cents: int = 0,
    ad_click_id: str = "",
    # Fraud context.
    ip_address: str = "",
    user_agent: str = "",
    view_time_ms: int = 0,
) -> Dict[str, Any]:
    """Record a broadcast ad event (impression/skip/complete/click).

    Best-effort: tracking, fraud, billing and analytics failures must never
    break playback. Fraud detection always runs (safety check); advertiser
    billing + creator revenue split is gated behind
    ``S.broadcast_ads_billing_enabled`` so it can be dark-launched and rolled
    back via a single env var (see GAP-0071 / GAP-0072).
    """
    if event_type not in _VALID_EVENTS:
        event_type = "impression"
    ts = now_ts()
    event_id = f"bae_{uuid4().hex}"

    # ── Fraud detection (always, not gated by the billing flag) ────────
    fraud_flagged = False
    fraud_score = 0
    if user_id:
        try:
            from app.services import ad_fraud_prevention as fraud

            result = fraud.check_fraud(
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                creative_id=creative_id,
                campaign_id=campaign_id,
                view_time_ms=view_time_ms,
                event_type=event_type,
            )
            fraud_flagged = result.flagged
            fraud_score = int(result.score)
            if fraud_flagged:
                fraud.record_fraud_event(
                    event_id=event_id,
                    user_id=user_id,
                    ip_address=ip_address,
                    account_id=account_id,
                    campaign_id=campaign_id,
                    creative_id=creative_id,
                    event_type=event_type,
                    fraud_result=result,
                )
                fraud.maybe_auto_suspend(account_id=account_id)
            else:
                fraud.record_account_activity(account_id=account_id, flagged=False)
        except Exception:  # pragma: no cover - fraud check must never block playback
            pass

    # Billing (broadcast pre-roll charge, gated by flag, never for fraud).
    # GAP-0071/0072: charge the ADVERTISER + credit the BROADCASTER 70/30 from
    # the authoritative AdClicks row (surface=broadcast_preroll,
    # content_owner_sub=broadcaster). Funds-guarded + idempotent per
    # ad_click_id so impression AND complete never double-charge.
    charge_id = None
    if (
        S.broadcast_ads_billing_enabled
        and not fraud_flagged
        and event_type in ("impression", "complete")
        and ad_click_id
    ):
        try:
            _res = _charge_broadcast_completion(
                ad_click_id=ad_click_id,
                session_id=session_id,
                surface=(
                    "broadcast_midroll"
                    if slot_type in ("broadcast_midroll", "mid_roll")
                    else "broadcast_preroll"
                ),
            )
            if _res and _res.get("ok"):
                charge_id = _res.get("entry_id")
        except Exception:  # pragma: no cover - billing must never break playback
            pass

    # ── Analytics rollup (best-effort, never blocks playback) ──────────
    if campaign_id and event_type in ("impression", "click"):
        try:
            from datetime import datetime, timezone

            from app.services import ad_analytics

            hour = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H")
            ad_analytics.compute_hourly_rollup(
                campaign_id=campaign_id, account_id=account_id, hour=hour
            )
        except Exception:  # pragma: no cover - analytics is best-effort
            pass

    # ── Raw event row ─────────────────────────────────────────────────
    try:
        T.broadcast_ad_events.put_item(
            Item={
                "session_id": session_id,
                "event_sk": f"{ts}#{event_id}",
                "event_id": event_id,
                "creative_id": creative_id,
                "user_id": user_id,
                "event_type": event_type,
                "slot_type": slot_type,
                "created_at": ts,
                "fraud_flagged": fraud_flagged,
                "fraud_score": fraud_score,
                **({"charge_id": charge_id} if charge_id else {}),
            }
        )
    except Exception:  # pragma: no cover - tracking is best-effort
        pass
    return {
        "ok": True,
        "event_id": event_id,
        "event_type": event_type,
        "fraud_flagged": fraud_flagged,
    }


def validate_midroll_duration(value: int) -> Optional[str]:
    """Return an error string if the duration is not one of the allowed values."""
    if value not in ALLOWED_MIDROLL_DURATIONS:
        return "mid_roll_ad_break_duration_seconds must be 15, 30, or 60"
    return None
