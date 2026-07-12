"""VOD-018 ad-supported viewing tier.

This service sits ON TOP of the existing VOD playback machinery
(:mod:`app.services.vod_playback_url`) and the ad selection engine
(:mod:`app.services.ad_serving` / :mod:`app.services.ad_placement`). It does
NOT recreate purchase, rental, or ad-serving logic — it WIRES them together:

When a viewer chooses the ad-supported option for an ``ad_supported`` video,
this layer:

1. Resolves an **ad schedule** (the list of ad break positions plus the served
   ad creative refs) by asking ``ad_placement`` for the configured slots and,
   when the live engine is enabled, ``ad_serving.serve_ad`` for the actual
   creative to play. In deterministic / dev mode (the default, and what E2E
   relies on) it uses the static placeholder creatives so the schedule is fully
   reproducible.
2. Issues a **free playback grant** (a minted playback URL — no charge) so the
   viewer can start watching immediately. Playback past each mid-roll position
   is gated on the corresponding ad break being reported complete.
3. Tracks **ad-break completion**: as the viewer reports each break complete,
   the session unlocks continued playback. Once every required (pre-roll /
   mid-roll) break is complete the session is marked ``completed``.

Sessions live in their own ``vod_ad_sessions`` DynamoDB table::

  pk = USER#{viewer_id}
  sk = VIDEO#{video_id}

Time is injectable (``now`` parameter) so the lifecycle is deterministically
testable without sleeping.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ad_placement import (
    calculate_ad_slots,
    get_default_ad_config,
    record_ad_impression,
)
from app.services.video_metadata_store import get_video
from app.services.vod_playback_url import mint_vod_playback_url

logger = logging.getLogger(__name__)

# Session lifecycle states.
STATUS_ACTIVE = "active"
STATUS_COMPLETED = "completed"
STATUS_ABANDONED = "abandoned"

# Ad-break event types (mirrors ad_placement.record_ad_impression).
EVENT_IMPRESSION = "impression"
EVENT_COMPLETE = "complete"
EVENT_SKIP = "skip"
VALID_EVENTS = frozenset({EVENT_IMPRESSION, EVENT_COMPLETE, EVENT_SKIP})

# Break types that gate playback (overlays do not block playback).
GATING_SLOT_TYPES = ("pre_roll", "mid_roll")


# ─── Keys ─────────────────────────────────────────────────────────────────────


def _pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _sk(video_id: str) -> str:
    return f"VIDEO#{video_id}"


def _get_session_item(user_id: str, video_id: str) -> Optional[Dict[str, Any]]:
    resp = T.vod_ad_sessions.get_item(
        Key={"pk": _pk(user_id), "sk": _sk(video_id)}, ConsistentRead=True
    )
    return resp.get("Item")


# ─── Ad schedule resolution ─────────────────────────────────────────────────


def _resolve_ad_schedule(*, video: Any, user_id: str) -> List[Dict[str, Any]]:
    """Build the ad schedule (break list) for an ad-supported viewing session.

    Wires the existing ad systems:

    - Slot positions / counts come from ``ad_placement.calculate_ad_slots``,
      driven by the creator-configured ``ad_config`` (or a duration-based
      default).
    - The served creative for each slot is selected via ``ad_serving.serve_ad``
      when the live engine is enabled, otherwise the deterministic placeholder
      creative chosen by ``calculate_ad_slots`` is used as-is.

    Each schedule entry is enriched with a stable ``break_id`` and a
    ``completed`` flag used for gating.
    """
    duration = video.duration_seconds or 60
    ad_config = video.ad_config or get_default_ad_config(duration)
    slots = calculate_ad_slots(duration, ad_config)

    # ADV-201: decouple the pre-roll gate from dev_mode. The platform runs
    # DEV_MODE=1 (moto S3 / stripe-mock) everywhere, so ORing dev_mode forced
    # the deterministic placeholder forever. Gate on the flag ONLY, so setting
    # vod_ad_supported_deterministic=false enables the LIVE serve_ad path.
    deterministic = bool(getattr(S, "vod_ad_supported_deterministic", True))

    schedule: List[Dict[str, Any]] = []
    for slot in slots:
        creative_id = slot.get("creative_id", "")
        creative_url = slot.get("creative_url", "")
        creative_type = slot.get("creative_type", "video")

        ad_click_id = ""
        ctas: List[Dict[str, Any]] = []

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
                    content_id=video.id,
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
                    ctas = served.get("ctas") or []
            except Exception:
                logger.warning(
                    "vod_ad_supported_serve_failed video=%s user=%s",
                    video.id,
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
                "ctas": ctas,
                "completed": False,
            }
        )
    return schedule


def _is_ads_free(*, video: Any, user_id: str) -> bool:
    """Return True if this viewer gets ad-free playback (subscriber benefit)."""
    if not getattr(video, "ads_free_for_subscribers", False):
        return False
    try:
        from app.services.subscription_access import has_active_subscription

        return has_active_subscription(
            subscriber_id=user_id, creator_id=video.owner_user_id
        )
    except Exception:
        return False


# ─── Gating computation ──────────────────────────────────────────────────────


def _required_break_ids(schedule: List[Dict[str, Any]]) -> List[str]:
    """Breaks that gate playback: pre_roll and mid_roll (overlays don't gate)."""
    return [b["break_id"] for b in schedule if b.get("slot_type") in GATING_SLOT_TYPES]


def _next_required_break(schedule: List[Dict[str, Any]]) -> Optional[str]:
    """Lowest-position gating break that is not yet completed, else None."""
    pending = [
        b
        for b in schedule
        if b.get("slot_type") in GATING_SLOT_TYPES and not b.get("completed")
    ]
    if not pending:
        return None
    pending.sort(key=lambda b: (int(b.get("position_seconds", 0)), int(b.get("slot_index", 0))))
    return pending[0]["break_id"]


def _playback_unlocked(schedule: List[Dict[str, Any]], *, ads_free: bool) -> bool:
    """Whether the viewer may begin / continue playback right now.

    A pending pre-roll (position 0) blocks the start of playback. Mid-rolls gate
    continued playback at their position but do not block the initial start, so
    the unlock signal here is True unless a pre-roll break is still pending.
    """
    if ads_free:
        return True
    for b in schedule:
        if b.get("slot_type") == "pre_roll" and not b.get("completed"):
            return False
    return True


def _breaks_completed(schedule: List[Dict[str, Any]]) -> int:
    return sum(1 for b in schedule if b.get("completed"))


def _compute_status(schedule: List[Dict[str, Any]], *, ads_free: bool) -> str:
    if ads_free:
        return STATUS_COMPLETED
    required = _required_break_ids(schedule)
    done = {b["break_id"] for b in schedule if b.get("completed")}
    if required and all(rid in done for rid in required):
        return STATUS_COMPLETED
    return STATUS_ACTIVE


# ─── Serialization ───────────────────────────────────────────────────────────


def _session_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    schedule = item.get("ad_schedule", []) or []
    # DynamoDB may return numeric values as Decimal — coerce for the response.
    norm_schedule: List[Dict[str, Any]] = []
    for b in schedule:
        norm_schedule.append(
            {
                "break_id": b.get("break_id", ""),
                "slot_type": b.get("slot_type", ""),
                "position_seconds": int(b.get("position_seconds", 0)),
                "duration_seconds": int(b.get("duration_seconds", 0)),
                "creative_id": b.get("creative_id", ""),
                "creative_url": b.get("creative_url", ""),
                "creative_type": b.get("creative_type", "video"),
                "skip_after_seconds": int(b.get("skip_after_seconds", 0)),
                "slot_index": int(b.get("slot_index", 0)),
                "ad_click_id": b.get("ad_click_id", "") or "",
                "ctas": b.get("ctas", []) or [],
                "completed": bool(b.get("completed", False)),
            }
        )
    ads_free = bool(item.get("ads_free", False))
    return {
        "session_id": item.get("session_id", ""),
        "video_id": item.get("video_id", ""),
        "status": item.get("status", STATUS_ACTIVE),
        "ad_schedule": norm_schedule,
        "breaks_total": len(norm_schedule),
        "breaks_completed": _breaks_completed(norm_schedule),
        "next_required_break_id": _next_required_break(norm_schedule),
        "playback_unlocked": _playback_unlocked(norm_schedule, ads_free=ads_free),
        "ads_free": ads_free,
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


# ─── Start a session ─────────────────────────────────────────────────────────


def start_session(
    *, user_id: str, video_id: str, now: Optional[int] = None
) -> Dict[str, Any]:
    """Start (or resume) an ad-supported viewing session for a video.

    Returns the ad schedule plus a free playback grant. Idempotent: an existing
    active session for the same viewer+video is returned (with its current
    progress) rather than recreating the schedule, so a page reload mid-watch
    does not reset completed breaks.

    Raises HTTPException for non-ad-supported videos / disabled feature.
    """
    if not getattr(S, "vod_ad_supported_enabled", True):
        raise HTTPException(status_code=403, detail="Ad-supported viewing is not enabled")

    ts = now if now is not None else now_ts()
    video = get_video(video_id)

    if video.access_mode != "ad_supported":
        raise HTTPException(
            status_code=400, detail="This video is not available on the ad-supported tier"
        )

    ads_free = _is_ads_free(video=video, user_id=user_id)

    existing = _get_session_item(user_id, video_id)
    if existing and existing.get("status") == STATUS_ACTIVE:
        item = existing
    else:
        schedule = [] if ads_free else _resolve_ad_schedule(video=video, user_id=user_id)
        status = _compute_status(schedule, ads_free=ads_free)
        session_id = f"vadsess_{uuid.uuid4().hex}"
        item = {
            "pk": _pk(user_id),
            "sk": _sk(video_id),
            "session_id": session_id,
            "video_id": video_id,
            "viewer_id": user_id,
            "creator_id": video.owner_user_id,
            "status": status,
            "ad_schedule": schedule,
            "ads_free": ads_free,
            "created_at": ts,
            "updated_at": ts,
        }
        T.vod_ad_sessions.put_item(Item=item)

    # Free playback grant — no charge. Ads are the gate, not a paywall.
    playback = mint_vod_playback_url(
        video_id=video_id,
        tenant_id=video.owner_user_id,
        ttl_seconds=getattr(S, "vod_ad_supported_playback_ttl_seconds", 3600),
    )

    out = _session_to_dict(item)
    out.update(
        {
            "playback_url": playback.url,
            "manifest_key": playback.manifest_key,
            "mode": playback.mode,
            "thumbnail_url": playback.thumbnail_url,
            "token_expires_at": playback.expires_at,
        }
    )
    return out


# ─── Report an ad break ──────────────────────────────────────────────────────


def _charge_preroll_completion(
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
    # ADV2-303 (F3): free self-promo -> no advertiser charge, no ledger, no
    # poster credit. Short-circuit BEFORE the 500c completion floor.
    if row.get("self_promo"):
        return {"ok": True, "reason": "self_promo", "charge_cents": 0}

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

    logger.info(
        "vod_ad_preroll_charged ad_click_id=%s account=%s campaign=%s result=%s",
        ad_click_id, account_id, campaign_id, result,
    )
    return result


def report_break(
    *,
    user_id: str,
    video_id: str,
    break_id: str,
    event_type: str = EVENT_COMPLETE,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Report an ad-break event for an active session.

    On a ``complete`` event the break is marked complete (unlocking continued
    playback past that position) and an impression record is written via the
    existing ``ad_placement.record_ad_impression`` (which also credits creator
    ad revenue for completed views). ``impression`` and ``skip`` events are
    recorded for tracking but do NOT mark the break complete (a skipped break
    still gates playback — the viewer must watch to unlock).

    Idempotent: re-reporting a completed break is a no-op for gating.

    Raises HTTPException(404) if no session / break exists.
    """
    if event_type not in VALID_EVENTS:
        raise HTTPException(status_code=400, detail=f"Invalid event_type '{event_type}'")

    ts = now if now is not None else now_ts()
    item = _get_session_item(user_id, video_id)
    if not item:
        raise HTTPException(status_code=404, detail="No ad-supported session found")

    schedule = item.get("ad_schedule", []) or []
    target = next((b for b in schedule if b.get("break_id") == break_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Ad break not found in session")

    was_completed = bool(target.get("completed", False))
    if event_type == EVENT_COMPLETE:
        target["completed"] = True

    new_status = _compute_status(schedule, ads_free=bool(item.get("ads_free", False)))

    # Persist updated schedule + status.
    T.vod_ad_sessions.update_item(
        Key={"pk": _pk(user_id), "sk": _sk(video_id)},
        UpdateExpression="SET ad_schedule = :s, #st = :status, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": schedule, ":status": new_status, ":ts": ts},
    )

    # Wire ad tracking + revenue via the existing placement service (best-effort).
    try:
        record_ad_impression(
            video_id=video_id,
            user_id=user_id,
            slot_type=target.get("slot_type", "pre_roll"),
            slot_index=int(target.get("slot_index", 0)),
            creative_id=target.get("creative_id", ""),
            event_type=event_type,
            # ADV-203: for a paid pre-roll (ad_click_id present) the poster is
            # credited from advertiser spend via _charge_preroll_completion, so
            # suppress the legacy phantom-CPM credit here to avoid double-credit.
            credit_revenue=not bool(target.get("ad_click_id")),
        )
    except Exception:
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
        "video_id": video_id,
        "break_id": break_id,
        "event_type": event_type,
        "completed": bool(target.get("completed", False)),
        "breaks_completed": _breaks_completed(schedule),
        "breaks_total": len(schedule),
        "next_required_break_id": _next_required_break(schedule),
        "playback_unlocked": _playback_unlocked(
            schedule, ads_free=bool(item.get("ads_free", False))
        ),
        "status": new_status,
    }


# ─── Session status ──────────────────────────────────────────────────────────


def get_session_status(
    *, user_id: str, video_id: str, now: Optional[int] = None
) -> Dict[str, Any]:
    """Return the current ad-supported session state (or a not-started stub)."""
    item = _get_session_item(user_id, video_id)
    if not item:
        return {
            "session_id": "",
            "video_id": video_id,
            "status": STATUS_ABANDONED,
            "ad_schedule": [],
            "breaks_total": 0,
            "breaks_completed": 0,
            "next_required_break_id": None,
            "playback_unlocked": False,
            "ads_free": False,
            "created_at": 0,
            "updated_at": 0,
        }
    return _session_to_dict(item)
