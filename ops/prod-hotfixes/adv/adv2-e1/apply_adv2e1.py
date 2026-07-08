#!/usr/bin/env python3
"""ADV2-E1 (live-stream ad breaks / mid-roll) backend hotfix — ADV2-101..104.

Idempotent, anchor-matched string patcher so it runs on both the divergent PROD
tree and the dev clone. Run: python apply_adv2e1.py [ROOT]  (ROOT default cwd).

Tickets:
  ADV2-101  build_mid_roll + POST /broadcast/sessions/{id}/ad-break/serve
  ADV2-102  surface-parametrized completion charge (broadcast_midroll:{ad_click_id})
  ADV2-103  poll-detectable break state (remaining_seconds + GET .../ad-break/state)
  ADV2-104  anti-abuse guardrails (min interval + max breaks/session)
"""
import io
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


def patch(rel, edits):
    path = os.path.join(ROOT, rel)
    with io.open(path, "r", encoding="utf-8") as f:
        src = f.read()
    orig = src
    for name, sentinel, old, new in edits:
        if sentinel in src:
            print("  SKIP  %s :: %s (already applied)" % (rel, name))
            continue
        if old not in src:
            print("  FAIL  %s :: %s (anchor NOT found)" % (rel, name))
            raise SystemExit(2)
        if src.count(old) != 1:
            print("  FAIL  %s :: %s (anchor not unique: %d)" % (rel, name, src.count(old)))
            raise SystemExit(2)
        src = src.replace(old, new, 1)
        print("  OK    %s :: %s" % (rel, name))
    if src != orig:
        with io.open(path, "w", encoding="utf-8") as f:
            f.write(src)
        print("  WROTE %s" % rel)
    else:
        print("  NOCHG %s" % rel)


# ── app/core/settings.py (ADV2-104 config) ───────────────────────────────────
patch("app/core/settings.py", [(
    "midroll guardrail settings",
    "broadcast_midroll_min_interval_seconds",
    '    broadcast_ads_billing_enabled: bool = os.environ.get("BROADCAST_ADS_BILLING_ENABLED", "1") not in ("0", "false", "False")',
    '    broadcast_ads_billing_enabled: bool = os.environ.get("BROADCAST_ADS_BILLING_ENABLED", "1") not in ("0", "false", "False")\n'
    "    # ADV2-104: mid-roll ad-break anti-abuse guardrails (config-driven).\n"
    '    broadcast_midroll_min_interval_seconds: int = int(os.environ.get("BROADCAST_MIDROLL_MIN_INTERVAL_SECONDS", "300"))\n'
    '    broadcast_midroll_max_breaks_per_session: int = int(os.environ.get("BROADCAST_MIDROLL_MAX_BREAKS", "4"))',
)])

# ── app/models_broadcast.py (persist last_ad_break_at) ────────────────────────
patch("app/models_broadcast.py", [(
    "last_ad_break_at model field",
    "last_ad_break_at",
    "    ad_break_started_at: Optional[int] = None\n    total_ad_breaks: int = 0",
    "    ad_break_started_at: Optional[int] = None\n    total_ad_breaks: int = 0\n"
    "    last_ad_break_at: Optional[int] = None  # ADV2-104 min-interval guardrail",
)])

# ── app/services/broadcast_store.py (persist/hydrate last_ad_break_at) ────────
patch("app/services/broadcast_store.py", [
    (
        "session_to_item last_ad_break_at",
        '"last_ad_break_at": session.last_ad_break_at',
        '        "total_ad_breaks": session.total_ad_breaks,\n',
        '        "total_ad_breaks": session.total_ad_breaks,\n'
        '        "last_ad_break_at": session.last_ad_break_at,\n',
    ),
    (
        "session_from_item last_ad_break_at",
        "last_ad_break_at=int(item",
        '        total_ad_breaks=int(item.get("total_ad_breaks", 0) or 0),\n',
        '        total_ad_breaks=int(item.get("total_ad_breaks", 0) or 0),\n'
        '        last_ad_break_at=int(item["last_ad_break_at"]) if item.get("last_ad_break_at") is not None else None,\n',
    ),
])

# ── app/services/broadcast_ads.py (ADV2-101 serve build + ADV2-102 charge) ────
patch("app/services/broadcast_ads.py", [
    (
        "start_ad_break records last_ad_break_at",
        '"last_ad_break_at": ts,',
        '            "ad_break_active": True,\n'
        '            "ad_break_started_at": ts,\n'
        '            "total_ad_breaks": int(session.total_ad_breaks) + 1,\n'
        "        },",
        '            "ad_break_active": True,\n'
        '            "ad_break_started_at": ts,\n'
        '            "total_ad_breaks": int(session.total_ad_breaks) + 1,\n'
        '            "last_ad_break_at": ts,\n'
        "        },",
    ),
    (
        "build_mid_roll + _break_remaining_seconds",
        "def build_mid_roll(",
        '    return {"pre_roll": pre_roll, "ad_free": False}\n',
        '    return {"pre_roll": pre_roll, "ad_free": False}\n\n\n'
        "def _break_remaining_seconds(session) -> int:\n"
        '    """Seconds left in the active ad break (0 when not active)."""\n'
        "    if not session.ad_break_active or not session.ad_break_started_at:\n"
        "        return 0\n"
        "    duration = int(session.mid_roll_ad_break_duration_seconds)\n"
        "    elapsed = now_ts() - int(session.ad_break_started_at)\n"
        "    return max(0, duration - elapsed)\n\n\n"
        "def build_mid_roll(session, viewer_id: str) -> Dict[str, Any]:\n"
        '    """Per-viewer mid-roll payload during an active ad break (ADV2-101).\n\n'
        "    Mirrors ``build_pre_roll`` but surface/slot ``broadcast_midroll``. Returns\n"
        '    ``{"mid_roll": <obj|None>, "ad_free": bool, "remaining_seconds": int}``. An\n'
        "    ad NEVER blocks the live stream: disabled / no-fill / ad-free all return\n"
        "    ``mid_roll=None`` so the viewer keeps watching live.\n"
        '    """\n'
        "    remaining = _break_remaining_seconds(session)\n\n"
        "    # Global platform kill-switch for mid-roll.\n"
        "    if not S.broadcast_midroll_enabled:\n"
        '        return {"mid_roll": None, "ad_free": True, "remaining_seconds": remaining}\n\n'
        "    # Only serve while a break is actually active.\n"
        "    if not session.ad_break_active:\n"
        '        return {"mid_roll": None, "ad_free": False, "remaining_seconds": 0}\n\n'
        "    # Ad-free subscribers (and the broadcaster themself) are never interrupted.\n"
        "    if is_ad_free(viewer_id, session.created_by):\n"
        '        return {"mid_roll": None, "ad_free": True, "remaining_seconds": remaining}\n\n'
        "    ad = serve_broadcast_ad(\n"
        '        surface="broadcast_midroll",\n'
        "        creator_id=session.created_by,\n"
        "        content_id=session.id,\n"
        '        slot_type="broadcast_midroll",\n'
        "        user_id=viewer_id,\n"
        "    )\n"
        '    if not ad.get("filled"):\n'
        "        # No-fill -> stay live (ad_free stays False; an ad could have shown).\n"
        '        return {"mid_roll": None, "ad_free": False, "remaining_seconds": remaining}\n\n'
        "    mid_roll = {\n"
        '        "creative_id": ad["creative_id"],\n'
        '        "format": ad["format"],\n'
        '        "video_url": ad.get("video_url"),\n'
        '        "image_url": ad.get("image_url"),\n'
        '        "cta_url": ad.get("cta_url"),\n'
        '        "skip_after_seconds": int(session.mid_roll_skip_after_seconds),\n'
        '        "ad_click_id": ad.get("ad_click_id", ""),\n'
        '        "impression_url": ad["impression_url"],\n'
        '        "click_url": ad["click_url"],\n'
        '        "skip_url": ad["skip_url"],\n'
        '        "remaining_seconds": remaining,\n'
        "    }\n"
        '    return {"mid_roll": mid_roll, "ad_free": False, "remaining_seconds": remaining}\n\n',
    ),
    (
        "charge fn surface param",
        "def _charge_broadcast_completion(",
        "def _charge_broadcast_preroll_completion(*, ad_click_id, session_id):",
        "def _charge_broadcast_completion(*, ad_click_id, session_id, surface=\"broadcast_preroll\"):",
    ),
    (
        "charge fn surface from row",
        "# ADV2-102: authoritative surface",
        '    content_owner = row.get("content_owner_sub", "")\n'
        '    charge_cents = int(row.get("effective_price_cents", 0) or 0)',
        '    content_owner = row.get("content_owner_sub", "")\n'
        "    # ADV2-102: authoritative surface = the one minted at serve time (falls\n"
        "    # back to the caller hint) so pre-roll and mid-roll bill under distinct\n"
        "    # idempotency namespaces (broadcast_preroll:{id} vs broadcast_midroll:{id}).\n"
        '    surface = str(row.get("surface", "") or "") or surface\n'
        '    charge_cents = int(row.get("effective_price_cents", 0) or 0)',
    ),
    (
        "charge fn meta/idempotency surface",
        'idempotency_key="%s:%s" % (surface, ad_click_id)',
        '        reason="Broadcast pre-roll impression",\n'
        "        meta={\n"
        '            "creative_id": creative_id,\n'
        '            "content_id": session_id,\n'
        '            "model": "cpm",\n'
        '            "surface": "broadcast_preroll",\n'
        '            "ad_click_id": ad_click_id,\n'
        "        },\n"
        '        idempotency_key="broadcast_preroll:%s" % ad_click_id,',
        '        reason="Broadcast %s impression"\n'
        '        % ("mid-roll" if surface == "broadcast_midroll" else "pre-roll"),\n'
        "        meta={\n"
        '            "creative_id": creative_id,\n'
        '            "content_id": session_id,\n'
        '            "model": "cpm",\n'
        '            "surface": surface,\n'
        '            "ad_click_id": ad_click_id,\n'
        "        },\n"
        '        idempotency_key="%s:%s" % (surface, ad_click_id),',
    ),
    (
        "charge fn backward-compat alias",
        "_charge_broadcast_preroll_completion = _charge_broadcast_completion",
        "    except Exception:\n        pass\n    return result\n\n\n"
        "def record_ad_event(",
        "    except Exception:\n        pass\n    return result\n\n\n"
        "# Backward-compatible alias: the row's own surface is authoritative, so this\n"
        "# name keeps charging correctly for both pre-roll and mid-roll click rows.\n"
        "_charge_broadcast_preroll_completion = _charge_broadcast_completion\n\n\n"
        "def record_ad_event(",
    ),
    (
        "record_ad_event passes surface",
        "surface=(\n                    \"broadcast_midroll\"",
        "            _res = _charge_broadcast_preroll_completion(\n"
        "                ad_click_id=ad_click_id, session_id=session_id\n"
        "            )",
        "            _res = _charge_broadcast_completion(\n"
        "                ad_click_id=ad_click_id,\n"
        "                session_id=session_id,\n"
        "                surface=(\n"
        '                    "broadcast_midroll"\n'
        '                    if slot_type in ("broadcast_midroll", "mid_roll")\n'
        '                    else "broadcast_preroll"\n'
        "                ),\n"
        "            )",
    ),
])

# ── app/routers/broadcast_ads.py (routes + models + guardrails) ───────────────
patch("app/routers/broadcast_ads.py", [
    (
        "import build_mid_roll + _break_remaining_seconds",
        "build_mid_roll,",
        "from app.services.broadcast_ads import (\n"
        "    ALLOWED_MIDROLL_DURATIONS,\n"
        "    build_pre_roll,\n"
        "    end_ad_break,\n"
        "    record_ad_event,\n"
        "    schedule_ad_break_end,\n"
        "    start_ad_break,\n"
        ")",
        "from app.services.broadcast_ads import (\n"
        "    ALLOWED_MIDROLL_DURATIONS,\n"
        "    build_pre_roll,\n"
        "    build_mid_roll,\n"
        "    _break_remaining_seconds,\n"
        "    end_ad_break,\n"
        "    record_ad_event,\n"
        "    schedule_ad_break_end,\n"
        "    start_ad_break,\n"
        ")",
    ),
    (
        "BroadcastAdConfigOut remaining_seconds",
        "    total_ad_breaks: int\n    remaining_seconds: int = 0",
        "    ad_break_active: bool\n"
        "    ad_break_started_at: Optional[int] = None\n"
        "    total_ad_breaks: int\n",
        "    ad_break_active: bool\n"
        "    ad_break_started_at: Optional[int] = None\n"
        "    total_ad_breaks: int\n"
        "    remaining_seconds: int = 0\n",
    ),
    (
        "mid-roll response models",
        "class MidRollServeOut(BaseModel):",
        "class BroadcastJoinOut(BaseModel):",
        "class MidRollOut(BaseModel):\n"
        "    creative_id: str\n"
        "    format: str\n"
        "    video_url: Optional[str] = None\n"
        "    image_url: Optional[str] = None\n"
        "    cta_url: Optional[str] = None\n"
        "    skip_after_seconds: int = 15\n"
        '    ad_click_id: str = ""\n'
        "    impression_url: str\n"
        "    click_url: str\n"
        "    skip_url: str\n"
        "    remaining_seconds: int = 0\n\n\n"
        "class MidRollServeOut(BaseModel):\n"
        "    session_id: str\n"
        "    mid_roll: Optional[MidRollOut] = None\n"
        "    ad_free: bool = False\n"
        "    remaining_seconds: int = 0\n\n\n"
        "class AdBreakStateOut(BaseModel):\n"
        "    session_id: str\n"
        "    ad_break_active: bool = False\n"
        "    ad_break_started_at: Optional[int] = None\n"
        "    remaining_seconds: int = 0\n"
        "    total_ad_breaks: int = 0\n"
        "    skip_after_seconds: int = 15\n\n\n"
        "class BroadcastJoinOut(BaseModel):",
    ),
    (
        "_config_out remaining_seconds",
        "remaining_seconds=_break_remaining_seconds(session),",
        "        ad_break_started_at=session.ad_break_started_at,\n"
        "        total_ad_breaks=session.total_ad_breaks,\n"
        "    )",
        "        ad_break_started_at=session.ad_break_started_at,\n"
        "        total_ad_breaks=session.total_ad_breaks,\n"
        "        remaining_seconds=_break_remaining_seconds(session),\n"
        "    )",
    ),
    (
        "ADV2-104 guardrails in trigger route",
        "MAX_BREAKS_REACHED",
        '            detail={"code": "AD_BREAK_ACTIVE", "detail": "Ad break already active"},\n'
        "        )\n\n"
        "    payload = start_ad_break(session)",
        '            detail={"code": "AD_BREAK_ACTIVE", "detail": "Ad break already active"},\n'
        "        )\n\n"
        "    # ADV2-104: anti-abuse guardrails (config-driven).\n"
        "    max_breaks = int(getattr(S, \"broadcast_midroll_max_breaks_per_session\", 4) or 4)\n"
        "    if int(session.total_ad_breaks) >= max_breaks:\n"
        "        raise HTTPException(\n"
        "            status_code=status.HTTP_429_TOO_MANY_REQUESTS,\n"
        "            detail={\n"
        '                "code": "MAX_BREAKS_REACHED",\n'
        '                "detail": "Maximum ad breaks for this session reached",\n'
        '                "max_breaks": max_breaks,\n'
        "            },\n"
        "        )\n"
        "    min_interval = int(getattr(S, \"broadcast_midroll_min_interval_seconds\", 300) or 300)\n"
        "    last_at = getattr(session, \"last_ad_break_at\", None)\n"
        "    if last_at:\n"
        "        from app.core.time import now_ts as _now_ts\n\n"
        "        elapsed = _now_ts() - int(last_at)\n"
        "        if elapsed < min_interval:\n"
        "            raise HTTPException(\n"
        "                status_code=status.HTTP_429_TOO_MANY_REQUESTS,\n"
        "                detail={\n"
        '                    "code": "AD_BREAK_TOO_SOON",\n'
        '                    "detail": "Too soon since the last ad break",\n'
        '                    "retry_after_seconds": max(0, min_interval - elapsed),\n'
        "                },\n"
        "            )\n\n"
        "    payload = start_ad_break(session)",
    ),
    (
        "serve + state routes",
        "def serve_mid_roll_route(",
        '    end_ad_break(session_id, ended_by="manual")\n'
        "    return {\"ok\": True}",
        '    end_ad_break(session_id, ended_by="manual")\n'
        "    return {\"ok\": True}\n\n\n"
        '@router.post("/sessions/{session_id}/ad-break/serve", response_model=MidRollServeOut)\n'
        "def serve_mid_roll_route(session_id: str, ctx: dict = Depends(_ctx)):\n"
        '    """Per-viewer mid-roll serve during an active ad break (ADV2-101).\n\n'
        "    Mints an ad_click_id + returns a creative when the viewer is billable and\n"
        "    a break is active; returns mid_roll=None (stay-live) otherwise. An ad never\n"
        "    blocks the broadcast.\n"
        '    """\n'
        "    session = get_session(session_id)\n"
        '    result = build_mid_roll(session, ctx["user_sub"])\n'
        '    mid = result["mid_roll"]\n'
        "    return MidRollServeOut(\n"
        "        session_id=session.id,\n"
        "        mid_roll=MidRollOut(**mid) if mid else None,\n"
        '        ad_free=result["ad_free"],\n'
        '        remaining_seconds=result["remaining_seconds"],\n'
        "    )\n\n\n"
        '@router.get("/sessions/{session_id}/ad-break/state", response_model=AdBreakStateOut)\n'
        "def ad_break_state_route(session_id: str, ctx: dict = Depends(_ctx)):\n"
        '    """Light poll-detectable ad-break state (ADV2-103)."""\n'
        "    _ = ctx\n"
        "    session = get_session(session_id)\n"
        "    return AdBreakStateOut(\n"
        "        session_id=session.id,\n"
        "        ad_break_active=session.ad_break_active,\n"
        "        ad_break_started_at=session.ad_break_started_at,\n"
        "        remaining_seconds=_break_remaining_seconds(session),\n"
        "        total_ad_breaks=session.total_ad_breaks,\n"
        "        skip_after_seconds=session.mid_roll_skip_after_seconds,\n"
        "    )\n",
    ),
])

print("ADV2-E1 patch complete on ROOT=%s" % ROOT)
