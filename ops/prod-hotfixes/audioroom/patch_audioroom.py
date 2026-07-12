#!/usr/bin/env python3
"""Apply the audio-room backend hotfix to prod (run with cwd=/home/ubuntu/testlogon).

Reads the two new-file payloads from /tmp (placed by the SSM wrapper):
  /tmp/broadcast_stage_store.py  -> app/services/broadcast_stage_store.py
  /tmp/audioroom_endpoints.py    -> appended to app/routers/broadcast.py
Then does exact-anchor string replacements in the existing prod files.
Every replacement asserts it changed the text; aborts loudly otherwise
(backups already taken by the wrapper).
"""
import io, sys, time, os

TS = os.environ.get("AUDIOROOM_TS") or str(int(time.time()))


def read(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()


def write(p, s):
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)


def repl(src, old, new, label):
    n = src.count(old)
    if n != 1:
        raise SystemExit("ANCHOR FAIL [%s]: found %d occurrences (need exactly 1)" % (label, n))
    return src.replace(old, new, 1)


# ---------------------------------------------------------------- new service file
STAGE_SRC = read("/tmp/broadcast_stage_store.py")
write("app/services/broadcast_stage_store.py", STAGE_SRC)
print("WROTE app/services/broadcast_stage_store.py (%d bytes)" % len(STAGE_SRC))

# ---------------------------------------------------------------- models_broadcast.py
MB = "app/models_broadcast.py"
mb = read(MB)
mb = repl(
    mb,
    "    ad_break_started_at: Optional[int] = None\n    total_ad_breaks: int = 0\n",
    "    ad_break_started_at: Optional[int] = None\n    total_ad_breaks: int = 0\n"
    "\n    # Audio Room (LiveKit broadcast stage)\n"
    "    mode: str = \"video\"                # \"video\" | \"audio_room\"\n"
    "    stage_max_slots: int = 20          # audio_room speaker cap (clamped 2..20)\n",
    "models.BroadcastSessionModel fields",
)
write(MB, mb)
print("PATCHED", MB)

# ---------------------------------------------------------------- broadcast_store.py
BS = "app/services/broadcast_store.py"
bs = read(BS)
# session_to_item
bs = repl(
    bs,
    '        "ad_break_started_at": session.ad_break_started_at,\n'
    '        "total_ad_breaks": session.total_ad_breaks,\n'
    "    }\n",
    '        "ad_break_started_at": session.ad_break_started_at,\n'
    '        "total_ad_breaks": session.total_ad_breaks,\n'
    "        # Audio Room (LiveKit)\n"
    '        "mode": session.mode,\n'
    '        "stage_max_slots": session.stage_max_slots,\n'
    "    }\n",
    "session_to_item",
)
# session_from_item
bs = repl(
    bs,
    "        total_ad_breaks=int(item.get(\"total_ad_breaks\", 0) or 0),\n    )\n",
    "        total_ad_breaks=int(item.get(\"total_ad_breaks\", 0) or 0),\n"
    "        # Audio Room (LiveKit)\n"
    "        mode=item.get(\"mode\") or \"video\",\n"
    "        stage_max_slots=int(item.get(\"stage_max_slots\", 20) or 20),\n"
    "    )\n",
    "session_from_item",
)
# create_session signature
bs = repl(
    bs,
    "    pre_roll_enabled: bool = True,\n"
    "    mid_roll_ad_break_duration_seconds: int = 30,\n"
    "    mid_roll_skip_after_seconds: int = 15,\n"
    ") -> BroadcastSessionModel:\n",
    "    pre_roll_enabled: bool = True,\n"
    "    mid_roll_ad_break_duration_seconds: int = 30,\n"
    "    mid_roll_skip_after_seconds: int = 15,\n"
    "    mode: str = \"video\",\n"
    "    stage_max_slots: int = 20,\n"
    ") -> BroadcastSessionModel:\n",
    "create_session signature",
)
# create_session body
bs = repl(
    bs,
    "        # Ad Breaks (ADS-006)\n"
    "        pre_roll_enabled=pre_roll_enabled,\n"
    "        mid_roll_ad_break_duration_seconds=mid_roll_ad_break_duration_seconds,\n"
    "        mid_roll_skip_after_seconds=mid_roll_skip_after_seconds,\n"
    "    )\n",
    "        # Ad Breaks (ADS-006)\n"
    "        pre_roll_enabled=pre_roll_enabled,\n"
    "        mid_roll_ad_break_duration_seconds=mid_roll_ad_break_duration_seconds,\n"
    "        mid_roll_skip_after_seconds=mid_roll_skip_after_seconds,\n"
    "        mode=(mode if mode in (\"video\", \"audio_room\") else \"video\"),\n"
    "        stage_max_slots=max(2, min(20, int(stage_max_slots or 20))),\n"
    "    )\n",
    "create_session body",
)
write(BS, bs)
print("PATCHED", BS)

# ---------------------------------------------------------------- broadcast.py
BR = "app/routers/broadcast.py"
br = read(BR)
# CreateIn
br = repl(
    br,
    "    pre_roll_enabled: bool = Field(default=True)\n"
    "    mid_roll_ad_break_duration_seconds: int = Field(default=30, ge=15, le=60)\n"
    "    mid_roll_skip_after_seconds: int = Field(default=15, ge=5, le=30)\n",
    "    pre_roll_enabled: bool = Field(default=True)\n"
    "    mid_roll_ad_break_duration_seconds: int = Field(default=30, ge=15, le=60)\n"
    "    mid_roll_skip_after_seconds: int = Field(default=15, ge=5, le=30)\n"
    "    # Audio Room (LiveKit): mode=\"audio_room\" makes this an audio broadcast stage\n"
    "    mode: str = Field(default=\"video\")\n"
    "    stage_max_slots: int = Field(default=20, ge=2, le=20)\n",
    "BroadcastSessionCreateIn",
)
# SessionOut
br = repl(
    br,
    "    ad_break_active: bool = False\n"
    "    ad_break_started_at: Optional[int] = None\n"
    "    total_ad_breaks: int = 0\n",
    "    ad_break_active: bool = False\n"
    "    ad_break_started_at: Optional[int] = None\n"
    "    total_ad_breaks: int = 0\n"
    "    # Audio Room (LiveKit)\n"
    "    mode: str = \"video\"\n"
    "    stage_max_slots: int = 20\n"
    "    speaker_count: int = 0\n"
    "    listener_count: int = 0\n",
    "BroadcastSessionOut",
)
# _to_session_out derived counts
br = repl(
    br,
    "                \"provider_state_snapshot\": output.provider_state_snapshot or {},\n"
    "            }\n"
    "        )\n"
    "    return BroadcastSessionOut(**payload)\n",
    "                \"provider_state_snapshot\": output.provider_state_snapshot or {},\n"
    "            }\n"
    "        )\n"
    "    # Audio Room derived counts (read-only)\n"
    "    if payload.get(\"mode\") == \"audio_room\":\n"
    "        try:\n"
    "            from app.services import broadcast_stage_store as _stage_ro\n"
    "            _spk = _stage_ro.speaker_count(session.id)\n"
    "            _viewers = _get_viewer_count(session.id)\n"
    "            payload[\"speaker_count\"] = _spk\n"
    "            payload[\"listener_count\"] = max(0, int(_viewers) - _spk)\n"
    "        except Exception:\n"
    "            pass\n"
    "    return BroadcastSessionOut(**payload)\n",
    "_to_session_out counts",
)
# create_session_route pass-through
br = repl(
    br,
    "        pre_roll_enabled=body.pre_roll_enabled,\n"
    "        mid_roll_ad_break_duration_seconds=body.mid_roll_ad_break_duration_seconds,\n"
    "        mid_roll_skip_after_seconds=body.mid_roll_skip_after_seconds,\n"
    "    )\n",
    "        pre_roll_enabled=body.pre_roll_enabled,\n"
    "        mid_roll_ad_break_duration_seconds=body.mid_roll_ad_break_duration_seconds,\n"
    "        mid_roll_skip_after_seconds=body.mid_roll_skip_after_seconds,\n"
    "        mode=body.mode,\n"
    "        stage_max_slots=body.stage_max_slots,\n"
    "    )\n",
    "create_session_route",
)
# /live signature
br = repl(
    br,
    "def list_live_sessions_route(\n"
    "    limit: int = Query(default=50, ge=1, le=200),\n"
    "    ctx: dict = Depends(_ctx),\n"
    "):\n",
    "def list_live_sessions_route(\n"
    "    limit: int = Query(default=50, ge=1, le=200),\n"
    "    mode: Optional[str] = Query(default=None, description=\"Filter by session mode, e.g. audio_room\"),\n"
    "    ctx: dict = Depends(_ctx),\n"
    "):\n",
    "/live signature",
)
# /live body
br = repl(
    br,
    "    _ = ctx\n"
    "    result = list_sessions_by_status(\"live\", limit=limit)\n"
    "    items = [_to_session_out(s) for s in result[\"items\"]]\n"
    "    return BroadcastSessionListOut(items=items, has_more=bool(result.get(\"cursor\")))\n",
    "    _ = ctx\n"
    "    result = list_sessions_by_status(\"live\", limit=limit)\n"
    "    sessions = result[\"items\"]\n"
    "    if mode:\n"
    "        sessions = [s for s in sessions if getattr(s, \"mode\", \"video\") == mode]\n"
    "    items = [_to_session_out(s) for s in sessions]\n"
    "    return BroadcastSessionListOut(items=items, has_more=bool(result.get(\"cursor\")))\n",
    "/live body",
)
# append endpoints (guard against double-apply)
if "AUDIO ROOM (LiveKit) — broadcast stage endpoints" not in br:
    br = br + "\n" + read("/tmp/audioroom_endpoints.py")
    print("APPENDED audio room endpoints to broadcast.py")
else:
    print("endpoints already present in broadcast.py (skipped append)")
write(BR, br)
print("PATCHED", BR)

# ---------------------------------------------------------------- settings.py
ST = "app/core/settings.py"
st = read(ST)
if "livekit_api_key" not in st:
    st = repl(
        st,
        "    messaging_webrtc_turn_ttl_seconds: int = int(os.environ.get(\"MESSAGING_WEBRTC_TURN_TTL_SECONDS\", \"600\"))\n",
        "    messaging_webrtc_turn_ttl_seconds: int = int(os.environ.get(\"MESSAGING_WEBRTC_TURN_TTL_SECONDS\", \"600\"))\n"
        "    # LiveKit (audio rooms) — token minting + server-authoritative controls\n"
        "    livekit_url: str = os.environ.get(\"LIVEKIT_URL\", \"\")\n"
        "    livekit_api_key: str = os.environ.get(\"LIVEKIT_API_KEY\", \"\")\n"
        "    livekit_api_secret: str = os.environ.get(\"LIVEKIT_API_SECRET\", \"\")\n"
        "    livekit_control_url: str = os.environ.get(\"LIVEKIT_CONTROL_URL\", \"http://127.0.0.1:7880\")\n",
        "settings.py livekit",
    )
    write(ST, st)
    print("PATCHED", ST)
else:
    print("settings.py already has livekit fields (skipped)")

print("PATCH COMPLETE ts=%s" % TS)
