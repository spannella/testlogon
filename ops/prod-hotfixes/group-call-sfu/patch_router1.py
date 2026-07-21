p = "app/routers/group_calls.py"
s = open(p).read()
old = (
    "def _signaling_info() -> GroupCallSignalingInfo:\n"
    "    return GroupCallSignalingInfo(\n"
    '        mode="sfu" if S.group_call_sfu_endpoint else "mesh",\n'
    '        ice_servers=[{"urls": "stun:stun.l.google.com:19302"}],\n'
    "    )\n"
)
assert old in s, "signaling anchor not found"
new = (
    "def _livekit_group_call_configured() -> bool:\n"
    '    """LiveKit SFU is usable for group calls when the shared LiveKit creds\n'
    '    are set and the provider is selected. Reuses the SAME LiveKit deployment\n'
    '    the audio rooms use (real selective forwarding + simulcast)."""\n'
    "    return bool(\n"
    '        getattr(S, "group_call_sfu_provider", "") == "livekit"\n'
    '        and getattr(S, "livekit_url", "")\n'
    '        and getattr(S, "livekit_api_key", "")\n'
    '        and getattr(S, "livekit_api_secret", "")\n'
    "    )\n"
    "\n"
    "\n"
    "def _group_call_room_name(call_id: str) -> str:\n"
    '    """LiveKit room name for a group call. Namespaced to avoid colliding with\n'
    '    audio-room (broadcast) sessions on the same LiveKit server."""\n'
    '    return f"groupcall:{call_id}"\n'
    "\n"
    "\n"
    "def _signaling_info(call_id: str = \"\") -> GroupCallSignalingInfo:\n"
    "    if _livekit_group_call_configured():\n"
    "        # Route through the existing LiveKit SFU. The client fetches a join\n"
    "        # token from /livekit-token and connects with the LiveKit client SDK.\n"
    "        return GroupCallSignalingInfo(\n"
    '            mode="sfu",\n'
    '            sfu_provider="livekit",\n'
    "            livekit_url=getattr(S, \"livekit_url\", \"\") or None,\n"
    "            room_name=_group_call_room_name(call_id) if call_id else None,\n"
    "            ice_servers=[],\n"
    "        )\n"
    "    # A bare (non-LiveKit) SFU endpoint is not implemented as a media path;\n"
    "    # fall back to the hand-rolled mesh transport, which IS implemented.\n"
    "    return GroupCallSignalingInfo(\n"
    '        mode="mesh",\n'
    '        ice_servers=[{"urls": "stun:stun.l.google.com:19302"}],\n'
    "    )\n"
)
s = s.replace(old, new, 1)
# join endpoint must pass call_id now
s = s.replace("signaling=_signaling_info(),", "signaling=_signaling_info(call_id),", 1)
open(p, "w").write(s)
print("router _signaling_info patched")
