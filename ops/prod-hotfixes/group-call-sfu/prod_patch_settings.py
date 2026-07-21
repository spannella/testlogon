p="app/core/settings.py"
s=open(p).read()
anchor='    group_call_dev_mesh_max_participants: int = int(os.environ.get("GROUP_CALL_DEV_MESH_MAX_PARTICIPANTS", "4"))\n'
assert anchor in s, "settings anchor missing"
if "group_call_sfu_provider" not in s:
    add=anchor+(
        "    # Group video calls route through the shared LiveKit SFU (audio rooms\n"
        "    # already use LIVEKIT_URL/API_KEY/API_SECRET above) when this provider is\n"
        "    # selected; unset the LiveKit creds => honest mesh fallback. GAP-0017-sfu.\n"
        '    group_call_sfu_provider: str = os.environ.get("GROUP_CALL_SFU_PROVIDER", "livekit")\n'
    )
    s=s.replace(anchor,add,1)
    open(p,"w").write(s)
    print("PROD settings.py: group_call_sfu_provider added")
else:
    print("PROD settings.py: group_call_sfu_provider already present (skip)")
