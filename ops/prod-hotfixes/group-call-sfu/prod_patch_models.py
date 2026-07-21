p="app/models.py"
s=open(p).read()
old=('class GroupCallSignalingInfo(BaseModel):\n'
     '    mode: str = "mesh"\n'
     '    ice_servers: list[dict] = []\n')
assert old in s, "models anchor missing"
if "sfu_provider" not in s.split("class GroupCallOut")[0]:
    new=('class GroupCallSignalingInfo(BaseModel):\n'
         '    mode: str = "mesh"\n'
         '    ice_servers: list[dict] = []\n'
         '    # SFU provider seam. When the platform\'s LiveKit SFU (shared with audio\n'
         '    # rooms) is configured, mode=="sfu" and sfu_provider=="livekit": clients\n'
         '    # fetch a join token from /ui/calls/group/{call_id}/livekit-token and\n'
         '    # connect to livekit_url with the LiveKit client SDK (real selective\n'
         '    # forwarding + simulcast). Empty/None => hand-rolled mesh transport.\n'
         '    sfu_provider: Optional[str] = None\n'
         '    livekit_url: Optional[str] = None\n'
         '    room_name: Optional[str] = None\n')
    s=s.replace(old,new,1)
    open(p,"w").write(s)
    print("PROD models.py: GroupCallSignalingInfo extended")
else:
    print("PROD models.py: already extended (skip)")
