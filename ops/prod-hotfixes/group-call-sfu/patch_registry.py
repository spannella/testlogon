p = "app/services/api_key_route_scope_registry.py"
s = open(p).read()
anchor = '    "GET:/ui/calls/group/{call_id}/participants": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},\n'
assert anchor in s, "registry anchor not found"
if "GET:/ui/calls/group/{call_id}/livekit-token" not in s:
    new = anchor + '    "GET:/ui/calls/group/{call_id}/livekit-token": {"product": "groups", "required_scopes": ["groups:read"], "entitlement_required": True},\n'
    s = s.replace(anchor, new, 1)
    open(p, "w").write(s)
    print("registry patched")
else:
    print("already present")
