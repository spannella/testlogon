import sys, os; sys.path.insert(0, os.getcwd())
import hashlib, inspect, json
import app.services.api_key_route_scope_registry as R

def sh(p):
    try:
        return hashlib.sha256(open(p,'rb').read()).hexdigest()[:16]
    except Exception as e:
        return "ERR:"+str(e)

print("=== FILE HASHES ===")
for p in ["app/services/api_key_route_scope_registry.py","app/services/api_key_capabilities.py","app/main.py","app/routers/admin_usage.py","app/metrics.py"]:
    print(p, sh(p))

print("=== PREFIXES ===")
print(list(R.API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES))
print("=== registry rows ===", len(R.API_KEY_ROUTE_SCOPE_REGISTRY))
print("=== exemption rows ===", len(R.API_KEY_ROUTE_EXEMPTIONS))
print("=== classify_registry_drift SRC ===")
print(inspect.getsource(R.classify_registry_drift))
print("=== unregistered_live_route_ids SRC ===")
print(inspect.getsource(R.unregistered_live_route_ids))
print("=== summarize_registry_drift SRC ===")
print(inspect.getsource(R.summarize_registry_drift))

# Build app and compute live routes
from app.main import create_app
a = create_app()
live=set()
for route in a.routes:
    path=str(getattr(route,"path","") or "").strip()
    methods=set(getattr(route,"methods",set()) or set())
    if not path or not methods: continue
    for m in methods:
        m=str(m or "").upper().strip()
        if not m or m in {"HEAD","OPTIONS"}: continue
        live.add(f"{m}:{path}")
print("=== TOTAL LIVE ROUTES ===", len(live))

# stored drift
d = getattr(a.state,"api_key_registry_drift",None)
print("=== STORED app.state.api_key_registry_drift ===")
print(json.dumps(d, indent=0, default=str))

# unregistered live via prod function
unreg = R.unregistered_live_route_ids(live)
print("=== UNREGISTERED LIVE COUNT ===", len(unreg))
from collections import Counter
def bucket(rid):
    p=rid.split(":",1)[1]
    for pre in ["/ui/catalog","/ui/shoppingcart","/ui/purchase-history","/ui/shop","/tickets","/ui/videos","/ui/vod-bridge","/ui/transcode-jobs","/ui/groups","/ui/calls","/v1/fs","/feed","/posts","/messaging"]:
        if p.startswith(pre): return pre
    return "OTHER:"+p
print("=== UNREGISTERED BY BUCKET ===")
for k,v in sorted(Counter(bucket(r) for r in unreg).items()):
    print(f"  {k}: {v}")
print("=== UNREGISTERED FULL LIST ===")
for r in sorted(unreg):
    print("  "+r)

# routers carrying policy dep but unmapped (fail-closed uncovered)
def has_dep(route):
    dep=getattr(route,"dependant",None)
    deps=list(getattr(dep,"dependencies",[]) or [])
    return any(str(getattr(getattr(d,"call",None),"__name__",""))=="maybe_enforce_api_key_route_policy" for d in deps)
policy_live=set()
for route in a.routes:
    if not has_dep(route): continue
    path=str(getattr(route,"path","") or "").strip()
    for m in set(getattr(route,"methods",set()) or set()):
        m=str(m).upper().strip()
        if m in {"HEAD","OPTIONS"} or not m: continue
        policy_live.add(f"{m}:{path}")
print("=== ROUTES WITH POLICY DEP ===", len(policy_live))
gated_unmapped=[r for r in policy_live if r not in R.API_KEY_ROUTE_SCOPE_REGISTRY and r not in R.API_KEY_ROUTE_EXEMPTIONS]
print("=== GATED-BUT-UNMAPPED (policy dep, no registry/exempt) COUNT ===", len(gated_unmapped))
for r in sorted(gated_unmapped):
    print("  "+r)

# stale = registry rows pointing to dead routes
stale=[r for r in R.API_KEY_ROUTE_SCOPE_REGISTRY if r not in live]
print("=== STALE (registry->dead) COUNT ===", len(stale))
for r in sorted(stale):
    print("  "+r)
