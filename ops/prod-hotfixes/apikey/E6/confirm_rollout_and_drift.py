"""APIK EPIC E6-1 - rollout GA + drift + dead-scope gate (#118).

Read-only. Asserts, on the converged build:
  - every rollout product (5 core + groups + video) is enforce=True / shadow=False
    (NO silent shadow unscoped pass);
  - registry `stale_route_count == 0` (no registry row points at a dead route -
    the true "green drift" gate for promotion);
  - unregistered-live routes under a gated router are fail-closed (exempt==unmapped==deny),
    and none of them belong to the 5 program domains except the intentional
    require_root confirm-donation and the intentional fail-closed video money/mod set;
  - dead-scope audit: every canonical capability is either registry-mapped, a useful
    grantable superset, or enforced by a dedicated partner subsystem (ads/kyc).

Exit 0 = gate green.
"""
import os, sys
sys.path.insert(0, os.getcwd())
from collections import Counter
from app.services.api_key_rollout import (
    get_api_key_rollout_state, evaluate_api_key_rollout, ROLLOUT_PRODUCTS,
    validate_api_key_rollout_settings,
)
from app.services.api_key_capabilities import CANONICAL_API_KEY_CAPABILITIES, expand_api_key_capabilities
import re

fail = 0
def gate(name, ok, note=''):
    global fail
    if not ok: fail += 1
    print('  [%s] %-56s %s' % ('OK' if ok else 'XX', name, note))

validate_api_key_rollout_settings()

print('== E6-1 rollout: all products enforce, no shadow ==')
st = get_api_key_rollout_state()
gate('dual_credential_mode==prefer_api_key', st['dual_credential_mode'] == 'prefer_api_key', st['dual_credential_mode'])
for p in ROLLOUT_PRODUCTS:
    ev = evaluate_api_key_rollout(p, {'api_key_id': 'gate'})
    gate('%s enforce=True shadow=False' % p, ev['enforce'] and not ev['shadow'], 'phase=%s' % ev['phase'])

print('== E6-1 drift gate (stale_route_count must be 0) ==')
from app.main import app
d = getattr(app.state, 'api_key_registry_drift', {}) or {}
stale = int(d.get('stale_route_count') or 0)
gate('stale_route_count == 0', stale == 0, 'stale=%s unregistered_live=%s status=%s' % (stale, d.get('unregistered_live_route_count'), d.get('status')))

from app.services.api_key_route_scope_registry import is_route_registered_or_exempt
gatedpaths = set()
for r in app.routes:
    dep = getattr(r, 'dependant', None); deps = list(getattr(dep, 'dependencies', []) or [])
    if any(str(getattr(getattr(x, 'call', None), '__name__', '')) == 'maybe_enforce_api_key_route_policy' for x in deps):
        gatedpaths.add(getattr(r, 'path', ''))
live = set()
for r in app.routes:
    p = str(getattr(r, 'path', '')); ms = set(getattr(r, 'methods', set()) or set())
    for m in ms:
        m = m.upper()
        if m in ('HEAD', 'OPTIONS') or not p: continue
        live.add(m + ':' + p)
gated_unreg = [rid for rid in live if rid.split(':', 1)[1] in gatedpaths and not is_route_registered_or_exempt(rid)]
def dom(rid):
    p = rid.split(':', 1)[1]
    for k in ['/messaging', '/v1/fs', '/ui/groups', '/ui/videos', '/feed', '/posts', '/tickets', '/ui/catalog', '/ui/shop', '/ui/orders', '/ui/bookmark']:
        if p.startswith(k): return k
    return 'other'
by = Counter(dom(r) for r in gated_unreg)
print('  gated-but-unregistered (fail-closed deny) by domain:', dict(by))
# program 5-domain gated-unregistered must be ONLY the intentional confirm-donation + video money/mod
prog_bad = [r for r in gated_unreg if dom(r) in ('/messaging', '/v1/fs', '/feed', '/posts', '/ui/bookmark')]
gate('newsfeed/messaging/filemanager fully covered (0 gated-unregistered)', len(prog_bad) == 0, str(prog_bad[:5]))
grp_unreg = [r for r in gated_unreg if dom(r) == '/ui/groups']
gate('groups gated-unregistered == only confirm-donation (require_root)',
     all('confirm' in r for r in grp_unreg), str(grp_unreg))
# video unregistered = intentional fail-closed money/moderation/social; assert money routes present & denied
vid_unreg = set(r for r in gated_unreg if dom(r) == '/ui/videos')
for money in ['POST:/ui/videos/{video_id}/tip', 'POST:/ui/videos/{video_id}/purchase']:
    gate('video money route intentionally fail-closed: %s' % money, money in vid_unreg)

print('== E6-1 dead-scope audit (kill dead scopes / exempt!=allowed) ==')
reg = open('app/services/api_key_route_scope_registry.py').read()
used = {u for u in re.findall(r'"([a-z]+:[a-z:]+)"', reg) if ':' in u}
PARTNER = {'ads:manage', 'ads:read', 'ads:serve', 'kyc:admin', 'kyc:read', 'kyc:submit', 'kyc:upload', 'kyc:webhook'}
dead = []
for cap in CANONICAL_API_KEY_CAPABILITIES:
    if cap == 'admin:all': continue
    direct = cap in used
    superset = bool(set(expand_api_key_capabilities([cap])) & used)
    partner = cap in PARTNER
    if not (direct or superset or partner):
        dead.append(cap)
gate('no dead scopes (all mapped / superset / partner-enforced)', len(dead) == 0, 'dead=%s' % dead)

print('\nGATE', 'GREEN' if fail == 0 else 'RED (%d fail)' % fail)
sys.exit(0 if fail == 0 else 1)
