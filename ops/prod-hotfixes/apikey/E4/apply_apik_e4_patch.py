#!/usr/bin/env python3
"""APIK-E4 (#118) groups parity -- idempotent patcher.

Wires ``Depends(maybe_enforce_api_key_route_policy)`` onto the 5 group routers
(user_groups, group_feed, group_calls, group_treasury, group_fundraising) and
registers their routes into API_KEY_ROUTE_SCOPE_REGISTRY under product="groups":
reads->groups:read, mutations->groups:write, settings/role/remove/dissolve->groups:manage,
treasury contribute/spend/goal->groups:treasury, campaign/fundraiser CRUD->fundraising:write.
confirm-donation is intentionally NOT registered (stays require_root_session -> fail-closed
to keys). Promotes the groups product phase shadow->ga so scopes actually enforce.
Idempotent: re-running is a no-op (guarded by markers / already-present checks).

Env overrides (for prod targeting): APIK_ROUTERS_DIR, APIK_REG, APIK_SETTINGS.
"""
import io, os

ROOT = os.environ.get('APIK_ROOT', os.getcwd())
RDIR = os.environ.get('APIK_ROUTERS_DIR', os.path.join(ROOT, 'app/routers'))
REG = os.environ.get('APIK_REG', os.path.join(ROOT, 'app/services/api_key_route_scope_registry.py'))
SETTINGS = os.environ.get('APIK_SETTINGS', os.path.join(ROOT, 'app/core/settings.py'))

IMPORT_LINE = 'from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy\n'
DEP = 'dependencies=[Depends(maybe_enforce_api_key_route_policy)]'

# (filename, old router ctor line, new router ctor line)
ROUTER_EDITS = [
    ('user_groups.py',
     'router = APIRouter(prefix="/ui/groups", tags=["user-groups"])',
     'router = APIRouter(prefix="/ui/groups", tags=["user-groups"], %s)' % DEP),
    ('group_feed.py',
     'router = APIRouter(tags=["group-feed"])',
     'router = APIRouter(tags=["group-feed"], %s)' % DEP),
    ('group_calls.py',
     'router = APIRouter(prefix="/ui/calls/group", tags=["group-calls"])',
     'router = APIRouter(prefix="/ui/calls/group", tags=["group-calls"], %s)' % DEP),
    ('group_treasury.py',
     'router = APIRouter(tags=["group-treasury"])',
     'router = APIRouter(tags=["group-treasury"], %s)' % DEP),
    ('group_fundraising.py',
     'group_fundraising_router = APIRouter(prefix="/ui/groups/fundraising", tags=["group-fundraising"])',
     'group_fundraising_router = APIRouter(prefix="/ui/groups/fundraising", tags=["group-fundraising"], %s)' % DEP),
]


def patch_router(fn, old, new):
    p = os.path.join(RDIR, fn)
    with io.open(p, 'r', encoding='utf-8') as f:
        src = f.read()
    changed = False
    if 'api_key_policy_enforcement import maybe_enforce_api_key_route_policy' not in src:
        lines = src.splitlines(keepends=True)
        out, done = [], False
        for ln in lines:
            out.append(ln)
            if (not done) and ln.startswith('from fastapi import'):
                out.append(IMPORT_LINE)
                done = True
        src = ''.join(out)
        changed = True
    if new not in src:
        assert old in src, 'router ctor not found in %s: %s' % (fn, old)
        src = src.replace(old, new, 1)
        changed = True
    if changed:
        with io.open(p, 'w', encoding='utf-8') as f:
            f.write(src)
    print('router %-24s %s' % (fn, 'patched' if changed else 'already'))


# ---- registry rows (product=groups) ----
READ = [
    ('GET', '/ui/groups'), ('GET', '/ui/groups/discover'), ('GET', '/ui/groups/{group_id}'),
    ('GET', '/ui/groups/{group_id}/members'), ('GET', '/ui/groups/{group_id}/pending'),
    ('GET', '/ui/groups/{group_id}/feed'),
    ('GET', '/ui/calls/group/{call_id}'), ('GET', '/ui/calls/group/{call_id}/participants'),
    ('GET', '/ui/calls/group/active/{conversation_id}'), ('GET', '/ui/calls/group/history/{conversation_id}'),
    ('GET', '/ui/groups/{group_id}/treasury'), ('GET', '/ui/groups/{group_id}/treasury/ledger'),
    ('GET', '/ui/groups/{group_id}/treasury/contributors'),
    ('GET', '/ui/groups/fundraising/{group_id}/campaigns'),
    ('GET', '/ui/groups/fundraising/{group_id}/campaigns/{campaign_id}/stats'),
    ('GET', '/ui/groups/fundraising/{group_id}/fundraisers'),
    ('GET', '/ui/groups/fundraising/{group_id}/fundraisers/{fundraiser_id}'),
    ('GET', '/ui/groups/fundraising/{group_id}/fundraisers/{fundraiser_id}/donations'),
]
WRITE = [
    ('POST', '/ui/groups'),
    ('POST', '/ui/groups/{group_id}/join'), ('POST', '/ui/groups/{group_id}/leave'),
    ('POST', '/ui/groups/{group_id}/invite'),
    ('POST', '/ui/groups/{group_id}/invites/{user_id}/respond'),
    ('POST', '/ui/groups/{group_id}/requests/{user_id}/review'),
    ('POST', '/ui/groups/{group_id}/posts'),
    ('POST', '/ui/groups/{group_id}/posts/{post_id}/pin'),
    ('DELETE', '/ui/groups/{group_id}/posts/{post_id}/pin'),
    ('DELETE', '/ui/groups/{group_id}/posts/{post_id}'),
    ('POST', '/ui/calls/group/create'),
    ('POST', '/ui/calls/group/{call_id}/join'), ('POST', '/ui/calls/group/{call_id}/leave'),
    ('POST', '/ui/calls/group/{call_id}/end'),
    ('POST', '/ui/calls/group/{call_id}/signal'), ('PATCH', '/ui/calls/group/{call_id}/media'),
]
MANAGE = [
    ('PATCH', '/ui/groups/{group_id}'), ('DELETE', '/ui/groups/{group_id}'),
    ('PATCH', '/ui/groups/{group_id}/members/{user_id}/role'),
    ('DELETE', '/ui/groups/{group_id}/members/{user_id}'),
]
TREASURY = [
    ('POST', '/ui/groups/{group_id}/treasury/contribute'),
    ('PATCH', '/ui/groups/{group_id}/treasury/goal'),
    ('POST', '/ui/groups/{group_id}/treasury/spend'),
]
FUNDRAISE = [
    ('POST', '/ui/groups/fundraising/{group_id}/campaigns'),
    ('PATCH', '/ui/groups/fundraising/{group_id}/campaigns/{campaign_id}'),
    ('POST', '/ui/groups/fundraising/{group_id}/fundraisers'),
    ('PATCH', '/ui/groups/fundraising/{group_id}/fundraisers/{fundraiser_id}'),
]


def rows():
    out = {}
    for m, p in READ:
        out['%s:%s' % (m, p)] = 'groups:read'
    for m, p in WRITE:
        out['%s:%s' % (m, p)] = 'groups:write'
    for m, p in MANAGE:
        out['%s:%s' % (m, p)] = 'groups:manage'
    for m, p in TREASURY:
        out['%s:%s' % (m, p)] = 'groups:treasury'
    for m, p in FUNDRAISE:
        out['%s:%s' % (m, p)] = 'fundraising:write'
    return out


def build_reg_block():
    R = rows()
    lines = []
    lines.append('    # Groups -- APIK-E4 (#118): groups parity. product=groups.')
    lines.append('    # reads->groups:read; mutations->groups:write; settings/role/remove/dissolve->groups:manage.')
    lines.append('    # MONEY (SECURITY): treasury contribute/spend/goal->groups:treasury (standalone high-priv);')
    lines.append('    # campaign+fundraiser CRUD->fundraising:write (standalone). confirm-donation is intentionally')
    lines.append('    # UNREGISTERED -> require_root_session only -> fail-closed (403 unmapped) to every key.')
    for key in sorted(R.keys()):
        lines.append('    "%s": {"product": "groups", "required_scopes": ["%s"], "entitlement_required": True},' % (key, R[key]))
    return [l + '\n' for l in lines]


def patch_registry():
    with io.open(REG, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    if any('# Groups -- APIK-E4' in l for l in lines):
        print('registry already has Groups block')
        return
    open_idx = next(i for i, l in enumerate(lines) if l.startswith('API_KEY_ROUTE_SCOPE_REGISTRY'))
    close_idx = next(i for i in range(open_idx, len(lines)) if lines[i].rstrip('\n') == '}')
    new = lines[:close_idx] + build_reg_block() + lines[close_idx:]
    with io.open(REG, 'w', encoding='utf-8') as f:
        f.writelines(new)
    print('registry Groups block inserted rows=%d' % len(rows()))


def patch_settings():
    with io.open(SETTINGS, 'r', encoding='utf-8') as f:
        src = f.read()
    old = 'os.environ.get("API_KEY_GROUPS_PHASE", "shadow")'
    new = 'os.environ.get("API_KEY_GROUPS_PHASE", "ga")'
    if new in src:
        print('settings groups phase already ga')
        return
    assert old in src, 'groups phase default not found in settings'
    src = src.replace(old, new, 1)
    with io.open(SETTINGS, 'w', encoding='utf-8') as f:
        f.write(src)
    print('settings groups phase shadow->ga (APIK-E4)')


def main():
    for fn, old, new in ROUTER_EDITS:
        patch_router(fn, old, new)
    patch_registry()
    patch_settings()
    print('E4 patch complete: registry_rows=%d' % len(rows()))


if __name__ == '__main__':
    main()
