import io, sys, os, time
ROOT = sys.argv[1] if len(sys.argv) > 1 else '/home/sean/dev/testlogon'
APPLY = '--apply' in sys.argv
TS = str(int(time.time()))
edits = []

def E(rel, old, new, count=1):
    edits.append((rel, old, new, count))

# ---------- capabilities.py (E0-1 admin:all, E0-2 groups/video/money) ----------
E('app/services/api_key_capabilities.py',
'''    "tickets:admin",
    "tickets:read",
    "tickets:write",
)

_CANONICAL_SET = set(CANONICAL_API_KEY_CAPABILITIES)
''',
'''    "tickets:admin",
    "tickets:read",
    "tickets:write",
    # APIK-E0-1: admin wildcard (grant-gated to admin/root owners in api_keys.create/set)
    "admin:all",
    # APIK-E0-2: groups capability family (routes wired in EPIC E4)
    "groups:read",
    "groups:write",
    "groups:manage",
    "groups:treasury",
    "fundraising:write",
    # APIK-E0-2: video capability family (routes wired in EPIC E5)
    "video:read",
    "video:write",
    "video:manage",
    "video:publish",
    "video:moderate",
    "video:monetize",
    # APIK-E0-2: newsfeed money scope (EPIC E1-2 gates tips/paid-unlock distinctly)
    "newsfeed:tips",
)

_CANONICAL_SET = set(CANONICAL_API_KEY_CAPABILITIES)

# APIK-E0-1: admin:all is a wildcard capability implying every canonical scope.
WILDCARD_API_KEY_CAPABILITY = "admin:all"
''')

E('app/services/api_key_capabilities.py',
'''    "newsfeed:moderate": ("newsfeed:read", "newsfeed:write"),
    "tickets:admin": ("tickets:read", "tickets:write"),
}''',
'''    "newsfeed:moderate": ("newsfeed:read", "newsfeed:write"),
    "tickets:admin": ("tickets:read", "tickets:write"),
    # APIK-E0-2: groups/video inheritance. manage>=write>=read; moderate>=read.
    # treasury/fundraising:write/monetize/tips are standalone high-priv money scopes.
    "groups:manage": ("groups:write",),
    "groups:write": ("groups:read",),
    "video:manage": ("video:write", "video:publish"),
    "video:write": ("video:read",),
    "video:moderate": ("video:read",),
}''')

E('app/services/api_key_capabilities.py',
'''    expanded: Set[str] = set(normalize_api_key_capabilities(values))
    queue = list(expanded)''',
'''    expanded: Set[str] = set(normalize_api_key_capabilities(values))
    if WILDCARD_API_KEY_CAPABILITY in expanded:
        # APIK-E0-1: the wildcard expands to the FULL canonical capability set.
        return sorted(set(CANONICAL_API_KEY_CAPABILITIES))
    queue = list(expanded)''')

# ---------- authorization.py (E0-1 wildcard short-circuit) ----------
E('app/services/api_key_authorization.py',
'from app.services.api_key_capabilities import expand_api_key_capabilities\n',
'from app.services.api_key_capabilities import expand_api_key_capabilities, WILDCARD_API_KEY_CAPABILITY\n')

E('app/services/api_key_authorization.py',
'''    entitlement_gate: Optional[EntitlementGate] = None,
) -> Dict[str, Any]:
    required = _normalize_required_scopes(required_scopes)
    if not required:''',
'''    entitlement_gate: Optional[EntitlementGate] = None,
) -> Dict[str, Any]:
    # APIK-E0-1: an admin:all wildcard key is allowed on EVERY route (incl. unmapped),
    # bypassing per-scope and entitlement checks.
    _granted_all = set(expand_api_key_capabilities(effective_api_key_capabilities(key_item)))
    if WILDCARD_API_KEY_CAPABILITY in _granted_all:
        return {
            "ok": True,
            "wildcard": True,
            "required_scopes": _normalize_required_scopes(required_scopes),
            "granted_scopes": sorted(_granted_all),
            "api_key_id": str(key_item.get("key_id") or ""),
            "entitlement": None,
        }
    required = _normalize_required_scopes(required_scopes)
    if not required:''')

# ---------- api_keys.py (E0-1 wildcard owner gate) ----------
E('app/services/api_keys.py',
'''def effective_api_key_capabilities(item: Dict[str, Any]) -> List[str]:''',
'''def _enforce_wildcard_owner_role_or_403(user_sub: str, capabilities: List[str]) -> None:
    # APIK-E0-1: the admin:all wildcard may be granted ONLY to admin/root owners.
    if "admin:all" not in {str(c).strip().lower() for c in capabilities or []}:
        return
    from app.auth.roles import normalize_role, Role
    try:
        item = T.users.get_item(Key={"user_sub": user_sub}).get("Item") or {}
    except Exception:
        item = {}
    role = normalize_role(item.get("role"))
    if role not in {Role.ADMIN, Role.ROOT}:
        raise HTTPException(
            403,
            {
                "code": "api_key_wildcard_forbidden",
                "message": "The admin:all capability may only be granted to admin/root owners",
                "details": {"required_role": "admin", "owner_role": role.value},
            },
        )


def effective_api_key_capabilities(item: Dict[str, Any]) -> List[str]:''')

E('app/services/api_keys.py',
'''    normalized_capabilities = _normalize_capabilities_or_400(capabilities)
    _enforce_capability_plan_or_403(user_sub, normalized_capabilities)
''',
'''    normalized_capabilities = _normalize_capabilities_or_400(capabilities)
    _enforce_wildcard_owner_role_or_403(user_sub, normalized_capabilities)
    _enforce_capability_plan_or_403(user_sub, [c for c in normalized_capabilities if c != "admin:all"])
''')

E('app/services/api_keys.py',
'''    normalized = _normalize_capabilities_or_400(capabilities)
    _enforce_capability_plan_or_403(user_sub, normalized)
    try:
        T.api_keys.update_item(''',
'''    normalized = _normalize_capabilities_or_400(capabilities)
    _enforce_wildcard_owner_role_or_403(user_sub, normalized)
    _enforce_capability_plan_or_403(user_sub, [c for c in normalized if c != "admin:all"])
    try:
        T.api_keys.update_item(''')

# ---------- rollout.py (E0-3 products) ----------
E('app/services/api_key_rollout.py',
'ROLLOUT_PRODUCTS = ("filemanager", "newsfeed", "tickets", "shopping", "messager")',
'ROLLOUT_PRODUCTS = ("filemanager", "newsfeed", "tickets", "shopping", "messager", "groups", "video")  # APIK-E0-3')

# ---------- settings.py (E0-3 phase flags) ----------
E('app/core/settings.py',
'''    api_key_messager_canary_subjects: str = os.environ.get("API_KEY_MESSAGER_CANARY_SUBJECTS", "")
    api_key_dual_credential_mode: str = os.environ.get("API_KEY_DUAL_CREDENTIAL_MODE", "prefer_api_key")''',
'''    api_key_messager_canary_subjects: str = os.environ.get("API_KEY_MESSAGER_CANARY_SUBJECTS", "")

    # APIK-E0-3: groups rollout product (default shadow until E4 canary->GA)
    api_key_groups: bool = os.environ.get("API_KEY_GROUPS", "1") not in ("0", "false", "False")
    api_key_groups_phase: str = os.environ.get("API_KEY_GROUPS_PHASE", "shadow")
    api_key_groups_canary_percent: int = int(os.environ.get("API_KEY_GROUPS_CANARY_PERCENT", "0"))
    api_key_groups_canary_subjects: str = os.environ.get("API_KEY_GROUPS_CANARY_SUBJECTS", "")

    # APIK-E0-3: video rollout product (default shadow until E5 canary->GA)
    api_key_video: bool = os.environ.get("API_KEY_VIDEO", "1") not in ("0", "false", "False")
    api_key_video_phase: str = os.environ.get("API_KEY_VIDEO_PHASE", "shadow")
    api_key_video_canary_percent: int = int(os.environ.get("API_KEY_VIDEO_CANARY_PERCENT", "0"))
    api_key_video_canary_subjects: str = os.environ.get("API_KEY_VIDEO_CANARY_SUBJECTS", "")

    api_key_dual_credential_mode: str = os.environ.get("API_KEY_DUAL_CREDENTIAL_MODE", "prefer_api_key")''')

# ---------- policy_enforcement.py (E0-4 authorize marker) ----------
E('app/services/api_key_policy_enforcement.py',
'''                record_api_key_policy_decision(
                    mode="shadow",
                    product=str(rollout.get("product") or ""),
                    outcome="error",
                    reason="internal_error",
                )
            return
''',
'''                record_api_key_policy_decision(
                    mode="shadow",
                    product=str(rollout.get("product") or ""),
                    outcome="error",
                    reason="internal_error",
                )
            # APIK-E0-4: shadow proceeds as owner; mark route api-key-authorized so the
            # identity bridge honors the principal. Un-gated routers never reach here.
            request.state.api_key_route_authorized = True
            return
''')

E('app/services/api_key_policy_enforcement.py',
'''        decision = requires_scope_for_request_from_registry(request, key_item, entitlement_gate=_entitlement_gate)
        request.state.api_key_scope_decision = decision
''',
'''        decision = requires_scope_for_request_from_registry(request, key_item, entitlement_gate=_entitlement_gate)
        request.state.api_key_scope_decision = decision
        # APIK-E0-4: scope check passed -> authorize the identity bridge for this route.
        request.state.api_key_route_authorized = True
''')

# ---------- deps.py (E0-4 fail-closed bridge) ----------
E('app/auth/deps.py',
'''    state = getattr(request, "state", None)
    principal = getattr(state, "api_key_principal", None) if state is not None else None
    if isinstance(principal, dict):
        user_sub = str(principal.get("user_sub") or "").strip()
        if user_sub:''',
'''    state = getattr(request, "state", None)
    principal = getattr(state, "api_key_principal", None) if state is not None else None
    # APIK-E0-4 (FAIL-CLOSED): only bridge an api-key principal to the owner identity when
    # the route explicitly admitted the key via maybe_enforce_api_key_route_policy (which
    # sets api_key_route_authorized after a scope/shadow decision). The global
    # _api_key_principal_middleware injects the principal on ALL routers; without this gate
    # an un-gated/session-only router would grant unscoped owner access (the prod over-scope
    # hole). No marker -> fall through to cookie/bearer auth -> 401.
    _route_authorized = bool(getattr(state, "api_key_route_authorized", False)) if state is not None else False
    if isinstance(principal, dict) and _route_authorized:
        user_sub = str(principal.get("user_sub") or "").strip()
        if user_sub:''')

# ---------- sessions.py (E0-4 fail-closed bridge) ----------
E('app/services/sessions.py',
'''    principal = getattr(getattr(request, "state", None), "api_key_principal", None)
    if isinstance(principal, dict):
        principal_sub = str(principal.get("user_sub") or "").strip()
        if principal_sub:''',
'''    principal = getattr(getattr(request, "state", None), "api_key_principal", None)
    # APIK-E0-4 (FAIL-CLOSED): honor the api-key principal only when the route admitted the
    # key via maybe_enforce_api_key_route_policy (api_key_route_authorized marker). Un-gated/
    # session-only routers never set the marker -> fall through to normal session auth.
    _route_authorized = bool(getattr(getattr(request, "state", None), "api_key_route_authorized", False))
    if isinstance(principal, dict) and _route_authorized:
        principal_sub = str(principal.get("user_sub") or "").strip()
        if principal_sub:''')

# ---------- main.py (E0-1 fold global middleware) ----------
E('app/main.py',
'''                request.state.playback_claims = claims
            except PlaybackEntitlementError as exc:
                return JSONResponse(status_code=401, content={"detail": {"code": exc.code, "message": exc.message}})
        return await call_next(request)
    return _middleware

# --- GAP-0323: crawler-detection meta-tag middleware ---------------------''',
'''                request.state.playback_claims = claims
            except PlaybackEntitlementError as exc:
                return JSONResponse(status_code=401, content={"detail": {"code": exc.code, "message": exc.message}})
        return await call_next(request)
    return _middleware


# --- APIK-E0-1: API-key principal injection (folds prod hotfix; decoupled from scope) ---
# When api-key headers (X-API-Key / Authorization: ApiKey) are present, validate the key and
# set request.state.api_key_principal so the shared identity deps resolve the OWNER for ALL
# routers -- matching prod. SECURITY (APIK-E0-4): the identity bridge only HONORS this
# principal when maybe_enforce_api_key_route_policy has set api_key_route_authorized, so
# un-gated/session-only routers fail CLOSED (no unscoped-owner over-scope).
def _api_key_principal_middleware():
    async def _middleware(request: Request, call_next):
        try:
            from app.services.api_key_policy_enforcement import _has_api_key_headers, _has_bearer_header
            from app.services.api_key_auth_dependency import require_api_key_principal
            from app.core.settings import S as _S
            state = getattr(request, "state", None)
            already = getattr(state, "api_key_principal", None) if state is not None else None
            if not isinstance(already, dict) and _has_api_key_headers(request):
                mode = str(getattr(_S, "api_key_dual_credential_mode", "prefer_api_key") or "prefer_api_key").strip().lower()
                proceed = True
                if _has_bearer_header(request):
                    if mode == "prefer_session":
                        proceed = False
                    elif mode == "reject":
                        return JSONResponse(status_code=400, content={"detail": {"code": "api_key_dual_credential_conflict", "reason": "dual_credential_conflict", "message": "Both API key and Bearer credentials were provided"}})
                if proceed:
                    try:
                        await require_api_key_principal(request)
                    except Exception:
                        # present-but-invalid key (revoked/expired/CIDR/bad): do NOT
                        # authenticate -- leave principal unset so route auth 401/403s.
                        pass
        except Exception:
            logger.debug("api_key_principal_middleware fell through", exc_info=True)
        return await call_next(request)
    return _middleware


# --- GAP-0323: crawler-detection meta-tag middleware ---------------------''')

E('app/main.py',
'''    app.middleware("http")(_playback_entitlement_middleware())
    if METRICS_ENABLED:''',
'''    app.middleware("http")(_playback_entitlement_middleware())
    app.middleware("http")(_api_key_principal_middleware())  # APIK-E0-1: set api_key_principal for ALL routers (bridge gated by APIK-E0-4)
    if METRICS_ENABLED:''')

# ---------- registry.py (E0-5 delete phantom rows) ----------
E('app/services/api_key_route_scope_registry.py',
'''    # File Manager
    "GET:/v1/files": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/files/upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "GET:/v1/files/download": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/files/share": {"product": "filemanager", "required_scopes": ["filemanager:share"], "entitlement_required": True},
    # File Manager (actual router paths)''',
'''    # File Manager (actual router paths) -- APIK-E0-5: phantom /v1/files* rows deleted
    # (real prefix is /v1/fs; those route_ids never existed -> permanent stale drift).''')

E('app/services/api_key_route_scope_registry.py',
'''    # Newsfeed
    "GET:/v1/newsfeed": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": False},
    "POST:/v1/newsfeed/posts": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": False},
    "DELETE:/v1/newsfeed/posts/{post_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:moderate"], "entitlement_required": False},
    # Tickets''',
'''    # Newsfeed -- APIK-E0-5: phantom /v1/newsfeed* rows deleted (real routes are /feed, /posts;
    # they are re-pointed at real route_ids in EPIC E1). Registry intentionally empty here.
    # Tickets''')

# ---------------- apply ----------------
print('EDITS defined:', len(edits))
files = {}
for rel, old, new, count in edits:
    files.setdefault(rel, [])
    files[rel].append((old, new, count))

fail = False
for rel, ops in files.items():
    p = os.path.join(ROOT, rel)
    with io.open(p, 'r', encoding='utf-8') as f:
        c = f.read()
    for old, new, count in ops:
        n = c.count(old)
        if n != count:
            print('ANCHOR FAIL', rel, 'expected', count, 'got', n, 'anchor:', repr(old[:70]))
            fail = True
if fail:
    sys.exit(3)
print('All anchors verified unique.')

if not APPLY:
    print('DRY-RUN only. Re-run with --apply to write.')
    sys.exit(0)

for rel, ops in files.items():
    p = os.path.join(ROOT, rel)
    with io.open(p, 'r', encoding='utf-8') as f:
        c = f.read()
    bak = p + '.bak_apik_e0_' + TS
    with io.open(bak, 'w', encoding='utf-8') as f:
        f.write(c)
    for old, new, count in ops:
        c = c.replace(old, new)
    with io.open(p, 'w', encoding='utf-8') as f:
        f.write(c)
    print('PATCHED', rel, '(bak', os.path.basename(bak) + ')')
print('APPLY complete. TS=' + TS)
