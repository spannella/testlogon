APP="/home/ubuntu/testlogon"

# ---- ui_session.py: augment prod's existing role/is_admin ui_me with admin_profile ----
p=f"{APP}/app/routers/ui_session.py"
s=open(p).read()

# 1) add roles import (idempotent). Prod import line is the plain one.
old_imp="from app.auth.deps import get_authenticated_user_sub, resolve_dev_or_authenticated_user_sub"
new_imp=("from app.auth.deps import get_authenticated_user_sub, resolve_dev_or_authenticated_user_sub\n"
"from app.auth.roles import AdminProfile, normalize_admin_profile")
if "from app.auth.roles import AdminProfile, normalize_admin_profile" not in s:
    assert old_imp in s, "PROD import anchor missing"
    s=s.replace(old_imp,new_imp,1)

# 2) inject a helper just before the /me route and add admin_profile to the return dict.
old_me='''@router.get("/me")
async def ui_me(req: Request, ctx: Dict[str, str] = Depends(require_ui_session)):
    # B7-SUPPORT: surface the caller's role + is_admin so cookie-session clients
    # (the Android app) have an AUTHORITATIVE admin signal without a readable JWT.
    # The support/helpdesk + admin screens use this to show the USER vs ADMIN
    # surface. Best-effort: a lookup failure degrades to a normal user (role="user").
    role_value = "user"
    is_admin = False
    try:
        from app.auth.deps import get_authenticated_user as _gau
        from app.auth.roles import Role as _Role
        _au = await _gau(req)
        role_value = getattr(_au.role, "value", str(_au.role))
        is_admin = _au.role in {_Role.ADMIN, _Role.ROOT}
    except Exception:
        role_value = "user"
        is_admin = False
    return {
        "user_sub": ctx["user_sub"],
        "session_id": ctx["session_id"],
        "ip": client_ip_from_request(req),
        "role": role_value,
        "is_admin": is_admin,
    }'''

new_me='''def _resolve_admin_profile_for_me(user_sub: str, auth_user) -> "AdminProfile":
    """Authoritative admin-profile (scopes) for the caller (WEBFIX BUG2).

    The users table row is the source of truth for scoped-admin assignment
    (admin_roles writes ``admin_profile`` there). The cookie-login path does not
    embed admin_profile in the access-token claims, so reading the table keeps
    scope-gated nav (ModerationBoard/DMCA/video-review) correct. Falls back to
    the claim-derived profile on the AuthenticatedUser, then a general profile.
    """
    try:
        item = T.users.get_item(Key={"user_sub": user_sub}).get("Item") or {}
        if item.get("admin_profile") is not None:
            return normalize_admin_profile(item.get("admin_profile"))
    except Exception:
        pass
    try:
        if auth_user is not None:
            return normalize_admin_profile(getattr(auth_user, "admin_profile", None))
    except Exception:
        pass
    return AdminProfile()


@router.get("/me")
async def ui_me(req: Request, ctx: Dict[str, str] = Depends(require_ui_session)):
    # B7-SUPPORT: surface the caller's role + is_admin so cookie-session clients
    # (the Android app) have an AUTHORITATIVE admin signal without a readable JWT.
    # The support/helpdesk + admin screens use this to show the USER vs ADMIN
    # surface. Best-effort: a lookup failure degrades to a normal user (role="user").
    role_value = "user"
    is_admin = False
    _au = None
    try:
        from app.auth.deps import get_authenticated_user as _gau
        from app.auth.roles import Role as _Role
        _au = await _gau(req)
        role_value = getattr(_au.role, "value", str(_au.role))
        is_admin = _au.role in {_Role.ADMIN, _Role.ROOT}
    except Exception:
        role_value = "user"
        is_admin = False
        _au = None
    body = {
        "user_sub": ctx["user_sub"],
        "session_id": ctx["session_id"],
        "ip": client_ip_from_request(req),
        "role": role_value,
        "is_admin": is_admin,
    }
    # WEBFIX BUG2: include admin_profile (scopes) so the SPA can render
    # scope-gated admin nav (moderation/DMCA) for scoped admins.
    if is_admin:
        body["admin_profile"] = _resolve_admin_profile_for_me(ctx["user_sub"], _au).to_dict()
    return body'''

assert old_me in s, "PROD ui_me(B7) anchor missing"
s=s.replace(old_me,new_me,1)
open(p,"w").write(s)
print("PROD ui_session.py patched (admin_profile added)")

# ---- order_lifecycle.py ----
p2=f"{APP}/app/routers/order_lifecycle.py"
s2=open(p2).read()
old='''    if not target_user and not status:
        # Non-admin with no derivable user (shouldn't happen) or admin asking for
        # an unscoped listing → require at least one scope.
        if not is_admin:
            target_user = ctx.get("user_sub")
        else:
            raise HTTPException(
                status_code=400,
                detail={"code": "scope_required", "message": "Pass user_id or status"},
            )'''
new='''    if not target_user and not status:
        # No explicit scope supplied. For BOTH non-admins and admins, default to
        # the caller's own orders (the SPA Orders page lists "your orders" and
        # calls GET /ui/orders?limit=50 with no filters). Previously an admin with
        # no user_id/status got a 400 scope_required, which surfaced in the SPA as
        # a raw "Bad Request". Admins can still pass ?user_id=/?status= to widen.
        target_user = ctx.get("user_sub")'''
assert old in s2, "PROD orders anchor missing"
s2=s2.replace(old,new,1)
open(p2,"w").write(s2)
print("PROD order_lifecycle.py patched")
