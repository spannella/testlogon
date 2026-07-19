#!/usr/bin/env python3
"""
Create E2E sessions for admin/root tests.

Creates:
  - User records in the *auth* users table (T.users / "users") for root,
    alice, bob, and charlie so that admin API endpoints can look them up.
  - Sessions in the sessions table for each test identity.
  - Role-bearing ui_access_token cookies (HS256, signed with
    UI_ACCESS_TOKEN_SECRET) so that the backend's cookie-auth path extracts
    the correct role / admin_profile for each request.
  - The role_audit table is created if it does not yet exist.

Identities created
  root    – role=root (ROOT_USER_SUB from env)
  alice   – role=user  (for 403 rejection tests)
  charlie – role=admin, admin_profile={type:general}  (general-admin tests)
  charlie_scoped – same sub, role=admin, admin_profile={type:scoped,scopes:[auth_support]}
  bob     – role=user  (target for grant/revoke and impersonation)

Output: JSON dict keyed by identity name (see above), each entry has the
same shape as e2e_session_setup.py (user_sub, session_id, csrf_token, cookies[]).
"""
import json
import os
import secrets
import sys
import time
import uuid
from pathlib import Path

# ── Load env vars ────────────────────────────────────────────────────────────
env_file = Path(__file__).parent / "app" / ".env"
if not env_file.exists():
    env_file = Path(__file__).parent / ".env.local"
if env_file.exists():
    # Match shell `set -a && . .env.local` semantics: within the file, the LAST
    # assignment for a key wins (not the first). A real pre-existing environment
    # variable still takes precedence over the file. Empty values never clobber a
    # non-empty one. This matters because .env.local can legitimately contain a
    # placeholder line (e.g. `UI_ACCESS_TOKEN_SECRET=`) that a later line fills in;
    # the old `setdefault` first-wins logic locked in the empty placeholder, so the
    # seeder signed ui_access_token cookies with an empty secret while the backend
    # (shell-sourced, last-wins) verified with the real secret -> every cookie-auth
    # spec 401'd with "Missing bearer token".
    _preexisting_env = dict(os.environ)
    _file_vals = {}
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if v == "" and _file_vals.get(k):
                continue  # do not let a later empty value wipe a non-empty one
            _file_vals[k] = v  # last non-empty assignment wins
    for k, v in _file_vals.items():
        if k not in _preexisting_env:  # a real env var still wins over the file
            os.environ[k] = v

import boto3
import jwt
from botocore.exceptions import ClientError

DDB_ENDPOINT     = os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001")
SESSIONS_TABLE   = os.environ.get("DDB_SESSIONS_TABLE", "sessions")
USERS_TABLE      = os.environ.get("USERS_TABLE_NAME", "users")
PROFILE_TABLE    = os.environ.get("PROFILE_TABLE_NAME", "profiles")
ROLE_AUDIT_TABLE = os.environ.get("ROLE_AUDIT_TABLE_NAME", "role_audit")
ROOT_USER_SUB    = os.environ.get("ROOT_USER_SUB", "root")
ACCESS_SECRET    = os.environ.get(
    "UI_ACCESS_TOKEN_SECRET",
    "ufeuNsYvb0u-eseP7UUCqFWiNwiEcDfJnIKGZ3kPPlTJeSBK6ZZh0VVRzue-RZly",
)
ACCESS_COOKIE    = os.environ.get("UI_ACCESS_TOKEN_COOKIE_NAME", "ui_access_token")
SESSION_COOKIE   = os.environ.get("UI_SESSION_COOKIE_NAME", "ui_session")
CSRF_COOKIE      = os.environ.get("UI_CSRF_COOKIE_NAME", "ui_csrf")

TTL_SECONDS = 7200  # 2 hours

dynamodb  = boto3.resource(
    "dynamodb",
    endpoint_url=DDB_ENDPOINT, region_name="us-east-1",
    aws_access_key_id="test", aws_secret_access_key="test",
)
ddb_client = boto3.client(
    "dynamodb",
    endpoint_url=DDB_ENDPOINT, region_name="us-east-1",
    aws_access_key_id="test", aws_secret_access_key="test",
)
sessions_tbl = dynamodb.Table(SESSIONS_TABLE)
users_tbl    = dynamodb.Table(USERS_TABLE)
profile_tbl  = dynamodb.Table(PROFILE_TABLE)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _ensure_role_audit_table() -> None:
    try:
        ddb_client.create_table(
            TableName=ROLE_AUDIT_TABLE,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        print(f"Created {ROLE_AUDIT_TABLE} table", file=sys.stderr)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceInUseException",
            "ResourceNotFoundException",
        ):
            raise


def ensure_auth_user(user_sub: str, display_name: str, role: str = "user") -> None:
    """Upsert a record in the auth *users* table (PK=user_sub)."""
    try:
        users_tbl.put_item(
            Item={
                "user_sub":    user_sub,
                "display_name": display_name,
                "role":        role,
                "created_at":  int(time.time()),
            },
            ConditionExpression="attribute_not_exists(user_sub)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Exists — ensure role is correct for the test run.
            users_tbl.update_item(
                Key={"user_sub": user_sub},
                UpdateExpression="SET #r = :r",
                ExpressionAttributeNames={"#r": "role"},
                ExpressionAttributeValues={":r": role},
            )
        else:
            raise


def ensure_profile(user_sub: str, display_name: str) -> None:
    """Upsert a record in the canonical *profiles* table (PK=user_sub).

    The social-graph follow service (app/services/social.py) rejects a follow
    with `user_not_found` (HTTP 404) when the target has no profile row. The
    test identities are seeded directly into DynamoDB, so a clean `just restart`
    leaves the profiles table empty — create the rows here so follow/unfollow
    and follower-list endpoints work in a fresh DB.
    """
    try:
        profile_tbl.put_item(
            Item={
                "user_sub":     user_sub,
                "display_name": display_name,
                "created_at":   int(time.time()),
            },
            ConditionExpression="attribute_not_exists(user_sub)",
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ConditionalCheckFailedException":
            # Row already exists. The messaging conversation list resolves peer
            # names via profile.get_profile_identity -> get_profile, which reads
            # the NESTED item["profile"]["display_name"] map (NOT the top-level
            # display_name). Older rows may have a stale/None nested name, which
            # breaks UI specs that locate a conversation by the seeded name.
            # Backfill BOTH the top-level and the nested profile.display_name.
            try:
                existing = profile_tbl.get_item(Key={"user_sub": user_sub}).get("Item") or {}
                nested = (existing.get("profile") or {}).get("display_name")
                if existing.get("display_name") != display_name or nested != display_name:
                    profile_tbl.update_item(
                        Key={"user_sub": user_sub},
                        UpdateExpression=(
                            "SET display_name = :dn, "
                            "#p = if_not_exists(#p, :empty)"
                        ),
                        ExpressionAttributeNames={"#p": "profile"},
                        ExpressionAttributeValues={":dn": display_name, ":empty": {}},
                    )
                    profile_tbl.update_item(
                        Key={"user_sub": user_sub},
                        UpdateExpression="SET #p.#dn = :dn",
                        ExpressionAttributeNames={"#p": "profile", "#dn": "display_name"},
                        ExpressionAttributeValues={":dn": display_name},
                    )
            except ClientError:
                pass
            return
        if code == "ResourceNotFoundException":
            # Profiles table missing in this environment — nothing to seed.
            return
        raise


def _make_cookie(name: str, value: str, now: int, ttl: int,
                 http_only: bool = True) -> dict:
    return {
        "name":     name,
        "value":    value,
        "domain":   "localhost",
        "path":     "/",
        "httpOnly": http_only,
        "secure":   False,
        "sameSite": "Lax",
        "expires":  now + ttl,
    }


def create_session(
    user_sub: str,
    *,
    role: str = "user",
    admin_profile: dict | None = None,
) -> dict:
    """Create a DDB session + signed access-token cookie with role claims."""
    session_id = str(uuid.uuid4())
    csrf_token = secrets.token_urlsafe(32)
    now        = int(time.time())
    ttl        = TTL_SECONDS

    sessions_tbl.put_item(
        Item={
            "user_sub":     user_sub,
            "session_id":   session_id,
            "csrf_token":   csrf_token,
            "created_at":   now,
            "last_seen_at": now,
            "ip":           "127.0.0.1",
            "user_agent":   "playwright-e2e-admin",
            "revoked":      False,
            "pending_auth": False,
            "ttl_epoch":    now + ttl,
        }
    )

    jwt_payload: dict = {
        "sub":  user_sub,
        "sid":  session_id,
        "role": role,
        "iat":  now,
        "exp":  now + ttl,
    }
    if admin_profile:
        jwt_payload["admin_profile"] = admin_profile

    access_token = jwt.encode(jwt_payload, ACCESS_SECRET, algorithm="HS256")

    return {
        "user_sub":    user_sub,
        "session_id":  session_id,
        "csrf_token":  csrf_token,
        "access_token": access_token,
        "cookies": [
            _make_cookie(ACCESS_COOKIE,  access_token, now, ttl, http_only=True),
            _make_cookie(SESSION_COOKIE, session_id,   now, ttl, http_only=True),
            _make_cookie(CSRF_COOKIE,    csrf_token,   now, ttl, http_only=False),
        ],
    }


# ── Setup ─────────────────────────────────────────────────────────────────────

_ensure_role_audit_table()

# Ensure auth-table records exist.
ensure_auth_user(ROOT_USER_SUB,           "E2E Root Admin",    "root")
ensure_auth_user("e2e_alice@test.local",  "E2E Alice",         "user")
ensure_auth_user("e2e_bob@test.local",    "E2E Bob",           "user")
ensure_auth_user("e2e_charlie@test.local","E2E Charlie",       "user")

# Ensure canonical profile rows exist (social follow service requires them).
ensure_profile(ROOT_USER_SUB,            "E2E Root Admin")
ensure_profile("e2e_alice@test.local",   "E2E Alice")
ensure_profile("e2e_bob@test.local",     "E2E Bob")
ensure_profile("e2e_charlie@test.local", "E2E Charlie")

# Build sessions with different role / profile combinations.
IDENTITIES = [
    # (key,              user_sub,                    role,    admin_profile)
    ("root",             ROOT_USER_SUB,               "root",  None),
    ("alice",            "e2e_alice@test.local",      "user",  None),
    ("bob",              "e2e_bob@test.local",        "user",  None),
    ("charlie_admin",    "e2e_charlie@test.local",    "admin", {"type": "general"}),
    ("charlie_scoped",   "e2e_charlie@test.local",    "admin", {"type": "scoped", "scopes": ["auth_support"]}),
    ("compliance_admin", "e2e_charlie@test.local",    "admin", {"type": "scoped", "scopes": ["content_moderation"]}),
]

results: dict = {}
for key, user_sub, role, admin_profile in IDENTITIES:
    results[key] = create_session(user_sub, role=role, admin_profile=admin_profile)
    print(
        f"Created session key={key!r} sub={user_sub!r} role={role!r}",
        file=sys.stderr,
    )

# Email/sub aliases so specs that key sessions by the user's email (e.g.
# "e2e_alice@test.local") resolve the same session as the short keys above.
_ALIASES = {
    "e2e_alice@test.local": "alice",
    "e2e_bob@test.local": "bob",
    "e2e_charlie@test.local": "charlie_admin",
    ROOT_USER_SUB: "root",
}
for _alias, _src in _ALIASES.items():
    if _alias not in results and _src in results:
        results[_alias] = results[_src]

print(json.dumps(results))
