#!/usr/bin/env python3
"""
Create E2E test users and sessions in DynamoDB Local, then output cookie
values that Playwright can inject into the browser.

Usage: python3 e2e_session_setup.py
Output: JSON dict { "alice": {...cookies...}, "bob": {...cookies...} }
"""
import json, time, uuid, secrets, os, sys

# Load env vars from .env.local so we get the right table names and secret
from pathlib import Path
env_file = Path(__file__).parent / "app" / ".env"
if not env_file.exists():
    env_file = Path(__file__).parent / ".env.local"
if not env_file.exists():
    env_file = Path(__file__).parent / ".env"
if env_file.exists():
    # Match shell `set -a && . .env.local` semantics: within the file, the LAST
    # assignment for a key wins (not the first), a real pre-existing env var still
    # wins over the file, and an empty value never clobbers a non-empty one. The old
    # `setdefault` first-wins logic locked in a placeholder `UI_ACCESS_TOKEN_SECRET=`
    # line so the seeder signed ui_access_token cookies with an empty secret while the
    # backend verified with the real (later-line) secret -> cookie-auth specs 401'd.
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

UI_ACCESS_TOKEN_SECRET = os.environ.get(
    "UI_ACCESS_TOKEN_SECRET",
    "ufeuNsYvb0u-eseP7UUCqFWiNwiEcDfJnIKGZ3kPPlTJeSBK6ZZh0VVRzue-RZly",
)
DDB_ENDPOINT = os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001")
SESSIONS_TABLE = os.environ.get("DDB_SESSIONS_TABLE", "sessions")
USERS_TABLE = os.environ.get("DDB_USERS", "ddb_users")

dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url=DDB_ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)
sessions_tbl = dynamodb.Table(SESSIONS_TABLE)
users_tbl = dynamodb.Table(USERS_TABLE)

TTL_SECONDS = 3600


def ensure_user(user_id: str, display_name: str) -> None:
    """Upsert a minimal user record so messaging lookups work."""
    try:
        users_tbl.put_item(
            Item={
                "user_id": user_id,
                "display_name": display_name,
                "created_at": int(time.time()),
            },
            ConditionExpression="attribute_not_exists(user_id)",
        )
    except Exception:
        pass  # Already exists


def create_session(user_sub: str) -> dict:
    session_id = str(uuid.uuid4())
    csrf_token = secrets.token_urlsafe(32)
    now = int(time.time())
    ttl = now + TTL_SECONDS

    sessions_tbl.put_item(
        Item={
            "user_sub": user_sub,
            "session_id": session_id,
            "csrf_token": csrf_token,
            "created_at": now,
            "last_seen_at": now,
            "ip": "127.0.0.1",
            "user_agent": "playwright-e2e",
            "revoked": False,
            "pending_auth": False,
            "ttl": ttl,
        }
    )

    access_token = jwt.encode(
        {"sub": user_sub, "sid": session_id, "iat": now, "exp": now + TTL_SECONDS},
        UI_ACCESS_TOKEN_SECRET,
        algorithm="HS256",
    )

    return {
        "user_sub": user_sub,
        "session_id": session_id,
        "csrf_token": csrf_token,
        "access_token": access_token,
        "cookies": [
            {
                "name": "ui_access_token",
                "value": access_token,
                "domain": "localhost",
                "path": "/",
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
                "expires": now + TTL_SECONDS,
            },
            {
                "name": "ui_session",
                "value": session_id,
                "domain": "localhost",
                "path": "/",
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
                "expires": now + TTL_SECONDS,
            },
            {
                "name": "ui_csrf",
                "value": csrf_token,
                "domain": "localhost",
                "path": "/",
                "httpOnly": False,
                "secure": False,
                "sameSite": "Lax",
                "expires": now + TTL_SECONDS,
            },
        ],
    }


TEST_USERS = [
    ("e2e_alice@test.local", "E2E Alice"),
    ("e2e_bob@test.local", "E2E Bob"),
    ("e2e_charlie@test.local", "E2E Charlie"),
]

results = {}
for user_id, display_name in TEST_USERS:
    ensure_user(user_id, display_name)
    session = create_session(user_id)
    results[user_id] = session
    print(f"Created session for {user_id}", file=sys.stderr)

print(json.dumps(results))
