#!/usr/bin/env python3
"""
Create E2E test users and sessions in DynamoDB Local, then output cookie
values that Playwright can inject into the browser.

Usage: python3 e2e_session_setup.py
Output: JSON dict { "alice": {...cookies...}, "bob": {...cookies...} }
"""
import json, time, uuid, secrets, os, sys

# Load env vars from .env so we get the right table names and secret
from pathlib import Path
env_file = Path(__file__).parent / "app" / ".env"
if not env_file.exists():
    env_file = Path(__file__).parent / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

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
]

results = {}
for user_id, display_name in TEST_USERS:
    ensure_user(user_id, display_name)
    session = create_session(user_id)
    results[user_id] = session
    print(f"Created session for {user_id}", file=sys.stderr)

print(json.dumps(results))
