#!/usr/bin/env python3
"""
Create a fresh test user for multi-device TOTP MFA E2E tests.

The user has:
  - Known email + password stored in the DDB credentials table
  - Active account_state record
  - A DDB session with mfa_verified_at stamped (so require_fresh_mfa()
    passes for TOTP device enrollment API calls)

Usage: python3 e2e_mfa_multidevice_setup.py
Output (JSON):
  {
    "email": "...", "password": "...", "user_sub": "...",
    "session_id": "...", "csrf_token": "...", "access_token": "...",
    "cookies": [ { name, value, domain, path, httpOnly, secure, sameSite, expires } ... ]
  }
"""
import base64, hashlib, json, os, secrets, sys, time, uuid
from pathlib import Path

# Load env vars from the first .env file found
for _cand in [
    Path(__file__).parent / ".env.local",
    Path(__file__).parent / "app" / ".env",
    Path(__file__).parent / ".env",
]:
    if _cand.exists():
        for _line in _cand.read_text().splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                k, v = _line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
        break

import boto3
import jwt

UI_ACCESS_TOKEN_SECRET = os.environ.get(
    "UI_ACCESS_TOKEN_SECRET",
    "ufeuNsYvb0u-eseP7UUCqFWiNwiEcDfJnIKGZ3kPPlTJeSBK6ZZh0VVRzue-RZly",
)
DDB_ENDPOINT          = os.environ.get("DDB_ENDPOINT_URL",           "http://localhost:8001")
USERS_TABLE           = os.environ.get("USERS_TABLE_NAME",            "users")
SESSIONS_TABLE        = os.environ.get("DDB_SESSIONS_TABLE",          "sessions")
ACCOUNT_STATE_TABLE   = os.environ.get("ACCOUNT_STATE_TABLE_NAME",    "account_state")
PROFILE_TABLE         = os.environ.get("DDB_USERS",                   "ddb_users")

PASSWORD               = "ValidPass1!@3456"
TTL_SECONDS            = 3600
PASSWORD_HASH_ITERS    = 260_000

dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url=DDB_ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)
users_tbl        = dynamodb.Table(USERS_TABLE)
sessions_tbl     = dynamodb.Table(SESSIONS_TABLE)
account_state_tbl = dynamodb.Table(ACCOUNT_STATE_TABLE)
profile_tbl      = dynamodb.Table(PROFILE_TABLE)


def _hash_password(password: str) -> dict:
    salt   = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_HASH_ITERS)
    return {
        "algorithm":  "pbkdf2_sha256",
        "iterations": str(PASSWORD_HASH_ITERS),
        "salt_b64":   base64.b64encode(salt).decode("ascii"),
        "hash_b64":   base64.b64encode(digest).decode("ascii"),
    }


def setup() -> dict:
    ts       = int(time.time())
    email    = f"e2e_mfa_multi_{ts}@test.local"
    user_sub = email

    # 1. Credentials record (DDB users table)
    users_tbl.put_item(Item={
        "user_sub":       user_sub,
        "email":          email,
        "full_name":      "E2E MFA Multi Test",
        "password_hash":  _hash_password(PASSWORD),
        "created_at":     ts,
    })
    print(f"Created credentials for {email}", file=sys.stderr)

    # 2. Account state → active
    account_state_tbl.put_item(Item={
        "user_sub":     user_sub,
        "status":       "active",
        "updated_at":   ts,
        "reason":       "e2e_test_setup",
        "requested_by": user_sub,
    })

    # 3. Profile record (display_name for conversations etc.)
    try:
        profile_tbl.put_item(Item={
            "user_id":      user_sub,
            "display_name": "E2E MFA Multi",
            "created_at":   ts,
        })
    except Exception:
        pass

    # 4. Session with mfa_verified_at = now (so require_fresh_mfa passes)
    session_id = str(uuid.uuid4())
    csrf_token = secrets.token_urlsafe(32)
    now        = int(time.time())
    ttl        = now + TTL_SECONDS

    sessions_tbl.put_item(Item={
        "user_sub":        user_sub,
        "session_id":      session_id,
        "csrf_token":      csrf_token,
        "created_at":      now,
        "last_seen_at":    now,
        "mfa_verified_at": now,
        "ip":              "127.0.0.1",
        "user_agent":      "playwright-e2e",
        "revoked":         False,
        "pending_auth":    False,
        "ttl":             ttl,
    })

    access_token = jwt.encode(
        {"sub": user_sub, "sid": session_id, "iat": now, "exp": now + TTL_SECONDS},
        UI_ACCESS_TOKEN_SECRET,
        algorithm="HS256",
    )

    cookies = [
        {
            "name": "ui_access_token", "value": access_token,
            "domain": "localhost", "path": "/",
            "httpOnly": True, "secure": False, "sameSite": "Lax",
            "expires": now + TTL_SECONDS,
        },
        {
            "name": "ui_session", "value": session_id,
            "domain": "localhost", "path": "/",
            "httpOnly": True, "secure": False, "sameSite": "Lax",
            "expires": now + TTL_SECONDS,
        },
        {
            "name": "ui_csrf", "value": csrf_token,
            "domain": "localhost", "path": "/",
            "httpOnly": False, "secure": False, "sameSite": "Lax",
            "expires": now + TTL_SECONDS,
        },
    ]

    return {
        "email":        email,
        "password":     PASSWORD,
        "user_sub":     user_sub,
        "session_id":   session_id,
        "csrf_token":   csrf_token,
        "access_token": access_token,
        "cookies":      cookies,
    }


if __name__ == "__main__":
    result = setup()
    print(json.dumps(result))
