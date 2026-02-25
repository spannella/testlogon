#!/usr/bin/env python3
"""
Create an E2E auth test user with a known password in DynamoDB Local.

This user is used for UI-based login flow tests (actually filling in the
login form, submitting, and verifying the redirect to home).

Usage: python3 e2e_auth_setup.py
Output: JSON dict { "email": "...", "password": "..." }
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

# Load env vars from .env
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

DDB_ENDPOINT = os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001")
# T.users = USERS_TABLE_NAME (defaults to "users") — the auth credentials table.
# DDB_USERS is a separate table used by the messaging/profile system.
USERS_TABLE = os.environ.get("USERS_TABLE_NAME", "users")
SESSIONS_TABLE = os.environ.get("DDB_SESSIONS_TABLE", "sessions")
ACCOUNT_STATE_TABLE = os.environ.get("ACCOUNT_STATE_TABLE_NAME", "account_state")

PASSWORD_HASH_ITERATIONS = 260_000

dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url=DDB_ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)
users_tbl = dynamodb.Table(USERS_TABLE)
sessions_tbl = dynamodb.Table(SESSIONS_TABLE)
account_state_tbl = dynamodb.Table(ACCOUNT_STATE_TABLE)

TEST_EMAIL = "e2e_logintest@test.local"
TEST_PASSWORD = "TestPass123!@#"


def hash_password(password: str) -> dict:
    """Hash a password using pbkdf2_sha256, matching app/services/registration.py."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": str(PASSWORD_HASH_ITERATIONS),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "hash_b64": base64.b64encode(digest).decode("ascii"),
    }


def ensure_user():
    ph = hash_password(TEST_PASSWORD)
    try:
        users_tbl.put_item(
            Item={
                "user_sub": TEST_EMAIL,
                "email": TEST_EMAIL,
                "full_name": "E2E Login Test",
                "password_hash": ph,
                "created_at": int(time.time()),
            },
            ConditionExpression="attribute_not_exists(user_sub)",
        )
        print(f"Created user {TEST_EMAIL}", file=sys.stderr)
    except Exception:
        # User already exists — refresh the password hash so the known password works.
        users_tbl.update_item(
            Key={"user_sub": TEST_EMAIL},
            UpdateExpression="SET password_hash = :ph",
            ExpressionAttributeValues={":ph": ph},
        )
        print(f"User {TEST_EMAIL} already exists, password refreshed", file=sys.stderr)


def ensure_account_active():
    account_state_tbl.put_item(
        Item={
            "user_sub": TEST_EMAIL,
            "status": "active",
            "updated_at": int(time.time()),
            "reason": "e2e_test_setup",
            "requested_by": TEST_EMAIL,
        }
    )


ensure_user()
ensure_account_active()

print(json.dumps({"email": TEST_EMAIL, "password": TEST_PASSWORD}))
