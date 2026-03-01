#!/usr/bin/env python3
"""
Create an E2E registration test scenario with MFA setup.

Strategy:
  1. POST /ui/register/start with a unique email + MFA flags to register the
     user through the normal flow (creates the Cognito user, DDB user record,
     and a verification challenge).
  2. Find the challenge in DDB and overwrite its code_hash with sha256 of a
     known 6-digit code so the test can fill it in without reading emails.
  3. Pre-register the Playwright browser device in DDB so getMe() (called by
     Register.tsx after confirm) doesn't hit "Re-auth required".

Usage:
  python3 e2e_register_mfa_setup.py --mfa totp
  python3 e2e_register_mfa_setup.py --mfa sms --phone +15551234567

Environment:
  E2E_PLAYWRIGHT_UA  — Playwright browser user agent string

Output (JSON):
  { "email": "...", "code": "...", "mfa_setup": [...], "phone": "..." }
"""
import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

# Load env vars (.env.local, app/.env, .env — first found)
_root = Path(__file__).parent
for _candidate in [
    _root / ".env.local",
    _root / "app" / ".env",
    _root / ".env",
]:
    if _candidate.exists():
        for _line in _candidate.read_text().splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())
        break

import boto3
import requests as http

API_BASE = os.environ.get("E2E_API_BASE", "http://localhost:8000")
DDB_ENDPOINT = os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001")
SESSIONS_TABLE = os.environ.get("DDB_SESSIONS_TABLE", "sessions")

dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url=DDB_ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)
sessions_tbl = dynamodb.Table(SESSIONS_TABLE)

REGISTRATION_LATEST_POINTER_ID = "register_verify_latest"


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def clear_rate_limits(email: str) -> None:
    """Clear any lockout/rate-limit records that could block the test user or 127.0.0.1."""
    for action in ("register_start", "register_confirm", "register_resend"):
        lockout_sid = f"lockout#{action}"
        for user_sub in (email, "ip#127.0.0.1"):
            try:
                sessions_tbl.delete_item(Key={"user_sub": user_sub, "session_id": lockout_sid})
            except Exception:
                pass
    print(f"Cleared rate limits for {email}", file=sys.stderr)


def register_start(email: str, password: str, mfa_type: str, phone: str) -> None:
    """Call /ui/register/start to create the user in Cognito + DDB."""
    # Clear any leftover rate limits from prior test runs
    clear_rate_limits(email)
    payload = {
        "email": email,
        "full_name": "E2E MFA Test",
        "password": password,
        "confirm_password": password,
        "enable_totp_mfa": mfa_type == "totp",
        "enable_sms_mfa": mfa_type == "sms",
        "phone": phone if mfa_type == "sms" else None,
    }
    resp = http.post(f"{API_BASE}/ui/register/start", json=payload, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "ok":
        raise RuntimeError(f"register_start failed: {data}")
    print(f"register_start ok for {email}", file=sys.stderr)


def patch_challenge_code(email: str, known_code: str) -> bool:
    """
    Replace the challenge's code_hash with sha256(known_code) so the test
    can submit the known code instead of reading the emailed code.
    """
    # Retry a few times; DDB write from register_start might need a moment
    for attempt in range(10):
        pointer = sessions_tbl.get_item(
            Key={"user_sub": email, "session_id": REGISTRATION_LATEST_POINTER_ID}
        ).get("Item")
        if pointer:
            break
        print(f"Waiting for challenge pointer (attempt {attempt + 1})…", file=sys.stderr)
        time.sleep(0.3)
    else:
        return False

    challenge_id = pointer.get("challenge_id", "")
    if not challenge_id:
        return False

    challenge = sessions_tbl.get_item(
        Key={"user_sub": email, "session_id": challenge_id}
    ).get("Item")
    if not challenge:
        return False

    # Overwrite code_hash with our known code
    new_hash = sha256_str(known_code)
    sessions_tbl.update_item(
        Key={"user_sub": email, "session_id": challenge_id},
        UpdateExpression="SET code_hash = :h",
        ExpressionAttributeValues={":h": new_hash},
    )
    print(f"Patched challenge {challenge_id} code_hash for {email}", file=sys.stderr)
    return True


def preregister_device(user_sub: str, user_agent: str) -> None:
    """Pre-register the Playwright browser device for this user."""
    device_id = sha256_str(user_agent)[:32]
    sid = f"dev#{device_id}"
    ts = int(time.time())
    sessions_tbl.put_item(Item={
        "user_sub": user_sub,
        "session_id": sid,
        "device_id": device_id,
        "user_agent": user_agent,
        "first_seen_at": ts,
        "last_seen_at": ts,
        "last_ip": "127.0.0.1",
        "last_ip_prefix": "127.0.0",
        "trusted": False,
        "token_hash": "",
    })
    print(f"Pre-registered device {device_id} for {user_sub}", file=sys.stderr)


def setup(mfa_type: str, phone: str, user_agent: str) -> dict:
    ts = int(time.time())
    email = f"e2e_mfa_{mfa_type}_{ts}@test.local"
    # Known code: 6 digits, deterministic for this run
    known_code = f"{hash(email + 'code') % 1000000:06d}"
    password = "ValidPass1!@3456"
    mfa_setup = [mfa_type]
    sms_phone = phone if mfa_type == "sms" else ""

    # 1. Register through the normal API (creates Cognito + DDB user)
    register_start(email, password, mfa_type, phone)

    # 2. Patch the challenge code in DDB so we know it
    if not patch_challenge_code(email, known_code):
        raise RuntimeError(f"Could not find/patch challenge for {email}")

    # 3. Pre-register Playwright device so getMe() doesn't 401
    if user_agent:
        preregister_device(email, user_agent)

    return {
        "email": email,
        "code": known_code,
        "mfa_setup": mfa_setup,
        "phone": sms_phone,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E2E MFA registration setup")
    parser.add_argument("--mfa", required=True, choices=["totp", "sms"])
    parser.add_argument("--phone", default="+15551234567")
    args = parser.parse_args()

    ua = os.environ.get("E2E_PLAYWRIGHT_UA", "")
    result = setup(args.mfa, args.phone, ua)
    print(json.dumps(result))
