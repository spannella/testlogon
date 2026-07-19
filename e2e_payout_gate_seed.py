#!/usr/bin/env python3
"""E2E helper: satisfy the PAY-20/21 verified-before-any-payout gate for a user.

The creator-payout request path (`POST /ui/payouts/request`) is now gated behind
BOTH an APPROVED KYC case (app.services.kyc_cases) AND a certified W-9 on file
(app.services.tax_info_w9): `_enforce_payout_gate` raises PayoutGateError ->
HTTP 403 (`kyc_required` / `tax_info_required`) until both are satisfied. Before
the real-charge/verification refactor a payout could be requested without either,
so the stale specs got a 201 where they now get a 403.

This script:
  1. creates the `kyc_cases` + `tax_info` DDB-Local tables if missing (matching the
     runtime key/GSI schema the services expect),
  2. seeds an APPROVED kyc_case owned by the user (via the real KycCaseStore so the
     item + GSI keys are exactly what resolve_kyc_status() reads),
  3. seeds a certified W-9 row (pk=USER#{sub}, sk=TAX_INFO, tin_last4, certified=True)
     — the exact fields has_tax_info_on_file() checks — bypassing KMS/full-W-9 input
     so no real key material is required in dev.

Usage:  python3 e2e_payout_gate_seed.py <user_sub>
Idempotent: re-running only adds another approved case (harmless) and re-certifies.
Prints a JSON status line on stdout.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# IMPORTANT: load .env.local (DDB_ENDPOINT_URL, AWS_* creds, feature flags) BEFORE
# importing any app module — otherwise `app.core.tables.T` resolves to real AWS
# (https://dynamodb.us-east-1.amazonaws.com) instead of DDB-Local:8001, and every
# put/query 404s. Mirrors the inline env-loader the other e2e Python helpers use.
_ROOT = Path(__file__).resolve().parent
for _env_file in (_ROOT / ".env.local", _ROOT / "frontend" / ".env.local"):
    if _env_file.exists():
        for _line in _env_file.read_text().splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())
os.environ.setdefault("DDB_ENDPOINT_URL", "http://localhost:8001")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_REGION", "us-east-1")

import boto3  # noqa: E402

from app.core.settings import S  # noqa: E402
from app.core.tables import T  # noqa: E402
from app.core.time import now_ts  # noqa: E402


def _client():
    return boto3.client(
        "dynamodb",
        endpoint_url=S.ddb_endpoint_url or "http://localhost:8001",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _has_table(c, name: str) -> bool:
    try:
        c.describe_table(TableName=name)
        return True
    except c.exceptions.ResourceNotFoundException:
        return False


def ensure_kyc_cases_table(c) -> None:
    name = S.kyc_cases_table_name
    if _has_table(c, name):
        return
    c.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi_owner_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_owner_sk", "AttributeType": "S"},
            {"AttributeName": "gsi_status_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_status_sk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": S.kyc_cases_owner_index_name,
                "KeySchema": [
                    {"AttributeName": "gsi_owner_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_owner_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": S.kyc_cases_status_index_name,
                "KeySchema": [
                    {"AttributeName": "gsi_status_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_status_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    c.get_waiter("table_exists").wait(TableName=name)


def ensure_tax_info_table(c) -> None:
    name = S.tax_info_table_name
    if _has_table(c, name):
        return
    c.create_table(
        TableName=name,
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
    c.get_waiter("table_exists").wait(TableName=name)


def seed_approved_kyc(user_sub: str) -> str:
    """Create an APPROVED kyc_case owned by user_sub via the real store (so the
    item + GSI keys match what resolve_kyc_status reads). If the user already has
    an approved case, this is a harmless additional one."""
    from app.services.kyc_cases import STORE

    case = STORE.create_case(user_sub=user_sub, status="approved")
    return case.get("kyc_case_id") or case.get("case_id") or ""


def seed_certified_w9(user_sub: str) -> None:
    """Seed the exact fields has_tax_info_on_file() checks (tin_last4 + certified)
    without exercising the KMS/full-W-9 input path."""
    ts = now_ts()
    T.tax_info.put_item(
        Item={
            "pk": f"USER#{user_sub}",
            "sk": "TAX_INFO",
            "user_sub": user_sub,
            "legal_name": "E2E Test Creator",
            "tin_last4": "6789",
            "tin_type": "ssn",
            "certified": True,
            "certified_at": ts,
            "updated_at": ts,
        }
    )


def seed_verified_default_method(user_sub: str) -> str:
    """PAY-10..12: ensure the user has a VERIFIED default payout method.

    `request_payout` targets the default payout method and rejects it unless
    method_status == 'verified' (`method_not_verified`). Prior runs may have left
    an UNVERIFIED method on file, so clear existing methods and add + verify a fresh
    bank_ach one via the real services (correct record_kind/status transitions).
    """
    from app.services.creator_payouts import (
        add_payout_method,
        list_payout_methods,
        delete_payout_method,
        set_default_payout_method,
        verify_payout_method,
    )

    for m in list_payout_methods(user_sub):
        try:
            delete_payout_method(user_sub, m.get("method_id") or m.get("payout_id"))
        except Exception:
            pass

    method = add_payout_method(
        user_sub,
        method_type="bank_ach",
        account_last4="6789",
        routing_last4="0021",
        nickname="E2E verified bank",
        set_as_default=True,
    )
    mid = method.get("method_id") or method.get("payout_id") or ""
    verify_payout_method(user_sub, mid)
    try:
        set_default_payout_method(user_sub, mid)
    except Exception:
        pass
    return mid


def main() -> None:
    user_sub = sys.argv[1] if len(sys.argv) > 1 else "e2e_alice@test.local"
    c = _client()
    ensure_kyc_cases_table(c)
    ensure_tax_info_table(c)
    case_id = seed_approved_kyc(user_sub)
    seed_certified_w9(user_sub)
    method_id = seed_verified_default_method(user_sub)

    # Verify against the real gate resolvers.
    from app.services.creator_payouts import (
        get_default_payout_method,
        has_tax_info_on_file,
        resolve_kyc_status,
    )

    dm = get_default_payout_method(user_sub) or {}
    status = {
        "user_sub": user_sub,
        "kyc_case_id": case_id,
        "kyc_status": resolve_kyc_status(user_sub),
        "tax_on_file": has_tax_info_on_file(user_sub),
        "method_id": method_id,
        "method_status": dm.get("method_status"),
        "method_is_default": dm.get("is_default"),
    }
    print(json.dumps(status))


if __name__ == "__main__":
    main()
