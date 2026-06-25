#!/usr/bin/env python3
"""Seed a default Visa payment method for the E2E identities so tip/unlock
flows are exercisable in the UI. Run AFTER `just restart`.
"""
import os
from pathlib import Path

import boto3

env = Path(__file__).resolve().parent.parent / ".env.local"
if env.exists():
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource(
    "dynamodb",
    endpoint_url=os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001"),
    region_name=os.environ.get("AWS_REGION", "us-east-1"),
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
)
table = ddb.Table(os.environ.get("BILLING_TABLE_NAME", os.environ.get("DDB_TABLE", "billing")))

USERS = {
    "e2e_alice@test.local": ("pm_alice_visa", "4242"),
    "e2e_bob@test.local": ("pm_bob_visa", "4111"),
    "e2e_charlie@test.local": ("pm_charlie_visa", "5555"),
}

for sub, (pm_id, last4) in USERS.items():
    pk = f"USER#{sub}"  # billing.py user_pk() prefixes with USER#
    table.put_item(Item={
        "pk": pk, "sk": f"PM#{pm_id}", "payment_method_id": pm_id,
        "method_type": "card", "label": "Personal Visa", "brand": "visa",
        "last4": last4, "exp_month": 12, "exp_year": 2030, "priority": 0,
        "provider": "stripe", "provider_method_id": pm_id,
    })
    table.put_item(Item={
        "pk": pk, "sk": "BILLING", "autopay_enabled": False,
        "currency": "usd", "default_payment_method_id": pm_id,
    })
    print(f"  ok PM for {sub} (visa •{last4})")

print("done.")
