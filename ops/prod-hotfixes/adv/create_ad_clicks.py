#!/usr/bin/env python3
"""ADV-002: create the ad_clicks DDB-Local table on prod (localhost:8001) + enable TTL.

Idempotent. Run on the prod box with the app venv:
    /home/ubuntu/testlogon/.venv/bin/python create_ad_clicks.py

Schema (matches app/core/tables.py T.ad_clicks + scripts/local-ddb-init.py):
  hash key   ad_click_id (S)
  GSI ByViewer: viewer_sub (S) HASH + created_at (N) RANGE, Projection ALL
  TTL on     expires_at (Unix epoch secs; last-click 7d CPA window)
Non-key attrs written by the app (not declared at create time): campaign_id,
creative_id, content_owner_sub, surface, status, effective_price_cents, ...
"""
import boto3
from botocore.exceptions import ClientError

NAME = "AdClicks"  # DDB_AD_CLICKS default; prod .env.local does not override it

def main():
    ddb = boto3.client("dynamodb", endpoint_url="http://localhost:8001",
                       region_name="us-east-1",
                       aws_access_key_id="local", aws_secret_access_key="local")
    if NAME not in ddb.list_tables().get("TableNames", []):
        ddb.create_table(
            TableName=NAME,
            AttributeDefinitions=[
                {"AttributeName": "ad_click_id", "AttributeType": "S"},
                {"AttributeName": "viewer_sub", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            KeySchema=[{"AttributeName": "ad_click_id", "KeyType": "HASH"}],
            GlobalSecondaryIndexes=[{
                "IndexName": "ByViewer",
                "KeySchema": [
                    {"AttributeName": "viewer_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.get_waiter("table_exists").wait(TableName=NAME)
        print("CREATED", NAME)
    else:
        print("EXISTS", NAME)
    try:
        ddb.update_time_to_live(TableName=NAME,
            TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires_at"})
    except ClientError as e:
        print("TTL note:", e.response["Error"]["Code"])
    print("TTL:", ddb.describe_time_to_live(TableName=NAME)["TimeToLiveDescription"])

if __name__ == "__main__":
    main()
