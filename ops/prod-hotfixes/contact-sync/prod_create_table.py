# Create ContactMatchIndex in the instance's DDB-Local (localhost:8001) + backfill + verify.
import os, time, json, hashlib, urllib.request, urllib.error
import boto3
from botocore.config import Config

ep = os.environ.get("DDB_ENDPOINT_URL", "http://localhost:8001")
c = boto3.client("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"),
                 endpoint_url=ep, aws_access_key_id="test", aws_secret_access_key="test",
                 config=Config(retries={"max_attempts": 5}))
name = os.environ.get("DDB_CONTACT_MATCH_INDEX_TABLE", "ContactMatchIndex")
existing = c.list_tables()["TableNames"]
if name in existing:
    print("TABLE_EXISTS", name)
else:
    c.create_table(TableName=name,
        AttributeDefinitions=[{"AttributeName": "id_hash", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id_hash", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST")
    c.get_waiter("table_exists").wait(TableName=name)
    print("TABLE_CREATED", name)
print("HAS_CONTACTS", "Contacts" in existing, "HAS_USERS", os.environ.get("DDB_USERS","ddb_users") in existing)
