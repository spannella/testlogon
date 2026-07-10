"""Create the LiveStreamProducts DDB table (PK session_id / SK), PAY_PER_REQUEST.
Idempotent: no-op if it already exists. Run in-process (uses app.core.aws.ddb)."""
import sys, os
BASE = "/home/ubuntu/testlogon"
sys.path.insert(0, BASE)
os.chdir(BASE)
from app.core.aws import ddb
from app.core.settings import S

name = S.live_stream_products_table_name
client = ddb.meta.client
existing = client.list_tables()["TableNames"]
if name in existing:
    print("TABLE_EXISTS", name)
else:
    client.create_table(
        TableName=name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "session_id", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "session_id", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
    )
    client.get_waiter("table_exists").wait(TableName=name)
    print("TABLE_CREATED", name)
d = client.describe_table(TableName=name)["Table"]
print("KEYS", d["KeySchema"], "STATUS", d["TableStatus"])
