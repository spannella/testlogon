"""Clean up old fan club test data (tiers, subscriptions) for E2E tests."""
import boto3
from boto3.dynamodb.conditions import Key

ddb = boto3.resource(
    "dynamodb",
    endpoint_url="http://localhost:8001",
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)
T = ddb.Table("subscriptions")

CREATOR = "e2e_alice@test.local"
SUBSCRIBERS = ["e2e_bob@test.local", "e2e_charlie@test.local"]

# Cancel all old subscriptions to Alice for Bob and Charlie
for uid in SUBSCRIBERS:
    resp = T.query(
        KeyConditionExpression=Key("pk").eq(f"SUBSCRIBER#{uid}")
        & Key("sk").begins_with("SUB#"),
    )
    for item in resp.get("Items", []):
        if item.get("creator_id") == CREATOR:
            T.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET #s = :c",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":c": "canceled"},
            )

# Archive all old tiers for Alice
resp = T.query(
    KeyConditionExpression=Key("pk").eq(f"CREATOR#{CREATOR}")
    & Key("sk").begins_with("TIER#"),
)
for item in resp.get("Items", []):
    T.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET active = :f",
        ExpressionAttributeValues={":f": False},
    )

print("fan_club_cleanup_done")
