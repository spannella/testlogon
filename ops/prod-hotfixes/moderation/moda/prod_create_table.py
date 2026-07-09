import time
import boto3
from botocore.exceptions import ClientError
from app.core.settings import S

region = S.aws_region or "us-east-2"
name = getattr(S, "moderation_cases_table_name", "ModerationCases")
c = boto3.client("dynamodb", region_name=region, endpoint_url=(S.ddb_endpoint_url or None))

try:
    c.create_table(
        TableName=name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "case_id", "AttributeType": "S"},
            {"AttributeName": "state", "AttributeType": "S"},
            {"AttributeName": "hold_until", "AttributeType": "N"},
        ],
        KeySchema=[{"AttributeName": "case_id", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByState",
                "KeySchema": [
                    {"AttributeName": "state", "KeyType": "HASH"},
                    {"AttributeName": "hold_until", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )
    print("CREATE_REQUESTED", name)
except ClientError as e:
    code = e.response.get("Error", {}).get("Code")
    if code in ("ResourceInUseException",):
        print("ALREADY_EXISTS", name)
    else:
        raise

for _ in range(30):
    d = c.describe_table(TableName=name)["Table"]
    st = d["TableStatus"]
    gsi = d.get("GlobalSecondaryIndexes", [])
    gstat = [g["IndexStatus"] for g in gsi]
    if st == "ACTIVE" and all(s == "ACTIVE" for s in gstat):
        print("ACTIVE", name, "gsi=", gstat)
        break
    time.sleep(2)
else:
    print("NOT_ACTIVE_YET", name)

# Seed the 4 new category TOPIC# guard rows on ContentReports (idempotent).
cr = boto3.resource("dynamodb", region_name=region, endpoint_url=(S.ddb_endpoint_url or None)).Table(S.content_reports_table_name)
for t in ["harassment", "hate", "violence_threats", "other"]:
    try:
        cr.put_item(
            Item={"report_id": "TOPIC#" + t, "entity_type": "topic_guard", "topic": t},
            ConditionExpression="attribute_not_exists(report_id)",
        )
        print("TOPIC_SEEDED", t)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            print("TOPIC_EXISTS", t)
        else:
            raise
print("DONE")
