"""Provision the payment_incidents GSIs on the running DDB-Local (dev clone was
created without them — the half-built PaymentIncident stack). Mirrors
scripts/migrations/20260324_payment_incidents_schema.py. Idempotent."""
import time
from app.core.aws import ddb
from app.core.settings import S

client = ddb.meta.client
table = S.payment_incidents_table_name

desired_gsis = [
    {
        "IndexName": "ByProviderIncidentUpdatedAt",
        "KeySchema": [
            {"AttributeName": "provider_incident_key", "KeyType": "HASH"},
            {"AttributeName": "updated_at", "KeyType": "RANGE"},
        ],
        "Projection": {"ProjectionType": "ALL"},
    },
    {
        "IndexName": "ByCustomerUpdatedAt",
        "KeySchema": [
            {"AttributeName": "customer_id", "KeyType": "HASH"},
            {"AttributeName": "updated_at", "KeyType": "RANGE"},
        ],
        "Projection": {"ProjectionType": "ALL"},
    },
    {
        "IndexName": "ByResponseDueAt",
        "KeySchema": [
            {"AttributeName": "response_due_scope", "KeyType": "HASH"},
            {"AttributeName": "response_due_at", "KeyType": "RANGE"},
        ],
        "Projection": {"ProjectionType": "ALL"},
    },
]
attrs_by_name = {
    "provider_incident_key": {"AttributeName": "provider_incident_key", "AttributeType": "S"},
    "updated_at": {"AttributeName": "updated_at", "AttributeType": "S"},
    "customer_id": {"AttributeName": "customer_id", "AttributeType": "S"},
    "response_due_scope": {"AttributeName": "response_due_scope", "AttributeType": "S"},
    "response_due_at": {"AttributeName": "response_due_at", "AttributeType": "S"},
}

desc = client.describe_table(TableName=table)["Table"]
existing = {g["IndexName"] for g in desc.get("GlobalSecondaryIndexes", [])}
existing_attrs = {a["AttributeName"] for a in desc.get("AttributeDefinitions", [])}
print("existing GSIs:", existing)

for gsi in desired_gsis:
    if gsi["IndexName"] in existing:
        print("skip (exists):", gsi["IndexName"])
        continue
    keys = [k["AttributeName"] for k in gsi["KeySchema"]]
    new_attrs = [attrs_by_name[k] for k in keys if k not in existing_attrs]
    kwargs = {"TableName": table, "GlobalSecondaryIndexUpdates": [{"Create": gsi}]}
    if new_attrs:
        kwargs["AttributeDefinitions"] = new_attrs
    client.update_table(**kwargs)
    existing_attrs |= set(keys)
    # DDB-Local creates GSIs synchronously; still wait to be safe.
    for _ in range(30):
        d = client.describe_table(TableName=table)["Table"]
        idx = {g["IndexName"]: g.get("IndexStatus") for g in d.get("GlobalSecondaryIndexes", [])}
        if idx.get(gsi["IndexName"]) == "ACTIVE":
            break
        time.sleep(0.5)
    print("created:", gsi["IndexName"])

d = client.describe_table(TableName=table)["Table"]
print("final GSIs:", [g["IndexName"] for g in d.get("GlobalSecondaryIndexes", [])])
