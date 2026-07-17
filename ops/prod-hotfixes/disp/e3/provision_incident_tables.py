"""Create the 4 missing PaymentIncident child tables on DDB-Local using the SAME
app ddb client the running server uses (so creds/region partition matches).
Idempotent. Mirrors scripts/migrations/20260324_payment_incidents_schema.py."""
import time
from app.core.aws import ddb
from app.core.settings import S

client = ddb.meta.client
existing = {t.name for t in ddb.tables.all()}
print("existing:", sorted(n for n in existing if "incident" in n.lower() or "dispute" in n.lower() or "retry" in n.lower()))

defs = [
    (S.payment_incident_events_table_name,
     [{"AttributeName": "incident_id", "AttributeType": "S"},
      {"AttributeName": "event_ts_id", "AttributeType": "S"}],
     [{"AttributeName": "incident_id", "KeyType": "HASH"},
      {"AttributeName": "event_ts_id", "KeyType": "RANGE"}], None),
    (S.payment_dispute_evidence_table_name,
     [{"AttributeName": "incident_id", "AttributeType": "S"},
      {"AttributeName": "version", "AttributeType": "S"}],
     [{"AttributeName": "incident_id", "KeyType": "HASH"},
      {"AttributeName": "version", "KeyType": "RANGE"}], None),
    (S.payment_retry_attempts_table_name,
     [{"AttributeName": "incident_id", "AttributeType": "S"},
      {"AttributeName": "attempt_id", "AttributeType": "S"}],
     [{"AttributeName": "incident_id", "KeyType": "HASH"},
      {"AttributeName": "attempt_id", "KeyType": "RANGE"}], None),
    (S.payment_incident_ticket_links_table_name,
     [{"AttributeName": "incident_id", "AttributeType": "S"},
      {"AttributeName": "ticket_id", "AttributeType": "S"}],
     [{"AttributeName": "incident_id", "KeyType": "HASH"}],
     [{"IndexName": "ByTicketId",
       "KeySchema": [{"AttributeName": "ticket_id", "KeyType": "HASH"}],
       "Projection": {"ProjectionType": "ALL"}}]),
]

for name, attrs, keys, gsis in defs:
    if name in existing:
        print("skip (exists):", name)
        continue
    kwargs = {"TableName": name, "AttributeDefinitions": attrs, "KeySchema": keys,
              "BillingMode": "PAY_PER_REQUEST"}
    if gsis:
        kwargs["GlobalSecondaryIndexes"] = gsis
    try:
        client.create_table(**kwargs)
        for _ in range(30):
            st = client.describe_table(TableName=name)["Table"]["TableStatus"]
            if st == "ACTIVE":
                break
            time.sleep(0.3)
        print("created:", name)
    except client.exceptions.ResourceInUseException:
        print("already exists (race):", name)

print("final:", sorted(t.name for t in ddb.tables.all() if "incident" in t.name.lower() or "dispute" in t.name.lower() or "retry" in t.name.lower()))
