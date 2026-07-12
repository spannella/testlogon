#!/usr/bin/env python3
"""MOD-1 prod ops: ensure ByOffenderCreatedAt is a user_id(HASH)+created_at(RANGE) GSI.
If a stale ByOffenderCreatedAt with a DIFFERENT key (offender_user_id) exists, delete it
first (only possible once it is ACTIVE). Then create the user_id-keyed index and wait
ACTIVE. Idempotent + safe to re-run. No backfill needed (user_id + created_at already
present + String on every row)."""
import sys, time
sys.path.insert(0, "/home/ubuntu/testlogon")
from app.core.aws import ddb
from app.core.settings import S
cl = ddb.meta.client
TN = S.user_enforcement_history_table_name

def gsi_map():
    d = cl.describe_table(TableName=TN)["Table"]
    return d["TableStatus"], {g["IndexName"]: (g["IndexStatus"], [k["AttributeName"] for k in g["KeySchema"]])
                              for g in d.get("GlobalSecondaryIndexes", [])}

tst, g = gsi_map()
print("table=%s gsis=%s" % (tst, g))
IDX = "ByOffenderCreatedAt"

# 1) if a wrongly-keyed index exists, delete it (must be ACTIVE to delete)
if IDX in g and g[IDX][1] != ["user_id", "created_at"]:
    st = g[IDX][0]
    if st != "ACTIVE":
        print("stale %s is %s (key=%s) -- cannot delete until ACTIVE; retry later." % (IDX, st, g[IDX][1]))
        raise SystemExit(3)
    print("deleting stale %s (key=%s)" % (IDX, g[IDX][1]))
    cl.update_table(TableName=TN, GlobalSecondaryIndexUpdates=[{"Delete": {"IndexName": IDX}}])
    for _ in range(120):
        tst, g = gsi_map()
        if IDX not in g and tst == "ACTIVE":
            print("stale deleted; table ACTIVE"); break
        time.sleep(5)
    else:
        print("!! delete did not finish"); raise SystemExit(3)

# 2) create user_id-keyed index if absent
tst, g = gsi_map()
if IDX in g and g[IDX][1] == ["user_id", "created_at"]:
    print("%s already correct (%s)" % (IDX, g[IDX]))
else:
    print("creating %s (user_id HASH + created_at RANGE)" % IDX)
    cl.update_table(
        TableName=TN,
        AttributeDefinitions=[
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexUpdates=[{"Create": {
            "IndexName": IDX,
            "KeySchema": [
                {"AttributeName": "user_id", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }}],
    )

# 3) wait ACTIVE
for _ in range(120):
    tst, g = gsi_map()
    if g.get(IDX, ("", []))[0] == "ACTIVE":
        print("READY: %s ACTIVE key=%s" % (IDX, g[IDX][1])); break
    print("  waiting index=%s" % (g.get(IDX)))
    time.sleep(5)
else:
    print("!! index not ACTIVE in time (still creating on AWS side; base-table fallback keeps MOD-1 correct meanwhile)")
