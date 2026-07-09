import os, sys
from boto3.dynamodb.conditions import Key
from app.core.aws import ddb
from app.core.tables import T
from app.services import moderation_case as MC

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
ts = sys.argv[1] if len(sys.argv) > 1 else None
if not ts:
    print("need ts arg"); sys.exit(1)

posts = [f"modp1_{ts}", f"modp2_{ts}", f"modp3_{ts}", f"modp4_{ts}", f"modp5_{ts}"]
owners = [f"modowner1_{ts}", f"modowner2_{ts}", f"modowner3_{ts}", f"modowner4_{ts}", f"modowner5_{ts}"]
n = 0
for p in posts:
    ddb.Table(APP_TABLE).delete_item(Key={"pk": f"POST#{p}", "sk": "META"}); n += 1
    try:
        T.moderation_cases.delete_item(Key={"case_id": MC.case_id_for("feed_post", p)}); n += 1
    except Exception as e:
        print("case del err", e)
# trusted account_state test row
try:
    T.account_state.delete_item(Key={"user_sub": f"modtrust_{ts}"}); n += 1
except Exception as e:
    print("acct del err", e)
# poster alerts
for o in owners:
    try:
        r = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(o), Limit=50)
        for a in r.get("Items", []):
            T.alerts.delete_item(Key={"user_sub": o, "alert_id": a["alert_id"]}); n += 1
    except Exception as e:
        print("alert del err", e)
print("CLEANED", n, "rows for ts", ts)
