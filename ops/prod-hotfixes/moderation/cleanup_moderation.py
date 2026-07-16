"""Cleanup the consolidated moderation verify test rows on PROD DDB. argv[1]=TS."""
import os, sys
from boto3.dynamodb.conditions import Key
from app.core.aws import ddb
from app.core.tables import T

TS = sys.argv[1]
APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MESSAGES_TABLE = os.environ.get("DDB_MESSAGES", "Messages")
import app.services.moderation_case as MC

pids = [f"pR1_{TS}", f"pR2_{TS}", f"pR3_{TS}", f"pR4_{TS}", f"pR5_{TS}",
        f"pA_{TS}", f"pB_{TS}", f"pC_{TS}", f"pD_{TS}", f"pD2_{TS}",
        f"pE_{TS}", f"pF_{TS}", f"pG_{TS}", f"pH_{TS}"]
owners = [f"ownR1_{TS}", f"ownR2_{TS}", f"ownR3_{TS}", f"ownR4_{TS}", f"ownR5_{TS}",
          f"ownA_{TS}", f"ownB_{TS}", f"ownC_{TS}", f"ownD_{TS}", f"ownD2_{TS}",
          f"ownE_{TS}", f"ownF_{TS}", f"ownG_{TS}", f"ownH_{TS}"]
state_users = [f"trust_{TS}", f"ownE_{TS}", f"ownF_{TS}",
               # MODX-3/MODX-5 reporter reputation + credibility seeds
               f"ahtrust_{TS}", f"repR3a_{TS}", f"repR3b_{TS}", f"repR3c_{TS}", f"repE_{TS}"]
n = 0
for pid in pids:
    ddb.Table(APP_TABLE).delete_item(Key={"pk": f"POST#{pid}", "sk": "META"}); n += 1
    try:
        T.moderation_cases.delete_item(Key={"case_id": MC.case_id_for("feed_post", pid)}); n += 1
    except Exception:
        pass
ddb.Table(MESSAGES_TABLE).delete_item(Key={"conversation_id": f"convM_{TS}", "message_id": f"msgM_{TS}"}); n += 1
for u in state_users:
    try:
        T.account_state.delete_item(Key={"user_sub": u}); n += 1
    except Exception:
        pass
# alerts + enforcement history for the owners (best-effort)
for u in owners:
    try:
        for a in T.alerts.query(KeyConditionExpression=Key("user_sub").eq(u)).get("Items", []):
            k = {kk: a[kk] for kk in T.alerts.key_schema and [s["AttributeName"] for s in T.alerts.key_schema]}
            T.alerts.delete_item(Key=k); n += 1
    except Exception:
        pass
    try:
        for e in T.user_enforcement_history.query(KeyConditionExpression=Key("user_id").eq(u)).get("Items", []):
            ks = [s["AttributeName"] for s in T.user_enforcement_history.key_schema]
            T.user_enforcement_history.delete_item(Key={kk: e[kk] for kk in ks}); n += 1
    except Exception:
        pass
print("cleanup deleted ~%d rows for TS=%s" % (n, TS))
# residual case count
try:
    print("ModerationCases scan count:", T.moderation_cases.scan(Select="COUNT").get("Count"))
except Exception as ex:
    print("count err", ex)
