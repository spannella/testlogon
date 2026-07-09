"""Delete all MOD-A4..B1 verify test rows from prod DDB (idempotent)."""
import os
from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.tables import T
import app.services.moderation_case as MC

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
TSS = ["1783611853", "1783611935"]
LETTERS = ["A", "B", "C", "D", "D2", "E", "F", "G", "H"]
n = 0

owners = set()
posts = []
for ts in TSS:
    for L in LETTERS:
        posts.append(f"p{L}_{ts}")
        owners.add(f"own{L}_{ts}")
    owners.update({f"rootadmin_{ts}", f"claimant_{ts}", f"trust_{ts}", f"admin_{ts}"})

tbl = ddb.Table(APP_TABLE)
for pid in posts:
    try:
        tbl.delete_item(Key={"pk": f"POST#{pid}", "sk": "META"}); n += 1
    except Exception:
        pass
    try:
        T.moderation_cases.delete_item(Key={"case_id": MC.case_id_for("feed_post", pid)}); n += 1
    except Exception:
        pass

# enforcement history + account_state + alerts, keyed per owner
def _del_by_query(table, hashkey, hashval, rangekey):
    global n
    try:
        r = table.query(KeyConditionExpression=Key(hashkey).eq(hashval), Limit=100)
    except Exception:
        return
    for it in r.get("Items", []):
        try:
            table.delete_item(Key={hashkey: hashval, rangekey: it[rangekey]}); n += 1
        except Exception:
            pass

for o in owners:
    _del_by_query(T.user_enforcement_history, "user_id", o, "enforcement_id")
    try:
        T.account_state.delete_item(Key={"user_sub": o}); n += 1
    except Exception:
        pass
    # alerts: discover range key dynamically
    try:
        ks = {k["KeyType"]: k["AttributeName"] for k in T.alerts.meta.client.describe_table(TableName=T.alerts.name)["Table"]["KeySchema"]}
        rk = ks.get("RANGE")
        r = T.alerts.query(KeyConditionExpression=Key(ks["HASH"]).eq(o), Limit=100)
        for it in r.get("Items", []):
            key = {ks["HASH"]: o}
            if rk:
                key[rk] = it[rk]
            T.alerts.delete_item(Key=key); n += 1
    except Exception:
        pass

# ModerationTickets for the seeded feed_posts
for pid in posts:
    try:
        from app.services.moderation_tickets_store import upsert_open_ticket_for_report  # noqa
    except Exception:
        pass
# tickets are keyed modtk_<hash(content_type:content_id)>; reuse the same hashing
import hashlib
for pid in posts:
    digest = hashlib.sha256(f"feed_post:{pid}".encode("utf-8")).hexdigest()[:20]
    try:
        T.moderation_tickets.delete_item(Key={"ticket_id": f"modtk_{digest}"}); n += 1
    except Exception:
        pass

# DmcaClaims: scan + delete claims targeting our owners / claimants
try:
    resp = T.dmca_claims.scan(Limit=500)
    for it in resp.get("Items", []):
        if str(it.get("target_user_id") or "") in owners or str(it.get("claimant_user_id") or "") in owners:
            try:
                T.dmca_claims.delete_item(Key={"claim_id": it["claim_id"]}); n += 1
            except Exception:
                pass
except Exception:
    pass

print("cleanup_modab deleted ~%d rows" % n)
