import json
import time
from app.core.tables import T

PREFIX = "subx1v-"
SPECS = [
    ("subscriptions", ["pk", "sk"]),
    ("billing", ["pk", "sk"]),
    ("purchase_transactions", ["user_sub", "sk"]),
    ("purchase_events", ["pk", "sk"]),
    ("orders", ["pk", "sk"]),
    ("order_items", ["pk", "sk"]),
    ("entitlements", ["pk", "sk"]),
    ("alerts", ["pk", "sk"]),
]


def sweep():
    per = {}
    for attr, keys in SPECS:
        tbl = getattr(T, attr, None)
        if tbl is None:
            continue
        deleted = 0
        remaining = 0
        lek = None
        while True:
            kw = {"ConsistentRead": True}
            if lek:
                kw["ExclusiveStartKey"] = lek
            try:
                r = tbl.scan(**kw)
            except Exception:
                # some tables may not support ConsistentRead on scan or not exist
                try:
                    kw.pop("ConsistentRead", None)
                    r = tbl.scan(**kw)
                except Exception:
                    break
            for it in r.get("Items", []):
                if PREFIX in json.dumps(it, default=str):
                    key = {k: it[k] for k in keys if k in it}
                    if len(key) == len([k for k in keys]):
                        try:
                            tbl.delete_item(Key=key)
                            deleted += 1
                        except Exception:
                            remaining += 1
                    else:
                        remaining += 1
            lek = r.get("LastEvaluatedKey")
            if not lek:
                break
        if deleted or remaining:
            per[attr] = {"deleted": deleted, "remaining": remaining}
    return per


p1 = sweep()
print("PASS1", json.dumps(p1))
time.sleep(3)
p2 = sweep()
print("PASS2", json.dumps(p2))
total_remaining = sum(v["remaining"] for v in p2.values())
still = sum(v["deleted"] for v in p2.values())
print("FINAL: deleted_pass2=%d remaining=%d" % (still, total_remaining))
