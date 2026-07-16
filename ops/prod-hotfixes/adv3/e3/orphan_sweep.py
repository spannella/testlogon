"""ADV3-7 (C4): one-time orphan AdClicks cleanup.

An orphan is an AdClicks row still in status "served" that never advanced to
impressed/clicked/converted/completed AND is past its 7-day TTL expiry
(``expires_at``). DynamoDB TTL reaps these automatically; this sweep is a manual
belt-and-suspenders for any TTL lag. The forward fix (deferred mint + commit in
serve_ad / newsfeed / shop / sponsored_feed) stops NEW orphans being created for
multi-slot fetches. Idempotent. Run:

    source .venv/bin/activate
    python3 orphan_sweep.py           # dry run (counts only)
    python3 orphan_sweep.py --apply   # delete expired served orphans
"""
import os, sys, time

os.chdir("/home/ubuntu/testlogon")
for line in open(".env.local"):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    os.environ.setdefault(k, v.strip())
sys.path.insert(0, "/home/ubuntu/testlogon")
from app.core.tables import T

APPLY = "--apply" in sys.argv
now = int(time.time())
items, r = [], T.ad_clicks.scan()
items += r.get("Items", [])
while r.get("LastEvaluatedKey"):
    r = T.ad_clicks.scan(ExclusiveStartKey=r["LastEvaluatedKey"])
    items += r.get("Items", [])
orphans = [i for i in items
           if str(i.get("status", "")) == "served"
           and int(i.get("expires_at", 0) or 0)
           and int(i.get("expires_at", 0)) < now]
print("total_adclicks", len(items),
      "served", sum(1 for i in items if i.get("status") == "served"),
      "expired_served_orphans", len(orphans))
if APPLY:
    for i in orphans:
        T.ad_clicks.delete_item(Key={"ad_click_id": i["ad_click_id"]})
    print("DELETED", len(orphans))
else:
    print("DRY_RUN (pass --apply to delete)")
