"""R2 (residual #118) probe — distinct status values in the VideoMetadata table.

Read-only. Confirms which stored `status` values are NOT in the VideoStatus
Literal (the ones that 500 GET /ui/videos/admin/by-status/{status} via a pydantic
ValidationError in video_from_item). Run in-process on PROD:
    python3 /tmp/ssm_run.py <this file>
Does NOT mutate any data — the fix is code-side (tolerant deserialization).

Prod result (2026-07-13, 61 rows): the only DIRTY v_ row is
    v_advb2_6a4db687  status='ready'   (advertising-v2 seed artifact)
'other'-prefix rows (vid_/vidV_/TICKET#) are filtered out by the endpoint's
begins_with('v_') FilterExpression and never deserialized.
"""
import sys, typing
sys.path.insert(0, "/home/ubuntu/testlogon")
from app.models_video import VideoStatus
from app.core.tables import T
from collections import Counter

t = T.video_metadata
print("TABLE", t.name)
allowed = set(typing.get_args(VideoStatus))
print("ENUM", sorted(allowed))
c = Counter(); examples = {}
kw = {"ProjectionExpression": "video_id, #s", "ExpressionAttributeNames": {"#s": "status"}}
n = 0
while True:
    r = t.scan(**kw)
    for it in r.get("Items", []):
        n += 1
        vid = str(it.get("video_id", ""))
        st = it.get("status")
        key = ("v_" if vid.startswith("v_") else "other", str(st))
        c[key] += 1
        examples.setdefault(key, vid)
    lek = r.get("LastEvaluatedKey")
    if not lek:
        break
    kw["ExclusiveStartKey"] = lek
print("TOTAL_ROWS", n)
for k, v in sorted(c.items()):
    prefix, st = k
    flag = "  <<< DIRTY (not in enum, 500s admin listing)" if (prefix == "v_" and st not in allowed and st != "None") else ""
    print("  %-6s status=%-22r count=%d ex=%s%s" % (prefix, st, v, examples[k], flag))
