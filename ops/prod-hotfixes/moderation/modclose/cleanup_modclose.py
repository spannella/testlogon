"""Cleanup throwaway e2e_ moderation verify rows from the close-out runs (bans,
cases, syndicate rows, dmca claim). Best-effort; keys derived from the run ids."""
import time
from app.routers.admin_moderation import ddb, APP_TABLE, T
import app.services.moderation_case as MC

# mode1 run ids (TS=1783623844) + posters that got banned
M1 = "1783623844"
banned = ["e2e_poster1_%s" % M1, "e2e_poster3_%s" % M1]
synd_id = "e2e_synd_%s" % M1
synd_pid = "e2e_sp_%s" % M1
feed_pids = ["e2e_fp1_%s" % M1, "e2e_fp2_%s" % M1]
n = 0
# clear bans / enforcement state on throwaway posters
for u in banned:
    try:
        T.account_state.delete_item(Key={"user_sub": u}); n += 1
    except Exception as e:
        print("acct_state", u, e)
# syndicate rows
try:
    T.syndicate_posts.delete_item(Key={"pk": "SYND#%s" % synd_id, "sk": "POST#%s" % synd_pid}); n += 1
    T.syndicates.delete_item(Key={"pk": "SYND#%s" % synd_id, "sk": "META"}); n += 1
except Exception as e:
    print("synd", e)
# orphan moderation_cases for feed + syndicate content refs
for ct, cid in [("feed_post", feed_pids[0]), ("feed_post", feed_pids[1]), ("syndicate_post", synd_pid)]:
    try:
        T.moderation_cases.delete_item(Key={"case_id": MC.case_id_for(ct, cid)}); n += 1
    except Exception as e:
        print("case", cid, e)
# leftover POST rows (mode1 fp2 dismissed = still present)
for pid in feed_pids:
    try:
        ddb.Table(APP_TABLE).delete_item(Key={"pk": "POST#%s" % pid, "sk": "META"}); n += 1
    except Exception:
        pass
print("cleanup_deleted_rows=%d" % n)
