"""SUB-E4 in-process verify on PROD DDB (run via ssm_run.py).
Seeds a creator with a known subscriber mix + a second isolated creator, then
calls the real list_creator_subscribers + get_creator_subscription_analytics
endpoints and asserts the contract + computed metrics."""
import asyncio, time, sys, os
sys.path.insert(0, "/home/ubuntu/testlogon")
os.environ.setdefault("PYTHONPATH", "/home/ubuntu/testlogon")
import app.routers.subscription_server as ss
from app.core.tables import T

NOW = ss.now_ts()
STAMP = int(time.time())
A = f"sube4_creatorA_{STAMP}"
B = f"sube4_creatorB_{STAMP}"

def seed_plan(creator, plan_id, name, price, interval):
    ss.save_plan({"plan_id": plan_id, "creator_id": creator, "name": name,
                  "price_cents": price, "currency": "usd", "interval": interval,
                  "status": "active", "created_at": NOW, "updated_at": NOW})

def seed_sub(creator, sid, subr, plan_id, interval, price, status, start_off,
             cpe_off, nbd_off, updated_off=None, trial_end_off=None,
             is_gift=False, gifter=None):
    sub = {"subscription_id": sid, "plan_id": plan_id, "creator_id": creator,
           "subscriber_id": subr, "interval": interval, "provider": "stripe",
           "provider_subscription_id": f"stub_{sid}", "status": status,
           "start_at": NOW+start_off, "current_period_end": NOW+cpe_off,
           "next_billing_date": NOW+nbd_off, "cancel_at_period_end": False,
           "price_cents": price, "currency": "usd", "auto_renew": True,
           "renewal_policy": "auto", "created_at": NOW+start_off,
           "updated_at": NOW+(updated_off if updated_off is not None else start_off)}
    if trial_end_off is not None:
        sub["trial_end"] = NOW+trial_end_off; sub["trial_start"] = NOW+start_off
    if is_gift:
        sub["is_gift"] = True; sub["gifter_id"] = gifter
    ss.save_subscription(sub)

def seed_profile(uid, name):
    try:
        T.profile.put_item(Item={"user_sub": uid, "profile": {"display_name": name}, "audit": [], "updated_at": NOW})
    except Exception as e:
        print("profile seed warn", uid, e)

D = 86400
# CREATOR A known mix: 3 active month@1000, 1 active year@12000, 1 trialing, 1 past_due, 1 canceled
seed_plan(A, f"{A}_basic", "Basic", 1000, "month")
seed_plan(A, f"{A}_pro", "Pro", 12000, "year")
seed_sub(A, f"{A}_m1", f"{A}_u1", f"{A}_basic", "month", 1000, "active", -10*D, 20*D, 20*D)
seed_sub(A, f"{A}_m2", f"{A}_u2", f"{A}_basic", "month", 1000, "active", -9*D, 21*D, 21*D)
seed_sub(A, f"{A}_m3", f"{A}_u3", f"{A}_basic", "month", 1000, "active", -8*D, 22*D, 22*D)
seed_sub(A, f"{A}_y1", f"{A}_u4", f"{A}_pro", "year", 12000, "active", -7*D, 358*D, 358*D)
seed_sub(A, f"{A}_tr", f"{A}_u5", f"{A}_pro", "month", 3000, "trialing", -2*D, 5*D, 5*D, trial_end_off=5*D)
seed_sub(A, f"{A}_pd", f"{A}_u6", f"{A}_basic", "month", 1000, "past_due", -40*D, -1*D, 2*D, updated_off=-1*D)
seed_sub(A, f"{A}_cx", f"{A}_u7", f"{A}_basic", "month", 1000, "canceled", -50*D, -3*D, -3*D, updated_off=-3*D, is_gift=True, gifter=f"{A}_g1")
for i,n in [(1,"Alice"),(2,"Bob"),(3,"Carol"),(4,"Dan"),(5,"Eve"),(6,"Frank"),(7,"Grace")]:
    seed_profile(f"{A}_u{i}", n)
# ledger (revenue-to-date): charge 5000, fee 500, refund 1000 -> net 3500
ss.save_ledger_entry(A, {"entry_id": "led1", "entry_type": "charge", "amount_cents": 5000, "currency": "usd", "created_at": NOW-5*D})
ss.save_ledger_entry(A, {"entry_id": "led2", "entry_type": "fee", "amount_cents": 500, "currency": "usd", "created_at": NOW-5*D})
ss.save_ledger_entry(A, {"entry_id": "led3", "entry_type": "refund", "amount_cents": 1000, "currency": "usd", "created_at": NOW-3*D})

# CREATOR B (isolation): 1 active sub only
seed_plan(B, f"{B}_basic", "BBasic", 500, "month")
seed_sub(B, f"{B}_s1", f"{B}_u1", f"{B}_basic", "month", 500, "active", -3*D, 27*D, 27*D)

fails = []
def ck(name, cond, got=None):
    print(("PASS" if cond else "FAIL"), name, "" if cond else f"(got {got})")
    if not cond: fails.append(name)

# E4-1 list (owner A)
lst = asyncio.run(ss.list_creator_subscribers(A, status=None, limit=50, cursor=None, x_user_id=A))
ck("A list total==7", lst.total == 7, lst.total)
byid = {s.subscription_id: s for s in lst.subscribers}
ck("m1 tier=Basic", byid[f"{A}_m1"].plan_name == "Basic", byid[f"{A}_m1"].plan_name)
ck("y1 tier=Pro", byid[f"{A}_y1"].plan_name == "Pro", byid[f"{A}_y1"].plan_name)
ck("m1 status active", byid[f"{A}_m1"].status == "active")
ck("m1 since=start_at", byid[f"{A}_m1"].since == NOW-10*D, byid[f"{A}_m1"].since)
ck("m1 next_billing set", byid[f"{A}_m1"].next_billing_date == NOW+20*D)
ck("tr is_trial", byid[f"{A}_tr"].is_trial is True)
ck("cx is_gift+gifter", byid[f"{A}_cx"].is_gift is True and byid[f"{A}_cx"].gifter_id == f"{A}_g1")
ck("u1 name=Alice", byid[f"{A}_m1"].subscriber_name == "Alice", byid[f"{A}_m1"].subscriber_name)

# filters
for st, exp in [("active",4),("trialing",1),("past_due",1),("canceled",1)]:
    r = asyncio.run(ss.list_creator_subscribers(A, status=st, limit=50, cursor=None, x_user_id=A))
    ck(f"filter {st}=={exp}", r.count == exp, r.count)

# pagination
p1 = asyncio.run(ss.list_creator_subscribers(A, status=None, limit=3, cursor=None, x_user_id=A))
p2 = asyncio.run(ss.list_creator_subscribers(A, status=None, limit=3, cursor=p1.next_cursor, x_user_id=A))
ck("page1==3 + cursor", p1.count == 3 and p1.next_cursor is not None)
ck("page2==3 disjoint", p2.count == 3 and {s.subscription_id for s in p1.subscribers}.isdisjoint({s.subscription_id for s in p2.subscribers}))

# owner scope / isolation
try:
    asyncio.run(ss.list_creator_subscribers(A, status=None, limit=50, cursor=None, x_user_id=B))
    ck("B->A list 403", False, "no raise")
except ss.HTTPException as e:
    ck("B->A list 403", e.status_code == 403, e.status_code)
blist = asyncio.run(ss.list_creator_subscribers(B, status=None, limit=50, cursor=None, x_user_id=B))
ck("B sees only own (1)", blist.total == 1, blist.total)
ck("B sees none of A", all(not s.subscription_id.startswith(A) for s in blist.subscribers))

# E4-2 analytics (owner A)
an = asyncio.run(ss.get_creator_subscription_analytics(A, period_days=30, x_user_id=A))
ck("active==4", an.active_subscribers == 4, an.active_subscribers)
ck("trialing==1", an.trialing == 1, an.trialing)
ck("past_due==1", an.past_due == 1, an.past_due)
ck("canceled_total==1", an.canceled_total == 1, an.canceled_total)
ck("MRR==4000 (3*1000+12000/12)", an.mrr_cents == 4000, an.mrr_cents)
ck("ARPU==1000", an.arpu_cents == 1000, an.arpu_cents)
ck("new_subs_30d==5", an.new_subs_30d == 5, an.new_subs_30d)
ck("churned_30d==1", an.churned_30d == 1, an.churned_30d)
ck("churn_rate==0.2", abs(an.churn_rate - 0.2) < 1e-9, an.churn_rate)
ck("gross_to_date==5000", an.gross_revenue_to_date_cents == 5000, an.gross_revenue_to_date_cents)
ck("fee_to_date==500", an.fee_to_date_cents == 500, an.fee_to_date_cents)
ck("refunded_to_date==1000", an.refunded_to_date_cents == 1000, an.refunded_to_date_cents)
ck("net_to_date==3500", an.net_revenue_to_date_cents == 3500, an.net_revenue_to_date_cents)

# analytics owner-scope (B cannot read A)
try:
    asyncio.run(ss.get_creator_subscription_analytics(A, period_days=30, x_user_id=B))
    ck("B->A analytics 403", False, "no raise")
except ss.HTTPException as e:
    ck("B->A analytics 403", e.status_code == 403, e.status_code)

print("\nSEEDED_CREATOR_A=", A)
print("SEEDED_CREATOR_B=", B)
print("ANALYTICS_A=", an.dict())
print("\nRESULT:", "OVERALL_ALL_PASS" if not fails else f"FAILS={fails}")
