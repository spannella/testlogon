"""Moto-backed logic dry-run for SUBX-1 (dev host has no live DDB).

On the dev host there is no endpoint_url configured, so moto's mock_aws
intercepts the app's default boto3 resource -> we can create the touched tables
in-memory and exercise the real endpoint functions. (The prod-isolation caveat
does NOT apply here: dev binds the default client, which moto owns.)
"""
import runpy
import boto3
from moto import mock_aws

TABLES = {
    "subscriptions": ("pk", "sk"),
    "billing": ("pk", "sk"),
    "profiles": ("user_sub", None),
    "users": ("user_sub", None),
    "calendar": ("calendar_id", "sk"),
    "purchase_transactions": ("user_sub", "sk"),
    "purchase_events": ("user_sub", "sk"),
}


def _mk(client, name, hk, rk):
    ks = [{"AttributeName": hk, "KeyType": "HASH"}]
    ad = [{"AttributeName": hk, "AttributeType": "S"}]
    if rk:
        ks.append({"AttributeName": rk, "KeyType": "RANGE"})
        ad.append({"AttributeName": rk, "AttributeType": "S"})
    client.create_table(TableName=name, KeySchema=ks, AttributeDefinitions=ad, BillingMode="PAY_PER_REQUEST")


with mock_aws():
    c = boto3.client("dynamodb", region_name="us-east-1")
    for n, (hk, rk) in TABLES.items():
        _mk(c, n, hk, rk)
    # profile stub so attach_subscription_profiles doesn't blow up
    from app.routers import subscription_server as ss
    ss.get_profile_identity = lambda uid: {"user_id": uid, "display_name": uid}
    # stub the commerce cycle-order emission (heavy, untouched by X1; unit tests do the same)
    _oc = {"n": 0}

    def _emit_stub(**k):
        _oc["n"] += 1
        return {"order_id": "ord-%d" % _oc["n"], "reconciliation": {"status": "processed"}}
    ss.emit_subscription_cycle_order_and_reconcile = _emit_stub
    runpy.run_path("verify_subx1.py", run_name="__main__")
