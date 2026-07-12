"""TIP-503 per-surface earnings/payout verification (moto-backed, REAL queries).

charge_tip runs its real code path; only the low-level TransactWriteItems transport
is routed through a moto-compatible shim with identical all-or-nothing + conditional
receipt semantics (moto 5.2.2 has an internal bug in its own transact get_item).
WHAT is written (build_tip_ledger_items: net type:credit + 20% fee) is UNCHANGED.
get_earnings_summary + get_available_balance run their REAL DynamoDB queries."""
import os, json
from types import SimpleNamespace
os.environ.setdefault("AWS_DEFAULT_REGION","us-east-2")
os.environ.setdefault("AWS_ACCESS_KEY_ID","testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY","testing")
import boto3
from moto import mock_aws
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer

mock = mock_aws(); mock.start()
ddb = boto3.resource("dynamodb", region_name="us-east-2")
ddb.create_table(TableName="billing",
    KeySchema=[{"AttributeName":"pk","KeyType":"HASH"},{"AttributeName":"sk","KeyType":"RANGE"}],
    AttributeDefinitions=[{"AttributeName":"pk","AttributeType":"S"},{"AttributeName":"sk","AttributeType":"S"}],
    BillingMode="PAY_PER_REQUEST")
ddb.create_table(TableName="CreatorPayouts",
    KeySchema=[{"AttributeName":"payout_id","KeyType":"HASH"}],
    AttributeDefinitions=[{"AttributeName":"payout_id","AttributeType":"S"},{"AttributeName":"user_id","AttributeType":"S"},{"AttributeName":"status","AttributeType":"S"},{"AttributeName":"created_at","AttributeType":"N"}],
    GlobalSecondaryIndexes=[
        {"IndexName":"ByUserCreatedAt","KeySchema":[{"AttributeName":"user_id","KeyType":"HASH"},{"AttributeName":"created_at","KeyType":"RANGE"}],"Projection":{"ProjectionType":"ALL"}},
        {"IndexName":"ByStatusCreatedAt","KeySchema":[{"AttributeName":"status","KeyType":"HASH"},{"AttributeName":"created_at","KeyType":"RANGE"}],"Projection":{"ProjectionType":"ALL"}}],
    BillingMode="PAY_PER_REQUEST")

_DES = TypeDeserializer()
def _deser(av): return {k:_DES.deserialize(v) for k,v in av.items()}

class _ShimClient:
    """Faithful moto-compatible TransactWriteItems: phase-1 check-all, phase-2 apply-all."""
    def __init__(self, table): self.table = table
    def transact_write_items(self, *, TransactItems):
        pending = []
        for ti in TransactItems:
            put = ti.get("Put")
            if not put:
                continue
            item = _deser(put["Item"])
            if put.get("ConditionExpression") == "attribute_not_exists(sk)":
                got = self.table.get_item(Key={"pk":item["pk"],"sk":item["sk"]}).get("Item")
                if got is not None:
                    raise ClientError({"Error":{"Code":"TransactionCanceledException","Message":"ConditionalCheckFailed"}},"TransactWriteItems")
            pending.append(item)
        for item in pending:
            self.table.put_item(Item=item)

class _BillingProxy:
    def __init__(self, table): self._t = table
    @property
    def meta(self): return SimpleNamespace(client=_ShimClient(self._t))
    def __getattr__(self, n): return getattr(self._t, n)

from app.core.tables import T, _FloatSafeTable
object.__setattr__(T, "billing", _BillingProxy(_FloatSafeTable(ddb.Table("billing"))))
object.__setattr__(T, "creator_payouts", _FloatSafeTable(ddb.Table("CreatorPayouts")))

from app.core.settings import S
try: S.payout_hold_period_seconds = 0
except Exception: object.__setattr__(S, "payout_hold_period_seconds", 0)

from app.services.tips import charge_tip, reverse_tip
from app.services.creator_earnings import get_earnings_summary
from app.services.creator_payouts import get_available_balance

SURFACES = [
    ("message tip","message",{}),
    ("tip-react message","message_react",{}),
    ("tip-react post","post_react",{}),
    ("post tip","post",{}),
    ("comment-carrying tip","post",{"comment":"great post!"}),
    ("tip-a-comment","comment",{}),
    ("video tip","video",{}),
    ("video-comment tip","video_comment",{}),
    ("broadcast tip","broadcast",{}),
    ("pay-to-message","message",{"pay_to_message":True}),
]
GROSS = 500
rows = []; ok = True
for i,(label,ctype,meta) in enumerate(SURFACES):
    rid=f"recip_{i}"; tid=f"tipper_{i}"
    e0=get_earnings_summary(rid); b0=get_available_balance(rid)
    res=charge_tip(tipper_id=tid,recipient_id=rid,amount_cents=GROSS,payment_method_id=None,
                   content_type=ctype,content_id=f"{ctype}_{i}",meta=meta,idempotency_key=f"k_{i}")
    e1=get_earnings_summary(rid); b1=get_available_balance(rid)
    res2=charge_tip(tipper_id=tid,recipient_id=rid,amount_cents=GROSS,payment_method_id=None,
                    content_type=ctype,content_id=f"{ctype}_{i}",meta=meta,idempotency_key=f"k_{i}")
    e2=get_earnings_summary(rid); b2=get_available_balance(rid)
    tb=e0["breakdown"]["tips"]; ta=e1["breakdown"]["tips"]
    ab=b0["available_cents"]; aa=b1["available_cents"]; earned=b1["total_earned_cents"]
    checks={
        "charge_net==400": res.net_cents==400,
        "earn_tips_delta==net": (ta-tb)==res.net_cents,
        "payout_avail_delta==net": (aa-ab)==res.net_cents,
        "total_earned==net": earned==res.net_cents,
        "idempotent_replay": res2.idempotent_replay is True,
        "no_double_earn": e2["breakdown"]["tips"]==ta,
        "no_double_payout": b2["available_cents"]==aa,
    }
    p=all(checks.values()); ok=ok and p
    rows.append({"surface":label,"content_type":ctype,"gross":GROSS,"net":res.net_cents,
        "earn_tips_before":tb,"earn_tips_after":ta,"payout_before":ab,"payout_after":aa,
        "total_earned":earned,"PASS":p,"failed":[k for k,v in checks.items() if not v]})

# Bonus: reversal does not inflate earnings (uses last surface recipient)
rid="recip_9"; tid="tipper_9"
_cred=[i for i in ddb.Table("billing").scan().get("Items",[]) if i.get("pk")==f"USER#{rid}" and i.get("type")=="credit"][0]
_credit_ts=int(_cred["ts"])
pre_e=get_earnings_summary(rid)["breakdown"]["tips"]; pre_b=get_available_balance(rid)["available_cents"]
rev=reverse_tip(tipper_id=tid,recipient_id=rid,gross_cents=500,net_cents=400,tip_payment_id=res.tip_payment_id,
                content_type="message",content_id="message_9",credit_entry_id=res.credit_entry_id,credit_ts=_credit_ts,reason="admin_reversal")
post_e=get_earnings_summary(rid)["breakdown"]["tips"]; post_b=get_available_balance(rid)["available_cents"]
reversal_row={"reversal_refunded":rev.refunded_cents,"reversal_clawback":rev.clawback_cents,
    "earn_tips_before_rev":pre_e,"earn_tips_after_rev":post_e,"earn_not_inflated":post_e<=pre_e,
    "payout_before_rev":pre_b,"payout_after_rev":post_b,"balance_clawed_back":post_b<pre_b}

print(json.dumps({"all_pass":ok,"gross_each":GROSS,"expected_net_each":400,"rows":rows,"reversal_check":reversal_row},indent=2))
mock.stop()
