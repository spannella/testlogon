# Broadcast paid-flow billing 500: transact client points at the wrong DDB endpoint

## Symptom
Every paid broadcast flow that writes a billing ledger entry via
transact_write_items 500s with
`RuntimeError: ... billing transaction failed (ResourceNotFoundException) ...`:
- private-chat purchase (broadcast_private_chat)
- paid-lottery entry (broadcast_lottery)
- broadcast tips / rich-chat paid actions (broadcast_private, broadcast_chat_rich)

## Root cause
These four services hand-rolled their transact client:

    endpoint_url = _ddb_endpoint_url()          # = DDB_ENDPOINT_URL
    client = boto3.client(dynamodb, region_name=_aws_region(),
                          endpoint_url=endpoint_url,
                          **_local_credentials_kwargs(endpoint_url))
    client.transact_write_items(... TableName=S.billing_table_name ...)

`_ddb_endpoint_url()` resolves `DDB_ENDPOINT_URL`, but the entire rest of the app
(incl. every OTHER billing writer) uses the app dynamodb *resource*, whose
endpoint is `aws_endpoint_url` (`AWS_ENDPOINT_URL`). In the dev split-brain setup
those differ — main/billing tables live on AWS_ENDPOINT_URL (moto :4566), broadcast
+ misc tables on DDB_ENDPOINT_URL (DynamoDB-Local :8001) — so the transact targeted
:8001, which has NO `billing` table -> ResourceNotFoundException -> 500.

(In prod both env vars point at the same real-AWS endpoint, so the ledger row DOES
land, but at best it is an undocumented inconsistency: the paid-broadcast billing
writer resolves its endpoint differently from all other billing code. Dev-visible,
prod-latent.)

## Fix
Replace the hand-rolled client with the canonical `ddb_transact_client()`
(`app.core.aws_clients`), which inherits endpoint/region/creds from the app
dynamodb resource — the SAME place the billing table lives and where all other
billing transacts write. One-line swap + import in each of the four services.
See broadcast_billing_transact_endpoint.patch (string-anchored).

## Prod-mirror status
LOW priority for prod (prod is single-endpoint so writes already land), but apply
for correctness/consistency so paid-broadcast billing uses the one blessed transact
client. Patch applies to /home/ubuntu/testlogon via SSM; restart uvicorn.

## e2e impact
Greens broadcast-private-chat (Section 125/126), broadcast-lottery (136 paid),
broadcast-private, broadcast-chat-rich paid-flow tests (all previously 500 on the
first paid write, cascading to 404s on missing chat/lottery ids).
