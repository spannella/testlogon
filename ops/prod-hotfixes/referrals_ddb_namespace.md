# Hotfix: referrals service DDB handle namespace mismatch (e2e 500s)

## Symptom
All /ui/referrals/* endpoints (code create, list, dashboard, commissions,
attribution) returned 500 under the dev/e2e stack. referrals.spec.ts: 0/9.

## Root cause
app/services/referrals.py resolved its own DynamoDB handle via a bare
boto3.resource(dynamodb, region_name=..., endpoint_url=...) WITHOUT explicit
credentials. That lets botocore fall back to the credential chain
(env -> ~/.aws/credentials). The dev host has a real ~/.aws/credentials, and
the lazy per-request resolution landed the handle in a DynamoDB-Local
(-inMemory, NOT -sharedDb) namespace partitioned differently from the one where
app_single_table was created -> ResourceNotFoundException -> 500. Every other
single-table service imports the shared, explicitly-credentialed
app.core.aws.ddb (= ddb_resource(), aws_access_key_id="test").

## Fix
referrals._tbl() now reuses  like all other
single-table callers. referrals.spec.ts: 19/19 green after fix.

## Prod impact
None / latent-only. Production talks to real AWS DynamoDB (single namespace via
the instance IAM role), so the credential-less handle resolved correctly there;
the bug only manifests under DynamoDB-Local-without-sharedDb (dev/e2e). The fix
is nonetheless correct and consistent for prod. No prod mirror required.
