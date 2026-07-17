#!/usr/bin/env python3
"""TIPFIX-TRANSACT patcher (idempotent).

Routes the tip-rail TransactWriteItems calls through a bare boto3 dynamodb client
instead of the resource-derived .meta.client, which rejects pre-serialized
AttributeValue maps against DDB-Local (ValidationException: Invalid attribute
value type) -> every real tip 500s on the running prod-mock instance.

Touches:
  app/core/aws_clients.py   -> add cached ddb_transact_client() (bare low-level client)
  app/services/tips.py      -> both _transact_* use ddb_transact_client()
  app/services/collaboration_splits.py -> collab-split tip transact uses it

Does NOT change any transaction items/keys/logic -- only the client that issues
transact_write_items. Re-runnable: no-ops if already applied.
"""
import io, sys, re

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'

def read(p):
    with io.open(p, 'r', encoding='utf-8') as f:
        return f.read()

def write(p, s):
    with io.open(p, 'w', encoding='utf-8', newline='\n') as f:
        f.write(s)

HELPER = '''

_DDB_TRANSACT_CLIENT = None


def ddb_transact_client():
    """Return a cached bare low-level DynamoDB client for transact_write_items.

    Callers that build raw AttributeValue maps ({"S": ...}/{"N": ...}) must issue
    transact_write_items through a *plain* client. The boto3 resource's
    .meta.client carries the document transform injector, which re-serializes
    already-serialized values -> DDB-Local rejects it with
    ValidationException: Invalid attribute value type (every real tip 500s).

    Endpoint/region/credentials are inherited from the app's live dynamodb
    resource client, so it targets the SAME table on both DDB-Local (dev/prod-mock)
    and real AWS with no S.dev_mode branch (matches group_treasury pattern).
    """
    global _DDB_TRANSACT_CLIENT
    if _DDB_TRANSACT_CLIENT is not None:
        return _DDB_TRANSACT_CLIENT
    from app.core.aws import ddb as _ddb_resource
    resource_client = _ddb_resource.meta.client
    endpoint = resource_client.meta.endpoint_url
    region = resource_client.meta.region_name
    creds = resource_client._request_signer._credentials
    kwargs = {"region_name": region, "endpoint_url": endpoint}
    if creds is not None:
        frozen = creds.get_frozen_credentials()
        kwargs["aws_access_key_id"] = frozen.access_key
        kwargs["aws_secret_access_key"] = frozen.secret_key
        if frozen.token:
            kwargs["aws_session_token"] = frozen.token
    _DDB_TRANSACT_CLIENT = boto3.client("dynamodb", **kwargs)
    return _DDB_TRANSACT_CLIENT
'''

def patch_aws_clients(root):
    p = root + '/app/core/aws_clients.py'
    s = read(p)
    if 'def ddb_transact_client' in s:
        print('  aws_clients.py: already has ddb_transact_client (skip)')
        return False
    # append helper at end of file
    if not s.endswith('\n'):
        s += '\n'
    s = s + HELPER
    write(p, s)
    print('  aws_clients.py: added ddb_transact_client()')
    return True

def patch_tips(root):
    p = root + '/app/services/tips.py'
    s = read(p)
    changed = False
    # add import if missing
    if 'from app.core.aws_clients import ddb_transact_client' not in s:
        anchor = 'from app.core.tables import T, _to_decimal\n'
        assert anchor in s, 'tips.py import anchor not found'
        s = s.replace(anchor, anchor + 'from app.core.aws_clients import ddb_transact_client\n', 1)
        changed = True
    n = s.count('client = T.billing.meta.client')
    if n:
        s = s.replace('client = T.billing.meta.client', 'client = ddb_transact_client()')
        changed = True
    print('  tips.py: replaced %d meta.client site(s)' % n)
    if changed:
        write(p, s)
    return changed

def patch_collab(root):
    p = root + '/app/services/collaboration_splits.py'
    s = read(p)
    changed = False
    if 'from app.core.aws_clients import ddb_transact_client' not in s:
        # anchor on the tables import in that file
        m = re.search(r'^from app\.core\.tables import [^\n]*\n', s, re.M)
        assert m, 'collab tables import anchor not found'
        s = s[:m.end()] + 'from app.core.aws_clients import ddb_transact_client\n' + s[m.end():]
        changed = True
    old = 'T.billing.meta.client.transact_write_items(TransactItems=tx_items)'
    new = 'ddb_transact_client().transact_write_items(TransactItems=tx_items)'
    n = s.count(old)
    if n:
        s = s.replace(old, new)
        changed = True
    print('  collaboration_splits.py: replaced %d meta.client site(s)' % n)
    if changed:
        write(p, s)
    return changed

def main():
    print('PATCHING root=%s' % ROOT)
    patch_aws_clients(ROOT)
    patch_tips(ROOT)
    patch_collab(ROOT)
    print('DONE')

if __name__ == '__main__':
    main()
