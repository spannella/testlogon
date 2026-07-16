# TIPFIX-TRANSACT — every real tip 500'd on the running prod-mock (bare-client rail fix)

Live prod hotfix (EC2 `i-08f937fc705ebea75`, us-east-2, via SSM), folded here for
re-apply. Completes the tipping smoothing program: turns "the TIPX verifiers pass"
into "tipping actually works on the running demo".

## The bug (PRE-EXISTING since the TIP-501 transactional rail)

`app/services/tips.py` `_transact_tip_ledger` (and the tip-reversal
`_transact_reversal_ledger`, and the tip-rail `collaboration_splits.write_collaboration_split_ledger`)
issued the atomic debit+credit+receipt `transact_write_items` through the DynamoDB
**resource-derived** low-level client (`T.billing.meta.client`) while passing
**pre-serialized** AttributeValue maps (`_av(...)` -> `{"S": ...}`/`{"N": ...}`).

The running prod-mock backend uses **DDB-Local (:8001)**. Through the resource-derived
client, DDB-Local REJECTS pre-serialized AV maps with
`ValidationException: Invalid attribute value type` -> `_transact_tip_ledger` raises
-> **every real tip 500s** on the running instance (post / message / video / comment /
profile — all fail identically). A bare `boto3.client("dynamodb")` at the SAME endpoint
ACCEPTS the same maps (which is exactly why the TIPX verifiers passed: TIPX-A shims in a
bare client, so the LOGIC was validated while the SHIPPED rail still 500'd).

On real AWS DynamoDB the resource-client path also works, so the fix must work on BOTH.

### Proven on the running server BEFORE the fix
```
RESOURCE_CLIENT (T.billing.meta.client): FAILED -> ClientError ValidationException: Invalid attribute value type
BARE_CLIENT (boto3.client at http://localhost:8001): SUCCESS
```

## The fix (rail-wide, minimal, behavior-preserving)

`app/core/aws_clients.py`: add a module-level cached `ddb_transact_client()` — a bare
low-level `boto3.client("dynamodb")` whose endpoint_url / region / credentials are
inherited from the app's live dynamodb **resource** client (so it hits the SAME table
on both DDB-Local and real AWS, with no `S.dev_mode` branch). Mirrors the already-proven
`group_treasury._transact_client` pattern.

`app/services/tips.py`: both `_transact_tip_ledger` (line ~193) and
`_transact_reversal_ledger` (line ~629) now issue `transact_write_items` via
`ddb_transact_client()` instead of `T.billing.meta.client`. **No transaction
items/keys/logic changed** — only the client.

`app/services/collaboration_splits.py`: the collab-split tip transact (line ~162) — the
other rail reached by `charge_tip` — uses `ddb_transact_client()` too.

### Other money paths checked (NOT changed)
- `group_treasury`, `maintenance_orders`, `ticket_bounties`, `hotel_folios` already build
  their own bare low-level client (`_transact_client()`) — already correct, not broken.
- `refund_requests.py:295` pre-serializes through `T.billing.meta.client` too, BUT wraps it
  in `except (ClientError, TypeError): <sequential puts>` — so on DDB-Local it silently
  degrades to non-atomic writes rather than 500ing. Not user-visible-broken; out of the
  tip-rail scope; left untouched (noted only).

## Apply
```
python3 patch_tipfix.py /path/to/testlogon    # idempotent; re-runs are no-ops
```
Baseline (pre-patch) md5s (dev == prod, byte-identical):
```
tips.py               5909639413e4f028a36b225cde29ff21
aws_clients.py        b6c985ee5ae8cdc716a37812d25b7a5e
collaboration_splits  4efd91836b95703a26ece0c2c708f893
```
Post-patch md5s (dev == prod):
```
tips.py               e05c27754abdfb041ed83d2820ede245
aws_clients.py        c4d7a404dc9f1660c68e7ca91571e684
collaboration_splits  8f2a67af45ac96ecb3f5bead97574162
```
Prod procedure: backup `*.bak_tipfix_<ts>` -> patch -> `chown ubuntu:ubuntu` ->
`py_compile` -> `sudo -u ubuntu bash /home/ubuntu/restart_backend.sh` -> openapi 200.
Prod backup ts: `1784219977`. Dev backup ts: `1784219939`.

## Verify (REAL HTTP against the running uvicorn — NOT a shim)
`verify_tipfix_http.py` seeds two tagged synthetic users, mints a real UI access-token
cookie, and hits `POST /ui/profile/{creator}/tip` on the live backend:
```
[PASS] real_tip_http_200            (was 500 before the fix)
[PASS] ledger_debit_present / ledger_credit_present / ledger_receipt_present
[PASS] replay_http_200 / replay_charges_once   (idempotent, charges once)
[PASS] pre_ledger_failure_rejected (non-owned PM -> 400) + no_new_rows
[PASS] cleanup_zero_residue
RESULT: ALL_PASS (10/10)
```
`verify_tipx_a_noshim.py` is the existing TIPX-A verifier with its bare-client SHIM
DISABLED (and the A4 forced-failure retargeted at `ddb_transact_client()`), proving the
RAIL ITSELF now uses a bare client: **17/17 PASS**, including
`A1 402-before-ledger (no orphan)` and `A4 collab split atomic (all-or-nothing)`.

Run on prod (as ubuntu, backend env):
```
PYTHONPATH=/home/ubuntu/testlogon DDB_ENDPOINT_URL=http://localhost:8001   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1   ./.venv/bin/python verify_tipfix_http.py
```

## Result
Tips now actually work end-to-end on the running prod-mock instance. stripe-mock cannot
synthesize a card-decline over HTTP (it returns a succeeded PaymentIntent for any
well-formed request), so the 402-card-decline path is proven via TIPX-A A1's in-process
charge-failure injection (402 -> no ledger rows) rather than over HTTP; the pre-ledger
rejection is additionally proven over real HTTP (non-owned PM -> 400, zero ledger rows).
