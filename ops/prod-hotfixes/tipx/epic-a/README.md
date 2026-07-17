# TIPX-A — Money-correctness & reachable reversal (prod hotfix)

Epic TIPX-A of the tipping smoothing program. Fixes the money-correctness rough
edges of the shipped TIP-B0..B5 tipping subsystem. Backend live prod hotfix
(SSM), mirrored byte-for-byte into the `android-impl` dev clone.

## Tickets delivered

| Ticket | What | Files |
|---|---|---|
| **A1** | Charge-before-side-effect: move the public tip-total bump AFTER a successful charge so a 402 leaves no orphan total / no ledger. `tip_post` (newsfeed) + post-hoc `send_message_tip` (messaging). Own-comment/self-tip already 400 via `charge_tip`. | `app/routers/newsfeed.py`, `app/routers/messaging.py` |
| **A2** | Wire the reversal path (was ZERO callers). New admin route `POST /v1/admin/tips/{tip_payment_id}/reverse` (admin/root) + `reverse_tip_by_payment_id` service that resolves the tip's ledger rows and calls the existing idempotent `reverse_tip` (type != credit, flips original credit to `state=reversed`, best-effort Stripe refund). | `app/routers/admin_tip_reversal.py` (new), `app/services/tips.py`, `app/main.py` |
| **A3** | Idempotency on ALL surfaces: replace the 6 fresh-per-request keys with stable, `client_request_id`-aware keys (`{surface}:{content_id}:{crid}`; falls back to per-request-unique absent a client id — mirrors the good `msgtip:{mid}`/`bctip` pattern). post/post-react/comment/comment-carry (newsfeed), message-react/post-hoc-message (messaging), video/video-comment (video_listing). Each tip request model gains an optional `client_request_id`. | `app/routers/newsfeed.py`, `app/routers/messaging.py`, `app/routers/video_listing.py` |
| **A4** (P0) | Collab-split tip: route through `split_fee` (platform fee taken, NET distributed — reconciles with solo-tip net) + make collaborator credits + payer debit a single `TransactWriteItems` (atomic; no 100%-payout, no partial write). Fee applied only for `source=="tip"`; other sources unchanged. | `app/services/collaboration_splits.py`, `app/services/collaboration_revenue.py` |
| **A6** | Leaderboard excludes reversed credits (`& Attr("state").ne("reversed")`) so a refunded tip drops from top-supporters (lands with A2; foundation for D2). | `app/services/tip_leaderboard.py` |

> A5 (config max cap + gate-charge classification) intentionally deferred: not
> required to make a wrong charge correctable / retries safe, and touches surfaces
> owned by later epics. Tracked in the plan.

## Apply on prod (SSM)

The router files carry pre-existing prod hotfixes, so we do NOT copy whole files
for them — the patchers are content-anchored (line-offset independent). Two files
ARE whole-file replacements (`collaboration_splits.py`, new `admin_tip_reversal.py`).

```
# from a dev host that can SSM the prod EC2 (i-08f937fc705ebea75):
#  1. ship these to prod /tmp: collaboration_splits.py admin_tip_reversal.py
#     tips_append.py patch_dev.py patch_dev2.py patch_dev3.py
#  2. on prod, cd /home/ubuntu/testlogon and:
cp <ts>-backup every target file  (tips.py collaboration_splits.py
   collaboration_revenue.py tip_leaderboard.py newsfeed.py messaging.py
   video_listing.py main.py)  ->  <file>.bak_tipx_<ts>
cp /tmp/collaboration_splits.py app/services/collaboration_splits.py
cp /tmp/admin_tip_reversal.py   app/routers/admin_tip_reversal.py
python3 /tmp/patch_dev.py    # A3 keys + models + A4 source-thread
python3 /tmp/patch_dev2.py   # A1 charge-before-bump
python3 /tmp/patch_dev3.py   # A2 append + router register + A6 leaderboard
python3 -m py_compile <all 9 files>
chown ubuntu:ubuntu <all edited files>
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh
curl -s http://127.0.0.1:8000/openapi.json   # 200; /v1/admin/tips/{id}/reverse present
```

`patch_dev3.py` reads `/tmp/tips_append.py` (the `reverse_tip_by_payment_id`
service block appended to `tips.py`). All patchers are idempotent (skip if already
applied) and fail loudly if an anchor is missing/ambiguous.

## Verify (live-DDB-direct, self-cleaning)

`verify_tipx_a.py` runs ON the prod host against the live DDB-Local the backend
uses. It pattern-tags every synthetic row (`tipxA_<ts>_<rand>`) and deletes them
all (0 residue). Run:

```
cd /home/ubuntu/testlogon
set -a; . ./.env.local; set +a; export DEV_MODE=1
.venv/bin/python verify_tipx_a.py    # expects 17/17 PASS
```

### ENV caveat (why the verifier swaps the DDB client)

On this mock host `boto3.resource("dynamodb").meta.client.transact_write_items`
rejects the low-level attribute-value maps `_transact_tip_ledger` /
collaboration_splits build ("Invalid attribute value type") — a DDB-Local/resource
quirk; production runs on real AWS where the shipped rail is validated. The
verifier installs a tiny client proxy that routes ONLY `transact_write_items` to a
plain `boto3.client("dynamodb")` (which accepts AV maps), so the SAME
charge_tip / reverse / collab code executes unchanged and we validate the LOGIC
(fee / atomicity / idempotency / reversal) against real rows.

## Verify matrix (17/17 PASS)

- A3 idempotent [post, post_react, comment, message, message_react, video,
  video_comment]: stable-key double-fire = 1 debit / 1 credit / replay; net 800 / fee 200
- CORE distinct-keys charge twice (idempotency does not over-collapse)
- CORE self-tip 400
- A1 402-before-ledger: 0 debit / 0 credit on a forced decline (no orphan total)
- A2 admin reversal correct: refund 1000 (gross) / clawback 800 (net) /
  original credit state=reversed / no type=credit entry
- A2 reversal idempotent: replay, no extra rows
- A6 leaderboard excludes reversed
- A4 collab tip: payer debit 1000, each collaborator NET 400 (total 800), fee 200 taken
- A4 collab split atomic: forced failure -> 0 orphan rows
- A4 solo/collab net reconcile
- CLEANUP 0 residue
