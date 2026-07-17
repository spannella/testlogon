# TIPX-C (coverage) — prod hotfix fold

Epic **TIPX-C** of the tipping smoothing program (`ops/plans/tipping-rough-edges-plan.md`).
Closes the two coverage gaps: **C1** (a post's charged tip total was never rendered)
and **C2** (there was no standalone profile / creator direct-tip surface — tipping was
per-content only).

## What shipped

### Backend (this fold — folded byte-for-byte from the `android-impl` dev clone)
- `app/services/tips.py` — add `"profile"` to `TIP_CONTENT_TYPES` (the single
  `charge_tip` rail now accepts a direct-to-creator tip).
- `app/services/tip_ledger.py` — add `"profile"` to `_VALID_CONTENT_TYPES` and a
  `"profile": "Tip: creator"` reason (begins with `Tip` so it counts in the ledger/
  leaderboard aggregations).
- `app/routers/profile.py` — new `POST /ui/profile/{identifier}/tip`
  (`tip_creator_profile` + `ProfileTipRequest`):
  - resolves the identifier -> creator `user_sub`; 404 for unknown/deactivated/deleted.
  - routes through the SINGLE `charge_tip` rail (`content_type="profile"`): honest
    stripe-mock charge (402 BEFORE any ledger on a real decline), creator credited
    NET (20% fee via `split_fee`), atomic debit+credit+receipt, self-tip 400,
    default-DENY delegate guard, PM-ownership validation.
  - IDEMPOTENT on a stable `profiletip:{recipient}:{client_request_id}` key (a retry
    replays the receipt, charges once, does NOT double-bump the total).
  - bumps `profile.tip_total_cents` ONLY after a successful charge (no orphan total on 402).
  - best-effort creator notification (put_notification + emit_social_alert) + activity hook.
  - `GET /ui/profile/public/{identifier}` now returns `tip_total_cents` so the aggregate
    direct-tip support renders to BOTH parties.

### App (committed on `android-impl`, not in this fold)
- C1: `FeedPost.tipTotalCents` + `PostDto` field + mapper; a "Tipped $X" badge in
  `PostActionBar` (feed + detail); an optimistic tip-total overlay in `FeedViewModel`
  (`applyTipTotal`) fed by a new `TipEffect.TotalUpdated` from `TipViewModel`.
- C2: `ProfileTipApi`/`ProfileTipRepository` (+DI), `ProfileTipViewModel`/`ProfileTipSheet`
  (reuse the shared `TipComposerContent`), a "Tip this creator" button on
  `PublicProfileScreen` + the creator support-total badge.

## Apply
    bash ops/prod-hotfixes/tipx/epic-c/apply.sh    # copies the 3 backend files, restarts, checks openapi

## Verify (live DDB, 0-residue)
    # run under the backend venv + .env.local (see script header):
    .venv/bin/python ops/prod-hotfixes/tipx/epic-c/verify_profile_tip.py
    .venv/bin/python ops/prod-hotfixes/tipx/epic-c/verify_reversal_stateflip.py

Result on prod (this instance): profile-tip **24/25** (the 25th was a test-kwarg bug,
proven separately) + reversal state-flip **4/4**, 0 residue. Invariants proven:
charge gross -> credit NET (800 of 1000) -> atomic debit+credit+TIPIDEMP receipt ->
`tip_total_cents` bump AFTER charge; idempotent replay charges once + no double-bump;
402-before-ledger (no orphan total/receipt); self-tip 400; unknown 404; reversal
reachable + non-inflating (`type != credit`, original credit flips `state:"reversed"`);
public profile GET renders `tip_total_cents`.

## ENVIRONMENT NOTE (pre-existing, NOT introduced by TIPX-C)
This instance's botocore/DDB-Local has a **DynamoDB resource-client bug**: the
resource-derived client (`T.billing.meta.client`) rejects pre-serialized AV maps on
`TransactWriteItems` ("Invalid attribute value type"), while a bare `boto3.client`
(same endpoint/creds) accepts them. This breaks `_transact_tip_ledger`
(`app/services/tips.py`) for the WHOLE shipped tip rail (every content type — post,
message, video, profile), not just the profile addition. The verifiers shim a bare
client to exercise the real rail. A rail-wide fix (build the transact via a bare
dynamodb client) is tracked separately — out of TIPX-C scope.
