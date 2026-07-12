# Content-moderation + advertising-v2 residuals (MOD-1 / MOD-2 / MOD-6 / ADV-sign)

Closes the four non-blocking BACKEND residuals left after the content-moderation +
advertising-v2 programs. LIVE PROD HOTFIX via SSM (`i-08f937fc705ebea75`), `.bak_resid_<ts>`
on every touched prod file, restart + openapi 200, verified in-process on prod DDB
(`verify_resid.py`, **28/28 ALL_PASS**). Anchored + idempotent; the same scripts patch the
dev clone and prod.

## MOD-1 — offender history is a COMPLETE indexed query (`apply_mod1.py`, `apply_ddbinit.py`, `create_gsi_userid.py`)
`admin_moderation._offender_history_summary` / `_prior_enforcement_history` / the
`/users/{id}/history` endpoint now use `_query_enforcement_history_by_offender`, which
returns **every** enforcement record for a user (no `Limit=100` truncation) so
`total_tickets` (distinct source tickets), `open_tickets` (active enforcements) and the new
`total_enforcements` are PRECISE counts.

- New **`ByOffenderCreatedAt` GSI** = `user_id` (HASH — the offender) + `created_at` (RANGE),
  registered in `scripts/local-ddb-init.py`. It hashes on the **existing** `user_id`
  attribute, so every row auto-indexes with **no new attribute and no backfill**, and
  enforcement writes never touch a not-yet-ACTIVE index key.
- The reader is **GSI-preferred with a COMPLETE base-table fallback**: it queries the GSI
  (DB-side newest-first); on any `ClientError` (index missing / not ACTIVE) it falls back to
  a fully-paginated base-table `Query` on `user_id` (still complete). So counts are ALWAYS
  precise, independent of index availability.
- **Prod GSI note:** the first attempt created the index keyed on a NEW `offender_user_id`
  attribute, which (a) needed a backfill and (b) made enforcement writes fail with
  `InternalFailure` while the index was in `CREATING` (writing a not-yet-ACTIVE index's HASH
  key). That design was reverted to the `user_id` hash above. The stale `offender_user_id`
  index wedged in `CREATING` on the AWS side and cannot be deleted until it goes ACTIVE.
  **MOD-1 is correct in the meantime via the base-table fallback** (verified). Run
  `create_gsi_userid.py` (self-healing / idempotent) once AWS clears the stale index: it
  deletes the stale index and creates `ByOffenderCreatedAt` on `user_id`.

## MOD-2 — reported message shows an "under review" PLACEHOLDER, not removal (`apply_mod2.py`, `messaging.py`)
D-MESSAGE-HIDE: a moderation-hidden message is no longer dropped from the thread for
non-sender members. `_message_out_from_item` now returns a stripped
`_under_review_placeholder_message_out` (text `"Message under review"`, `under_review=True`,
media / reactions / tips / ad payload all omitted) whenever the message is
`moderation_hidden`/`moderation_removed_at` and `viewer != sender`; the SENDER keeps
owner-view (real content). The two thread-listing loops keep the row via
`_should_render_under_review_placeholder` instead of `continue`. Gallery / search / report
paths still exclude the message (no leak). On unhide the flags clear (non-destructive) so
the real content returns **byte-for-byte**. New `MessageOut.under_review` field.

## MOD-6 — DMCA hide/restore covers message_media + (feed/video) comment (`dmca_content_operations.py`)
`dmca_content_operations.hide_content_for_dmca` / `restore_content_after_dmca` extended
beyond feed_post/feed_media/video: `message_media` (was a stub) and `comment` /
`video_comment` (were unsupported) now hide + restore **non-destructively** by delegating to
`moderation_hide` (the intact-row flag writer the moderation state-machine uses — the
messaging/comment read paths already respect it). Composite `content_id` carries the parent
key: `conversation_id|message_id`, `post_id|comment_id`, `video_id|comment_id`
(`resolve_content_from_url` also parses `.../comments/<id>` URLs). Restore is guarded by DMCA
case-ownership + a `prior_hidden` snapshot so a concurrent moderation hide is never clobbered.

## ADV-sign — `ad_revenue_reversal` in LEDGER_ENTRY_SIGN (`apply_advsign.py`, PROD-ONLY)
`billing_shared.LEDGER_ENTRY_SIGN["ad_revenue_reversal"] = -1` (creator clawback = debit
direction). Harmless today (the row is not `type=="credit"` so no earnings/balance reader
sums it) but completes the canonical sign map so `derive_signed_amount_cents` no longer
defaults it to `+1` (and stops the "not in LEDGER_ENTRY_SIGN" WARNING). **This file
DIVERGES: prod has the signed-amount system; the older android-impl dev clone
`billing_shared.py` predates it entirely, so `apply_advsign.py` safely NO-OPs on the dev
clone** — the fix is prod-only (`.bak_resid_<ts>`), folded here.

## Apply / verify
```
# dev clone: python ops/prod-hotfixes/residuals/apply_mod1.py <ROOT>
#            python ops/prod-hotfixes/residuals/apply_mod2.py <ROOT>
#            python ops/prod-hotfixes/residuals/apply_ddbinit.py <ROOT>
#            (dmca_content_operations.py is a full-file replacement; billing_shared no-ops)
# prod: make_prod_apply.py | ssm_send.py  (pushes + applies AS ubuntu with .bak_resid_<ts>)
#       restart_backend.sh ; openapi 200 ; ssm_run.py verify_resid.py  -> 28/28 ALL_PASS
```
Prod backups: `.bak_resid_1783629869` on admin_moderation.py / messaging.py /
dmca_content_operations.py / billing_shared.py.
