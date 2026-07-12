# TIP-B3 — comment-carrying tip + comment-tip PM + video-comment tip (LIVE PROD HOTFIX, folded)

Epic B3 backend (TIP-301/302/303). Applied LIVE to prod (EC2 i-08f937fc705ebea75 via SSM)
with `.bak_tipb3_1783480681` backups, then mirrored into this dev clone and committed.

## What changed (charge_tip is the ONLY money path; net credit stays `type:"credit"`)

- **TIP-301** `app/routers/newsfeed.py` — `TipRequest` gains `payment_method_id: Optional[str]`
  so `POST /posts/{post_id}/comments/{comment_id}/tip` can name an explicit / tip-default PM
  (resolved via `charge_tip` -> `resolve_tip_payment_method`: explicit -> tip_default -> default).
  `tip_comment` reordered so `charge_tip` runs BEFORE the `tip_total_cents` stamp — a declined
  charge (402) now leaves NO stamp and NO ledger row.
- **TIP-302** `app/routers/newsfeed.py` — `CreateCommentRequest` gains
  `tip_amount_cents` / `tip_currency` / `tip_payment_method_id`. `create_comment` charges the tip
  FIRST (recipient = the POST author) via `charge_tip(content_type="comment", content_id=comment_id)`
  BEFORE writing the comment row, so a failed charge raises with no orphaned comment / stamp / ledger.
  On success the comment row + response are stamped `tip_total_cents`.
- **TIP-303** `app/routers/video_listing.py` — new
  `POST /ui/videos/{video_id}/comments/{comment_id}/tip` -> `charge_tip(content_type="video_comment")`,
  recipient = the video-comment author; stamps `tip_total_cents` on the comment.
  `app/services/video_comments.py` gains `get_comment` + `bump_comment_tip_total` helpers.
  `app/services/tips.py` `TIP_CONTENT_TYPES` and `app/services/tip_ledger.py` allowlist + reason
  map gain `"video_comment"`. (`creator_earnings.classify_entry` already buckets it as `tips` — TIP-B2.)

## Apply / re-apply
`python3 apply_tipb3.py <APP_ROOT> <TS>` — idempotent-guarded (skips already-applied edits),
writes `.bak_tipb3_<TS>` per file. chown ubuntu:ubuntu on prod after; restart_backend.sh; openapi 200.

## Verify (in-process TestClient on prod, real DDB + stripe-mock)
`verify_tipb3.py` -> 6/6 PASS: comment-carry (302) debit 500/credit 400 net + stamp + PM flows;
tip existing comment w/ tip-default PM (301) credit 640; video-comment tip (303) debit 700/credit 560
+ stamp; self-tip 400 (both surfaces); failed charge 402 -> no comment, no ledger; classify=tips.
