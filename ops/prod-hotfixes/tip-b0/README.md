# TIP-B0 — centralized tip charge service + call-site migration (TIP-001..013)

## What this epic did

**Phase 1 (TIP-001..004)** — added `app/services/tips.py`: the single
`charge_tip(...) -> TipResult` seam every tipping surface calls. Behavior-preserving
centralization of PM-resolution, one-time PM-ownership validation, the delegate
`can_tip` guard (default-DENY), idempotency-key dedup, the existing mock charge, and
the UNCHANGED `write_tip_ledger` (net `type:"credit"`, 20% `fee_tips_bps` split).

**Phase 2 (TIP-005..012)** — migrated the 6 tip call sites onto `charge_tip`,
behavior-preserving, and fixed the latent orphan-credit bug:

| Surface | File | Change |
|---|---|---|
| messaging attached-tip send (text/image/gallery/scheduled) | `app/routers/messaging.py` | inline mock + `write_tip_ledger` → `charge_tip(content_type="message")` |
| post-hoc `send_message_tip` | `app/routers/messaging.py` | `write_tip_ledger` → `charge_tip`; PM scan + minted id + invoice + license-split kept |
| newsfeed `tip_post` | `app/routers/newsfeed.py` | dropped `PaymentProvider` stub + `write_tip_ledger` → `charge_tip(content_type="post")` |
| newsfeed `tip_comment` | `app/routers/newsfeed.py` | dropped stub + `write_tip_ledger` → `charge_tip(content_type="comment")`; keeps `payment_intent`-shaped response |
| broadcast `send_tip_message` | `app/services/broadcast_tip_store.py` | `write_tip_ledger` → `charge_tip(content_type="broadcast")`; PM/bounds/self-tip/rate-limit checks PRESERVED |
| video `tip_video_endpoint` | `app/routers/video_listing.py` | dropped stub + `write_tip_ledger` → `charge_tip(content_type="video")` |

**Orphan-credit fix (TIP-005):** in the messaging TEXT send path the tip+lock
mutual-exclusion 400 previously fired AFTER `write_tip_ledger`, so a lock+tip text
send settled a credit and THEN 400'd (orphan credit). The check is now moved BEFORE
any ledger write (mirroring the image/gallery paths). After the fix a lock+tip text
send 400s with NO ledger row written.

**`charge_tip` extension:** an optional `tip_payment_id` param was added so callers
that already mint a tip id and store it on their content row (messaging attached,
send_message_tip, broadcast chat) keep the row↔ledger id linkage; otherwise
`charge_tip` mints one. `write_tip_ledger` output is unchanged.

## Prod-only bits folded into git (TIP-010, TIP-012)

Prod had these as hotfixes; they are now in the dev clone too:
- `app/routers/video_listing.py` `tip_video_endpoint` + `VideoTipIn/Out` (migrated).
- `app/services/tip_ledger.py` — `"video"` added to the content_type allowlist + reason map.
- `app/services/delegates.py` — `"can_tip"` added to `VALID_PERMISSIONS` (the actual
  guard is centralized in `charge_tip._guard_delegate_can_tip`, default-DENY).

## Files (re-appliable)

- `app_services_tips.py` — the migrated `charge_tip` (incl. the `tip_payment_id` param).
- `migrate_shared_surfaces.py <ROOT>` — anchored patcher for the 6 shared call sites
  + the orphan-credit reorder + the `charge_tip` param. Idempotent-safe: fails loudly
  if an anchor is absent (already applied / drifted).
- `migrate_video_prod.py <ROOT>` — migrates the (prod-existing) `tip_video_endpoint`
  onto `charge_tip` + adds `import uuid`.
- `fold_video_ledger_delegate.py <ROOT>` — for a fresh clone lacking the prod-only
  bits: folds the video endpoint + tip_ledger `"video"` + delegate `can_tip`.
- `apply.sh [DEST]` — copies `tips.py` then runs the patchers; py_compiles.

## Re-apply to a fresh prod

```
bash apply.sh /home/ubuntu/testlogon
su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"
```

Money-path is UNCHANGED (real Stripe charge is B1/TIP-101). `.bak_tipb0_<ts>` copies
were made before every prod edit.

## Verification (prod, DynamoDB Local @ localhost:8001)

- In-process `charge_tip` for `message/post/comment/broadcast/video`: each wrote
  DEBIT gross 500 + CREDIT net 400 (`type:"credit"`, settled) to the right users,
  fee 100; idempotent replay → no new rows; self-tip + bogus content_type → 400.
- HTTP orphan test: lock+tip text send → `400 "Cannot combine lock_price_cents with
  tip_amount_cents"` with NO credit row written; tip-only send → 200 with a net-400
  credit to the recipient.
