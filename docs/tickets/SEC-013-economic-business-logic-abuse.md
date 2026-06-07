# SEC-013: Economic / Business-Logic Abuse (idempotency & atomicity)

**Ticket**: SEC-013 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 2)

## Problem
- **Affiliate commission replay** — `app/services/referrals.py:289` `put_item` with no
  idempotency on `transaction_id` → replaying the event pays the commission repeatedly.
- **Free-trial unlimited re-subscribe** — `app/routers/subscription_server.py:817` — no
  per-(subscriber,plan) trial-claim record → cancel + resubscribe = infinite free trials.
- **Promo per-user limit race / TOCTOU** — `app/services/promo_codes.py` validate vs
  redeem aren't atomic; per-user cap not enforced on redeem → redeem > limit; validated
  code redeemable after deactivation.
- **Referral attribution race** — `referrals.py:156-204` check-then-put, no
  ConditionExpression → duplicate attributions.
- **View-once re-read race** — `messaging.py:11343` `ADD view_once_seen` not guarded →
  re-read the once-only message under a race.

## Fix
- Make every credit/claim **idempotent + atomic**: ConditionExpression
  `attribute_not_exists(pk)` on attribution/commission keyed by `transaction_id`;
  per-(subscriber,plan) trial-claim record (reject if exists); enforce promo per-user
  limit atomically in redeem (and re-validate active/expiry at redeem time); guard
  view-once consume with a conditional update.
- Require/verify idempotency keys on money/credit endpoints.

## Testing
pytest: replaying a commission/attribution by transaction_id is a no-op; second trial
on the same plan rejected; concurrent promo redeems respect per-user cap; view-once
returns content exactly once under concurrent reads.
