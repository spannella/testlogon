# TEST-001: Residual E2E Shard-Interference Failures (~12/6366)

**Ticket**: TEST-001
**Author**: Engineering
**Status**: Open
**Date**: 2026-06-04
**Priority**: Medium
**Dependencies**: none (test-infra; product is per-spec green)

---

## 1. Overview

After a large stabilization campaign (**507 → ~12 failures**, ~30 real product bugs
fixed), the E2E suite is **100% green per-spec in clean isolation** — every spec
passes when run alone after `just restart`. The residual failures appear **only in
the canonical restart-per-shard run** (20 specs sharing one backend), where data
accumulated by earlier specs in a shard perturbs later ones, plus a thin layer of
load-induced flakiness.

This ticket tracks closing that last ~0.2% so a single restart-per-shard run is
fully green. Full history + methodology: `docs/e2e-shard-failure-investigation.md`.

**Current state (re-shard #8, 17 shards of 20, retry-on-zero-passed guard):**
`failing-tests = 12`, 12 of 17 shards fully clean.

## 2. The residual failures (re-shard #8)

| Test | Class | Notes |
|------|-------|-------|
| `fan-club.spec.ts:351` (2.2 Charlie badge) | **flake** | Passed on rerun; load-induced. |
| `group-feed.spec.ts:359` (Pin badge) | **deterministic** | Pinned badge missing in-shard; `_batch_get_posts` UnprocessedKeys retry added but still recurs — needs deeper look (moto BatchGet throttling under load vs the pinned-index derivation). |
| `group-feed.spec.ts:377` (pin >3 → 409) | **deterministic** | `_count_pinned` undercounts under load → 4th pin not rejected. Same root area as :359. |
| `agent-product.spec.ts:340` | likely interference | Was :197 (per-agent idea cap) — fixed with unique agent_id; line shifted, recheck whether this is a new/remaining assertion. |
| `billing-wallet.spec.ts:418` | likely interference | 70.6 ledger; seeded unique markers added — recheck. |
| `delegates-newsfeed.spec.ts:228` | likely interference | 495.x post-list under shared author partition; self-find-by-id added — recheck. |
| `kyc-address-verification.spec.ts:360` | interference | Re-verify under accumulation; add 429/retry + scope. |
| `bug-fixes.spec.ts:814`, `:1050` | interference/flake | TTL/expiry + sidebar-preview timing on a busy DM list. |
| `video-upload.spec.ts:495` | unclassified (new) | Surfaced in #8; not yet diagnosed. |
| `vod-broadcast-pricing.spec.ts:277`, `:292` | unclassified (new) | Surfaced in #8; not yet diagnosed. |

Note: line numbers shift between runs because several specs were edited during
stabilization; map by test title, not line. A stability re-run (separating
deterministic vs flaky) was in progress when this was filed — fold its result in.

## 3. Root-cause classes (all test-infra, not product, except where noted)

1. **Shared-user data accumulation**: specs hammer the same identities (alice/root)
   and shared global partitions (billing ledger, `POST_AUTHOR#alice`, product
   ideas, kyc cases) → absolute-count / `.first()` / newest-N assertions see
   cross-spec data. *Fix pattern (applied broadly already):* scope to unique
   per-run markers, self-find by id, assert deltas, seed uniquely-identifiable rows.
2. **Load-induced flakiness**: 20 specs/backend + Playwright `retries:1` → the
   occasional double-fail (fan-club, some bug-fixes timing). *Fix:* targeted waits,
   retry-on-429 in helpers (rate-limit caps already inflated dev-only).
3. **A couple of genuine load-sensitive backend bugs** (group-feed batch-get /
   pinned-count) that only manifest under shard concurrency — worth a real fix.

## 4. Proposed fix

1. **Run the stability re-run** to get the deterministic-vs-flaky split, then fix
   each deterministic spec by the patterns above (scope to unique data, self-find
   by id, seed unique markers). Re-classify `video-upload`, `vod-broadcast-pricing`.
2. **group-feed (real):** finish the pinned-index/`_count_pinned` robustness under
   BatchGet throttling (`app/services/group_feed.py`).
3. **CI guidance:** the suite is reliable per-spec; for CI, use restart-per-shard
   with **smaller shards** (e.g. 10/shard) to cut accumulation, or treat the
   documented residual set as known-flaky with auto-retry, until the above lands.

## 5. Definition of done

A full restart-per-shard run (with the zero-passed retry guard) reports **0
failing tests** across all shards on two consecutive runs.

## 6. What's already done (context)

- 507 → ~12 across ~11 fix waves; every spec green in isolation.
- ~30 real product bugs fixed (models.py dedup, security-groups reserved word,
  license None-coercion, delegates GSI type, ssh OpenSSH keys, ec2/admin-compute
  quota, KYC MRZ/screening/risk, group-feed pin desync, vod presign/cursor,
  feed-fanout regex, missing `ui/alert` & `ui/use-toast` components, App.tsx
  routes, etc.). See `docs/e2e-shard-failure-investigation.md`.
- Dev-only rate-limit cap inflation to remove shard 429 interference (production
  untouched).
