# E2E Shard-Run Failure Investigation & Fix Plan

_Generated during the restart-per-shard verification run (2026-06-03). Static code analysis only — no tests were run against the live backend while the shard runner was executing._

## Method

The suite (335 specs / ~6,366 tests) is being run in **17 shards of 20 specs**, each shard preceded by a clean `just restart` (DB wipe + reseed). This eliminates *cross-run* accumulation but NOT *within-shard* accumulation (20 specs share one backend sequentially).

At 9/17 shards: **385 failures**, heavily clustered. Five parallel static investigators traced each cluster to root cause. Findings below are split into **REAL BACKEND BUGS** (fix in code, will fail regardless of harness) and **TEST-HARNESS / INTERFERENCE** (artifacts of shared state or test setup).

---

## A. REAL BACKEND BUGS (fix in code)

### A1. `app/models.py` EC2/K8s output models corrupted by bad merge — **CONFIRMED, HIGH** ★ highest leverage
**Impact:** ec2-launcher 13/13 (total wipeout), k8s-launcher 9 (partial). ~22 tests.
**Evidence (verified by reading `app/models.py:5329–5496`):**
- `Ec2InstanceOut` (5329–5338) truncated after `private_ip`; K8s class spliced in at 5339. Missing: `ssh_key_id, host_id, created_at, started_at, stopped_at, terminated_at, last_activity_at, auto_terminate_after` — all passed by `app/routers/ec2_launcher.py` `_instance_out` (lines ~55-62) and silently dropped (Pydantic `extra='ignore'`).
- `Ec2InstanceTypeInfo` (5380–5384) missing `cost_cents_per_min` (router builds it at `ec2_launcher.py:75`).
- `Ec2AmiInfo` (5469–5475) has bogus REQUIRED `ttl_seconds`/`expires_at` + spurious `terminated_at`/`last_activity_at`, and is missing `os_type`/`username` (router builds `os_type`/`username` at `ec2_launcher.py:85`) → **ValidationError → HTTP 500** on `/amis`.
- `K8sPodOut` (5351–5372) missing `ttl_seconds`/`expires_at` (passed by `k8s_launcher.py` `_pod_out` ~65-66).

**Fix:** Repair the region — de-interleave the classes and restore dropped fields. Exact field sets to be cross-checked against the routers' `_instance_out` / `_pod_out` / type-list / ami-list builders before editing:
- `Ec2InstanceOut`: append `ssh_key_id, host_id, created_at, started_at, stopped_at, terminated_at, last_activity_at, auto_terminate_after`.
- `Ec2InstanceTypeInfo`: add `cost_cents_per_min: float` (and confirm `vcpu`/`memory_gb`/`description`).
- `Ec2AmiInfo`: should be `{ami_id, name, os_type, username}` — remove `terminated_at`/`ttl_seconds`/`expires_at`/`last_activity_at`.
- `K8sPodOut`: add `ttl_seconds: int = 14400` and `expires_at: int = 0`.

### A2. Unbounded global-partition reads in agent services — **MEDIUM** (real defect; trigger-under-load uncertain at shard scale)
**Impact:** agent-qa (8), agent-fleet (7), agent-product (5) and the agent cluster's back-half tests.
**Evidence:**
- `app/services/agent_qa.py:342–370` `find_qa_eligible_tickets` queries the `ByStatus` GSI on global `STATUS#code_complete` (`tickets.py:89-90`) with NO `Limit`/`LastEvaluatedKey` loop, then sorts oldest-first and truncates `[:50]` → newest ticket can fall off the single 1MB page.
- `app/services/agent_fleet.py:295–321` two `T.tickets.scan(FilterExpression=...)` calls with no pagination loop.
- `app/services/agent_project.py:405,442,445` global `STATUS#submitted` partition + unbounded `product_ideas.scan()`.

**Caveat:** Under restart-per-shard a single shard only accumulates ~20 specs' worth of tickets — likely under one 1MB page — so this may NOT be the dominant cause of the observed agent failures (rate-limit interference, A-side below, is a stronger candidate). **Fix anyway** (correctness): wrap each in a `while True … ExclusiveStartKey=LastEvaluatedKey` loop (mirror the correct pattern at `agent_orchestrator.py:161-181`). **Verify in isolation post-run before assuming this clears agent failures.**

### A3. compute-billing float in spending path — **MEDIUM**
**Impact:** compute-billing 3 (640.1, 642.x, 643.x; budget-only 641.x pass).
**Evidence:** `SpendingSummaryOut`/`BudgetOut` models are intact; seed uses `rateCentsPerMin: 0.4` (float). Likely a float→Decimal issue in the spending-aggregation / `/tick` path (`app/services/compute_billing.py`).
**Fix:** Coerce float rates to Decimal/int in the spending aggregation + tick path. **Confirm by reproducing 640.1 in isolation.**

---

## B. TEST-HARNESS / INTERFERENCE (not product bugs)

### B1. Per-IP rate-limit buckets shared across the shard — **MEDIUM-HIGH** ★ highest leverage on the harness side
**Impact (broad):** follow-system (9), delegates-newsfeed (7), delegates-management (4), delegates-broadcast (4), post-interesting (4), post-hide (4), media-preferences (6), alerts-delivery (7), creator-earnings (6), billing-config (3), admin-email-sms-dashboards (4), admin-subscription-tiers (3), offline-queue (5), mobile-ui (5), drag-drop (4), emoji-messages (3), feed-fanout (1).
**Mechanism:** `app/middleware/rate_limit.py:227-268` buckets per-IP limits under `ENDPOINT#{group}#IP#{ip}` (fixed-window, `rate_limit_store.py:26-77`). All specs run from one localhost IP, so within a 60s window the whole shard shares one counter per group. Per-group per-IP caps are hard-coded (`rate_limit_config.py:21-93`): newsfeed 1000, billing 600, admin 300, search 600, auth 200. `root`/`admin` bypass some groups; USER identities (Alice/Bob/Charlie) do not. `.env.local` raises only the *global* IP cap (10000), not per-group caps. Shard traffic → 429 on page loads/API calls → whole-`describe`-block cascades.
**Fix (single highest-leverage):** Allowlist the E2E localhost IP in `is_allowlisted` (`rate_limit_store.py:99`) when `DEV_MODE=1`, OR set per-group per-IP caps very high in dev mode. Secondary: retry on 429 in test API helpers.

### B2. Cookie-only `injectAuth` missing `localStorage["auth-store"]` → ProtectedRoute redirect — **HIGH**
**Impact:** kyc-self-service (10), kyc-proof-of-funds (2), kyc-id-scanner (2), kyc-documents (2), kyc-screening (1), kyc-webhooks (7, the UI ones), group-feed (5). UI-render tests only.
**Mechanism:** `frontend/src/components/ProtectedRoute.tsx:9-13` gates routes on `useAuthStore.isAuthenticated`, hydrated from `localStorage["auth-store"]` (`stores/authStore.ts:74-78`). Cookie-only `injectAuth` variants never set it → `page.goto("/kyc")` redirects to `/login` → testids never appear. Correct pattern exists in `kyc-business.spec.ts:57-66` / `kyc-admin-dashboard.spec.ts:64-72`.
**Fix:** Add the auth-store localStorage seed to each cookie-only `injectAuth` (copy `kyc-business.spec.ts:61-65`): `await page.goto("/login"); await page.evaluate(uid => localStorage.setItem("auth-store", JSON.stringify({state:{userId:uid,accessToken:null,isAuthenticated:true},version:0})), session.user_sub);`

### B3. group-treasury wallet seeded with `if_not_exists + :amt` (increment, not set) — **HIGH**
**Impact:** group-treasury 12 (459.4 cascade onward).
**Mechanism:** `group-treasury.spec.ts:187-198` `seedGroupAndWallets` does `wallet_balance_cents = if_not_exists(...) + :amt` on `pk=USER#{sub}` (stable sub, not TS-keyed). Across runs the balance grows unbounded; test 459.4 ("Insufficient wallet fails") seeds `99999999` which then leaks into the fresh treasury and corrupts all downstream balance assertions.
**Fix:** `SET wallet_balance_cents = :amt, currency = :c, updated_at = :t` (deterministic per run). _Note: restart-per-shard mitigates the cross-run growth, so confirm whether this still fails on a clean shard; the in-run `99999999` leak into treasury is the part that persists._

### B4. Ads specs: unguarded `beforeAll` cascade — **HIGH** (test robustness; ads backend is clean)
**Impact:** ad-dayparting 11, ad-optimization 11, ads-targeting/creatives/analytics/accounts-campaigns partials.
**Mechanism:** Account-create → root-approve → campaign-create chain in `beforeAll` asserts nothing (`ad-dayparting.spec.ts:118-142`, `ad-optimization.spec.ts:147-192`). A single flaky setup call (under shard load / B1 rate limits) leaves `accountId`/`campaignId` undefined → every campaign-scoped test fails. Verified backend has NO per-advertiser cap/quota/name-uniqueness (`ad_accounts.py:14-32`, `ad_campaigns.py:35-61`) — so it's a setup cascade, not a product bug. (The only surviving tests are pure-validation 422 cases that don't need a valid campaign — diagnostic proof.)
**Fix:** Assert each setup step (`expect(resp.status()).toBe(201)`, `expect(accountId).toBeTruthy()`) so a flaky setup fails loudly instead of silently nuking 11 tests; combined with B1 the setup stops being flaky.

### B5. account-deletion: leftover pending request disables the button — **HIGH mechanism**
**Impact:** account-deletion 6 (section 535 UI).
**Mechanism:** Button `disabled={!!activeRequest}` where `activeRequest = requests.find(r => r.status==="pending")` (`AccountDeletionPage.tsx:70-71,217`). If a prior section's `afterAll cleanupUser` didn't run / left Bob `pending|processing` (`_ACTIVE_STATUSES`, `account_deletion.py:38`), the button stays disabled. The `execSync` cleanup subprocess in `beforeAll` can also throw under load → whole section fails. No other spec touches deletion endpoints (so it's intra-file ordering, not cross-spec).
**Fix:** Move `cleanupUser(BOB_ID)` into `beforeEach`; wrap the `execSync` in a retry; assert no pending request before relying on the button.

### B6. broadcast-lottery: 31s sleep exceeds default 30s test timeout — **HIGH**
**Impact:** broadcast-lottery test 135.3 + chained cascade (10 total).
**Mechanism:** `broadcast-lottery.spec.ts:261` does `await sleep(31_000)` for the lottery cooldown (`broadcast_lottery.py:37` `LOTTERY_CREATE_COOLDOWN_MS=30_000`) but never raises the per-test timeout; `playwright.config.ts:5` default is 30_000 → guaranteed timeout (sometimes rescued by `retries:1`). Chained `sessionId`/`lotteryId` vars then orphan downstream tests.
**Fix:** `test.setTimeout(40_000)` on 135.3; guard chained tests with `test.skip(!sessionId)` or assert setup succeeded.

### B7. admin-rate-limits: dashboard reads the bloated `rate_limit_events` table — **MEDIUM-HIGH**
**Impact:** admin-rate-limits 4 (section 562 Event Log / Live tabs).
**Mechanism:** `_log_event_async` writes `rate_limit_events` on every 429 across the shard (`rate_limit.py:247`); the dashboard aggregates `DATE#{today}` → large/slow response → tab assertions time out (the documented "200KB+ response hides UI" pattern). Root loads the page (bypasses limits) but the data tabs choke.
**Fix:** Paginate/cap the dashboard event query server-side, or clear `rate_limit_events` for today in `beforeAll`. B1 also reduces the 429 volume that bloats the table.

### B8. license specs: code clean — environment/accumulation — **MEDIUM**
**Impact:** license-issuance 14, license-requests 6, license-compliance 4, license-agreements 1.
**Mechanism:** Models/service/table-def/registration all correct (`issued_licenses.py:25-143`, `local-ddb-init.py:1709-1718`, `main.py:684/701`). Every *write* test fails, every *validation/negative* test passes → points to the `issued_licenses` table not initialized in the running DDB during the shard, or accumulated-state interference.
**Fix:** No code change. Confirm table presence on a clean restart and reproduce `POST /ui/licenses/issued` (467.1) in isolation; if it still fails on a clean table, capture the actual `put_item` exception.

---

## C. Execution plan (after the shard run completes — do NOT run tests against the live backend until then)

1. **Fix A1** (models.py) — cross-check field sets against the ec2/k8s routers, repair the region. Reproduce ec2-launcher + k8s-launcher in isolation → expect green.
2. **Fix B1** (rate-limit allowlist for E2E IP in dev mode) — single change clearing the largest interference cluster (~60 tests). Re-run follow-system, delegates-*, post-*, alerts-delivery, creator-earnings, admin-* in a shard to confirm.
3. **Fix B2** (auth-store in cookie-only injectAuth) — patch the KYC + group-feed specs. Re-run KYC cluster.
4. **Fix B3/B4/B5/B6** (group-treasury SET; ads beforeAll asserts; account-deletion beforeEach cleanup; broadcast-lottery timeout).
5. **Verify A2/A3/B7/B8** in isolation first (medium confidence) — only fix if reproduced.
6. Re-run the affected shards with restart-between to confirm green; then a final full restart-per-shard pass.

---

## A′ / B′. SECOND-WAVE CLUSTERS (shards 10–17, added after the 9-shard snapshot)

Final run: **17 shards, ~5,755 passed, 507 failing** (~8%, clustered). The following clusters were found in the later shards.

### A4. Syndicate per-user cap counts archived/dissolved syndicates — **REAL BUG, HIGH**
**Impact:** syndicate-feed 13 (near total), syndicate-bundles 8, syndicate-revenue-split 4, syndicate-open-licensing 4, syndicate-treasury 3 (~32).
**Evidence:** `app/services/syndicates.py:18` `MAX_SYNDICATES_PER_USER = 10`, enforced at `:36-38` via `list_user_syndicates(creator_sub)` which (`:115-120`) returns ALL `USER_SYND#{user}` rows with **no status filter** — archived/dissolved + prior-run rows still count. Every spec's `beforeAll` creates a syndicate as **Alice** (shared sub across both session setups); ~15 Alice-owned creations per shard, no `afterAll` cleanup → the Nth `create_syndicate` returns HTTP 400. syndicate-feed `beforeAll` (`syndicate-feed.spec.ts:95-100`) reads `data.syndicate_id` unguarded → `undefined` → all sections hit `/ui/syndicates/feed/undefined/...` → 13-fail cascade.
**Fix:** (A) Exclude archived/dissolved from the cap count in `syndicates.py:36-38` (filter by META status / add an active flag). (B) Make `MAX_SYNDICATES_PER_USER` env-overridable + raise it in dev. Optional test hardening: `afterAll` leave/archive + guard feed's `beforeAll` with `expect(resp.status()).toBe(201)`.

### A5. `/seo` missing from the Vite dev proxy — **REAL BUG, HIGH**
**Impact:** seo-metadata 8 (all API tests; the 2 client-side SeoHead tests pass).
**Evidence:** `frontend/vite.config.ts:24-117` proxies `/ui`, `/api`, `/messaging`, `/posts`, … but has **no `/seo` entry**. Tests use the `request` fixture with `baseURL: localhost:3000` + relative `/seo/*` paths → fall through to Vite's SPA fallback → `index.html` (200, text/html) → `resp.json()`/`body.title` undefined; even `/seo/robots.txt` (line 103) and `/seo/sitemap.xml` (114) fail (only explainable by a routing miss). Backend `app/routers/seo_metadata.py` is clean.
**Fix:** Add `"/seo": "http://localhost:8000",` to the `frontend/vite.config.ts` proxy table (before any catch-all).

### A6. vod-purchase reason-string mismatch + unpaginated `list_purchases` — **REAL BUG, HIGH**
**Impact:** vod-purchase 3 (105.3, 105.6, 105.9).
**Evidence:** Spec asserts `reason==="not_purchased"` / `"purchase"`, but `check_vod_access` (`app/services/vod_purchase.py:204,180`) returns `"none"` / `"purchased"`, passed through unmapped (`app/routers/video_listing.py:1086-1088`) — deterministic (fails in isolation too). 105.9: `list_purchases` (`vod_purchase.py:565-572`) uses `Limit=50` with **no LastEvaluatedKey loop** → under entitlement accumulation the PPV video falls off page 1.
**Fix:** Reconcile the reason strings (decide canonical contract — change service OR spec; service strings `none`/`purchased` are arguably the better names → update spec, OR map in the router to the spec's contract). Add a pagination loop to `list_purchases`.

### B2′ (extends B2). More cookie-only `injectAuth`/`newIdentityPage` missing `auth-store` — **HIGH**
**Impact:** moderation-video-queue 3 (section 98 UI; `moderation-video-queue.spec.ts:52-55` cookies-only), sms-production 2 (`sms-production.spec.ts:49-55` cookies-only). UI nav → ProtectedRoute redirect to /login. Same fix as B2 (add the auth-store localStorage seed).

### B9. user-groups retry-worker state reset — **MEDIUM-HIGH**
**Impact:** user-groups 5 (450.x UI + 451.1/2 API). `injectAuth` DOES set auth-store, pages/routes/testids exist. Module-level `let groupId=""` is reset when Playwright `retries:1` spawns a fresh worker after a 429/render failure → the contiguous 450.1→451.2 block cascades.
**Fix:** Make 450.x/451.x self-seed their own group instead of relying on module-level `groupId`; B1 reduces the triggering 429s.

### B1′ (extends B1). Rate-limit / shared-page interference — the dominant second-wave cause — **MEDIUM-HIGH**
**Impact:** theme-customization 11 + theme-switcher 7 + dark-mode-sync 1 (reload/nav tests gate on a `/messaging/conversations` GET that 429s under load; in-place CSS-var tests pass — backend + themeStore are clean), security-groups 11 + ssh-key-manager 7 (**models verified INTACT — NOT the A1 corruption**; SG rule-add success path + 50-rule bulk loop trips the per-IP bucket, SSH upload tests depend on a CPU-bound `execSync` RSA keygen that starves under suite load), rate-limiting 2 (section E *dashboard UI* — collateral of the very 300/min global IP bucket it reads), user-journey 3, payouts 3, referrals 1, creator-storefront 1, and the API singles (tax-documents, stories, risk-scoring, collaboration-revenue, connection-profiles, host-inventory, carrier-tracking, rich-comments, video-*, vod-pipeline/download, bulk-payout-tools). Mechanism: single localhost IP shares the global `IP#{ip}` 300/60s bucket (`app/core/settings.py:1712`) + per-group caps (`rate_limit_config.py`), all hard-coded, not raised in dev. **Same fix as B1** (allowlist E2E IP / raise dev caps) clears the bulk; verify theme/SG/SSH in isolation to confirm they're load-only.

**NOTE on A1 scope:** security-groups & ssh-key-manager were checked against the corruption — their `SecurityGroupOut` (9805), `SshKeyOut` (4628) models are OUTSIDE the damaged 5316–5497 range and intact. A1 only affects ec2-launcher / k8s-launcher.

---

## A″. SECOND-PASS: NEW REAL BUGS (reproduce in ISOLATION — not interference)

The first investigation left 29 tests in 14 specs unmapped. An **isolation re-run proved they fail on a clean backend** → real bugs, not shard interference. Root causes (static deep-dive, high confidence unless noted):

### A7. webrtc — `seedConversation` test helper writes the wrong table — **HIGH** (~14 tests)
**Impact:** webrtc.spec.ts all of sections 74–77 (invite/accept/decline/end). Routes exist + auth works (the 401 test passes).
**Evidence:** `seedConversation` (`webrtc.spec.ts:451-469`) writes one `Conversations` row with a `participant_ids` list. But `create_invite` resolves participants via `_load_conversation_participants` (`app/services/messaging_call_lifecycle.py:49-59`) which queries the **`Participants`** table on `GSI1` (`GSI1PK=conversation_id`, reading `user_id`) — one row per participant (real schema: `scripts/local-ddb-init.py:390-395`, writer `messaging.py:6296-6307`). No `Participants` rows exist → resolver returns empty set → `_ensure_participant` raises `forbidden` → invite returns 403; accept/decline/end all chain off a successful invite → 14 fails.
**Fix (test helper):** make `seedConversation` write `Participants` rows per id: `{user_id, conversation_id, status:"active", GSI1PK:conversation_id, GSI1SK:user_id}`.

### A8. file-share-links — `/public/files` missing from Vite proxy — **HIGH** (1 test) — same class as A5
**Evidence:** Public page calls `GET /public/files/share/{id}/info` (`api/endpoints/fileShareLinks.ts:24-28`); backend serves it (`file_share_links.py:31` prefix `/public/files/share`). `frontend/vite.config.ts` proxies `/public/groups` + `/public/fundraisers` but **not `/public/files`** → returns index.html → page shows "not found" → `public-download-button` never renders.
**Fix:** add `"/public/files": "http://localhost:8000"` (or broaden to `/public`) to the Vite proxy. **Bundle with A5.**

### A9. watermarked-downloads — spec targets a dead testid — **HIGH** (2 tests)
**Evidence:** spec asserts `[data-testid="watermarked-download-button"]` (`watermarked-downloads.spec.ts:485,494`), but `VideoPlayerPage.tsx:510-511,36` renders `VodWatermarkDownloadButton` (testid `vod-watermark-download-button`); the `WatermarkedDownloadButton` component is never imported.
**Fix (test):** change the spec to `vod-watermark-download-button`.

### A10. billing-wallet — ledger humanizes the type label — **HIGH** (1 test)
**Evidence:** spec asserts raw `wallet_withdrawal`/`wallet_deposit` (`billing-wallet.spec.ts:388`); `Ledger.tsx:74-78` renders `row.type.replace(/_/g," ")` + capitalize → "Wallet withdrawal". Assertion can never match.
**Fix (test):** assert `/wallet withdrawal/i` / `/wallet deposit/i`.

### A11. Residual singles — need error-capture rerun — **LOW confidence, likely flaky/timing** (~9 tests)
vod-watermark-download §2/§3, activity-feed-soc003 §201.6, analytics §C3, analytics-depth §8, api-keys §6 (3), bot-templates §514.4, contacts §556, custom-emojis §732.1, bug-fixes §10/§11. Static review found **correct source logic** for all; suspected causes: auth-injection timing (fresh context + immediate nav → 401 → logout), data-accumulation row-matching (`.first()` hits an older row), or serial-page shared-state. **Action:** rerun each individually capturing the actual response/status before deciding test-fix vs product-fix. NOTE: these reproduced in a 14-spec batch (not pure isolation), so some may still be intra-batch interference — the per-spec isolation pass will reclassify.

## A‴. SECOND-PASS VERIFICATION (per-bucket isolation runs)

To validate the "interference" verdicts empirically, one representative spec per bucket was run **entirely alone** on a clean backend:
| Spec | Bucket | Isolation result | Verdict |
|------|--------|-----------------|---------|
| follow-system | B1 | 18 passed, 0 fail (9.9s) | ✅ interference confirmed |
| theme-customization | B1 | 23 passed (1.6m) | ✅ interference confirmed |
| security-groups | B1 | 17 passed (1.8m) | ✅ interference confirmed |
| alerts-delivery | B1 | 28 passed (3.0m) | ✅ interference confirmed |
| admin-rate-limits | B7 | 26 passed (1.7m) | ✅ interference confirmed |
| ad-dayparting | B4 | _passed count ambiguous — needs failed-count recheck_ | pending |
| _(kyc-self-service, kyc-admin-dashboard, syndicate-feed, group-treasury, license-issuance, ec2-launcher, seo-metadata, agent-qa, delegates-newsfeed, payouts)_ | various | _in flight_ | pending |

**Implication:** B1 rate-limit interference is now empirically validated for the big newsfeed/messaging/admin specs — the rate-limit allowlist fix (B1) will clear them. ec2-launcher/seo-metadata are expected to FAIL alone (real bugs A1/A5); syndicate-feed/license may PASS alone (cap/accumulation only shows in a shard). The remaining rows finalize the classification.

---

## E. CLEAN-ISOLATION VERIFICATION (authoritative — overrides static labels)

`just restart` → run ONE spec alone → record. This is the source of truth. **Result: the static "interference/accumulation" labels were wrong for almost every spec.**

| Spec | clean failed | shard failed | static label | **VERIFIED** |
|------|-----------|-----------|------|------|
| follow-system | 0 (dirty run, 18/18) | 9 | B1 interference | ✅ interference (label held) |
| theme-customization | 11 | 11 | B1 | ❌ **REAL BUG** |
| security-groups | 11 | 11 | B1 | ❌ **REAL BUG** |
| alerts-delivery | 7 | 7 | B1 | ❌ **REAL BUG** |
| admin-rate-limits | 4 | 4 | B7 | ❌ **REAL BUG** |
| kyc-admin-dashboard | 7 | 7 | B-kyc accum | ❌ **REAL BUG** |
| delegates-newsfeed | 5 | 7 | B1 | ❌ **REAL** (5) + 2 interference |
| payouts | 3 | 3 | B1 | ❌ **REAL BUG** |
| ad-dayparting | 11 | 11 | B4 load-cascade | ❌ **REAL BUG** (not load-triggered) |
| syndicate-feed | 8 | 13 | A4 cap | ❌ **REAL** (8) + 5 cap/accum |
| group-treasury | 12 | 12 | B3 wallet | ❌ **REAL BUG** |

**Conclusion:** the bulk of the 507 are **real, reproducible bugs in the newer feature areas** (ADS/KYC/AGENT/BROADCAST/syndicate/theme/infra/license — the expansion that grew the suite from ~1,070 → ~6,366 tests). Only a thin layer of true interference sits on top (follow-system; the deltas on syndicate-feed/delegates). **B1's "rate-limit allowlist clears ~120 tests" is invalid.** Fixes must come from actual error output, captured per cluster.

## F. FIXES APPLIED (code-verified; verification pending in the capture run)
- **A1** `app/models.py` — repaired Ec2InstanceOut (added ssh_key_id/host_id/created_at/started_at/stopped_at/terminated_at/last_activity_at/auto_terminate_after), K8sPodOut (added ttl_seconds/expires_at), Ec2InstanceTypeInfo (added cost_cents_per_min), Ec2AmiInfo (restored to ami_id/name/os_type/username). Field sets matched to `ec2_launcher.py`/`k8s_launcher.py` builders.
- **A5+A8** `frontend/vite.config.ts` — added `/seo` and `/public/files` proxy entries.
- **A7** `frontend/e2e/webrtc.spec.ts` — `seedConversation` now writes `Participants` rows (GSI1PK=conversation_id) so `create_invite` resolves participants instead of 403.

## G. EXECUTION LOOP for "all clusters to green"
Serial-backend constraint → only one test run at a time. Loop:
1. **Capture** (restart-per-spec, rich `list` reporter) → real errors per representative cluster spec. _(in progress: /tmp/cap/*.log)_
2. **Fix** (parallel static agents per cluster, from real errors) → patch product or test.
3. **Verify** (restart-per-cluster) → confirm green; iterate on stragglers.
Representatives captured: ec2-launcher, k8s-launcher, seo-metadata, file-share-links, webrtc (verify fixes) + ad-dayparting, agent-qa, kyc-self-service, kyc-admin-dashboard, syndicate-feed, license-issuance, group-treasury, broadcast-lottery, delegates-newsfeed, theme-customization, security-groups, ssh-key-manager, vod-purchase, media-preferences, alerts-delivery, admin-rate-limits, payouts, account-deletion.

---

## H. FIXES APPLIED — full log (two parallel waves + routing)

**Confirmed via capture run (already green):** seo-metadata (A5), file-share-links (A8), webrtc (A7) → 0 failed. ec2/k8s improved (A1) with a second issue (routes) since fixed.

**Product bugs fixed:**
- `app/models.py` — A1 EC2/K8s class repair.
- `app/services/security_groups.py` — `_save_rules` used DDB reserved word `rules`; added `ExpressionAttributeNames` (fixes security-groups 11). *live-verified by agent.*
- `app/services/issued_licenses.py` + `app/routers/issued_licenses.py` + `license_agreements.py` + `license_compliance.py` — `display_name` None→`str` validation 400; coerced `or ""` (fixes license cluster ~25). *live-verified.*
- `app/services/delegate_feed.py` — GSI5SK written as int into a String-typed index → 500; zero-padded string (fixes delegates-newsfeed 5).
- `app/services/ssh_key_manager.py` — `_load_private_key` couldn't parse OpenSSH-format keys → 400; added `load_ssh_private_key` (fixes ssh-key-manager upload). *live-verified.*
- `app/services/agent_coder.py` — `mark_ticket_code_complete` didn't maintain GSI status-index → QA-eligible query missed it (fixes agent-qa 656.x).
- `app/services/agent_qa.py` — flaky-verdict logic (`initial_reg_fail`).
- `app/auth/policy.py` + `app/routers/agent_qa.py`/`agent_coder.py`/`agent_devops.py` — added `require_admin_or_root_csrf` for CSRF-required config PUTs.
- `app/services/vod_purchase.py` — `list_purchases` pagination loop.
- `app/services/syndicates.py` — per-user cap now counts only active syndicates (`count_active_user_syndicates`) + env-overridable.
- `frontend/src/App.tsx` — added missing routes: KYC admin (queue/case/metrics), `/agents/llm-keys`, `/remote/ec2`, `/remote/ssh-keys`, `/syndicates/my-bundles`, `/calls/settings`. (Several "UI not rendering" clusters were unrouted pages.)
- `frontend/vite.config.ts` — `/seo`, `/public/files` proxies.

**Test-harness bugs fixed (the dominant category):**
- **auth-store missing** in cookie-only `injectAuth`/`newIdentityPage` → ProtectedRoute redirect. Fixed across ~30+ specs: all KYC, ~13 agent-*, moderation-video-queue, vod-watermark-download, admin-rate-limits, admin-email-sms-dashboards, admin-subscription-tiers, account-deletion.
- **wrong/ambiguous selectors:** theme-customization (`.first()` on `Customization` strict-mode), payouts (CardTitle is a `<div>`, not heading → `getByText`), mobile-ui (`Dashboard` not `Home`), alerts-delivery (AlertsPage tab redesign → "All" tab).
- **venv-less subprocess:** group-treasury (`dissolve_treasury` via `.venv/bin/python3`), media-preferences (`local-ddb-init` via venv).
- **closed/undefined page lifecycle:** syndicate-feed (shared pages → file-scope hooks).
- **request-contract type:** ad-dayparting/ad-optimization (campaign dates ISO-string → int timestamp; the model wants int) + setup-step asserts.
- **31s sleep > 30s timeout:** broadcast-lottery (135.3/137.x), clip-sharing (`test.setTimeout`), + describe.serial guard.
- **wallet seed accumulation:** group-treasury (`SET` not `if_not_exists+`), `amount_cents` within model max.
- **dead testid:** watermarked-downloads (`vod-watermark-download-button`).
- **stale-state / self-containment:** account-deletion (cleanup→beforeEach), alerts-delivery 99.5, ec2-launcher 250 (instance cleanup).

## I. VERIFICATION (restart-per-spec, in progress)
Re-running the 21 baselined specs to confirm before→after. Results: `/tmp/verify_results.txt` + `/tmp/cap/verify_*.log`. Stragglers feed the next fix wave. Clusters not yet captured (offline-queue, drag-drop, live-qa, broadcast-scheduling, the smaller singles, and the un-captured members of fixed clusters) get a follow-up capture+fix+verify cycle.

## J. VERIFICATION RESULTS (representative re-run, restart-per-spec) — 168 → 36 (79% fixed)

| Spec | before | after wave 1-2 | after wave 3 |
|------|------|------|------|
| license-issuance | 14 | 0 ✅ | 0 ✅ |
| kyc-admin-dashboard | 7 | 0 ✅ | 0 ✅ |
| group-treasury | 12 | 0 ✅ | 0 ✅ |
| broadcast-lottery | 10 | 0 ✅ | 0 ✅ |
| security-groups | 11 | 0 ✅ | 0 ✅ |
| vod-purchase | 3 | 0 ✅ | 0 ✅ |
| admin-rate-limits | 4 | 0 ✅ | 0 ✅ |
| payouts | 3 | 0 ✅ | 0 ✅ |
| account-deletion | 6 | 0 ✅ | 0 ✅ |
| moderation-video-queue | 3 | 0 ✅ | 0 ✅ |
| agent-qa | 8 | 1 (+3 flaky) | pending |
| kyc-self-service | 10 | 1 | fixed (upload path) |
| theme-customization | 11 | 2 | fixed (accent race) |
| ec2-launcher | 13 | 3 | fixed (quota 3→5) |
| k8s-launcher | 9 | 4 | fixed (selectors) |
| ssh-key-manager | 7 | 3 | fixed (selectors) |
| syndicate-feed | 8 | 4 | fixed (auth-store) |
| delegates-newsfeed | 5 | 1 | fixed (post visibility) |
| ad-dayparting | 11 | 6 | fixed (validate_flights 500) |
| media-preferences | 6 | 6 | fixed (mediaSupported gate) |
| alerts-delivery | 7 | 5 | fixed (mark_read + AlertCenter) |

## K. WAVE 3 — residual fixes (product bugs in bold)
- **media-preferences**: `MediaSettingsPage` gated whole page behind `navigator.mediaDevices.getUserMedia` (false headless) → fallback card; removed early-return, inline warning instead.
- **ad-dayparting**: `validate_flights` compared str date vs int-timestamp campaign bounds → TypeError → 500; added `_to_date_str` normalization.
- **ec2-launcher**: `COMPUTE_QUOTA_DEFAULT_MAX_EC2` (3) ≠ `ec2_max_instances_per_user` (5) → 409; aligned to 5.
- **alerts-delivery**: `mark_read` ConditionExpression failed when `read` attr absent → `read_at` never stamped; made unconditional + ALL_OLD. `AlertCenter` crashed on null `event`; guarded.
- **theme-customization**: ThemeProvider server-config effect raced/clobbered accent CSS vars; added `skipAccent`.
- k8s/ssh selectors (strict-mode), syndicate-feed auth-store, kyc upload predicate (`/v1/fs/upload`), delegates post visibility (public).

## L. FULL RE-SHARD (authoritative, in progress)
All 335 specs, restart-per-shard (17 shards) — directly comparable to the 507 baseline; catches regressions from shared-file edits (App.tsx, ThemeProvider, AlertCenter, settings.py). Results: `/tmp/shard2_results.txt` + `/tmp/shard2_fails.txt`. This measures the true remaining failures across the WHOLE suite (representatives + the ~100 non-representative specs covered by cluster-wide fixes like the auth-store sweep).

## M. FULL RE-SHARD #1 RESULT: 507 → 278 (45% cleared suite-wide)
Confirmed the cluster-wide fixes carried to non-representative specs. Remaining 278 split: real-bug clusters not yet deeply fixed, shard-only accumulation (syndicate cap), and a thin interference layer.

## N. WAVE 4 + systemic dedup (more product bugs)
- **media-preferences**: `@/components/ui/alert` component **did not exist** → page chunk crash (prior agents missed it). Created `frontend/src/components/ui/alert.tsx`. + PYTHONPATH for the seed.
- **group-fundraising**: `groups.ts` imported uninstalled `axios` → chunk crash breaking GroupAds/Fundraising/Donation pages. Switched to the `api` client.
- **agent-workers/fleet**: `_provision_worker_dev` called `launch_instance` without required `label`/`ami_id` → worker error state; fixed. Response-model shadowing dropped fields → dropped response_model.
- **delegates-management**: `permissions` (DDB reserved word) in UpdateExpression → 500; aliased.
- **post-interesting**: counter written to `billing` table instead of `app_single_table`; fixed `_post_meta_table`.
- **follow-system**: `e2e_admin_session_setup.py` never seeded the `profiles` table → follow 404 on clean DB; added `ensure_profile`.
- **offline-queue**: `useOfflineQueue` returned early when `SyncManager` present → queue never flushed; removed early-return + IDB cleanup.
- **ads-analytics**: inclusive date window off-by-one → double-count; `start = now-(days-1)`.
- **ads-targeting**: duplicate `AdBlockIn` w/ spurious `startup_seconds` → 422; local model in router.
- **license-requests**: `display_name` None → 500; coerced.
- Test fixes: theme-switcher/kyc-webhooks(arg-shift)/agent-orchestrator(ticket envelope)/post-hide(limit≤50)/live-qa/group-feed/user-groups(auth-store + self-seed).
- **App.tsx routes added** (wave 4): `/earnings`, `groups/:groupId/settings`, `ads/targeting`, `ads/creatives`, `admin/ads/creatives`.

### SYSTEMIC: models.py duplicate-class dedup (union-merge corruption)
**22 classes were defined twice** → Python kept the last (often corrupted) copy, silently shadowing response models across ads/groups/agents/compute/tax/license. Resolved all 22: 18 deletions of corrupted/identical dups + 4 genuine domain-collisions renamed with importer updates (`CapacityOut`→`AgentProjectCapacityOut`, `EligibleTicketOut`→`EligibleTicketOutCoder`, `GroupListOut`→`HostGroupListOut`, `SpendingSummaryOut`→`TaxSpendingSummaryOut`). Fixed latent bugs in user-groups/compute-billing/tax-documents/host-inventory. `app.main` imports OK; zero duplicates remain.

## O. RE-SHARD #3 (authoritative, in progress)
All 335 specs after wave 3+4+dedup+routes. Measures cumulative effect + catches regressions from the models.py dedup. Results: `/tmp/shard3_results.txt`.

## D. Confidence summary
| Item | Type | Confidence | Est. tests |
|------|------|-----------|-----------|
| A1 models.py | real bug | **confirmed** | ~22 |
| B1 rate-limit IP | interference | med-high | ~60 |
| B2 auth-store | harness | high | ~25 |
| B3 treasury wallet | harness | high | ~12 |
| B4 ads beforeAll | harness | high | ~40 |
| B5 account-deletion | harness | high | 6 |
| B6 broadcast-lottery | harness | high | ~10 |
| B7 admin-rate-limits | interference | med-high | 4 |
| A2 agent pagination | real bug | medium | ~30 (uncertain trigger) |
| A3 compute-billing | real bug | medium | 3 |
| B8 license | env | medium | ~25 |
| **A4 syndicate cap** | **real bug** | **high** | **~32** |
| **A5 seo vite proxy** | **real bug** | **high** | **8** |
| **A6 vod-purchase** | **real bug** | **high** | **3** |
| **B2′ moderation/sms auth-store** | harness | high | ~5 |
| **B9 user-groups retry state** | harness | med-high | 5 |
| **B1′ rate-limit (theme/SG/SSH/etc.)** | interference | med-high | ~60 |

Final run: 17 shards, ~5,755 passed, **507 failing** (~8%). Highest-leverage fixes: **A1** (models.py, ~22), **A5** (one-line Vite proxy, 8), **A4** (syndicate cap, ~32), and **B1/B1′** (rate-limit allowlist — ~120 tests across both waves). Real backend bugs total: A1, A2, A3, A4, A5, A6. Everything else is test-harness/interference. Medium-confidence items (A2, A3, B8) must be reproduced in isolation before fixing.
