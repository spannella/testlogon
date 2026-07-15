# ADV3 EPIC E5 — Policy / fraud / limits (ADV3-10, ADV3-11, ADV3-12)

Prod hotfix bundle. Backend = LIVE PROD HOTFIX via SSM (EC2 `i-08f937fc705ebea75`,
DynamoDB Local). Dev clone `android-impl`; prod `main` diverges only on
`ad_billing.py` + `settings.py` (applied as a targeted patch, not a full-file
mirror). Prod backend restarted via `restart_backend.sh`; `/openapi.json` -> 200.

## What changed (ticket -> fix)

### ADV3-10 — close the three review-bypass surfaces (E2, E3, E7)
- **E2 seller-boost** (`shop_ads.boost_listing`): the product creative no longer
  ships `status="approved"` unconditionally. It is routed through the SAME
  automated ad-policy pass as a submitted creative (account auto-provision kept):
  a HARD violation -> `rejected` (never serves); a risk result -> `pending_review`
  (held for a human); only a CLEAN self-serve boost auto-approves. Response now
  carries `creative_status` + `serving` so the app distinguishes "live" vs
  "in review".
- **E3 sponsored-as-creator** (`sponsored_creator_posts.approve_and_publish`),
  enforced BEFORE the atomic claim so a block never strands the proposal:
  (1) policy-scan the post body -> HARD violation `SponsoredPostError(422)`;
  (2) any linked `creative_id` MUST be admin-`approved` else `409`;
  (3) a non-empty platform-standard disclosure/label is FORCED server-side
  (`ad_default_disclosure_label`, default "Paid partnership") — no longer
  advertiser-optional.
- **E7 ad-messaging** (`ad_messaging.approve_and_send` / `_run_send`):
  (1) policy-scan the (creator-overridable) body BEFORE claim -> HARD `422`;
  (2) force a non-empty `sponsor_label` server-side; (3) a GLOBAL per-recipient
  daily frequency cap (`ad_msg_recipient_daily_cap`, default 5) across ALL
  senders — an inbox at cap is dropped (`excluded_freq_cap`, no charge/send),
  independent of each creator's own audience cap.

### ADV3-11 — automated ad-content policy pass (E1)
- New `app/services/ad_policy.py`: deterministic three-way `screen_creative`
  (`clean` / `review` / `reject`) — deny-list of prohibited scam/malware/illegal
  terms + prohibited categories + landing-URL/domain reputation (blocked domains,
  URL-shortener + non-HTTPS soft signals + no-TLD) + reuse of the platform
  `content_filter` profanity list. HARD violation or score >= 80 -> reject; score
  >= 20 -> review (risk-ranked); else clean.
- Wired into `ad_creatives.submit_creative_for_review`: a HARD policy violation
  AUTO-REJECTS before a human sees it; otherwise -> `pending_review` with
  `policy_decision/policy_score/policy_flags/policy_reasons` stamped on the row.
  Fails OPEN to `pending_review` (never auto-rejects on a screening bug).
- `GET /ui/admin/ads/creatives/pending` now RISK-RANKS the queue by
  `policy_score` desc. No ad text/URL reaches serve without a policy pass.

### ADV3-12 — advertiser limits + fraud coverage + state-machine validation (E4, E5, E6, E8, E9)
- **E4** (already landed in E1): `record_cta_click` runs `check_fraud` +
  `record_account_activity` before charging CPC (verified present).
- **E5** (`ad_billing._process_charge`): pre-charge `check_spend_limits` gate —
  (a) account-level DAILY SPEND VELOCITY cap (`daily_spend_cap_cents` override,
  else `ad_account_daily_spend_cap_cents` established vs
  `ad_new_account_daily_spend_cap_cents` new/boost until first settlement) and
  (b) a minimal-KYC threshold gate (`ad_account_kyc_required_spend_cents`, cleared
  via `kyc_cleared`/`kyc_status==verified`). Blocked charge writes NOTHING
  (releases idempotency marker); fails OPEN on internal error. A charged deposit
  stamps `first_settled_at` so an account graduates to the established cap.
- **E6**: `serve_ad` now requires the resolved account `status=="active"` (not
  merely not-suspended) — a `rejected`/`pending` account stops serving
  immediately; `admin_ad_platform.moderate_account` now cascade-pauses campaigns
  on `reject` as well as `suspend`.
- **E8**: `review_ad_account` / `review_creative` validate the decision against an
  enum and raise `ValueError`; the admin endpoints map it to `422` (an unknown
  decision no longer writes an undefined status).
- **E9**: `serve_ad._campaign_targeting_countries` threads the campaign targeting
  countries into `check_fraud` on both the `track_ad_event` and `record_cta_click`
  paths (the geo-mismatch rule now fires on the live path); account activity is
  recorded even when fraud scoring errors.

App: `AdCreativeReviewApi.PendingCreativeDto` gains `policy_*` fields;
`AdCreativeReviewScreen` renders a risk badge ("Policy risk HIGH/ELEVATED (score)
· flags") on each row + policy reasons in the review dialog. `assembleDebug`
green; on-device (A15) the seeded flagged creative shows
"Policy risk HIGH (85) · risk_term, url_shortener".

## Files
- Full-file mirror (prod baseline byte-identical to dev HEAD): `ad_policy.py`
  (new), `ad_serving.py`, `ad_creatives.py`, `ad_accounts.py`, `shop_ads.py`,
  `sponsored_creator_posts.py`, `ad_messaging.py`, `admin_ad_platform.py`,
  `ads.py`.
- `adv3e5_billing_settings.patch` — targeted `git apply` patch onto prod's
  divergent `app/services/ad_billing.py` + `app/core/settings.py`
  (`git apply --check` clean, applied clean).
- `verify_adv3e5.py` — the deep-verification (run against prod DDB).

## Apply (prod)
1. `cp -p <file> <file>.bak_adv3_1784138300` for all 11 targets (backup ts on prod).
2. `git -c safe.directory=... apply adv3e5_billing_settings.patch` (billing+settings).
3. Overwrite the 9 mirrored files.
4. `chown ubuntu:ubuntu` + `python3 -m py_compile` (OK) + `restart_backend.sh`.
5. `/openapi.json` -> 200.

Prod `.bak` suffix: `.bak_adv3_1784138300`.

## Verify matrix (prod DDB, synthetic advertisers, auto-cleaned -> 0 residue)
`verify_adv3e5.py`: **29 PASS / 0 FAIL**.
- ADV3-11: clean->clean; deny-term->reject; blocked-domain->reject; risk->review
  (ranked, score 55); submit deny-term auto-rejected + meta stamped; submit
  clean->pending_review.
- ADV3-10/E2: clean boost auto-approves+serves; policy-violating boost held (not
  serving).
- ADV3-10/E3: hard-violation body -> 422; unapproved linked creative -> 409;
  empty disclosure forced to "Paid partnership".
- ADV3-10/E7: hard-violation body -> 422; per-recipient freq cap (under ok / at
  blocked).
- ADV3-12/E5: velocity first-under ok / over blocked (no debit); new cap 20000 <
  est cap 500000; KYC gate blocks uncleared crossing / cleared passes.
- ADV3-12/E6: active serves / rejected does NOT serve; reject cascade-pauses.
- ADV3-12/E8: unknown account & creative decision raise; valid decision works.
- ADV3-12/E9: targeting countries resolved; geo-mismatch fires (5) / match (0).
- ADV3-12/E4: `record_cta_click` fraud check present.

No regression: live paid serving still fills (real prod campaign wins the auction
in the diagnostic); money subsystems (funds-guard/idempotency/budget-guard/split)
untouched except the additive pre-charge limit gate.
