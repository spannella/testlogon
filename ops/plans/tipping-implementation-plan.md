# TestLogon — Tipping Implementation Plan & Ticket Breakdown

Status: PLAN (no product/app code changed by this document). Grounded in the live
`~/dev/testlogon` dev clone on host `192.168.0.249` (2026-07-07). Prod diverges from
this clone where noted (video tip + delegate `can_tip` are prod-only hotfixes not yet
folded into git).

Cross-refs: memory `tipping-scope-plan.md` (3 locked decisions + B0–B5), `android-web-parity.md`
(ecom **Bug#3**: creator credits MUST use ledger `type:"credit"` to show in earnings/payouts;
`ops/prod-hotfixes/` fold convention; prod≠dev clone), `android-test-fleet-admin.md` (2-device verify:
Galaxy A15 `192.168.0.238:5555` + Pixel 7a `192.168.0.101:5555`, admin acct
`crash1782189692@testlogon.example`).

---

## 1. Overview + Current Truth (with file:line evidence)

Tipping in TestLogon is **half-built**: the shared *credit* primitive is real and correct, but
every *charge* is mocked, the app charge seam is a stub, and several surfaces/capabilities are missing.

### 1.1 The ledger primitive is REAL + correct (keep it)

`app/services/tip_ledger.py:89 write_tip_ledger(entry)` writes a paired, settled debit+credit:

- **DEBIT** under `USER#{tipper}` — full gross (`tip_ledger.py:142-153`, `type:"debit"`, `state:"settled"`).
- **CREDIT** under `USER#{recipient}` — **net after platform fee**, `type:"credit"` (`tip_ledger.py:163-174`).
  The `type:"credit"` is load-bearing: it is exactly what makes the tip visible to earnings/payouts
  (avoids ecom Bug#3).
- Fee split: `split_fee("tip_debit", amount)` (`tip_ledger.py:135`) → `app/services/billing_config.py:444`,
  `_FEE_FIELD_BY_ENTRY_TYPE["tip_debit"]="fee_tips_bps"` (`billing_config.py:426`), default **2000 bps = 20%**
  (`billing_config.py:580`). Fee is truncated toward the creator's net.
- FIN-011 collaboration split short-circuit (`tip_ledger.py:103-121`) writes its own paired entries.
- FIN-018 fee metadata + GAP-0152 `earnings:update` SSE to the recipient dashboard (`tip_ledger.py:182-199`).
- `content_type` validated to `{message, post, comment, broadcast}` (`tip_ledger.py:51`); **prod adds `"video"`**
  (`ops/prod-hotfixes/app_services_tip_ledger.py.patch`).

Downstream consumers confirm the credit is honored:
- Earnings: `app/services/creator_earnings.py:36 classify_entry` buckets `content_type in {message,post,comment}`
  → `"tips"` (`creator_earnings.py:48-49`), else `reason` contains `"tip"` → `"tips"` (`:53`);
  `_query_credit_entries` filters `Attr("type").eq("credit")` (`:149`).
- Payouts: `app/services/creator_payouts.py:84 get_available_balance` sums `type==credit &
  state!=reversed & amount_cents>0` (`creator_payouts.py:107-111`).

> Note: new `content_type`s introduced by this plan (`video`, `message_react`, `post_react`,
> `video_comment`) are NOT in the earnings `classify_entry` allowlist, but they classify as `"tips"`
> anyway via the `reason` fallback (`reason` = `"Tip: <type>"` contains `"tip"`). B2/B3 still add
> them explicitly to the allowlist so category breakdowns are exact (TIP-205).

### 1.2 The CHARGE side is MOCKED everywhere (3 duplicated mocks)

No surface actually moves money out of a wallet / hits a payment processor before crediting:

1. **Newsfeed** — `app/routers/newsfeed.py:1026-1052 class PaymentProvider` ("pretends payments succeed"):
   `create_payment_intent` returns a stub intent; `confirm_payment_intent` always returns
   `status:"succeeded"`. Used by `tip_post` (`newsfeed.py:4748`) and `tip_comment` (`newsfeed.py:5916`).
2. **Messaging** — inline `tip_payment_id = "tip_" + new_id()` with NO charge, in the post-hoc
   `send_message_tip` (`app/routers/messaging.py:13903`) and in every attached-tip send path
   (text `messaging.py:8098`, image `:8422`, gallery `:9037`, scheduled delivery `:13626`).
3. **Broadcast** — `app/services/broadcast_tip_store.py:90 send_tip_message` writes the ledger
   (`:134-149`, `content_type="broadcast"`, recipient = broadcaster) but performs **no charge** either
   (validate-only: rate-limit + config checks, then straight to `write_tip_ledger`).

The real charge machinery already exists elsewhere and should be reused: `app/routers/billing.py:1095`
`stripe.PaymentIntent.create(..., off_session=True, confirm=True, idempotency_key=idem)` (also `:1197`,
`:2507`) against the configured **stripe-mock** (`STRIPE_API_BASE`, `app/core/settings.py:360-366`).
Tips bypass this.

### 1.3 The app charge seam is a STUB (flag AND-031) — tips never POST in release

`android/.../data/messaging/BillingAuthorizer.kt:54 StubBillingAuthorizer` (bound in
`MessagingDataModule.kt:98`): in **DEBUG** it authorizes with a **blank** `payment_method_id`
(`BillingAuthorizer.kt:64-65`) — the dev backend skips PM validation when the id is blank and mock-charges;
in **RELEASE** it returns `BillingResult.NotConfigured` (`:67`), so `TipRepository`/`VideoTipViewModel`/
`ThreadViewModel` surface "payments unavailable" and **never POST the tip**. So tips are non-functional
in a release APK. `TipRepository.kt` documents this as the AND-031 STOP-AND-FLAG.

### 1.4 Surface + capability gaps

| Capability / surface | State | Evidence |
|---|---|---|
| Attached tip on message SEND (backend) | EXISTS | send DTOs `messaging.py:1872/1957/2024`; write `messaging.py:8128-8142` |
| Attached tip on SEND (app) | **MISSING** | app send request DTOs omit `tip_amount_cents` (only the read projection has it, `MessagingDtos.kt:146`) |
| Post-hoc tip a message | EXISTS (mock) | `send_message_tip` `messaging.py:13867`, inline PM check `:13887-13901`, no charge `:13903` |
| Standalone post tip | EXISTS (mock) | `tip_post` `newsfeed.py:4726`; `PostTipRequest` HAS `payment_method_id` `newsfeed.py:1926-1929` |
| Tip on a comment | EXISTS (mock) | `tip_comment` `newsfeed.py:5895`; **`TipRequest` LACKS `payment_method_id`** `newsfeed.py:1749-1751` |
| Broadcast tip | EXISTS (real credit, no charge) | `broadcast.py:2036 /sessions/{id}/chat/tip`; `broadcast_tip_store.py:90` |
| Video tip | **PROD-ONLY hotfix** | dev `video_listing.py` has NO `/tip`; prod adds `tip_video_endpoint` (`ops/prod-hotfixes/app_routers_video_listing.py.patch`, ~L895), dev clone `write_tip_ledger` rejects `content_type=video` |
| Tip-as-REACTION (message) | **MISSING** | `react_to_message` `messaging.py:11194` is emoji ADD/DELETE only |
| Tip-as-REACTION (post) | **MISSING** | `add_reaction` `newsfeed.py:4890` emoji-only |
| Tip-CARRYING comment | **MISSING** | `CreateCommentRequest` `newsfeed.py:1658` has no tip fields |
| Video-comment tip | **MISSING** | no endpoint (video comments are prod-side; no tip path) |
| Default tip PM | **MISSING** | general default exists (`billing.py:779 current_default_pm`) but tips never fall back to it |
| Pay-to-message gate + allowlist | **MISSING** | `find_or_create_dm` `messaging.py:6123` only checks blocks (`is_any_block` `:6131`); `accept_conversation` `:6158` no tip gate |
| Group attached-tip recipient | **BROKEN** | `_resolve_tip_recipient` returns `None` for groups (`messaging.py:5613,5635`) → silently uncredited |
| Delegate `can_tip` guard | **PROD-ONLY** | `_delegate_guard_tip` default-deny in `ops/prod-hotfixes/delegate-rest/newblock_messaging.py.txt`; not in dev git |
| Tip + PPV-locked | correctly forbidden (keep) | `messaging.py:8145 raise 400 "Cannot combine lock_price_cents with tip_amount_cents"` |

---

## 2. Locked Decisions + Still-Open Defaults

### The 3 LOCKED decisions (reflected throughout this plan)

1. **PAY-TO-MESSAGE** — the required inbound tip is **normal creator earnings**: credited to the
   recipient like any tip, minus the 20% platform fee, and **NON-refundable** whether or not they reply.
   No hold, no reply-tracking. (Implemented via the existing attached-tip credit path.)
2. **GROUP TIPS** — credit the **single content author** (post author / message sender), **never split**
   among members. Fixes `_resolve_tip_recipient` returning `None` for groups by crediting the message author.
3. **TIP + PPV-LOCKED** — stays **mutually exclusive**; keep the existing `400` rejection
   (`messaging.py:8145`). Do NOT allow both.

### Still-open defaults (assume these unless the user overrides — see §7)

- **Amounts**: min `100` cents ($1), max `100_000` cents ($1000). (Message send DTOs already validate
  `ge=1, le=100_000`; broadcast uses `tip_min_cents=100`/`tip_max_cents=100000`, `broadcast.py:162-163`.)
  Proposed platform floor = **100** for consistency; allowlist per-surface presets `[100,500,1000]`
  (matches app `TipConfig`).
- **Tip visibility**: default **public** (tipper shown on the surface); a private/anonymous flag is a B5
  add-on (TIP-505).
- **Keep BOTH** standalone tip AND money-reaction — they coexist (money-reaction is a fast one-tap tip;
  standalone tip is amount-picker).
- **Tip-default PM**: **distinct** field `tip_default_payment_method_id`, falling back to the general
  default — so a user can route tips to a specific card without changing their subscription default.
- **Platform fee**: **20%** `fee_tips_bps` on ALL surfaces including pay-to-message (already the ledger default).
- **Delegate `can_tip`**: **default-DENY**; opt-in per delegate (prod convention, fold to git).

---

## 3. Target Architecture

### 3.1 ONE shared charge service — `app/services/tips.py`

```
charge_tip(*, tipper, recipient, amount_cents, currency, payment_method_id: str|None,
           content_type, content_id, meta: dict, idempotency_key: str,
           acting_delegate_id: str|None = None) -> TipResult
```

Responsibilities (each currently duplicated/absent, centralized here ONCE):

1. **Resolve PM** via fallback chain: explicit `payment_method_id` → user's
   `tip_default_payment_method_id` → `current_default_pm(user)` (`billing.py:779`) → else `400 no_payment_method`.
2. **Validate PM ownership ONCE** (the `PM#`-prefix scan currently copy-pasted in `send_message_tip`
   `messaging.py:13887`, `tip_post` `newsfeed.py:4734`, `unlock` `newsfeed.py:6195`). Dev blank-PM bypass
   preserved behind `S.dev_mode`.
3. **Delegate `can_tip` guard** in one place (the prod `_delegate_guard_tip`, default-deny → `403
   delegate_tip_forbidden`).
4. **REAL charge** via stripe-mock `PaymentIntent` (mirroring `billing.py:1095` `off_session=True,
   confirm=True`), **keyed by `idempotency_key`** so a retry never double-charges. Dev stub path when
   `STRIPE_API_BASE` unset.
5. **Transactional + idempotent** `write_tip_ledger` (keep the correct net credit); a prior receipt for
   the same `idempotency_key` returns the stored receipt instead of re-writing.
6. Return a **receipt** (`TipResult{tip_payment_id, charged_cents, net_cents, fee_cents, recipient,
   payment_intent_id, idempotent_replay: bool}`).

Every surface handler then shrinks to: **authz → resolve recipient → `charge_tip(...)` → increment the
surface's `tip_total_cents` → fan out SSE/notification.**

`content_type ∈ {message, post, comment, broadcast, video, message_react, post_react, video_comment}`
(extend the `tip_ledger.py:51` validation set + `_reason_for_content_type` map accordingly).

### 3.2 Default-tip-PM fallback chain

New per-user field `tip_default_payment_method_id` on the `USER#..#BILLING` row (co-located with
`default_payment_method_id`, `billing.py:781`). Resolution order inside `charge_tip`:
`explicit → tip_default → general default → 400`. Get/set endpoints mirror `set_default` (`billing.py:1015`).

### 3.3 Tip-reaction endpoints (NEW, distinct from emoji reactions)

Emoji reactions (`react_to_message` `messaging.py:11194`, `add_reaction` `newsfeed.py:4890`) stay
free/unchanged. Add **separate** money endpoints:
- `POST /messaging/conversations/{cid}/messages/{mid}/reactions/tip` → `charge_tip(content_type="message_react")`.
- `POST /ui/newsfeed/posts/{pid}/reactions/tip` → `charge_tip(content_type="post_react")`.

A tip-reaction is a fixed/preset-amount one-tap tip that also records a reaction glyph; it credits the
content author (locked #2) and increments `tip_total_cents` like any tip.

### 3.4 Pay-to-message gate model

New `MessagePrivacy` per-user record: `require_tip_to_message: bool`, `min_tip_cents: int`,
`tip_free_allowlist: [user_id]`. Enforced when a NON-allowlisted stranger opens/accepts a conversation:
- `find_or_create_dm` (`messaging.py:6123`) and `accept_conversation` (`:6158`) → if the target requires a
  tip and the initiator is not allowlisted and no tip is attached → **`402 tip_required`** (payload carries
  `min_tip_cents`).
- The **first message carries the tip** via the existing attached-tip path (`messaging.py:8128`), so it is
  credited as normal earnings (locked #1) — non-refundable, no hold. Allowlisted users + existing
  conversations bypass the gate.

### 3.5 Money-path risks to guard

- **Bug#3** — the credit MUST remain `type:"credit"` (`tip_ledger.py:169`). All new surfaces go THROUGH
  `write_tip_ledger`; none write their own ledger rows.
- **Idempotency** — every `charge_tip` call requires an `idempotency_key`; the stripe `idempotency_key` +
  a stored-receipt guard prevent double-charge on client retry (the message-send path already replays
  BEFORE billing side effects, `messaging.py:8066`).
- **No double-charge / orphan-credit** — charge and credit must be atomic-enough that we never (a) charge
  twice, or (b) charge then fail to credit (orphan). B5 adds a `TransactWriteItems` debit+credit and a
  reversal path for charged-but-not-credited.

---

## 4. Epics

- **B0 — Foundations.** Extract `app/services/tips.py charge_tip`; migrate the 6 existing call sites
  behavior-preservingly; add idempotency + single PM-check + `can_tip` guard; **fold** the prod video-tip
  endpoint + tip_ledger `"video"` + delegate `can_tip` into git.
- **B1 — Real charge + release enablement.** Real stripe-mock `PaymentIntent` inside `charge_tip`; fix the
  release `BillingAuthorizer` (AND-031); default tip PM; tip-as-message-attribute on the app (send DTOs +
  composer); fix the group recipient.
- **B2 — Tip reactions.** New money-reaction endpoints + app UI for messages and posts.
- **B3 — Comment-carrying tip + video parity.** Comment created WITH a tip; video-comment tip; add
  `payment_method_id` to comment `TipRequest`; group-post TipButton in the app.
- **B4 — Pay-to-message gate.** `MessagePrivacy` (`require_tip_to_message` + `min_tip_cents` +
  `tip_free_allowlist`); enforce on DM create/accept → `402`; first message carries the tip.
- **B5 — Hardening.** Transactional/idempotent ledger; reversal path for charged-but-not-credited;
  per-surface earnings/payout verification; unify feed vs broadcast tip composer; tip visibility flags.

---

## 5. Tickets

Effort key: **S** ≈ ≤0.5 day, **M** ≈ 1–2 days, **L** ≈ 3–5 days.

### EPIC B0 — Foundations

#### TIP-001 — Create `app/services/tips.py charge_tip` skeleton + `TipResult`
- **Type:** backend · **Effort:** M
- **Description:** New module wrapping `write_tip_ledger`. Define `charge_tip(**kw) -> TipResult`,
  the `TipResult` dataclass, and the `content_type` enum incl. the 4 new types. No behavior change yet
  (dev charge remains a stub inside the service); this is the seam every surface will call.
- **Acceptance:** `charge_tip` importable; validates `amount_cents>0` + `content_type` in the 8-value set;
  returns a `TipResult` with `tip_payment_id/charged_cents/net_cents/fee_cents/recipient`; unit test proves
  it calls `write_tip_ledger` with `type:"credit"` net.
- **Files/models:** NEW `app/services/tips.py`; reuse `tip_ledger.py`, `billing_config.split_fee`.
- **Deps:** none · **Verify:** `pytest` unit; assert ledger credit `type==credit`, net = gross−20%.

#### TIP-002 — Single PM-resolution + ownership helper with fallback chain
- **Type:** backend · **Effort:** S
- **Description:** `resolve_tip_payment_method(user, explicit_pm)` implementing explicit →
  `tip_default_payment_method_id` → `current_default_pm` → `400 no_payment_method`, plus the one shared
  `PM#`-ownership check (replacing the 3 copy-pasted scans). Preserve dev blank-PM bypass under `S.dev_mode`.
- **Acceptance:** returns a valid owned PM or raises `400`; rejects a PM not under `USER#{user}` with
  `400 payment_method_not_found`; dev blank PM allowed only when `S.dev_mode`.
- **Files/endpoints:** `app/services/tips.py`; reads `billing.py:779 current_default_pm`; the tip-default
  field (TIP-102 provides the writer; reader lands here).
- **Deps:** TIP-001 · **Verify:** unit + contract: tip with no PM but a set default → 200 on that default.

#### TIP-003 — Idempotency layer (no double-charge / stored-receipt replay)
- **Type:** backend · **Effort:** S
- **Description:** Require `idempotency_key` on `charge_tip`; persist a receipt keyed by it; on replay
  return the stored `TipResult` (`idempotent_replay=true`) without re-charging or re-crediting.
- **Acceptance:** two calls with the same key → one ledger debit+credit, one PaymentIntent, identical
  receipt; different keys → independent charges.
- **Files:** `app/services/tips.py` (+ a small idempotency record on `T.billing` or a dedicated key row).
- **Deps:** TIP-001 · **Verify:** unit: double-call asserts single credit.

#### TIP-004 — Centralize delegate `can_tip` guard in `charge_tip`
- **Type:** backend · **Effort:** S
- **Description:** Move `_delegate_guard_tip` (prod) into `charge_tip` via `acting_delegate_id`; default-DENY,
  `403 delegate_tip_forbidden` unless the delegate has `can_tip`.
- **Acceptance:** delegate without `can_tip` → 403 on every surface; with `can_tip` → 200; non-delegate
  path unaffected.
- **Files:** `app/services/tips.py`; source of truth `ops/prod-hotfixes/delegate-rest/newblock_messaging.py.txt`.
- **Deps:** TIP-001 · **Verify:** contract with a managed-creator token (see android-web-parity delegate).

#### TIP-005 — Migrate messaging ATTACHED-tip send paths to `charge_tip`
- **Type:** backend · **Effort:** M
- **Description:** Replace the inline mock + duplicated ledger writes in the text (`messaging.py:8094-8142`),
  image (`:8417-8442`), gallery (`:9032-9055`), and scheduled-delivery (`:13623-13638`) paths with a single
  `charge_tip(content_type="message")` call. Preserve: replay-before-billing (`:8066`), tip+lock 400
  (`:8145`), scheduled deferral (charge on delivery, not on schedule).
- **Acceptance:** attached-tip send still credits recipient net; scheduled tipped message charges on delivery
  only; cancelling a scheduled tipped message does not charge; behavior otherwise identical.
- **Files/endpoints:** `app/routers/messaging.py` send handlers + `_deliver_scheduled_message`.
- **Deps:** TIP-001,002,003,004 · **Verify:** contract: tip DM, recipient earnings +net.

#### TIP-006 — Migrate post-hoc `send_message_tip` to `charge_tip`
- **Type:** backend · **Effort:** S
- **Description:** Replace the inline PM scan + `tip_"+new_id()` mock + direct `write_tip_ledger` in
  `send_message_tip` (`messaging.py:13867-13945`) with `charge_tip(content_type="message")`; keep the
  `tip_amount_cents` accumulation on the message row, invoice, and `message:tip` fanout.
- **Acceptance:** endpoint contract unchanged (`TipOut`); PM validation now via shared helper; credit still net.
- **Files:** `app/routers/messaging.py`.
- **Deps:** TIP-001..004 · **Verify:** contract on `/messages/{id}/tip`.

#### TIP-007 — Migrate `tip_post` to `charge_tip` (drop PaymentProvider stub)
- **Type:** backend · **Effort:** S
- **Description:** Replace the `payments.create/confirm_payment_intent` stub calls (`newsfeed.py:4748-4756`)
  and the direct `write_tip_ledger` (`:4767`) with `charge_tip(content_type="post")`. Keep
  `tip_total_cents` increment, notification, social alert.
- **Acceptance:** `POST /posts/{id}/tip` still 200; own-post 400 preserved; credit net; no stub PaymentProvider used.
- **Files:** `app/routers/newsfeed.py`.
- **Deps:** TIP-001..004 · **Verify:** contract.

#### TIP-008 — Migrate `tip_comment` to `charge_tip`
- **Type:** backend · **Effort:** S
- **Description:** Replace stub + direct ledger in `tip_comment` (`newsfeed.py:5895-5960`) with
  `charge_tip(content_type="comment")`. (PM field added in TIP-301.)
- **Acceptance:** endpoint contract preserved; deleted-comment 409 preserved; credit net.
- **Files:** `app/routers/newsfeed.py`.
- **Deps:** TIP-001..004 · **Verify:** contract.

#### TIP-009 — Migrate broadcast `send_tip_message` to `charge_tip`
- **Type:** backend · **Effort:** S
- **Description:** Route `broadcast_tip_store.send_tip_message` (`broadcast_tip_store.py:90-149`) through
  `charge_tip(content_type="broadcast")` so broadcast tips ALSO get the real charge + idempotency (they
  currently credit with no charge). Keep rate-limit, tip goals, `chat:tip` SSE.
- **Acceptance:** broadcast tip now charges before crediting; rate-limit + goal progress unchanged.
- **Files:** `app/services/broadcast_tip_store.py`, `app/routers/broadcast.py:2036`.
- **Deps:** TIP-001..004 · **Verify:** contract on `/sessions/{id}/chat/tip`.

#### TIP-010 — Fold prod video-tip endpoint + tip_ledger `"video"` into git (dev clone)
- **Type:** infra/backend · **Effort:** M
- **Description:** Apply `ops/prod-hotfixes/app_routers_video_listing.py.patch` (adds `tip_video_endpoint`
  ~L895, `VideoTipIn/Out`, video reactions, `tip_total_cents`) and `app_services_tip_ledger.py.patch`
  (adds `"video"` to the validation set + reason map) into the dev clone so `content_type=video` no longer
  rejects and the endpoint exists in git.
- **Acceptance:** dev `POST /ui/videos/{id}/tip` reachable; `write_tip_ledger(content_type="video")` no
  longer raises; patch removed from the pending-fold list.
- **Files:** `app/routers/video_listing.py`, `app/services/tip_ledger.py`.
- **Deps:** TIP-001 · **Verify:** dev contract on the video tip endpoint.

#### TIP-011 — Migrate `tip_video_endpoint` to `charge_tip`
- **Type:** backend · **Effort:** S
- **Description:** After folding (TIP-010), replace the newsfeed-`payments` stub call inside
  `tip_video_endpoint` with `charge_tip(content_type="video")`. Keep the `tip_total_cents` accumulation on
  `video_metadata` + social hook.
- **Acceptance:** video tip charges for real; own-video 400 + unpublished 403 preserved; credit net.
- **Files:** `app/routers/video_listing.py`.
- **Deps:** TIP-010, TIP-001..004 · **Verify:** contract.

#### TIP-012 — Fold prod delegate `can_tip` guard into git
- **Type:** infra · **Effort:** S
- **Description:** Bring `_delegate_guard_tip` + the per-delegate `can_tip` permission
  (`ops/prod-hotfixes/delegate-rest/`) into git and route it through TIP-004.
- **Acceptance:** git dev clone denies delegate tips without `can_tip`; permission opt-in works.
- **Files:** `app/routers/messaging.py` (delegate block), delegate permissions store.
- **Deps:** TIP-004 · **Verify:** delegate contract.

#### TIP-013 — Behavior-preserving contract tests for all 6 migrated surfaces
- **Type:** test · **Effort:** M
- **Description:** Assert each migrated surface (message attached, post-hoc message, post, comment,
  broadcast, video) still credits the author net-of-20%, shows in `creator_earnings` + moves
  `get_available_balance`, and is idempotent under retry.
- **Acceptance:** 6 surfaces × {credit net, earnings visible, payout balance moves, idempotent} green.
- **Files:** tests only.
- **Deps:** TIP-005..011 · **Verify:** pytest + earnings/payout query.

### EPIC B1 — Real charge + release enablement + tip-on-send

#### TIP-101 — Real charge via stripe-mock PaymentIntent inside `charge_tip`
- **Type:** backend · **Effort:** M
- **Description:** Implement the real charge step in `charge_tip`, mirroring `billing.py:1095`
  (`stripe.PaymentIntent.create(off_session=True, confirm=True, idempotency_key=...)` against
  `STRIPE_API_BASE`). On non-`succeeded` → `402 payment_failed` and NO ledger write. Dev keeps a stub
  when stripe not configured.
- **Acceptance:** a tip creates a confirmed PaymentIntent, then credits; a declined intent → 402 + no
  credit; idempotency_key dedups at the processor.
- **Files:** `app/services/tips.py`; settings `stripe_*` (`settings.py:360`).
- **Deps:** TIP-001, TIP-003 · **Verify:** contract: check stripe-mock log; recipient credited only on success.

#### TIP-102 — `tip_default_payment_method_id` storage + get/set endpoints
- **Type:** backend · **Effort:** S
- **Description:** Add the field to the `USER#..#BILLING` row + `GET/PUT /ui/billing/tip-default`
  mirroring `set_default` (`billing.py:1015`); wire the reader into TIP-002's fallback chain.
- **Acceptance:** setting a tip-default routes tips to it when no explicit PM is given; clearing falls back
  to the general default.
- **Files:** `app/routers/billing.py`.
- **Deps:** TIP-002 · **Verify:** contract.

#### TIP-103 — Fix release `BillingAuthorizer` (AND-031)
- **Type:** app · **Effort:** M
- **Description:** Replace `StubBillingAuthorizer.NotConfigured` in release with a real authorizer backed
  by the PM picker (list PMs → user selects → return its `payment_method_id`). Keep the dev blank-PM path
  for debug. Rebind in `MessagingDataModule` (`:98`).
- **Acceptance:** in a **release** build, tipping a post/message/video shows a PM picker and POSTs a real
  `payment_method_id`; no faked charge; "no PM" routes to add-card.
- **Files:** `android/.../data/messaging/BillingAuthorizer.kt`, `MessagingDataModule.kt`, PM picker reuse
  from `feature/billing/PaymentMethodsScreen.kt`.
- **Deps:** TIP-101 (functional), TIP-102 · **Verify:** 2-device on a release APK.

#### TIP-104 — Default tip PM UI
- **Type:** app · **Effort:** S
- **Description:** Add "Use as tip default" to `PaymentMethodsScreen.kt`, calling TIP-102's endpoint.
- **Acceptance:** user can mark a card as the tip default; subsequent tips use it without a picker.
- **Files:** `feature/billing/PaymentMethodsScreen.kt` + billing repo.
- **Deps:** TIP-102, TIP-103 · **Verify:** on-device.

#### TIP-105 — Fix group attached-tip recipient (credit the message author)
- **Type:** backend · **Effort:** S
- **Description:** Change `_resolve_tip_recipient` (`messaging.py:5613`) so group conversations credit the
  MESSAGE AUTHOR instead of returning `None` (locked #2). DM behavior unchanged. Attached-tip paths then
  always credit.
- **Acceptance:** an attached tip on a group message credits the sender's author; DM still credits the
  other participant; no more silently-dropped group tips.
- **Files:** `app/routers/messaging.py`.
- **Deps:** TIP-005 · **Verify:** contract: group tip → author earnings +net.

#### TIP-106 — Tip-on-SEND from the app (send DTOs + composer)
- **Type:** app · **Effort:** M
- **Description:** Add `tip_amount_cents` + `tip_payment_method_id` to the app SEND request DTOs
  (`MessagingDtos.kt` send model ~L254, plus `ImageMessageDtos.kt`/`FileMessageDtos.kt`), and a tip
  affordance in the composer/`MessageActionsUi`/`ThreadScreen` that authorizes via `BillingAuthorizer`
  then sends. Backend already accepts these fields (`messaging.py:1872`).
- **Acceptance:** user attaches a tip when sending a message; recipient credited; tip+lock combination
  blocked client-side too.
- **Files:** `MessagingDtos.kt`, `ImageMessageDtos.kt`, `FileMessageDtos.kt`,
  `feature/messaging/thread/{MessageActionsUi,ThreadScreen,ThreadViewModel}.kt`.
- **Deps:** TIP-103, TIP-105 · **Verify:** 2-device send-with-tip.

#### TIP-107 — 2-device verification: real charge end-to-end
- **Type:** test · **Effort:** M
- **Description:** On both phones + a release APK: tip a post, a message (attached + post-hoc), a broadcast,
  and a video; confirm tipper is charged (stripe-mock), recipient earnings +net, payout balance moves.
- **Acceptance:** all 5 surfaces PASS on-device with a real `payment_method_id`.
- **Deps:** TIP-101..106 · **Verify:** 2-device (fleet + admin acct).

### EPIC B2 — Tip reactions (message + post)

#### TIP-201 — Message tip-reaction endpoint (`message_react`)
- **Type:** backend · **Effort:** M
- **Description:** `POST /messaging/conversations/{cid}/messages/{mid}/reactions/tip` → `charge_tip(
  content_type="message_react")`, crediting the message author (locked #2 for groups), recording a
  reaction glyph, incrementing `tip_amount_cents`, fanning a `reaction:tip` event. Distinct from
  `react_to_message` (`:11194`).
- **Acceptance:** tip-react credits net; own-message 400; emoji reaction path untouched.
- **Files:** `app/routers/messaging.py`.
- **Deps:** TIP-101 · **Verify:** contract.

#### TIP-202 — Post tip-reaction endpoint (`post_react`)
- **Type:** backend · **Effort:** M
- **Description:** `POST /ui/newsfeed/posts/{pid}/reactions/tip` → `charge_tip(content_type="post_react")`,
  credit post author, increment `tip_total_cents`, notify. Distinct from `add_reaction` (`:4890`).
- **Acceptance:** tip-react credits net; own-post 400; free emoji reactions unaffected.
- **Files:** `app/routers/newsfeed.py`.
- **Deps:** TIP-101 · **Verify:** contract.

#### TIP-203 — App: message tip-reaction UI
- **Type:** app · **Effort:** M
- **Description:** Add a money-reaction affordance to `MessageActionsUi`/`ThreadScreen` (preset amounts),
  authorizing via `BillingAuthorizer` then hitting TIP-201.
- **Acceptance:** long-press/react → "tip react" → charged + reaction shown.
- **Files:** `feature/messaging/thread/{MessageActionsUi,ThreadScreen,ThreadViewModel}.kt`.
- **Deps:** TIP-201, TIP-103 · **Verify:** 2-device.

#### TIP-204 — App: post tip-reaction UI
- **Type:** app · **Effort:** M
- **Description:** Add a money-reaction affordance to `PostActionBar`.
- **Acceptance:** react-with-tip on a feed post → charged + reaction shown.
- **Files:** `feature/feed/PostActionBar.kt` + feed VM.
- **Deps:** TIP-202, TIP-103 · **Verify:** 2-device.

#### TIP-205 — Earnings classification for `*_react` (and `video`, `video_comment`)
- **Type:** backend · **Effort:** S
- **Description:** Add `message_react/post_react/video/video_comment` to `classify_entry`'s tips allowlist
  (`creator_earnings.py:48`) so category breakdowns are exact (reason fallback already buckets them, but
  make it explicit).
- **Acceptance:** these credits report under the `tips` category in the earnings breakdown.
- **Files:** `app/services/creator_earnings.py`.
- **Deps:** TIP-201, TIP-202 · **Verify:** earnings breakdown unit.

#### TIP-206 — 2-device verification: tip reactions both surfaces
- **Type:** test · **Effort:** M
- **Deps:** TIP-201..205 · **Verify:** 2-device.

### EPIC B3 — Comment-carrying tip + video parity

#### TIP-301 — Add `payment_method_id` to comment `TipRequest`
- **Type:** backend · **Effort:** S
- **Description:** Add `payment_method_id: Optional[str]` to `TipRequest` (`newsfeed.py:1749`) so
  `tip_comment` can pass a real PM into `charge_tip`.
- **Acceptance:** comment tip accepts + validates a PM; blank/none falls back via TIP-002 chain.
- **Files:** `app/routers/newsfeed.py`.
- **Deps:** TIP-008 · **Verify:** contract.

#### TIP-302 — Comment-carrying tip (create comment WITH a tip)
- **Type:** backend · **Effort:** M
- **Description:** Add optional tip fields to `CreateCommentRequest` (`newsfeed.py:1658`); when present,
  the create-comment handler calls `charge_tip(content_type="comment")` atomically with the comment write.
- **Acceptance:** posting a comment with a tip creates the comment AND credits the post author net; failure
  to charge → no comment orphaned without its tip (or clearly separated — see OQ-4).
- **Files:** `app/routers/newsfeed.py`.
- **Deps:** TIP-101 · **Verify:** contract.

#### TIP-303 — Video-comment tip endpoint (`video_comment`)
- **Type:** backend · **Effort:** M
- **Description:** Add a video-comment tip endpoint (mirroring `tip_comment`) →
  `charge_tip(content_type="video_comment")`, crediting the comment author.
- **Acceptance:** tipping a video comment credits its author net; own-comment 400.
- **Files:** `app/routers/video_listing.py` / video comments router.
- **Deps:** TIP-010, TIP-101 · **Verify:** contract.

#### TIP-304 — App: comment-carrying tip UI
- **Type:** app · **Effort:** M
- **Description:** Comment composer "add a tip" in `CommentsViewModel`/comments UI (authorize → create with tip).
- **Files:** `feature/feed/CommentsViewModel.kt` + comments screen.
- **Deps:** TIP-302, TIP-103 · **Verify:** 2-device.

#### TIP-305 — App: video-comment tip UI
- **Type:** app · **Effort:** S
- **Files:** `data/videos/VideosApi.kt` + video detail comments UI.
- **Deps:** TIP-303, TIP-103 · **Verify:** 2-device.

#### TIP-306 — App: group-post TipButton in feed
- **Type:** app · **Effort:** S
- **Description:** Ensure the feed TipButton is present + wired for group/syndicate posts (parity with the
  main feed post tip).
- **Files:** `feature/feed/PostActionBar.kt` + group-feed screens.
- **Deps:** TIP-103 · **Verify:** on-device.

#### TIP-307 — Verification: comment/video-comment/group tips
- **Type:** test · **Effort:** M
- **Deps:** TIP-301..306 · **Verify:** contract + 2-device.

### EPIC B4 — Pay-to-message gate

#### TIP-401 — `MessagePrivacy` model + get/set endpoints
- **Type:** backend · **Effort:** M
- **Description:** Per-user record `{require_tip_to_message, min_tip_cents, tip_free_allowlist[]}` with
  `GET/PUT` endpoints.
- **Acceptance:** a user can enable pay-to-message with a min amount and an allowlist.
- **Files:** `app/routers/messaging.py` (+ a privacy store).
- **Deps:** none · **Verify:** contract.

#### TIP-402 — Enforce gate on DM create / accept → `402 tip_required`
- **Type:** backend · **Effort:** M
- **Description:** In `find_or_create_dm` (`messaging.py:6123`) and `accept_conversation` (`:6158`): if the
  target requires a tip, the initiator is not allowlisted, no existing conversation, and no tip attached →
  `402 {code:"tip_required", min_tip_cents}`. Allowlisted/existing convos bypass.
- **Acceptance:** stranger→gated user without a tip gets 402; allowlisted user bypasses; existing DM bypasses.
- **Files:** `app/routers/messaging.py`.
- **Deps:** TIP-401 · **Verify:** contract.

#### TIP-403 — First message carries the required tip (credited, non-refundable)
- **Type:** backend · **Effort:** M
- **Description:** Accept the gate by sending the first message WITH an attached tip (≥`min_tip_cents`)
  via the existing attached-tip path → `charge_tip(content_type="message")`, credited as normal earnings
  (locked #1), non-refundable, no hold. Conversation opens on success.
- **Acceptance:** first message + tip ≥ min opens the conversation and credits the recipient net; tip < min
  rejected; no refund logic.
- **Files:** `app/routers/messaging.py`.
- **Deps:** TIP-402, TIP-101, TIP-105 · **Verify:** contract.

#### TIP-404 — App: pay-to-message settings UI
- **Type:** app · **Effort:** M
- **Files:** messaging settings/privacy screen.
- **Deps:** TIP-401 · **Verify:** on-device.

#### TIP-405 — App: handle `402 tip_required` → prompt tip → send first message with tip
- **Type:** app · **Effort:** M
- **Description:** On 402, show the min-tip prompt, authorize via `BillingAuthorizer`, resend the first
  message with the attached tip.
- **Files:** messaging thread/new-DM flow + `ThreadViewModel`.
- **Deps:** TIP-403, TIP-103 · **Verify:** 2-device.

#### TIP-406 — 2-device verification: pay-to-message
- **Type:** test · **Effort:** M
- **Deps:** TIP-401..405 · **Verify:** 2-device (A gates, B pays to open).

### EPIC B5 — Hardening

#### TIP-501 — Transactional/idempotent ledger (TransactWriteItems)
- **Type:** backend · **Effort:** M
- **Description:** Make the debit+credit atomic (`TransactWriteItems`) so a partial write can't leave a
  debit without a credit; carry the idempotency guard into the transaction.
- **Acceptance:** injected failure between debit and credit leaves NO half-written pair; retry is a no-op.
- **Files:** `app/services/tip_ledger.py`, `app/services/tips.py`.
- **Deps:** TIP-101 · **Verify:** fault-injection unit.

#### TIP-502 — Reversal path for charged-but-not-credited (orphan handling)
- **Type:** backend · **Effort:** M
- **Description:** If the charge succeeds but the credit fails, either retry-to-completion or reverse the
  charge (PaymentIntent refund) + mark the credit `state:"reversed"`. Detection job for orphans.
- **Acceptance:** a charged-but-uncredited tip is reconciled (credited or refunded); no silent money loss.
- **Files:** `app/services/tips.py`, reconcile job (`billing_reconcile.py` pattern).
- **Deps:** TIP-501 · **Verify:** fault-injection + reconcile.

#### TIP-503 — Per-surface earnings/payout verification (all 8 content_types)
- **Type:** test · **Effort:** M
- **Description:** Golden test: each of the 8 `content_type`s produces a `type:"credit"` net entry that is
  (a) counted by `creator_earnings`, (b) moves `get_available_balance`, (c) buckets under `tips`.
- **Deps:** all surfaces · **Verify:** pytest.

#### TIP-504 — Unify feed vs broadcast tip composer (app)
- **Type:** app · **Effort:** M
- **Description:** Extract a single reusable tip composer/sheet (amount presets + PM + confirm) shared by
  feed, messaging, video, broadcast (`TipsGoalsPanel`), replacing the divergent per-surface UIs.
- **Files:** new `feature/common/tip/*` + call sites.
- **Deps:** B2, B3 · **Verify:** on-device parity across surfaces.

#### TIP-505 — Tip visibility flags (public/private) on all surfaces
- **Type:** backend · **Effort:** S
- **Description:** Optional `visibility: public|private` on tips; private tips hide the tipper identity on
  the surface but still credit + notify.
- **Files:** `app/services/tips.py` + surface fanout payloads.
- **Deps:** TIP-101 · **Verify:** contract.

#### TIP-506 — Money-path guard test (Bug#3 + no double-charge/orphan)
- **Type:** test/backend · **Effort:** S
- **Description:** Assert across all surfaces: credit entry_type is exactly `"credit"` (Bug#3 regression
  guard) and that a retried tip neither double-charges nor orphans a credit.
- **Deps:** TIP-501 · **Verify:** pytest.

---

## 6. Execution Sequence + Summary Table

**Dependency-ordered:** B0 (TIP-001 → 002/003/004 → migrations 005–009, fold 010/012 → 011 → 013) →
B1 (101 → 102 → 103/104, 105 → 106 → 107) → B2 (201/202 → 203/204, 205 → 206) →
B3 (301 → 302/303 → 304/305/306 → 307) → B4 (401 → 402 → 403 → 404/405 → 406) →
B5 (501 → 502, 503/504/505/506). B2/B3/B4 are largely parallelizable once B1's `charge_tip` real charge
(TIP-101) + release authorizer (TIP-103) land.

| Ticket | Epic | Type | Effort | Deps |
|---|---|---|---|---|
| TIP-001 | B0 | backend | M | — |
| TIP-002 | B0 | backend | S | 001 |
| TIP-003 | B0 | backend | S | 001 |
| TIP-004 | B0 | backend | S | 001 |
| TIP-005 | B0 | backend | M | 001-004 |
| TIP-006 | B0 | backend | S | 001-004 |
| TIP-007 | B0 | backend | S | 001-004 |
| TIP-008 | B0 | backend | S | 001-004 |
| TIP-009 | B0 | backend | S | 001-004 |
| TIP-010 | B0 | infra | M | 001 |
| TIP-011 | B0 | backend | S | 010,001-004 |
| TIP-012 | B0 | infra | S | 004 |
| TIP-013 | B0 | test | M | 005-011 |
| TIP-101 | B1 | backend | M | 001,003 |
| TIP-102 | B1 | backend | S | 002 |
| TIP-103 | B1 | app | M | 101,102 |
| TIP-104 | B1 | app | S | 102,103 |
| TIP-105 | B1 | backend | S | 005 |
| TIP-106 | B1 | app | M | 103,105 |
| TIP-107 | B1 | test | M | 101-106 |
| TIP-201 | B2 | backend | M | 101 |
| TIP-202 | B2 | backend | M | 101 |
| TIP-203 | B2 | app | M | 201,103 |
| TIP-204 | B2 | app | M | 202,103 |
| TIP-205 | B2 | backend | S | 201,202 |
| TIP-206 | B2 | test | M | 201-205 |
| TIP-301 | B3 | backend | S | 008 |
| TIP-302 | B3 | backend | M | 101 |
| TIP-303 | B3 | backend | M | 010,101 |
| TIP-304 | B3 | app | M | 302,103 |
| TIP-305 | B3 | app | S | 303,103 |
| TIP-306 | B3 | app | S | 103 |
| TIP-307 | B3 | test | M | 301-306 |
| TIP-401 | B4 | backend | M | — |
| TIP-402 | B4 | backend | M | 401 |
| TIP-403 | B4 | backend | M | 402,101,105 |
| TIP-404 | B4 | app | M | 401 |
| TIP-405 | B4 | app | M | 403,103 |
| TIP-406 | B4 | test | M | 401-405 |
| TIP-501 | B5 | backend | M | 101 |
| TIP-502 | B5 | backend | M | 501 |
| TIP-503 | B5 | test | M | all |
| TIP-504 | B5 | app | M | B2,B3 |
| TIP-505 | B5 | backend | S | 101 |
| TIP-506 | B5 | test | S | 501 |

**Totals:** 45 tickets. Rough roll-up: **S ≈ 18**, **M ≈ 27**, **L = 0** (no single ticket is L; the L-scale
work is the epics as wholes). Approx effort ≈ 18×0.4 + 27×1.5 ≈ **~47 engineer-days** (~9–10 engineer-weeks),
backend-heavy in B0/B1, app-heavy in B2–B4. B0+B1 (the money-correctness core) ≈ 20 tickets / ~18 days.

---

## 7. Open Questions (resolve before/at build)

1. **Min/max + presets** — confirm platform floor (proposed 100¢) and per-surface presets `[100,500,1000]`.
2. **Tip-react amount** — fixed single amount, or a mini amount-picker? (Proposed: preset chips.)
3. **Tip visibility default** — public vs private-by-default (proposed public; private is TIP-505 opt-in).
4. **Comment-carrying tip atomicity** — if the charge fails, do we still post the comment (tip-less) or
   reject the whole action? (Proposed: reject, so intent is preserved.)
5. **Pay-to-message allowlist semantics** — is a prior conversation an implicit allowlist? mutual-follow?
   (Proposed: existing conversation + explicit allowlist bypass; follows do not.)
6. **Pay-to-message + group** — gate DMs only, or also group invites? (Proposed: DMs only for v1.)
7. **Idempotency key source** — client-supplied header vs server-derived from `(user, content_id, amount,
   window)`. (Proposed: client `X-Idempotency-Key` with a server fallback, matching ecom checkout.)
8. **Delegate `can_tip` for pay-to-message** — can a delegate pay to open a DM as the creator? (Proposed:
   yes only with `can_tip`, since it spends the creator's money.)
9. **Refunds** — pay-to-message is locked non-refundable, but should *ordinary* tips ever be refundable
   (mistap)? (Proposed: no user refund; admin-only reversal via TIP-502.)
10. **Prod parity** — video-tip + delegate `can_tip` are prod hotfixes; confirm folding them into git
    (TIP-010/012) won't collide with the divergent prod source (re-apply artifact per android-web-parity).
