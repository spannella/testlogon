# Tipping Subsystem — Rough-Edges Audit & Smoothing Plan (TIPX-*)

Audit target: `android-impl` @ HEAD `af2c0fb9` (== main after #194). Read-only audit of the shipped
TIP-B0..B5 unification program (single `charge_tip` rail, real charge + default tip PM,
tip-as-message-attribute, tip reactions, comment/video/video-comment tips, pay-to-message gate +
tip-free allowlist, hardening). This document is the ONLY write from the audit.

Conventions respected (not re-litigated): reversal writes `type != "credit"` so earnings are not
inflated; stripe-mock accept-under-mock, real `CardError` -> 402.

---

## 1. HEADLINE VERDICT

**Tipping is a genuinely real, money-correct CORE wrapped in a rough, under-finished shell.** The
central rail — `app/services/tips.py:262` `charge_tip` — is solid: atomic `TransactWriteItems`
(debit + credit + idempotency receipt), a real stripe-mock PaymentIntent that 402s *before* any
ledger write (no free tip on decline), default-DENY delegate guard, self-tip 400, PM-ownership
validation, and correct 20% fee-net crediting. `reverse_tip` is itself money-correct. So the
foundation is not a simulation — it moves real money correctly on the happy path.

The roughness is everything *around* the rail: per-surface call sites that diverge from the gold
path, measurement that reports three disagreeing totals, and a notification layer that is wired to
the wrong tables. **This is a polished core with rough edges, NOT a fake core.** Completeness
estimate: tipper happy-path ~80% (feed/video/DM excellent; comment/broadcast/profile rough);
creator reconcile-and-recognize path ~50% (real earnings exist but totals disagree and the app has
no top-supporter/tip-history surface at all); notifications ~30% (most tip surfaces notify to a
store the app never reads, or don't notify at all).

### The 5 load-bearing rough edges (fix these and tipping goes from "rough" to "trustworthy")

1. **Collaboration-content tips leak the platform fee and are non-atomic (P0).**
   `collaboration_splits.py:70` writes `type:"credit"` for the **full gross** `share_cents` with **no
   `split_fee`**, via swallow-on-fail `put_item`s — so tipping collab content pays creators 100%
   (platform collects $0 fee) and can half-write (credit collaborators without debiting the payer).
   The one place the rail is bypassed is the one place money is wrong.

2. **Idempotency is defeated on 6 of 9 surfaces — a double-tap / retry double-charges (P1).**
   post/comment/comment-carry/post-react/message-react/post-hoc-message/video/video-comment tips all
   mint a **fresh** idempotency key per request, so `charge_tip`'s replay short-circuit and the
   Stripe idempotency key never dedupe. With no reachable refund path, a double-charge is permanent.

3. **The reversal/refund engine has ZERO production callers (P1).** `reverse_tip` (tips.py:482) is
   fully built and correct but wired to nothing — no admin route, no dispute hook, no UI. Every money
   bug above (orphan totals, phantom tips, double-charges, gate mischarges) is therefore
   **uncorrectable in-product**; creator earnings can only ever go up.

4. **Creators see three "tips received" totals that don't reconcile; the biggest is the wrongest
   (P1).** Ledger earnings (fee-net, all 8 surfaces, reversed-excluded) vs leaderboard (fee-net, all
   surfaces, reversed NOT excluded) vs the web **TipsFeed** alert-stream total — which is **GROSS**
   (over-reports by the 20% fee), covers only **2 of 8** surfaces, truncates at 1000 alerts, and
   labels itself **"Total Earned."** Video/broadcast/comment-heavy creators see near-zero.

5. **Tip notifications are wired to three different stores/vocabularies and none is correct
   end-to-end on mobile (P1).** `put_notification` (post/comment tips) writes to a table the app's
   Notification Center never queries; `record_social_interaction` (video tips) lands as an amountless
   `TIP` that the app resolves to `Unknown` (dead-links); the well-formed `emit_social_alert`s
   (post/post-react/message) are ignored because `AlertsScreen` has **no tip dispatch branch**.
   Comment tips are fully silent; money-reaction tips only fire an ephemeral in-thread SSE.

---

## 2. PRIORITIZED PUNCH-LIST (deduped, merged across dimensions)

Effort key: S = <0.5d, M = 0.5-2d, L = >2d. Overlapping findings from multiple dimensions are
merged into one row and cross-referenced.

### A. MONEY-CORRECTNESS (fix first — real money is wrong/uncorrectable)

| # | Rough edge | Sev | Tipper impact | Creator impact | Fix-shape | Effort |
|---|---|---|---|---|---|---|
| M1 | Collab tips pay 100% (no `split_fee`), non-atomic best-effort `put_item`s (`collaboration_splits.py:63-90`, bypass at `tips.py:395`) | **P0** | Charged gross either way | Over-credited vs solo; platform loses 20% fee; partial-write risk | Split the NET via `split_fee("tip_debit",…)`, retain fee; make collaborator credits + payer debit one `TransactWriteItems` mirroring TIP-501 | L |
| M2 | Idempotency defeated on 6/9 surfaces — fresh key per request (`newsfeed.py:5070/5277/6313/6716`, `messaging.py:12192/15189`, `video_listing.py:869/949`) | **P1** | Double-tap / retry double-charges | Double-credited; no unwind | Accept client `Idempotency-Key`/`client_request_id`, thread into `charge_tip` so a retry replays the receipt | M |
| M3 | Reversal/refund path unreachable — `reverse_tip` has zero callers (`tips.py:482`) | **P1** | Wrong/double/disputed charge is permanent | Earnings can only go up; no safety net | Wire `reverse_tip` to an admin/internal refund route + a "charged-but-not-delivered" reconcile job | M |
| M4 | `tip_post` bumps `tip_total_cents` BEFORE charge -> orphan total on 402 (`newsfeed.py:5050` bump vs `:5060` charge) | **P1** | Billed nothing | Fake inflated post total, no ledger | Move `charge_tip` above the `ddb_update_item` bump (as video already does) | S |
| M5 | `send_message_tip` (post-hoc) bumps `tip_amount_cents` + stamps `tip_payment_id` BEFORE charge -> phantom tip on 402 (`messaging.py:15155-15173`) | **P1** | Sees a tip that never happened | Sees a tip badge + payment id, no money | Charge first, then update the row | S |
| M6 | Own-comment tip skips charge but still stamps total + returns `succeeded` (`newsfeed.py:6707` guarded charge / `:6720` unconditional bump) | **P1** | — | Can self-inflate comment tip totals for free; ledger mismatch | Raise 400 `cannot_tip_self` when `comment_author == tipper_id` (match message/video path) | S |
| M7 | No server-side max cap on post/comment/message/video/reaction tips (`ge=1` only) | P2 | $50k fat-finger chargeable at real PI, no reversal | — | Shared config-driven max enforced inside `charge_tip` (mirror `broadcast_tip_max_cents`) | S |
| M8 | Gate/attached tip charges BEFORE `put_item` -> charged-but-not-delivered (`messaging.py:8931` charge vs `~9048` put) | P2 | Pays gate, message lost | Keeps the money | Persist first (or same txn), charge after; on charge-fail roll back; on put-fail after charge enqueue `reverse_tip` (needs M3) | M |
| M9 | Scheduled tipped message drops charge for groups/changed participants but still renders tip (`messaging.py:14859` `_resolve_tip_recipient` returns None) | P2 | Free phantom tip render | Tip badge, never paid | Persist resolved `tip_recipient_id` at schedule time; if unresolvable, fail visibly not phantom-stamp | M |
| M10 | Gate charge folded into creator "tips" bucket (`creator_earnings.py:48` classifies `content_type=="message"` as tips) | P2 | — | Forced pay-to-DM fees mixed with voluntary tips; can't separate | Tag gate charges `meta.tip_kind="message_gate"`, classify into own bucket | S |

### B. FLOW / UX (tipper flow — smooth after money is safe)

| # | Rough edge | Sev | Tipper impact | Fix-shape | Effort |
|---|---|---|---|---|---|
| F1 | Broadcast tipping dead in debug/dev builds — blank dev PM -> "payments unavailable" (`TipsGoalsViewModel.kt:137`) | **P1**(dev) | Live-broadcast tip 100% fails in the demo/test build | Treat `Authorized` (blank or not) as go, or gate the blank->unavailable on `!BuildConfig.DEBUG` | S |
| F2 | Comment tip sheets are hand-rolled, preset-only, **one-tap-charges**, no custom amount / no confirmation (`CommentsSection.kt:862`, `VideoCommentsSection.kt:602`) | P2 (P1 for accidental one-tap charge) | Mis-tap charges instantly; can't tip custom amount; no receipt | Replace both bodies with shared `TipComposerContent` (custom amount + explicit Send + confirm) | M |
| F3 | No in-flow "add a card" path anywhere — empty wallet dead-ends on a "payments unavailable" snackbar despite `RealBillingAuthorizer` KDoc claiming it routes to add-card (`:56`) | P2 | New user who wants to tip hard-stops, misleading copy | On `NotConfigured`, actionable error + button deep-linking to add-card, re-open sheet on return | M |
| F4 | Pay-to-message gate has no in-app recovery on DM-open / image / encrypted-first send — only text-send 402 routes to the tip prompt (`ThreadViewModel.kt:680`) | P2 | Raw failure, can't tell they must pay | Route `find_or_create_dm` + image/gallery/encrypted first-send 402s into `TipRequiredPromptState` | M |
| F5 | Inconsistent public/private visibility toggle — present post/group/video, absent DM + both comment sheets (`PaidMessageUi.kt:839`) | P3 | Can't choose private tip on comment/DM; always public-attributed | Pass `visibility`/`onVisibility` into DM composer; add toggle when comment sheets adopt shared composer (F2) | S |
| F6 | DM tip success is a transient snackbar, not the in-sheet amount receipt shown on feed/video (`ThreadViewModel.kt:2474`) | P3 | Never sees how much charged in-sheet; snackbar missable | Give DM tip sheet a Confirmed state (amount + checkmark) or put amount in snackbar copy | S |
| F7 | Own-comment tip hidden via `!comment.canDelete` proxy -> mods/admins lose the button on others' comments (`CommentsSection.kt:444`) | P3 | Privileged users can't tip others' comments | Gate on real authorship (viewer sub == author) not `canDelete` | S |
| F8 | Confirmed tip sheet has no explicit Done/close, no auto-dismiss (`TipSheet.kt:125`) | P3 | Momentary "what now?"; scrim works but non-obvious | Add Done button or short auto-dismiss to `TipConfirmedBody` | S |
| F9 | Web comment tip sends no `payment_method_id` — always default PM (`newsfeed.ts:102`, also misnamed `tipPost`) | P3 | Web: charged on wrong/default card silently | Thread `payment_method_id` through; rename `tipPost`->`tipComment` | S |
| F10 | Tip response exposes no per-tip receipt (gross/net/fee) — most endpoints echo only running total (`newsfeed.py:6741`, `video_listing.py:895`) | P3 | No charge confirmation/receipt; no fee visibility | Return `TipResult` fields (`charged_cents`, `net_cents`, `fee_cents`, `tip_payment_id`) in each body | S |

### C. COVERAGE (tip surfaces that half-exist)

| # | Rough edge | Sev | Impact | Fix-shape | Effort |
|---|---|---|---|---|---|
| C1 | Post-level `tip_total_cents` charged but never rendered on the feed (`PostActionBar.kt:183` shows only reaction chips) | **P1** | Tipper: post looks identical after tipping. Creator: can't see aggregate direct-tip support | Render `post.tipTotalCents` badge in `PostActionBar` (feed + detail), mirror comment "Tipped $X" | S |
| C2 | No standalone profile/creator tip surface — tipping is per-content only (no `/profile/{id}/tip`, no `profile` in `TIP_CONTENT_TYPES` tips.py:60) | P2 | Most natural intent ("support the person") dead-ends | Add `POST /ui/profile/{id}/tip` + new `profile` content type + render surface | M |
| C3 | Pay-to-message gate creates a dangling empty conversation then 402s (`messaging.py:6755` `start_conversation` before gate check) | P2 | Confusing two-step; gated inbox pollutes with empty convos | Evaluate gate BEFORE `start_conversation` (no side effect), or roll back on 402 | S |
| C4 | Scheduled tipped-message delivery renders tip even if delivery-time charge fails (`messaging.py:14840` put before `:14853` charge; scheduler swallows) | P3 | Half-delivered tip-stamped-but-uncharged message; fanout may not fire | Charge before re-key/put; on 402 strip tip fields or leave scheduled | M |

### D. MEASUREMENT (creator reconcile)

| # | Rough edge | Sev | Creator impact | Fix-shape | Effort |
|---|---|---|---|---|---|
| D1 | Three disagreeing "tips received" totals; **TipsFeed** is GROSS + only post/message + capped 1000, labeled "Total Earned" (`alerts.py:645/659/663`, `TipsFeed.tsx:41`) | **P1** | Over-reports by 20% fee; drops 6/8 surfaces; the biggest number is the wrongest | Retire the alert-stream total; back `TipsFeed` (and leaderboard) with the ledger; report fee-net | M |
| D2 | Leaderboard counts reversed tips — missing `state != reversed` (`tip_leaderboard.py:66`) vs earnings which excludes everywhere | P1 (latent until M3 ships) | Refunded whale stays #1; disagrees with earnings | Add `& Attr("state").ne("reversed")` to the leaderboard filter | S |
| D3 | App has NO tip-history / top-supporters / tips-summary screen (web has both) | P2 | Mobile creator can't recognize/thank top tippers; no drill-down | Add app screen backed by `GET /ui/creators/{me}/top-supporters` + ledger tip transactions | M |
| D4 | No tipper-side tip history or receipt anywhere (debit rows exist but no `type=="debit"` query/endpoint/screen) | P2 | Tipper: zero spend visibility, no receipts, can't reconcile | Add `GET /ui/tips/sent` (tipper's `debit` + `reason begins_with "Tip"`) + "Tips sent" list | M |
| D5 | `alerts/tips-summary` truncates at last 1000 alerts, not a time window (`alerts.py:663`) | P3 | High-activity creators' tip total silently drifts down | Paginate to period cutoff, or (preferred) back with ledger (subsumed by D1) | S |
| D6 | `pending_payout_cents` hard-coded 0 in quick-stats (`creator_earnings.py` `# populated after MON-004`) | P3 | Misleading always-$0 payout tile next to tip numbers | Wire MON-004 or hide the tile until real | S |

### E. NOTIFICATIONS

| # | Rough edge | Sev | Impact | Fix-shape | Effort |
|---|---|---|---|---|---|
| N1 | Comment/post tips notify via `put_notification` to the main table the app's Notification Center never reads; token `tip_on_*` also resolves to `UNKNOWN` (`newsfeed.py:6727/5099`, `NotificationDomain.kt:15`) | **P1** | Comment tip fully silent on mobile (no bell either — no `emit_social_alert`) | Route through the engine table the app reads + normalize `tip_*`->`TIP`; add comment-tip social alert | M |
| N2 | Video / video-comment tips fire no bell alert + amountless + dead-link (`video_listing.py:886/955` only `record_social_interaction`; `TIP`->`Unknown` target) | **P1** | Creator can't see amount/source; tapping goes nowhere; no bell | Add `emit_social_alert(alert_type="video_tip", action_url, amount)`; give TIP resolver a target from `data.video_id` | M |
| N3 | `AlertsScreen` has no tip dispatch branch — well-formed post/message tip alerts dead-link (`AlertsScreen.kt:358`) | **P1** | Every tip bell alert only marks read, navigates nowhere | Add `isTipAlert(event)` + parse `action_url` -> open post/thread | S |
| N4 | Money-reaction (message tip-react) fires only ephemeral in-thread SSE — no persistent notification (`messaging.py:12183`) | P2 | Paid emoji reactions vanish unless creator is live in the thread | Mirror post-react: `emit_social_alert(alert_type="message_tip", action_url, emoji, amount)` | S |
| N5 | Attached-tip (tip on a sent message) fires no distinct tip notification (`messaging.py:8931/9244/9870`, scheduled 14854) | P2 | Attached tips blend into normal message noise | On immediate + scheduled delivery, after attached charge emit `message_tip` alert | S |
| N6 | No tipper-side receipt notification on any surface (only an internal `audit_event`) | P2 | Tipper has no durable proof-of-tip | In `charge_tip` (single choke point) emit tipper-side `tip_sent` notification | S |
| N7 | Pay-to-message gate: no "paid message received" signal + no sender delivery confirmation | P2 | Creator can't prioritize paid DMs; sender paid with no ack | Tag recipient alert `paid_message` (amount); return `gate_satisfied` flag to sender | M |
| N8 | Tip reversal/refund notifies neither party (`reverse_tip` emits nothing) | P2 (P1 once M3 ships) | Creator earnings drop unexplained; tipper not told refund landed | In `reverse_tip` emit `tip_reversed` (creator) + `tip_refunded` (tipper) | S |
| N9 | post_tip and post-react tip share one `batch_key` `tip:{post_id}` -> distinct payments collapse (`social_alerts.py:49`) | P3 | Under-counts distinct tip events in the bell feed | Include txn in key (`tip:{post_id}:{tip_payment_id}`) or surface aggregate total in batched copy | S |

**Cross-cutting notification root cause:** three notification vocabularies/stores are in play
(`put_notification`/main table, `send_notification`/notifications_engine, `emit_social_alert`/alerts)
and no tip surface is correctly wired end-to-end through any single one on mobile. A single
`notify_tip(recipient, tipper, amount, surface, action_url)` helper called from `charge_tip` collapses
N1/N2/N4/N5/N6.

---

## 3. TICKETED PLAN (TIPX-*)

Dependency-ordered epics, money-correctness first. Style mirrors the moderation/advertising/
subscriptions plans. Each ticket: scope + acceptance criteria.

### EPIC TIPX-A — Money-correctness & the reversal safety net (do first)

- **TIPX-A1 — Charge-before-side-effect everywhere** (M4, M5, M6). Move the `charge_tip` call above
  every public-total bump / row stamp on `tip_post` and post-hoc `send_message_tip`; add
  `cannot_tip_self` 400 to `tip_comment`.
  *AC:* a forced 402 on post/post-hoc-message/own-comment leaves NO `tip_total_cents`/
  `tip_amount_cents`/`tip_payment_id` mutation and NO ledger row; own-comment tip returns 400, not a
  fake `succeeded`. Regression test per surface asserting order.
- **TIPX-A2 — Wire the reversal/refund path** (M3, prerequisite for M8 rollback + N8). Add an
  admin/internal `POST /internal/tips/{tip_payment_id}/reverse` (+ a "charged-but-not-delivered"
  reconcile hook) calling `reverse_tip`.
  *AC:* reversal writes `type:"reversal"`+`"refund"` (never `credit`), flips original credit to
  `state:"reversed"`, is idempotent (`TIPREVERSAL#`), best-effort Stripe refund with `tiprev:` idem;
  a reversed tip disappears from earnings summary AND leaderboard (see TIPX-D2).
- **TIPX-A3 — Idempotency keys accept client request id** (M2). Every tip endpoint accepts a client
  `Idempotency-Key`/`client_request_id`, threaded into `charge_tip` as the idempotency key.
  *AC:* replaying the same request id returns the SAME receipt with no second Stripe charge and no
  second ledger row; app clients send a stable id per tip action. Covers post/comment/comment-carry/
  post-react/message-react/post-hoc-message/video/video-comment.
- **TIPX-A4 — Collaboration-split tip: fee + atomicity** (M1, P0). Route collab tips through
  `split_fee("tip_debit", …)` (split the NET, retain platform fee) and make collaborator credits +
  payer debit a single `TransactWriteItems`.
  *AC:* tipping collab content deducts the same 20% fee as solo; no partial write possible; collab
  and solo tips reconcile to the same net formula.
- **TIPX-A5 — Shared max cap + gate charge classification** (M7, M10). Enforce a config-driven max in
  `charge_tip`; tag gate charges `meta.tip_kind="message_gate"` and classify into their own bucket.
  *AC:* an over-cap tip is 400 on every surface; gate revenue reports separately from voluntary tips
  in `creator_earnings`.
- **TIPX-A6 — Deliver-then-charge for gate/attached + scheduled** (M8, M9, C3, C4). Persist message
  first / evaluate gate before `start_conversation`; on charge-fail roll back or enqueue reversal
  (needs TIPX-A2); persist resolved `tip_recipient_id` at schedule time.
  *AC:* no charged-but-undelivered message; no dangling empty gated convo; scheduled group tip either
  resolves a real recipient or fails visibly (no phantom badge).

### EPIC TIPX-B — Tipper flow / UX (after money is safe)

- **TIPX-B1 — Unblock broadcast tipping in dev** (F1). *AC:* debug build completes a broadcast tip
  end-to-end; no false "payments unavailable".
- **TIPX-B2 — Comment tip sheets adopt the shared composer** (F2, F5, F6). Replace both hand-rolled
  preset-only sheets with `TipComposerContent` (custom amount, explicit Send, error, confirmation,
  visibility toggle); give DM tip an in-sheet Confirmed state. *AC:* no one-tap accidental charge;
  custom amount + private-tip available on comment/DM; in-sheet amount receipt shown.
- **TIPX-B3 — In-flow add-card + gate recovery** (F3, F4). `NotConfigured` shows an actionable
  add-card button that re-opens the sheet; route DM-open/image/encrypted first-send gate-402s into
  `TipRequiredPromptState`. *AC:* empty-wallet tipper can add a card and complete without leaving the
  flow; every gate 402 surfaces the tip prompt.
- **TIPX-B4 — Small consistency fixes** (F7, F8, F9, F10). Authorship-based own-comment hiding; Done
  button on Confirmed; web comment tip carries `payment_method_id` (+ rename); return `TipResult`
  receipt fields. *AC:* mods can tip others' comments; explicit close; web honors chosen PM; response
  includes charged/net/fee.

### EPIC TIPX-C — Coverage gaps

- **TIPX-C1 — Render post tip total** (C1). *AC:* a post's `tipTotalCents` shows as a badge on feed +
  detail for both parties.
- **TIPX-C2 — Profile/creator direct tip surface** (C2). Add `profile` to `TIP_CONTENT_TYPES`,
  `POST /ui/profile/{id}/tip`, and a "Tip this creator" affordance on the profile. *AC:* a fan can
  tip a creator with no specific content open; charge routes through `charge_tip`.

### EPIC TIPX-D — Measurement / reconciliation

- **TIPX-D1 — One ledger-backed tip total** (D1, D5). Retire the alert-stream total; back web
  `TipsFeed` (and the leaderboard) with the ledger, fee-net, all 8 surfaces, relabel gross vs net.
  *AC:* TipsFeed total == earnings-summary tips bucket == leaderboard total for the same creator.
- **TIPX-D2 — Leaderboard excludes reversed** (D2). Add `& Attr("state").ne("reversed")`. *AC:* a
  reversed tip drops from top-supporters (must land with/before TIPX-A2).
- **TIPX-D3 — App creator tip-measurement screen** (D3). Backed by `top-supporters` + ledger tip
  transactions. *AC:* mobile creator sees top tippers + tip history reconciling to earnings.
- **TIPX-D4 — Tipper-sent history + receipts** (D4, F10). `GET /ui/tips/sent` + "Tips sent" list on
  web/app. *AC:* a tipper sees every tip they've sent with amount/recipient/date.
- **TIPX-D5 — Wire or hide pending payout** (D6). *AC:* pending-payout tile shows a real value or is
  hidden.

### EPIC TIPX-E — Notifications (single choke point + client dispatch)

- **TIPX-E1 — `notify_tip` helper in `charge_tip`** (N1, N2, N4, N5, N6). One helper emits a
  recipient alert (correct engine store, amount, `action_url`) AND a tipper `tip_sent` receipt, from
  the single choke point; back-fill video/video-comment/message-react/attached surfaces. *AC:* every
  successful tip produces one recipient notification (with amount + deep-link) and one tipper receipt,
  in the store the app reads.
- **TIPX-E2 — Client tip dispatch + token normalization** (N1, N2, N3). `AlertsScreen` `isTipAlert`
  dispatch; `NotificationDomain.fromToken` normalizes `tip_*`->`TIP`; TIP resolver derives a real
  target. *AC:* tapping any tip alert/notification opens the tipped post/thread/video.
- **TIPX-E3 — Gate + reversal notifications** (N7, N8). `paid_message` recipient alert + sender
  `gate_satisfied`; `tip_reversed`/`tip_refunded` on reversal (needs TIPX-A2). *AC:* creator sees paid
  DMs flagged; both parties notified on reversal.
- **TIPX-E4 — Batch-key de-collision** (N9). *AC:* two distinct tips on the same post appear as
  distinct (or the batched alert shows an aggregate total).

---

## Recommended build sequence

1. **TIPX-A (money-correctness) first** — A1/A2/A3 immediately (A2 unblocks A6/E3/D2), then A4 (P0
   fee leak), A5, A6. Nothing else ships until a wrong charge is *correctable* and retries don't
   double-charge.
2. **TIPX-B (tipper flow)** — B1 (dev unblock, tiny) then B2/B3/B4, so the tipper path is consistent
   and self-serve.
3. **TIPX-C (coverage)** — C1 (render post total, trivial), then C2 (profile tip).
4. **TIPX-D (measurement)** — D2 lands with A2; then D1 (one true total), D3/D4, D5.
5. **TIPX-E (notifications)** — E1 (choke-point helper) + E2 (client dispatch) together make tips
   visible on mobile; E3 depends on A2; E4 last.

Rationale: money-correctness is a live-money integrity issue and gates the reversal-dependent work;
tipper flow is the highest-traffic UX; coverage and measurement make the creator side trustworthy;
notifications are last because they layer on top of correct charges + correct action_urls.
