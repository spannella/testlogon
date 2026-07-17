# TIPX-B — Tipper flow / UX (app + web)

Epic B smooths the tipper flow so tipping is **consistent across every surface**, self-serve, and
gives clear confirmation/decline feedback. It is **app + web only** — the backend money-path was
already correct after TIPX-A (comment/video tips charge via the single `charge_tip` rail BEFORE the
public total bump, and honor an explicit `payment_method_id`). No prod backend hotfix was needed for
Epic B; the fold ships the app/web diff + a live-DDB verifier that re-proves the money path.

## Ticket-by-ticket

| Ticket | Delivered |
|---|---|
| **B1** (F1) unblock broadcast tip in dev | `TipsGoalsViewModel.submitTip` no longer treats a BLANK payment-method id as "payments unavailable" in a **DEBUG** build — the blank id is the dev/demo path (`RealBillingAuthorizer` authorizes blank; the dev backend mock-completes + falls back to tip-default). The blank→unavailable gate now applies only to RELEASE (`!BuildConfig.DEBUG`), so live-broadcast tipping completes end-to-end in the demo build. |
| **B2** (F2/F5/F6) comment/DM sheets adopt the shared composer | Both hand-rolled preset-only, **one-tap-charges** comment sheets (feed `CommentsSection.CommentTipSheet` + `VideoCommentsSection.VideoCommentTipSheet`) were replaced with the shared `TipComposerContent` (presets **+ custom amount + public/private visibility + an EXPLICIT Send** + inline error + an **in-sheet amount receipt** on Confirmed). Comment tip state became a real `Hidden→Entry→Submitting→Confirmed→NoCard` machine (feed) / equivalent state fields (video). DM tip: the success snackbar now carries the charged amount (`"Tip sent · $X.XX"`, `formatTipAmount`) — F6's in-flow receipt. |
| **B3** (F3/F4) in-flow add-card + gate recovery | `NotConfigured` (empty wallet) on a comment/video tip now routes to a **NoCard** state with an actionable "Add a card" button that navigates to `AddCardDest`; on return (`ON_RESUME`) the sheet resumes to `Entry` with the chosen amount preserved so the tipper completes without leaving the flow. `onAddCard` is threaded `Nav → PostDetailRoute/VideoDetailRoute → …Section → sheet`. |
| **B4** (F7/F8/F9/F10) small consistency fixes | **F7:** comment Tip button now gates on real authorship (`isOwnAuthor`, added to `Comment`/`VideoComment`) instead of the `canDelete` permission proxy, so a moderator/admin who can delete others' comments still sees Tip. **F8:** the shared feed `TipSheet` Confirmed body + both comment Confirmed bodies got an explicit **Done** button (`tip_done`). **F9:** the web comment tip endpoint `tipPost` → **`tipComment`** (correct name) now threads `payment_method_id`; `TipDialog` loads payment methods for comment tips too and renders the PM selector, so a web comment tip is charged on the chosen card (was always default). **F10:** partially — the app confirmation shows the charged amount in-sheet (server `TipResult` fields already returned by the endpoints per TIPX-A). |

## Files

### App (`android/app/src/main/java/com/testlogon/android/`)
- `data/feed/EngagementDomain.kt` — `Comment.isOwnAuthor` (authorship, decoupled from `canDelete`).
- `data/videos/VideoCommentsApi.kt` — `VideoComment.isOwnAuthor`.
- `feature/broadcast/tips/TipsGoalsViewModel.kt` — B1 blank-PM gate is RELEASE-only.
- `feature/feed/CommentsViewModel.kt` — `CommentTipState` state machine + `selectTipPreset`/`setTipCustomAmount`/`setTipVisibility`/`sendTip`/`resumeTipAfterAddCard`.
- `feature/feed/CommentsSection.kt` — `CommentTipSheet` uses `TipComposerContent`; NoCard/add-card; ON_RESUME resume; F7 authorship gate; `onAddCard` param.
- `feature/feed/PostDetailScreen.kt` — threads `onAddCard`.
- `feature/feed/TipSheet.kt` — F8 Done button on Confirmed.
- `feature/videos/detail/VideoCommentsSection.kt` — video comment tip state + shared composer + NoCard/add-card + F7 gate.
- `feature/videos/detail/VideoDetailScreen.kt` — threads `onAddCard`.
- `feature/messaging/thread/ThreadViewModel.kt` — F6 amount in the DM tip snackbar (`formatTipAmount`).
- `navigation/PostDetailNavigation.kt`, `navigation/VideosNavigation.kt` — wire `onAddCard` → `AddCardDest`.
- `res/values/strings.xml` — `tip_done`, `tip_no_card_body`, `tip_add_card`.

### Web (`frontend/src/`)
- `api/endpoints/newsfeed.ts` — `tipPost` → `tipComment(postId, commentId, amountCents, paymentMethodId?)`.
- `pages/feed/TipDialog.tsx` — loads PMs for comment tips + renders the PM selector + passes the chosen PM.

## Verify — 7/7 PASS (live-DDB-direct on prod, pattern-tagged `tipxB_*`, 0 residue)

`verify_tipx_b.py` runs ON the prod host against the live DDB-Local the backend uses (same client-proxy
trick as `epic-a`: only `transact_write_items` is routed to a plain low-level client for DDB-Local
compatibility; production runs on real AWS where the shipped rail is valid). It re-proves the money
path that Epic B's UI relies on:

```
cd /home/ubuntu/testlogon
set -a; . ./.env.local; set +a; export DEV_MODE=1
.venv/bin/python verify_tipx_b.py    # 7/7 PASS
```

- **B-F9 explicit PM honored (comment):** an explicit `payment_method_id` is recorded on the debit ledger row; net 800 / fee 200; one charge.
- **B-F9 comment idempotent:** the same stable `cmttip:` key double-fires → 1 debit / 1 credit / replayed receipt (no double charge on retry/double-tap).
- **B-F9 foreign PM rejected 400 (no ledger):** a PM the tipper does not own → 400, no debit/credit.
- **B-F9 tip-default fallback honored:** no explicit PM → resolves to the tipper's `tip_default_payment_method_id` and records it.
- **CORE video_comment net/credit:** the `video_comment` surface still charges NET (1600/400) + credits once.
- **CORE 402 before ledger (comment):** a forced decline leaves NO debit/credit (charge-before-bump).
- **cleanup 0 residue.**

## Build gates
- `./gradlew :app:assembleDebug` — **BUILD SUCCESSFUL** (warnings are pre-existing deprecations).
- Web `npx tsc --noEmit` — **0 errors**; `npm run build` — **green**.
- (The `:app:testDebugUnitTest` source set has PRE-EXISTING compile errors on HEAD in unrelated
  syndicate/vod-ad tests — not touched by this epic.)

## On-device (A15, admin `crash1782189692@`)
Installed the debug APK, launched, navigated Feed → post detail → comments and Inbox → conversation →
message action sheet → **Send a tip**: the DM tip sheet renders the shared `TipComposerContent`
(presets $1/$5/$10/$20 + Custom amount + Note 0/500 + explicit **Send tip**); selecting $5 + Send
routed through the charge rail and surfaced the inline in-sheet error for a non-tippable call-event
target. Zero crashes across the flow (crash buffer empty).
