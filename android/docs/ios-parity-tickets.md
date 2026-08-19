# Android ↔ iOS Feature-Parity Tickets

> Source: iOS↔Android parity audit, 2026-08-02. iOS reference = `sean/testlogon-ios` (GitLab, main HEAD f088263, Swift/SwiftUI). Android target = `~/dev/testlogon/android` @ `android-impl`.
> **Framing:** Android is at/ahead of iOS at the module level. These tickets are capability-level gaps *within* modules. Citations are file paths + symbols captured during the audit; **line numbers are approximate — verify against current code before coding.** iOS paths are under `App/Sources/Features/` unless noted.
> Sizes: S ≈ ≤1d · M ≈ 2-4d · L ≈ 1-2wk · XL ≈ 2wk+.

---

## TIER 1 — Real functional holes (P0/P1)

### PAR-01 — Story creation (post a story)  ·  P0 · M
**Gap:** Android is view-only; users can watch stories but cannot post one. No compose UI, no "＋ Your story" tile, no upload path.
**iOS (port from):** `Stories/CreateStoryScreen.swift`, `Stories/CreateStoryViewModel.swift`, `Stories/StoryBarRow.swift` (always-present "＋ Your story" tile). Library-pick or camera, text caption + tappable link, multipart `POST /ui/stories`, per-day rate-limit handling.
**Android (build in):** `data/stories/StoriesApi.kt` currently exposes only `GET bar`, `GET user/{id}`, `POST {id}/view` → add `POST /ui/stories` (multipart). New compose screen + ViewModel under `feature/stories/`. Add compose tile to the story tray composable.
**AC:** pick from gallery or capture; caption + optional link; upload with progress; rate-limit surfaced; new story appears in own ring + tray.

### PAR-02 — Group-call media (real mesh WebRTC)  ·  P0 · L
**Gap:** Group calls render grid/roster/pin but **no audio/video ever connects** — the mesh manager is a no-op stub and the VM force-disables media.
**iOS (port from):** `Calls/Group/GroupPeerConnection.swift` (real `RTCPeerConnection` per peer: offer/answer/ICE, remote video tracks), `Calls/Group/GroupCallController` (roster→live-peer reconcile).
**Android (build in):** `data/webrtc/MeshConnectionManager.kt` binds `StubMeshConnectionManager` (`MeshResult.NotConfigured`) → implement `RealMeshConnectionManager` (reuse `RealPeerConnectionController` from 1:1 which already works). `feature/call/group/GroupCallViewModel.kt` forces `mediaUnavailable = true` → remove once real manager is bound. VM is already structured for a drop-in.
**AC:** N-party audio+video connects; roster reconcile add/remove; active-speaker; pin; leave.

### PAR-03 — Watch Parties: synced player + host controls  ·  P0 · L
**Gap:** Android shows a text sync **card** only ("Playing at 12:34"/"Paused"); no real player, no host play/pause/seek, no heartbeat, no end-party. Feature is non-functional as a watch party.
**iOS (port from):** `WatchParties/WatchPartyDetailViewModel.swift` (cookie-auth `AVPlayer`, drift reconcile, `play()/pause()/seek()` → `POST .../control`, host `end()`), `WatchParties/WatchPartyEventStream.swift` (SSE).
**Android (build in):** `feature/watchparties/WatchPartyDetailViewModel.kt:~30` ("Realtime playback sync intentionally NOT implemented"); `data/watchparties/WatchPartiesApi.kt:~19` (control/heartbeat/playback-url not surfaced) → add `control()`/`heartbeat()`/`playbackUrl()` to API+repo; embed existing `ExoVideoPlayerController`/`VideoPlayer` in the detail screen; drive from the already-computed `WatchPartiesUiState.PlaybackSyncState`; host play/pause/seek/end.
**AC:** participant player follows host within drift tolerance; host controls broadcast to all; heartbeat keeps liveness; host can end party.

### PAR-04 — Collaboration deal actions  ·  P1 · M  *(money-bearing)*
**Gap:** Collaboration detail is read-only; a creator cannot Accept/Reject/Counter-offer/Cancel/Terminate a revenue-share agreement in-app.
**iOS (port from):** `Collaborations/CollaborationDetailScreen.swift` (`actionsCard`, `CounterOfferSheet`).
**Android (build in):** `feature/collaborations/ui/CollaborationDetailScreen.kt` (read-only); `data/CollaborationsRepository.kt` states "performs NO mutations … OUT OF SCOPE" → add accept/reject/counter/cancel/terminate repo methods + action UI.
**AC:** each lifecycle action calls its endpoint, updates state, shows confirmation.

### PAR-05 — KYC guided active-liveness capture  ·  P1 · L  *(may be vendor/ML-gated — confirm)*
**Gap:** Android only books a scheduled liveness **call**; no in-app anti-spoof camera flow.
**iOS (port from):** `KYC/Liveness/{KycLivenessCaptureScreen,KycLivenessCameraView,KycLivenessProvider,KycLivenessSessionViewModel,VisionLivenessProvider}.swift`, wired into `KycFacialScreen`.
**Android (build in):** `feature/kyc/liveness/` has only `LivenessCall*` (booking) → build CameraX capture + on-screen challenge sequence (look left/right) + frame streaming + timeout handling; wire into the KYC facial flow.
**AC:** guided challenge sequence; frames streamed to liveness engine; pass/fail + timeout handled. **Flag:** decide liveness engine (ML Kit face vs vendor) before estimating firmly.

### PAR-06 — Signing: compose & send for signature (sender side)  ·  P1 · L
**Gap:** Android can receive/sign but cannot originate a signature request.
**iOS (port from):** `Signing/PacketComposeScreen.swift`, `Signing/PacketComposeViewModel.swift`, `Signing/FieldPlacementEditor.swift`, `Signing/TemplatePickerScreen.swift`.
**Android (build in):** `feature/signing/` is receive-only (`SigningEntryScreen`, `SubmitSignScreen`, `DocumentViewerScreen`; `editor/` is just `SigningEditorState.kt`) → build packet compose (recipients + signing order), PDF field-placement editor, template picker, send.
**AC:** assemble packet, add recipients/order, place fields on PDF, send; appears in recipients' queues.

### PAR-07a — Agent task console  ·  P2 · M
**Gap:** Android can start/stop/terminate workers but can't submit commands or watch output.
**iOS (port from):** `Agents/AgentConsoleScreen.swift` + `AgentConsoleViewModel.swift` (submit `run_command`/`run_test_suite`, live poll, exit code + stdout/stderr tails, task history/cancel).
**Android (build in):** `agents/workers/ui/WorkerDetailScreen.kt` (lifecycle only) → add console screen + VM.
**AC:** submit command/test-suite; poll; show exit + output tails; history; cancel.

### PAR-07b — Agent orchestrator console  ·  P2 · M
**iOS (port from):** `Agents/AgentOrchestratorScreen.swift` + VM (loop start/pause/resume/stop, current-ticket, release/complete-with-summary+PR-URL, eligible-ticket preview + claim).
**Android (build in):** no equivalent → add orchestrator screen + VM.
**AC:** drive loop lifecycle; see current ticket; claim eligible tickets; complete with PR URL.

### PAR-08 — Checkout payment-method picker  ·  P1 · M
**Gap:** Android checkout has no payment step — charges account default; multi-card users can't choose.
**iOS (port from):** `Checkout/CheckoutFlowScreen.swift:~175-271` + `PaymentSelectViewModel` (address → payment-method → review).
**Android (build in):** `checkout/OrderReviewScreen.kt:~292` (the "Choose payment method" button was removed); `checkout/CheckoutSessionViewModel.kt` (AND-031 not wired) → insert payment-method step selecting among saved methods, pass selection to the charge call.
**AC:** picker lists saved methods; selection drives the charge; default preselected.

### PAR-09 — Product variants (size/color/option)  ·  P1 · M
**Gap:** Android product detail is single-SKU + qty; variant products can't be purchased correctly.
**iOS (port from):** `Shop/ProductDetailScreen.swift:~66-140` (variant section, per-variant price).
**Android (build in):** `catalog/ProductDetailScreen.kt` / `catalog/ProductDetailViewModel.kt` (no variant concept) → add variant model, selection UI, per-variant price, variant-aware add-to-cart.
**AC:** variants shown; selection updates price/availability; correct variant added to cart.

---

## TIER 2 — Smaller but real gaps (P2)

### PAR-10 — Group discovery + join  ·  S-M
iOS `Groups/CommunityGroupsListScreen.swift` (My/Discover tabs, `/ui/groups/discover`) + Join in detail. Android `feature/groups/.../GroupsListScreen.kt` is a single list; repo has `leave` but no `join`/`discover`. **Build:** discover tab + join.

### PAR-11 — Group fundraiser donation  ·  S
iOS `Groups/CommunityGroupFundraisingScreen.swift` (Donate). Android `GroupFundraisingScreen.kt` view-only. **Build:** donate path.

### PAR-12 — PPV locked-gallery authoring  ·  M
Single locked image/video/file send IS parity. Mixed free+locked **gallery** compose missing. iOS `Messaging` `GalleryComposeViewModel.swift` (`DraftItem.isLocked`, `toggleLock`, `CreateGalleryMessageBody(freeImages:,lockedImages:,lockPriceCents:)`). Android `StagedMedia` has no `isLocked`; `MessagingRepository.kt` gallery send posts `freeImages` only (can receive/unlock, cannot author). **Build:** per-item lock toggle + lockPrice in gallery composer.

### PAR-13 — Scheduled-posts management screen  ·  S
iOS `Feed/ScheduledPostsScreen.swift` + VM (`GET /posts/scheduled`, cancel `POST /posts/{id}/cancel`). Android can schedule in composer (`feature/feed/compose/ComposePostScreen.kt:~307`, `ComposePostViewModel.kt onScheduleChange`) but has no list/cancel screen. **Build:** list + cancel.

### PAR-14 — File share-link create/list/revoke  ·  M
iOS `Files/ShareLinksScreen.swift` + `ShareLinksViewModel.swift` (`GET`/`DELETE /ui/files/share-links`), `FileManager/FsShareLinkSheet.swift` (mint). Android `feature/files/` has `ShareRepository`/`ShareSheet` (OS-share of a downloaded file) but no share-link lifecycle. **Build:** mint/list/revoke share links. *(Verify Android generic ShareSheet doesn't already meet the need.)*

### PAR-15 — Profile cover-photo upload  ·  S
iOS `Profile/ProfileScreen.swift` (cover banner + change, `ProfilePhotoKind.cover`). Android `feature/profile/own/OwnProfileScreen.kt` uploads `MediaKind.AVATAR` only (`COVER` defined, referenced nowhere). **Build:** cover upload UI.

### PAR-16 — Story Highlights (saved collections on profile)  ·  M
iOS `Stories/HighlightsScreen.swift` + VM (`GET/POST /ui/stories/highlights/...`). Android: only a passive `highlighted: Boolean` DTO field; no screen/VM/endpoints. **Build:** create/list highlight groups, pin stories.

### PAR-17 — Viewer clip-from-live broadcast  ·  M
iOS `Broadcast` `BroadcastViewerScreen.swift` `ClipButton` + `BroadcastViewerViewModel.createClip(lastSeconds:)` (last 15/30/60s; CLIPPING_DISABLED/QUOTA/RATE_LIMITED handling). Android: none in `feature/broadcast/**` (separate `feature/clips/` not wired to live viewer). **Build:** clip-from-live in viewer.

### PAR-18 — Story viewer: report story / block author  ·  S  *(safety)*
iOS `Stories/StoriesViewer.swift` "⋯" menu → Report + Block. Android `StoryViewerScreen.kt`: none. **Build:** report/block affordance.

### PAR-19 — Payout cancel button  ·  S
iOS `Payouts/PayoutDetailScreen.swift` (Cancel → `POST /ui/payouts/{id}/cancel`, returns to available balance). Android `PayoutsRepository.cancelPayout`/`PayoutsApi.kt` exist but `payouts/PayoutDetailScreen.kt` is read-only → **wire existing method into UI.**

### PAR-20 — Wallet account-balance breakdown  ·  S-M
iOS `Billing/WalletScreen.swift` ("Account balance" from `GET /ui/billing/balance`: amount due, pending due, owed/paid settled+pending). Android `billing/wallet/WalletTransactionsViewModel.kt` fetches header + ledger only, no balance call. *(Note: `payouts/WalletScreen.kt` is money-OUT, a different concept.)* **Build:** balance section.

### PAR-21 — Ad-creative list + detail management  ·  M
iOS `Ads` `AdCreativesScreen.swift` → `AdCreativeDetailScreen.swift` (asset replace, PATCH edit headline/body/CTA/rotation-weight, submit-for-review, attach/remove affiliate discount) from `AdCampaignDetailScreen.swift:~99`. Android `ads/create/creative/CreateCreativeScreen.kt` is one-shot create+submit; no list/detail/edit; `AdCampaignDetailScreen.kt` has no Creatives link. **Build:** creative list + detail + edit.

### PAR-22 — Wishlist → move/add to cart  ·  S
iOS `Wishlist/WishlistScreen.swift:~45-93` (`onMoveToCart`). Android `wishlist/WishlistViewModel.kt`: refresh/remove/tap-through only. **Build:** move-to-cart.

### PAR-23 — Ad campaign picker (multi-campaign scoping)  ·  S
iOS scopes targeting/scheduling/optimization editors to the campaign chosen in `AdCampaignDetailScreen.swift:~102-110`. Android `ads/studio/data/AdsStudioCampaignResolver.kt` self-resolves to the caller's FIRST campaign ("no campaign-picker nav yet"). **Build:** campaign picker nav so editors scope to a chosen campaign.

### PAR-24 — Tax spending summary  ·  S
iOS `Billing/TaxDocumentsView.swift` (`GET /ui/tax-documents/summary`: per-category + total). Android `taxdocs/TaxDocsScreen.kt` lists per-year documents only. **Build:** summary section.

### PAR-25 — Admin consoles (bundle; split as needed)  ·  M each
Missing/degraded vs iOS `Admin/`:
- **Impersonation** — iOS `AdminImpersonationScreen.swift` (audit log, start w/ reason+ticket, stop). Android: none.
- **Entitlements** — iOS `AdminEntitlementsScreen.swift` (revoke / extend-hours / add-credits + reason). Android: none.
- **Usage leaderboard** — iOS `AdminUsageScreen.swift` (top-N, dimension/metric pickers). Android: none.
- **Notification templates** — iOS `AdminNotificationsScreen.swift` (list/toggle/test-send). Android: none.
- **KYB business review** — iOS `AdminKycBusinessReviewScreen.swift` (working queue). Android `kycadmin/KycBusinessAdmin.kt` is a scaffold/stub. *(Confirm stub depth.)*
- **Email unsuppress + SMS send-test** — iOS `AdminEmailScreen`/`AdminSmsScreen` (mutations). Android folds both into read-only `admin/MessagingDashboardScreen.kt`.

### PAR-26 — Webhook test-send + rotate-secret  ·  S
iOS `Webhooks/WebhookDetailViewModel.swift` (`runTest()` `POST /ui/webhooks/{id}/test`, `rotateSecret()`). Android `webhooks/ui/WebhookDetailViewModel.kt`: neither. **Build:** both actions.

### PAR-27 — Safety Center hub  ·  S
iOS `Safety/SafetyCenterScreen.swift` (blocked accounts, data/privacy, DMCA, account deletion). Android has the pieces (`feature/blocking`, `feature/privacy`, DMCA under support) but no unified entry. **Build:** hub screen linking existing surfaces.

### PAR-28 — Report categories 6 → 10  ·  S
iOS `Safety/SafetyModels.swift` = 10 reasons. Android `report/ReportSheet.kt` + `messaging/ReportDomain.kt` = 6. **Add:** self_harm, misinformation, impersonation, copyright (and split nudity out of "sexual").

### PAR-29 — Legal screens  ·  S
iOS `Legal/` (About, CommunityGuidelines, Terms, Contact, AgeGate). Android `more/MoreCatalog.kt` marks About `comingSoon=true`; others absent. **Build:** the static legal screens.

### PAR-30 — SEO interactive lookup  ·  S
iOS `Seo/SeoScreen.swift` (resource/path lookup form: mode toggle, type picker, id/path input). Android `feature/seo/ui/SeoScreen.kt` renders metadata for nav-arg ids only. **Build:** lookup form.

### PAR-31 — Projects: tracked-files list + Drive disconnect  ·  S
iOS `Projects/ProjectDetailScreen.swift` (tracked-files section + Disconnect). Android `feature/projects/ui/detail/ProjectDetailScreen.kt` has neither (connect-only). **Build:** both.

### PAR-32 — Bots "Send test"  ·  S
iOS `Bots/BotsListScreen.swift` (send-test sheet). Android `feature/bots/`: absent. **Build:** send-test.

### PAR-33 — Activity feed rows tappable  ·  S
iOS `Activity/ActivityScreen.swift` navigates rows → post/profile. Android `feature/activity/ActivityFeedScreen.kt` rows have no click. **Build:** row navigation.

### PAR-34 — Analytics depth  ·  M
iOS `Analytics/EngagementScreen.swift` + `AnalyticsDashboardScreen.swift` (engagement public-visibility toggle, platform benchmarks/percentile, revenue-over-time chart). Android `feature/analytics/`: missing these. **Build:** toggle + benchmarks + revenue chart.

### PAR-35 — Syndicate / Org lifecycle  ·  M
Discover/browse syndicates (iOS `Syndicates/SyndicatesListScreen.swift`) missing on Android; Org **leave** missing; Org **transfer-ownership** dead-wired (Android `data/OrgsRepository.kt transferOwnership()` has no UI caller). Syndicate open-licensing terms + revenue-split history thinner. **Build:** discover, leave, wire transfer-ownership.

---

## PLATFORM CATCH-UPS — iOS-native features → Android-idiomatic equivalents

### PAR-P1 — Home-screen widgets (Glance)  ·  M
iOS `Widgets/TestLogonWidgetBundle.swift`, `Widgets/QuickActionsWidget.swift` (New Post/Messages/Discover/Home, deep-link `testlogon://widget/<id>`), `Widgets/{Call,Broadcast,RentalCountdown}LiveActivity.swift`. Android: no Glance/AppWidget anywhere. **Build:** Glance Quick-Actions widget (high value/low cost); live-activity analogs → ongoing/MediaStyle notifications.

### PAR-P2 — App Shortcuts / assistant  ·  S
iOS `AppIntents/TestLogonAppIntents.swift` + `AppRouteCoordinator.swift` (NewPost/OpenMessages/OpenFeed/DiscoverCreators). Android: no `shortcuts.xml`/`ShortcutManager`. **Build:** static + dynamic App Shortcuts (deep-link routing already exists → cheap).

### PAR-P3 — Rich push (preview + image + direct-reply)  ·  M  *(== existing task #77)*
iOS `NotificationService/NotificationService.swift` (NSE rewrites banner: sender title, decrypted body, image thumbnail, handles E2E-encrypted payloads). Android `notifications/NotificationPresenter.kt` (~102 lines) is `BigTextStyle` only — no image, no `MessagingStyle`, no `RemoteInput` reply. **Build:** `NotificationCompat.MessagingStyle` + `BigPictureStyle` + `RemoteInput` direct-reply (in-process; no extension needed).

### PAR-P4 — Offline mutation queue  ·  L
iOS `Sync/MutationQueueRunner.swift` (durable FIFO outbox, drain on reconnect w/ fresh CSRF + single-flight 401-refresh, pending/failed banner, cancel-before-send, dead-letter). Android: none (WorkManager used only for push-reg + VOD watermark download). **Build:** Room-backed outbox + WorkManager drain + sync banner. Affects reliability of every write on flaky networks.

### PAR-P5 — Broadcast host ongoing notification  ·  S
iOS `LiveActivity/BroadcastActivityController.swift` (Lock Screen/Dynamic Island live viewer count). Android: no foreground service/ongoing notification for broadcast host (calls have `feature/call/service/CallForegroundService.kt`). **Build:** foreground service + ongoing notification for host; **also verify backgrounded-publish reliability.**

---

## NOT DOING — iOS-platform-only (Android already has the idiomatic equivalent, or Apple-mandated)
- **CallKit** → Android has `telecom/TestLogonConnectionService.kt` (parity).
- **VoIP/PushKit** → Android `incoming/CallPushHandler.kt` + `IncomingCallNotifier` full-screen intent (parity).
- **StoreKit / Apple IAP** for digital goods, subscriptions, tips → Android correctly uses the card rail (`BillingAuthorizer`). Do NOT copy StoreKit.
- **PDFKit in-app viewer** → Android uses Chrome Custom Tabs (idiomatic).
- **Edition SFW/EU build lanes** → App-Store-review compliance construct; low priority on Android (no App Store lane) unless a clean-vs-full distribution split is required.

---

## Where Android is AHEAD of iOS (context — no action)
Admin/infra ops dashboards (AuditExports/Risk/PaymentHealth/Financials), Tip Insights, subscription tier authoring + trials/proration/dunning, seller fulfillment w/ carrier tracking, ad CTAs with real CPC charge (iOS has none), API-key CIDR allow/deny + post-create capability edit, sessions "sign out all others", tabbed global search + recommendations, richer public profile (direct-tip/subscribe), in-call text chat + system PiP, message tip/money reactions, syndicate ad revenue-split editing.
