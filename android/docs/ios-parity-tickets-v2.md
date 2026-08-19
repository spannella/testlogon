# Android ↔ iOS Feature-Parity Tickets — v2 (verified second pass)

> Second pass, 2026-08-02. Every ticket re-checked against **current** code on both apps + the backend (Python `routers/` and C++ `testlogon-cpp/app/main.cpp`). Line numbers pinned by opening files. iOS = `sean/testlogon-ios` (`App/Sources/Features/<Name>/`). Android = `~/dev/testlogon/android` @ `android-impl` (`app/src/main/java/com/testlogon/android/...`).
> Sizes: S ≈ ≤1d · M ≈ 2-4d · L ≈ 1-2wk · XL ≈ 2wk+.

## What changed vs v1 (read this first)
- **FALSE GAPS (already done on Android — close, don't build):** **PAR-14** file share-links (full create/list/revoke exists in `feature/share/`), **PAR-25e** KYB business review (`feature/kycadmin/KycBusinessAdmin.kt` is a complete 385-line screen, arguably ahead of iOS).
- **BACKEND-BLOCKED (needs server change, not just Android):** **PAR-02** group-call media (the group-signal relay writes to an in-memory queue with **no read/drain endpoint** on either backend — blocks iOS too), **PAR-08** checkout payment picker (`CartPurchaseIn` has no `payment_method_id`; the iOS picker is **cosmetic** today too), **PAR-28** report categories (content-report backend enforces a fixed topic allow-list; adding codes requires editing it + the web reference).
- **C++ CUTOVER GAPS:** product variants (PAR-09), SEO metadata (PAR-30), Projects/Drive (PAR-31) exist in Python but are **not ported to C++** — flag for the cutover.
- **Size changes:** ↑ PAR-02 L→XL, PAR-03 L→XL, PAR-08 M→L, PAR-11 S→M, PAR-24 S→M, PAR-28 S→M, PAR-30 S→M, PAR-31 S→M. ↓ PAR-20 →S, PAR-14 →S (audit-only), PAR-25e →S (close-out).
- **Scope corrected smaller than v1 implied:** PAR-06 signing (Android already has signer-side placement + PDF render + scaffolded transport), PAR-15 cover photo (`MediaKind.COVER` + uploader already exist — UI wiring only), PAR-19 payout-cancel (data layer already complete), PAR-20 wallet balance (data layer already complete — pure wiring), PAR-23 ad campaign-picker (persisted selection exists; only the 3 studio editors lack an in-screen picker), PAR-27 safety center (all 4 sub-screens exist — aggregation only), PAR-32 bots (feature exists; only send-test missing), PAR-35 org transfer (repo method exists, dead-wired), PAR-P4 offline queue (messaging-scoped `OutboxDao` already exists).
- **Flag-gated / LATENT backends (verify flag before demo):** PAR-07a agent console (`agent_ssh_qa_enabled`, default OFF→404), PAR-09 variants (`product_depth_enabled`), PAR-25c usage leaderboard (`open_bank_project_enabled` && `metrics_leaderboard_enabled`).
- **New follow-up recommended:** an ads-admin / tenants / roles / subscription-tiers parity sweep (iOS `AdminTenantsScreen`, `AdminRolesScreen`, `AdminSubscriptionTiersScreen`, `AdminAdPlatformScreen`, `AdminAdCreativeReviewScreen`, `AdminAdFraudScreen` — mostly no Android counterpart). See end.

---

## TIER 1 — Real functional holes

### PAR-01 — Story creation (post a story) · P0 · M
- **Assumptions:** CONFIRMED. Android view-only; `StoriesApi.kt` has only GET bar / GET user / POST view.
- **iOS ref:** `Stories/CreateStoryViewModel.swift:104` `createStory()` (image upload → `POST /ui/stories {media_type,media_url,text_overlay?,link_url?,link_label?}`, 429→limit; image-first, video rejected `:66`); `CoreNetwork/StoriesApi.swift:35`; `CoreModel/StoriesDTOs.swift:263/278`.
- **Android current:** `data/stories/StoriesApi.kt:20-31` (no create); `feature/stories/StoriesTray.kt:51-68` (no compose tile). Reusable upload rail: `data/feed/PostComposeApi.kt:150` `@Multipart uploadImage` wrapped by `CommentImageUploader.uploadImage(uri):278`.
- **Backend:** `POST /ui/stories` — EXISTS: Python `stories.py:66` (429 `:89`), C++ `main.cpp:165193`.
- **Plan:** add `CreateStoryReqDto/RespDto` in `data/stories/StoriesDtos.kt`; `createStory` in `StoriesApi.kt`+`StoriesRepository.kt` (reuse `call{}`+`errorParser`, refresh tray on success); CREATE `feature/stories/CreateStoryViewModel.kt` (inject repo + `CommentImageUploader`, mirror iOS UploadState) + `CreateStoryScreen.kt` (photo picker, overlay/link fields, Share); prepend "+Your story" tile in `StoriesTray.kt`; add `stories/create` nav destination.
- **Edge/risks:** image-first (reject video up front); 429 friendly copy; relative `/uploads/...` URL sent as-is; cancel in-flight on exit; omit empty overlay/link.
- **Test plan:** **Unit** `CreateStoryViewModelTest` (upload ok/fail, share pop, 429, video reject) + repo contract (`StoriesRepositoryContractTest.kt`). **UI** tile present/clickable; Maestro pick→overlay→Share→own ring appears. **Manual** post image story A15→appears on 2nd device bar. **Backend** `curl POST /ui/stories` 201 + 429 after cap.
- **Size:** M.

### PAR-02 — Group-call media (real mesh WebRTC) · P0 · XL  ⚠ BACKEND-BLOCKED
- **Assumptions:** CORRECTED. The native `livekit.org.webrtc` SDK IS integrated (`app/build.gradle.kts:206`, `RealPeerConnectionController.kt` is a full impl) — only the *mesh* manager is a stub. But the true blocker is backend: the group-signal relay is write-only. Also the 1:1 `SignalingTransport` is itself still `StubSignalingTransport` (`WebRtcDataModule.kt:108`).
- **iOS ref:** `Calls/Group/GroupPeerConnection.swift:1-15` (one RTCPeerConnection/peer, lower-userId=offerer; notes relay is non-delivering); `Calls/Group/GroupCallController.swift`.
- **Android current:** `data/webrtc/MeshConnectionManager.kt:28-104` (`StubMeshConnectionManager` always `NotConfigured`); `feature/call/group/GroupCallViewModel.kt:51,71-72,136-139` (collects `mesh.events`; forces `mediaUnavailable=true`); `data/webrtc/CallMediaHolder.kt:15-21` (single `remoteVideo` → needs `Map<userId,VideoTrack>`); reuse `RealPeerConnectionController.kt`, pure seam `PeerConnectionController.kt:24-51`.
- **Backend:** control plane EXISTS (`group_calls.py`, C++ `main.cpp:164890-164899`). **`POST /ui/calls/group/{id}/signal` EXISTS but LATENT** — `relay_signal` writes `_signal_queues` (`group_call_service.py:435`) with **no read path**; **a drain endpoint is MISSING** on both backends.
- **Plan:** (1) BACKEND FIRST — add `GET /ui/calls/group/{id}/signals` drain OR fan onto `messaging/events/poll`, in Python + C++ (HUMAN DECISION on transport). (2) CREATE `data/webrtc/RealMeshConnectionManager.kt` (Map of per-peer controllers sharing one capture; deterministic offerer=lower userId). (3) generalize `CallMediaHolder` to per-peer map. (4) bind Real in `WebRtcDataModule.kt:117`. (5) remove forced `mediaUnavailable`; addPeer per roster. (6) render per-peer in `ParticipantTile.kt`. (7) reuse `IceServersRepository`.
- **Edge/risks:** mesh scale N×(N-1) (cap participants); GLARE; renegotiation on join/leave; single shared capture; FGS for backgrounded (see PAR-P5). **Backend transport is the real blocker; without drain neither platform connects remote media.**
- **Test plan:** **Unit** mesh state machine over pure `MeshEvent`/`MeshResult`. **UI** grid renders tile per connected peer, clears on disconnect. **Manual** 3-device call (A15+Pixel+3rd) after backend drain lands. **Backend** curl: POST signal from A→B, GET drain as B, assert delivered (fails today — proves gap).
- **Size:** XL (raised — 2-backend signal delivery + mesh + multi-peer render; cross-platform blocked).

### PAR-03 — Watch Parties: synced player + host controls · P0 · XL
- **Assumptions:** CONFIRMED — sync intentionally unimplemented.
- **iOS ref:** `WatchParties/WatchPartyDetailViewModel.swift:11` (AVPlayer), `:154-169` (play/pause/seek→control), host `end()`; `WatchPartyEventStream.swift:6-23` (SSE `playback_control`); `WatchPartyPlayerView.swift:10`.
- **Android current:** `feature/watchparties/WatchPartyDetailViewModel.kt:30` ("sync NOT implemented"); `data/watchparties/WatchPartiesApi.kt:19-20` (control/heartbeat/playback-url not surfaced); `WatchPartiesUiState.kt:62-85` (`PlaybackSyncState` already auto-filled); `WatchPartyDetailScreen.kt:212-241` (text card only). Reuse `ExoVideoPlayerController`/`VideoPlayer` from feature/player.
- **Backend:** all EXIST — `POST .../{id}/control` (`watch_party.py:181`, C++ `main.cpp:165372`), `.../heartbeat` (`:241`), `GET .../playback-url` (`:252`), `GET .../stream` SSE (`:262`).
- **Plan:** surface control/heartbeat/playback-url in API+repo; wrap `ExoVideoPlayerController` as `WatchPartyPlayerController`; on join load URL + reconcile `PlaybackSyncState`→player (seek if drift>2s); render `VideoPlayer` above the card; host controls (gated `canControl`)→POST control; ~9s heartbeat loop; SSE listener for `playback_control`.
- **Edge/risks:** SSE reconnect+backoff; 2s drift tolerance; host end mid-view (409→ended/pause); late-join catch-up; REST poll backstop.
- **Test plan:** **Unit** `targetPositionSeconds()`, `shouldReseek()`. **UI** join loads player; host play/seek/pause syncs participant <2s; controls only when `canControl`; ended dismisses. **Manual** 2-device sync across latency + heartbeat. **Backend** control returns PartyOut; stream emits `playback_control`.
- **Size:** XL (raised L→XL — real-time player + event stream + 3 endpoints + reconciliation).

### PAR-04 — Collaboration deal actions · P1 · M
- **Assumptions:** CORRECTED — actions mutate agreement STATE only, no charge fires (NOT money-gated). Android API/repo genuinely read-only. iOS also has a `revisions` history card Android's API lacks.
- **iOS ref:** `Collaborations/CollaborationDetailScreen.swift:130-155` (actionsCard gating), `:44-66` (CounterOfferSheet + confirms); `CollaborationDetailViewModel.swift:64-71`.
- **Android current:** `core-network/.../collaborations/CollaborationsApi.kt:20-41` (3 GETs only); `feature/collaborations/data/CollaborationsRepository.kt:36-76` ("performs NO mutations"); `ui/CollaborationDetailScreen.kt` read-only.
- **Backend:** `POST /ui/collaborations/{id}/accept|reject|counter|cancel|terminate` + `GET .../revisions` — ALL EXIST (Python `collaborations.py:184/200/216/240/254`, C++ `main.cpp:169384-169389`); `counter` body `counter_split_pct` 1-99, `terminate` body per `models.py:3696/3703`.
- **Plan:** add 5 `@POST` + `@GET revisions` to Api; `CounterOfferInDto`/`TerminateInDto`/`RevisionOut` DTOs; repo mutations via `call{}`; mapper helpers (awaitingResponse/isActive/isPending) + revision map; VM `busy` flag + one-shot events + 5 actions reloading detail; screen actions card (iOS gating) + counter sheet (split slider 1-99) + confirm dialogs + revisions card. NO BillingAuthorizer.
- **Edge/risks:** do NOT money-gate; no server idempotency key → `busy`+disable against double-tap; validate split 1-99; map 403(not your turn)/409(bad state) to toast.
- **Test plan:** **Unit** repo POST→ApiResult, 403/409/timeout; counter validation; VM gating+re-entrancy. **UI** actions per status; counter payload; confirms. **Manual** two accounts propose→counter→accept→terminate. **Backend** extend `CollaborationsApiTest.kt`; verify vs C++ :8080.
- **Size:** M.

### PAR-05 — KYC guided active-liveness capture · P1 · L
- **Assumptions:** CONFIRMED. Android `feature/kyc/liveness/` is only call-booking; **no CameraX and no ML Kit anywhere** in the app (every camera surface is a system-intent or stub). iOS `VisionLivenessProvider` uses Apple Vision (no vendor SDK).
- **iOS ref:** `KYC/Liveness/KycLivenessProvider.swift:26-50` (challenges blink/turnLeft/turnRight/smile), `:153-164` (vendor-injection factory→Vision fallback); `VisionLivenessProvider.swift:96-120` (per-frame landmarks); `KycLivenessCameraView.swift:46-79` (front-cam frame pump); `KycLivenessSessionViewModel.swift:64-73` (best-frame JPEG); `KycFacialScreen.swift:38-43,70`.
- **Android current:** `feature/kyc/liveness/model/LivenessCallDomain.kt` (booking); submission rail to reuse `feature/kyc/facial/data/FaceComparisonRepository.kt:79-127` `submitSelfie` (presign→PUT→attach SELFIE→compareFace); `FaceComparisonContract.kt:39` `autoCaptureUnavailable=true`; **vendor-seam pattern to copy**: `feature/kyc/idscanner/IdFrameAnalyzer.kt:22` + `StubIdFrameAnalyzer:55` + Hilt `@Binds` in `idscanner/data/IdScannerModule.kt`.
- **Backend:** `POST v1/kyc/cases/{id}/compare-face` — EXISTS (C++ `main.cpp:58380`), reuses manual-selfie rail. N/A backend change.
- **Plan:** (1) add CameraX + ML Kit `face-detection` deps (the "human decision / new dependency"). (2) CREATE `feature/kyc/liveness/capture/`: `LivenessProvider.kt` interface + challenge enum, `MlKitLivenessProvider.kt` (eye-open→blink, smiling→smile, headEulerAngleY→turn; best frontal frame JPEG), Hilt `@Binds` default→ML Kit (vendor override seam). (3) `LivenessCaptureScreen.kt`+VM (CameraX PreviewView+ImageAnalysis front cam, randomized challenges, progress dots, timeout, CAMERA gate). (4) hand best frame to `FaceComparisonRepository.submitSelfie`; add `onLivenessCompleted(file)`. (5) launch from `FaceComparisonScreen.kt`, flip `autoCaptureUnavailable`.
- **Edge/risks:** permission denial; no front cam; multi/no face; replay (randomize order); frame throttling; model download vs bundled; low light; tune thresholds as named constants.
- **Test plan:** **Unit** challenge state machine w/ synthetic `Face` fixtures + best-frame selection. **UI** permission-gate states; `submitSelfie` invoked w/ captured file. **Manual** run 4 challenges A15/Pixel → selfie posts, case advances. **Backend** compare-face accepts liveness selfie (DEV_MODE mock).
- **Size:** L (CameraX+ML Kit dep add is the gating cost).

### PAR-06 — Signing: compose & send for signature · P1 · L
- **Assumptions:** CORRECTED — Android is NOT receive-only: it already has signer-side placement/capture state machine, built-in PDF render, and a scaffolded (unwired) `mutateField`. Missing = sender compose UI + recipient mgmt + field-authoring + `addSigner` client.
- **iOS ref:** `Signing/PacketComposeViewModel.swift:198-290` (create `:211`→addSigner `:235`→fields `:267`→send `:281`); `FieldPlacementEditor.swift:1` (PDFKit, drag `:230-232`, clamp `:319-324`, 4 field types `:126`); coords = normalized top-left 0…1.
- **Android current:** `feature/signing/SigningEntryScreen.kt:112-141`+`SigningEntryViewModel.kt:62-88` (create-draft only); `editor/SigningEditorState.kt:32-66,134-198` (full reducer, but signer-scoped per `model/PlacedField.kt:65-70`); `document/PdfPageRenderer.kt:59-111` (built-in `PdfRenderer`); `DocumentViewerScreen.kt:212-218` (normalized-bounds overlay seam); `core-network/.../signing/SigningApi.kt` (`mutateField:42-46` unwired, `sendPacket:56-57`, templates `:81-88`; **no addSigner**).
- **Backend:** all EXIST — C++ create `main.cpp:49168`, addSigner `:49219`, removeSigner `:49255`, field `:49268`, send `:49338`, templates `:46241`; Python `signature_packets.py:263/330/358/388/458`.
- **Plan:** add `POST .../{id}/signers` (+ DELETE) to `SigningApi.kt`; add `addSigner()`+`mutateField()` to `SignatureRepository.kt`; CREATE `feature/signing/compose/PacketComposeScreen.kt`+VM (orchestrate create→signers→fields→send) + `FieldPlacementScreen.kt` (reuse `PdfPageRenderer`+overlay seam+`NormalizedRect`, field palette, tap-add/drag-move, per-field recipient) + `TemplatePickerScreen.kt`; generalize (don't reuse verbatim) the signer-scoped editor for author semantics.
- **Edge/risks:** coords 0…1 top-left doubles; clamp to page; multipage; required-vs-optional; signer order; draft-only mutation (backend rejects after SENT); large PDFs (2048px cap).
- **Test plan:** **Unit** compose orchestration + rollback; coord normalize/clamp; DTO map. **UI** drag-place field; assign recipient; send disabled until ≥1 recipient+field. **Manual** compose from seeded PDF, place signature+date, send; 2nd account signs. **Backend** create→signers→fields→send → SENT; malformed geometry 422.
- **Size:** L.

### PAR-07a — Agent task console · P2 · M  ⚠ flag-gated backend
- **Assumptions:** CONFIRMED — `WorkerDetailScreen/VM` lifecycle-only; greenfield console.
- **iOS ref:** `Agents/AgentConsoleViewModel.swift:69` (submit), `:100-121` (1.5s poll, ≤80 iters, stop on terminal); `AgentActionsApi.swift:46/62/70/54`; `AgentConsoleScreen.swift:80-115`.
- **Android current:** `feature/agents/workers/ui/WorkerDetailViewModel.kt:66-83` (start/stop/terminate); repo `workers/data/WorkersRepository.kt:23-32`; no poll loop anywhere.
- **Backend:** `POST/GET /ui/agents/{id}/actions`, `.../{action_id}`, `.../{action_id}/cancel` — EXISTS both, **flag-gated `agent_ssh_qa_enabled` (default OFF→404)**. Path `ui/agents` (plural) vs workers' `ui/agent/workers`.
- **Plan:** CREATE `core-network/.../agents/AgentActionsApi.kt`+DTOs (model on `WorkersApi.kt`); provider in `AgentsNetworkModule.kt`; CREATE `feature/agents/console/data/{ConsoleRepository,Domain,Module}.kt` (copy Workers fold); CREATE `feature/agents/console/ui/{AgentConsoleScreen,ViewModel,ConsoleUiState}.kt` (submit run_command/run_test_suite, `while{delay(1500)}` poll terminating on terminal, exit+tails, cancel, history, 404→"not enabled"); route + MoreCatalog entry.
- **Edge/risks:** flag-off 404→clean "not enabled" state; bound poll (~2min)+cancel on clear; output truncation; 401→login.
- **Test plan:** **Unit** poll terminates on terminal+cancel; action-type map; 404→notEnabled. **UI** submit→running→exit+tails; cancel; history. **Manual** with flag on, run a command. **Backend** 404 when off; lifecycle when on.
- **Size:** M (verify flag before demo).

### PAR-07b — Agent orchestrator console · P2 · M
- **Assumptions:** CONFIRMED — greenfield; PR handling read-only (`agents/prs/`).
- **iOS ref:** `Agents/AgentOrchestratorApi.swift` base `ui/agent/orchestrator/{id}` (status `:25`, start/pause/resume/stop `:30-47`, eligibleTickets `:75`, claim `:52`, release `:60`, complete(summary,prUrl) `:67`); VM `:58-78`; Screen `:52-183`.
- **Android current:** none. `agents/prs/data/PrsRepository.kt:21-24` list/get only; `PrsDomain.kt:20-37` carries prUrl/ticketId (reusable display).
- **Backend:** `/ui/agent/orchestrator/{worker_id}/{status,start,pause,resume,stop,eligible-tickets,claim-ticket,release-ticket,complete-ticket}` — EXISTS both, **NOT flag-gated**. Path `ui/agent` (singular).
- **Plan:** CREATE `AgentOrchestratorApi.kt`+DTOs (complete body {summary,prUrl}); provider; `feature/agents/orchestrator/data/*` (copy Workers fold); `ui/*` (status card w/ current-ticket + counts, loop buttons, eligible list+Claim, release, complete sheet); route + MoreCatalog.
- **Edge/risks:** loop-state transitions; claim race→refresh; complete requires non-empty summary; 401→login.
- **Test plan:** **Unit** action→state transitions; complete serialization; claim/release refresh. **UI** loop buttons per state; complete validates summary+PR. **Manual** start loop, claim ticket, complete w/ PR. **Backend** reachable (not gated); complete records summary+pr_url.
- **Size:** M (more demoable than 07a — not gated).

### PAR-08 — Checkout payment-method picker · P1 · L  ⚠ BACKEND-BLOCKED
- **Assumptions:** CORRECTED heavily. "AND-031 BillingAuthorizer not wired" is stale (VM charges via `cartRepository.purchase`). Picker was deliberately removed (ECOMX-41). **iOS's own picker is cosmetic** — `selectedPaymentMethodId` captured but never passed to purchase (`CheckoutSessionViewModel.swift:114-129`). Real gap is BACKEND.
- **iOS ref:** `Checkout/CheckoutFlowScreen.swift:175-224` (PaymentStepView lists `BillingAccountApi.paymentMethods()`, defaults to `vm.defaultMethodId`), `:225-247`; `CheckoutSessionViewModel.swift:114-129` (selection NOT threaded).
- **Android current:** `feature/checkout/CheckoutSessionViewModel.kt:155-186` (purchase, no PM); `OrderReviewScreen.kt:291-308` (picker removed); `data/cart/CartDtos.kt:106-119` (`CartPurchaseInDto` no PM); no payment-methods API in app.
- **Backend:** `GET /ui/billing/payment-methods` EXISTS (Python `billing.py:1101`; C++ `main.cpp:13840` — verify `/ui/` path on C++). `POST /ui/shoppingcart/carts/{id}/purchase` EXISTS (`shoppingcart.py:181`) but **does NOT accept `payment_method_id` → LATENT** for honoring a chosen card.
- **Plan (two layers — FLAG):** (1) product decision: real charge-chosen-card vs cosmetic parity (iOS is cosmetic today). (2) if honoring: EDIT backend `CartPurchaseIn`+`ui_purchase_cart`+`purchase_cart` to thread `payment_method_id`; mirror in C++ `h_shoppingcart_purchase`. (3) CREATE `PaymentMethodsApi.kt`+DTOs+`PaymentMethodRepository.kt`. (4) thread PM through `CartDtos`/`CartRepository.purchase`/VM. (5) re-introduce PM section in `OrderReviewScreen.kt`, persist to SavedStateHandle (mirror `KEY_ADDRESS_ID`).
- **Edge/risks:** reuse persisted idempotency key so re-select+retry can't double-charge; empty PM list→default; deleted/expired PM→backend 4xx; **if backend param not added, picker stays cosmetic — say so, don't ship misleading UI**; C++ route lacks param → cutover drops chosen PM silently.
- **Test plan:** **Unit** PM list map; VM default-select + SavedState round-trip; purchase carries id. **UI** picker renders, default preselected, threaded. **Manual** two cards, pick non-default, charge lands on it (needs backend). **Backend** `payment_method_id` honored + settles chosen method; verify `GET ui/billing/payment-methods` on Python + C++.
- **Size:** L (M if scoped to cosmetic picker only).

### PAR-09 — Product variants · P1 · M (display) / L (if wired to charge)  ⚠ C++ gap
- **Assumptions:** CONFIRMED single-SKU. Android mirror is `feature/catalog/*` (not checkout). Backend variant enrichment is flag-gated `product_depth_enabled` and **not ported to C++**.
- **iOS ref:** `Shop/ProductDetailScreen.swift:66-68/120-143` (variantsSection, per-variant priceCents); `CoreModel/CatalogDTOs.swift:129-162` (`StorefrontVariant`, tolerant default []).
- **Android current:** `feature/catalog/ProductDetailViewModel.kt:29-37` (no variant state); `ProductDetailScreen.kt` (price+qty); `data/catalog/CatalogDtos.kt:46-62` (no variants — dropped on decode); `CatalogDomain.kt:22-31`.
- **Backend:** inline `CatalogItemOut.variants` via `enrich_catalog_item` (`services/store_integration.py:126-157`, `catalog.py:139-149`) — **LATENT** (gated `product_depth_enabled` `catalog.py:141`); standalone `GET .../items/{id}/variants` (`catalog.py:1167`, 501 when off); owner CRUD `catalog.py:1155/1180`. **C++ MISSING (cutover blocker).**
- **Plan:** add `variants` to `CatalogDtos.kt` (+`CatalogVariantDto{variant_id,sku,option_selections,price_cents,availability}`); `variants`+`optionLabel` on domain + map; "Options" section in `ProductDetailScreen.kt`; if selection drives cart: `selectedVariant` state + post variant SKU + **its** price.
- **Edge/risks:** flag OFF → array absent → hide via tolerant decode; if wired, charged price MUST be variant `price_cents` (money-correctness); **C++ has no variants → cutover blocker if shipped real**; sort option_selections deterministically.
- **Test plan:** **Unit** DTO decode w/ & w/o variants; optionLabel; per-variant price. **UI** Options shows multi-variant / hidden single-SKU. **Manual** flag on, seed variant, verify effective price; (if wired) variant price charged. **Backend** enriched variants against flag-on Python; note C++ absent.
- **Size:** M display-only / L if wired-to-charge or C++ parity required.

---

## TIER 2

### PAR-10 — Group discovery + join · M
- **Assumptions:** CORRECTED — backend has BOTH discover + join live; Android missing discover tab, join, search.
- **iOS ref:** `Groups/CommunityGroupsListScreen.swift:20-22` (mine/discover Picker); `CommunityGroupDetailScreen.swift:70-83` (join when canJoin).
- **Android current:** `feature/groups/GroupsListScreen.kt:102` (my-groups only); `GroupDetailScreen.kt` (leave only, testTag `:52`); `core-network/.../groups/GroupsApi.kt:133` (only `leave()`).
- **Backend:** `GET /ui/groups/discover` (`user_groups.py:95-106`), `POST /ui/groups/{id}/join` (`:156-165`) — EXIST.
- **Plan:** Tab enum + dual state + `loadMyGroups()`/`loadDiscover(query)` in VM; tab Picker + search field; add `joinGroup` to Api+repo; derive `canJoin` (isMember==false); join button (disabled while mutating).
- **Edge/risks:** cancel in-flight on tab switch; debounce search (limit 20–100); private-group visibility; join-already-member→409 snackbar.
- **Test plan:** **Unit** loadDiscover transitions, canJoin. **UI** tab switch retains search; join disabled while mutating. **Manual** discover→join flips to leave. **Backend** discover cursor/has_more; join 200 / member 409.
- **Size:** M.

### PAR-11 — Group fundraiser donation · M  (money-gated)
- **Assumptions:** CORRECTED — Android file `feature/groups/GroupFundraisingScreen.kt` (not `ui/`), view-only. iOS Groups Donate runs StoreKit only (no backend record); the recorded donate lives in `Public/DonationScreen.swift`. Backend donate route is public/unauth.
- **iOS ref:** `Groups/CommunityGroupFundraisingScreen.swift:90-99` (Donate); `Public/DonationScreen.swift:77-121` (StoreKit→`POST /public/fundraisers/{id}/donate` 201→receipt).
- **Android current:** `feature/groups/GroupFundraisingScreen.kt:223-268` (view-only); `GroupFundraisingViewModel.kt` (load/create only); `GroupsRepository.kt:135-144`+`GroupsApi.kt:154-164` (no donate).
- **Backend:** `POST /public/fundraisers/{id}/donate` — EXISTS (Python `group_fundraising.py:204-213`, body `{amount_cents,donor_name,donor_email}`, `_check_enabled` gate; C++ `main.cpp:165126`→`h_grpfund_public_donate:20831`); receipt `:216`. Prod stays `pending` until webhook/ROOT confirm.
- **Plan:** add donate `@POST`+DTOs to `GroupsApi.kt`; `donate()` to repo; **money-gate via `BillingAuthorizer.authorize()` exactly like `data/tip/TipRepository.kt:96-102`** (NotConfigured→PaymentsUnavailable STOP); only on Authorized call endpoint; VM `donate()` w/ `donatingId` guard + "Thanks"+reload; Donate button (active only) + amount dialog.
- **Edge/risks:** MUST gate on BillingAuthorizer (don't hit endpoint on NotConfigured); prod donation `pending`→UI copy "recorded/pending"; no idempotency key→client guard; only status==active shows Donate.
- **Test plan:** **Unit** VM happy/cancel/declined/network via fake repo + `StubBillingAuthorizer` (pattern `TipRepositoryContractTest.kt`); repo asserts POST body + no call on NotConfigured. **UI** Donate only on active; dialog; spinner; snackbar. **Manual** on-device donate→snackbar→refresh. **Backend** POST 201; receipt; 404 when flag off.
- **Size:** M (raised — API/DTO/repo/VM + amount dialog + real money gate).

### PAR-12 — PPV locked-gallery authoring · M
- **Assumptions:** PARTLY — single locked send IS parity; mixed free+locked GALLERY compose missing AND no Android gallery-compose UI exists at all.
- **iOS ref:** `Messaging/GalleryComposeViewModel.swift:19-23` (`DraftItem.isLocked`), `:98-109` (`toggleLock`), `:185-194` (`CreateGalleryMessageBody(freeImages,lockedImages,lockPriceCents)`); `GalleryComposeScreen.swift:41,49,67`.
- **Android current:** `data/messaging/GalleryMessageDtos.kt:33-44` (only `freeImages`); `MessagingRepository.kt:1899-1905` (sends `freeImages` only); no `GalleryCompose*` screen; `StagedMedia` no `isLocked`.
- **Backend:** `POST /messaging/conversations/{id}/messages/gallery` — EXISTS (`messaging.py:9216`); `CreateGalleryMessageIn` (`:2025-2035`) has free_images/locked_images/lock_price_cents/lock_description; validation `:2044-2045` (locked+price together).
- **Plan:** extend req DTO w/ `lockedImages`+nullable `lockPriceCents`; add `StagedMedia.isLocked`; build `GalleryComposeSheet` (grid + per-item lock toggle + price + caption) + VM (`toggleLock`/`updatePrice`/`send`); enforce caps; send() partitions by isLocked, uploads via existing `MediaUploader`, POSTs both lists.
- **Edge/risks:** price 1–100000 cents; free/locked caps separate; preview "N free · M locked at $X"; per-item encryption envelope; retain draft on failure.
- **Test plan:** **Unit** price validation, caps. **UI** lock toggles update counts; send builds both lists; non-payer teaser. **Manual** DM+group mixed gallery, recipient gating. **Backend** POST returns locked gallery gated for non-payer.
- **Size:** M.

### PAR-13 — Scheduled-posts management screen · S
- **Assumptions:** CONFIRMED — composer can schedule, no list/cancel screen.
- **iOS ref:** `Feed/ScheduledPostsScreen.swift:69`; `ScheduledPostsViewModel.swift:32` (GET /posts/scheduled), `:48` (POST /posts/{id}/cancel optimistic).
- **Android current:** `feature/feed/compose/ComposePostScreen.kt:307` (schedule picker); `ComposePostViewModel.kt:132` (onScheduleChange); no management screen.
- **Backend:** `GET /posts/scheduled` (Python `newsfeed.py:3926`, C++ `main.cpp:18014`); `POST /posts/{id}/cancel` (`:4272` / `:17917`) — EXIST.
- **Plan:** CREATE `feature/feed/scheduled/ScheduledPostsScreen.kt`+VM; add `getScheduledPosts(limit,cursor)`+`cancelScheduledPost(id)` to FeedRepository; wire as sheet from Feed toolbar; reuse `FeedPost`+`PostItem`.
- **Edge/risks:** cursor pagination (C++ keyset vs Python offset); optimistic cancel + rollback; post published while open; empty state.
- **Test plan:** **Unit** repo success/404/409/network. **UI** loading→content→empty; cancel. **Manual** create→appears→cancel→removed. **Backend** cancel 404/409/200.
- **Size:** S.

### PAR-14 — File share-links · CLOSE (FALSE GAP — already done)
- **Assumptions:** CORRECTED — Android already has the full share-link lifecycle.
- **Android current:** `feature/share/ShareSheetViewModel.kt:33` (`listLinks:58`, `createLink:104`, `revokeLink:131`); `feature/share/data/ShareRepository.kt:54`; routed from `feature/files/ui/FilesScreen.kt:222,318`.
- **Backend:** `POST/GET /ui/files/share-links`, `DELETE .../{id}` — EXIST (Python `file_share_links.py:41/56/64`, C++ `main.cpp:6379/6420/6430`).
- **Action:** No code. Audit-only: confirm ShareSheet is the primary affordance across all Files entry points + DI wired in all variants; spot-check create-with-expiry/password + revoke on-device.
- **Size:** S (close-out).

### PAR-15 — Profile cover-photo upload · S
- **Assumptions:** CONFIRMED — `MediaKind.COVER` + kind-parameterized `ProfileMediaUploader` already exist; backend accepts `cover`; only UI wiring missing.
- **iOS ref:** `Profile/ProfileScreen.swift:130-132` (cover banner + edit badge, `.cover`).
- **Android current:** `feature/profile/own/OwnProfileScreen.kt:61-68` (avatar only), `OwnProfileRoute:69-71` (picker→AVATAR only); `data/profile/ProfileMediaUploader.kt:50` (accepts kind, never called w/ COVER).
- **Backend:** `POST /ui/profile/photos/{kind}/upload` — EXISTS (C++ `main.cpp:23694-23720`, validates kind∈{profile,cover} `:23699`, writes cover_photo_url `:23713`, 10MB `:23704`). No change.
- **Plan:** confirm `coverPhotoUrl` on model; render 16:9 cover banner + "Change cover" overlay w/ avatar overlapping; `onChangeCoverPhoto`→`mediaViewModel.startUpload(MediaKind.COVER, uri)`; null placeholder.
- **Edge/risks:** null placeholder; avatar/cover z-order; warn if >~5MB (limit 10MB).
- **Test plan:** **Unit** DTO includes coverPhotoUrl. **UI** banner testTag; pencil tappable; picker launches. **Manual** pick→upload→refresh; null→placeholder. **Backend** POST cover multipart 200.
- **Size:** S.

### PAR-16 — Story Highlights · M
- **Assumptions:** CORRECTED — iOS has both Screen + VM; all 5 highlight routes live in Python + C++. Android has only a passive `highlighted` field.
- **iOS ref:** `CoreNetwork/StoriesApi.swift:43-56` (userHighlights/createHighlightGroup/addStoryToHighlight); `Stories/HighlightsScreen.swift:8`; `CoreModel/StoriesDTOs.swift:320-461`.
- **Android current:** `data/stories/StoriesDtos.kt:56` (only `highlighted`); `feature/profile/**` (no highlight refs).
- **Backend:** `GET /ui/stories/highlights/{user_id}` (`stories.py:127`, C++ `165196`); `POST .../groups` (`:136`/`165197`); `DELETE .../groups/{id}` (`:151`/`165198`); `POST /ui/stories/{id}/highlight`+DELETE (`:223`/`:237`, `165203`/`165204`) — ALL EXIST.
- **Plan:** add highlight DTOs; CREATE `HighlightsApi.kt`+`HighlightsRepository.kt` (reuse `call{}`+refresh); provide in `StoriesDataModule.kt`; CREATE `HighlightsViewModel.kt`+`HighlightsScreen.kt` (groups list, create dialog, pin menu); add Highlights row to `PublicProfileScreen.kt`+nav.
- **Edge/risks:** owner-only mutations (hide on others); pin unowned→403; `group_id` omitted serializes absent; epoch created_at; empty state.
- **Test plan:** **Unit** VM load/create/pin/unowned-error + repo contract. **UI** groups render + create dialog + pin menu; Maestro create→pin→in list. **Manual** create group, pin story, view on profile from 2nd device. **Backend** create→GET→group present; pin→GET→segment under group.
- **Size:** M.

### PAR-17 — Viewer clip-from-live broadcast · M
- **Assumptions:** CONFIRMED — no clip button on viewer; `feature/clips/` is consume-only; `ClipsApi.kt` has no create.
- **iOS ref:** `Broadcast/BroadcastViewerScreen.swift:176,352,363` (ClipButton [15,30,60]s); `BroadcastViewerViewModel.swift:514-570` (start=max(0,elapsed-N), createClip, error map `:561`).
- **Android current:** `feature/broadcast/viewer/ViewerScreen.kt` (no clip); `ViewerViewModel.kt:59` (has sessionId); `data/broadcast/BroadcastDomain.kt:35` (`BroadcastSession.startedAt` for elapsed); `data/clips/ClipsApi.kt:33-58` (no create).
- **Backend:** `POST /broadcast/sessions/{id}/clips` — EXISTS (Python `broadcast_clips.py:39`, C++ `main.cpp:165462`); body `{start_seconds,end_seconds,title?}`.
- **Plan:** add `createClip` `@POST`+`CreateClipReqDto`; repo `createClip(...)` mapping quota/rate/disabled; VM `createClip(lastSeconds)` (elapsed from `startedAt`, fallback wall-clock) + banner + `isCreatingClip`; floating clip IconButton over player w/ [15,30,60]s menu.
- **Edge/risks:** only while live; rate-limit 1/30s + quota banners; async-processing message; clamp start>=0; timeline origin fallback.
- **Test plan:** **Unit** elapsed/start/end math; quota/rate/disabled banners; not-live guard. **UI** clip button while live, opens picker; Maestro clip-30s→success. **Manual** clip last 30s on A15→appears in gallery. **Backend** POST clip → ClipOut; repeat <30s → rate-limit.
- **Size:** M.

### PAR-18 — Story viewer report/block · S (safety)
- **Assumptions:** CONFIRMED — no ⋯ safety menu on Android story viewer; reply/react parity confirmed. All plumbing exists.
- **iOS ref:** `Stories/StoriesViewer.swift:305-324` (storySafetyMenu report/block, hidden on own), `:63` (.safetyActions).
- **Android current:** `feature/stories/StoryViewerScreen.kt:186-206` (only Close), `:268-339` (reply/react parity). Reusable: `feature/report/ContentReportHost.kt:31` (`ContentReportSheetHost`), `data/report/ModerationReportApi.kt:33` (POST moderation/reports); Block: `core/ui/blocking/BlockConfirmDialog` + `feature/blocking/BlockInteractionViewModel` (used `PublicProfileScreen.kt:371-380`).
- **Backend:** `POST moderation/reports` + block endpoint — EXIST (proven live rails). Confirm story `content_type` value vs server enum.
- **Plan:** add `MoreVert` IconButton (hidden if own) → DropdownMenu Report/Block; host `ContentReportSheetHost` w/ `ReportTarget.Content(storyId,authorId)`; reuse `BlockInteractionViewModel`+`BlockConfirmDialog` as in PublicProfile; pause playback while menu/sheet open.
- **Edge/risks:** hide on own; pause auto-advance; idempotent already-reported; after block skip author; verify story content_type accepted.
- **Test plan:** **Unit** menu suppressed for isOwnStory. **UI** MoreVert on other's story→menu; Report launches sheet; Block launches dialog; playback pauses. **Manual** report+block from viewer; block reflected on profile. **Backend** POST report → report_id; block → in block list.
- **Size:** S.

### PAR-19 — Payout cancel button · S
- **Assumptions:** CONFIRMED — `PayoutsRepository.cancelPayout`+`PayoutsApi` already exist; near-done UI wiring. iOS Cancel is in `Payouts/PayoutHistoryScreen.swift` (not a PayoutDetailScreen).
- **iOS ref:** `Payouts/PayoutHistoryScreen.swift:146-149` (isCancelable=requested/pending), `:181-205` (destructive+confirm), `:207-221` (cancel→api→status+onChange).
- **Android current:** `feature/payouts/PayoutDetailScreen.kt:120-225` (read-only); `PayoutDetailViewModel.kt:58-72` (load only); EXISTS `data/payouts/PayoutsRepository.kt:59/102-104`, `PayoutsApi.kt:66-67`, `PayoutStatus`+`PayoutActionResult` (`PayoutsDomain.kt:36-59`).
- **Backend:** `POST /ui/payouts/{id}/cancel` — EXISTS (Python `creator_payouts.py:91-96` user-scoped, C++ `main.cpp:165602`).
- **Plan:** VM `cancel()`→`cancelPayout(id)`→reload + in-flight flag + one-shot error (reuse injected `BillingErrorMapper:43`); when status==REQUESTED render destructive Cancel + confirm + footer copy.
- **Edge/risks:** Cancel only for REQUESTED (backend rejects terminal); in-flight+confirm vs double-tap; reversal→no BillingAuthorizer; consider nav-result to refresh history.
- **Test plan:** **Unit** cancel success(status→CANCELLED)/4xx/network. **UI** button only for REQUESTED; confirm; spinner→refreshed. **Manual** cancel pending→balance returns. **Backend** POST 200; 4xx on paid.
- **Size:** S.

### PAR-20 — Wallet account-balance breakdown · S
- **Assumptions:** CORRECTED (favorably) — entire data layer already exists, unused. Pure wiring.
- **iOS ref:** `Billing/WalletScreen.swift:93-102` (6-row Account balance), `:56-60` (best-effort).
- **Android current:** `feature/billing/wallet/WalletTransactionsViewModel.kt:83-99` (wallet+ledger only); EXISTS `data/billing/BillingApi.kt:46-47`, `BillingRepository.kt:65/131-132`, `BillingDomain.kt:58-64` (`BillingBalance` 6 fields + mapper `:141-147`).
- **Backend:** `GET /ui/billing/balance` — EXISTS (Python `billing.py:868-884` + `compute_due` `billing_shared.py:232-242`; C++ `main.cpp:165788`).
- **Plan:** add `balance` to UiState; third parallel `async{getBalance()}` in fetch(), fold best-effort (failure doesn't change load); "Account balance" section (6 rows via `formatWalletMoney`, omit null due rows); 6 label strings.
- **Edge/risks:** best-effort (balance fail must not block ledger); duePending/dueSettled nullable; integer cents; consistent currency.
- **Test plan:** **Unit** balance ok→carried; balance fail/ledger ok→Loaded+null; both fail→Error. **UI** 6 rows; null due omitted. **Manual** due/owed/paid match backend. **Backend** GET balance shape.
- **Size:** S (down from S-M).

### PAR-21 — Ad-creative list + detail management · M
- **Assumptions:** CONFIRMED — no list/detail screen; only one-shot create. Android `AdCreative` model lean (missing headline/body/cta/rotation).
- **iOS ref:** `Ads/AdCreativesScreen.swift:20-46`; `AdCreativeDetailScreen.swift:99-109` (asset replace), `:158-221` (PATCH edit), `:136-152` (submit), `:226-272` (AttachDiscountSheet); `AdCampaignDetailScreen.swift:97-112`.
- **Android current:** `feature/ads/create/creative/CreateCreativeScreen.kt`+`CreateCreativeViewModel.kt:240-311` (create/upload/submit); `core-network/.../ads/AdsAccountsApi.kt:157-181` (no list/get/PATCH/DELETE); `data/discounts/AffiliateDiscountsApi.kt:31-40` (read-only); `AdCampaignDetailScreen.kt:135-208` (no Creatives link); `core-model/.../ads/AdCreate.kt:25-33`.
- **Backend:** ALL EXIST + mounted (Python `ads.py` prefix `/ui/ads`: GET creatives `:273`, GET `:279`, PATCH `:290` body `CreativeUpdateIn` `models.py:4994`, DELETE `:304`, upload `:315`, submit `:333`; affiliate `ad_creative_affiliate.py:46/71/100/125`; C++ `main.cpp:36334/36343/36354/36464/36477/36534` + `:41253`).
- **Plan:** add list/get/PATCH/DELETE + `CreativeUpdateIn` DTO; widen creative DTO+model+mapper; add affiliate attach/remove; CREATE `feature/ads/creatives/data/AdCreativesRepository.kt` + `ui/AdCreativesListScreen.kt`+VM + `AdCreativeDetailScreen.kt`+VM (reuse `ProfileMediaUploader`+OS-picker seam, edit dialog + rotation Slider + discount section); nav + register in `AuthenticatedGraph.kt`; "Creatives" button in `AdCampaignDetailScreen.kt`.
- **Edge/risks:** not money-gated; PATCH/DELETE idempotent, submit not (guard in-flight); PATCH only draft/pending; affiliate flag-gated 404→hide; asset-replace image-only (video iOS-only); 403 ownership.
- **Test plan:** **Unit** VM list/detail(404 discount hidden)/update/delete/submit/asset-fail; repo mapping. **UI** list nav; edit PATCH round-trip; submit disabled while busy; discount toggle. **Manual** create draft→list→detail→replace→edit→attach discount→submit. **Backend** JSON DTO tests pinning snake_case (`models.py:4994`, `ad_creative_affiliate.py:46`).
- **Size:** M.

### PAR-22 — Wishlist → move/add to cart · S
- **Assumptions:** CONFIRMED — only remove/refresh/add-heart.
- **iOS ref:** `Wishlist/WishlistScreen.swift:83-91` (Move to cart, disabled !available); `WishlistViewModel.swift:71-100` (optimistic remove→addCatalogItem→remove).
- **Android current:** `feature/wishlist/WishlistViewModel.kt:78-86` (remove only, ctor `:39` repo-only); `WishlistScreen.kt:150-156/218-230` (onRemove only); `data/wishlist/WishlistRepository.kt:28-50` (no move-to-cart).
- **Backend:** `POST /ui/shoppingcart/carts/{id}/items` (via `CartApi.addItem` `data/cart/CartApi.kt:47-48`; Python `shoppingcart.py:89/105`, C++ `main.cpp:142591`); `DELETE /ui/wishlist/{cat}/{item}` (C++ `164704`) — EXIST. No new backend.
- **Plan (reuse `CartRepository.addToCart`):** `WishlistItem.toCatalogItem()` mapper (default null name/price); inject `CartRepository`; `moveToCart(item)`: addToCart→on Success remove→on Failure `MoveToCartFailed`; per-row in-flight guard; `AddShoppingCart` IconButton (disable !available/in-flight), thread `onMoveToCart`, `MOVE_TO_CART` testTag + snackbar.
- **Edge/risks:** null name/price default + disable when price null; partial failure (add ok/remove fail)→recommend add-first (remove after success) over iOS optimistic; sku=itemId (web parity); NOT money-gated (confirmed).
- **Test plan:** **Unit** success removes/no event; cart Failure emits + no remove; in-flight guard; mapper defaults. **UI** cart button per row; disabled when unavailable; tag. **Manual** save→cart→in Cart, leaves Wishlist; airplane→banner, row stays. **Backend** none new.
- **Size:** S.

### PAR-23 — Ad campaign picker (multi-campaign scoping) · S
- **Assumptions:** PARTLY CORRECTED — `AdsStudioCampaignResolver.kt:42-61` already honors a persisted selection (ADV3-5) + a picker exists in CREATE screens; the 3 STUDIO editors (targeting/scheduling/optimization) lack an in-screen picker.
- **iOS ref:** `Ads/AdCampaignDetailScreen.swift:97-112` (editors constructed with campaignId via drill-down).
- **Android current:** `feature/ads/studio/data/AdsStudioCampaignResolver.kt:42-61`; `feature/ads/create/data/AdsStudioSelection.kt:47-64` (persisted); consumers w/o picker `AdTargetingViewModel.kt:50-58`, `AdSchedulingViewModel.kt:50-55`, `AdOptimizationViewModel.kt:46-51`; reusable picker logic `CreateCreativeViewModel.kt:131-177`.
- **Backend:** `GET /ui/ads/accounts/{id}/campaigns` + `/accounts` — EXIST (already called via `AdsBillingRepository`). N/A new.
- **Plan:** CREATE reusable `StudioCampaignPicker.kt` (account+campaign dropdown, writes `AdsStudioSelection`); add `resolve()` honoring selection w/o silent first-of-first when >1 campaign; expose accounts/campaigns + `onCampaignSelected` in the 3 VMs (shared helper); render picker atop the 3 screens.
- **Edge/risks:** not money-gated; closes ADV3-5 silent-wrong-campaign risk; new-account clears stale campaign; zero-campaign→NoCampaign; **selection also read by sponsored-post/mass-DM compose VMs** — changing it changes their prefill (acceptable, note it).
- **Test plan:** **Unit** resolver honors selection; onCampaignSelected writes+reloads; NoCampaign. **UI** picker shows current; switch reloads+persists across VM recreate. **Manual** ≥2 campaigns: switch in Targeting, reopen Scheduling on same. **Backend** none new.
- **Size:** S.

### PAR-24 — Tax spending summary · M
- **Assumptions:** CORRECTED — router `consumer_tax_documents.py` (prefix `/ui/tax-documents`); summary is EARNINGS (FIN-004), not spend; `/summary` requires `year` OR date range (422 otherwise) — iOS calls it with no year (which 422s here).
- **iOS ref:** `Billing/TaxDocumentsView.swift:39-60` (concurrent, tolerant), `:110-129` (summary section); `CoreNetwork/BillingApi.swift:95-101` (`taxSummary(year:Int?=nil)`).
- **Android current:** `data/taxdocs/TaxDocsApi.kt:24-29` (only /history); `TaxDocsDomain.kt`; `TaxDocsRepository.kt:26-33`; `feature/taxdocs/TaxDocsViewModel.kt:66-91` (list only); `TaxDocsScreen.kt`.
- **Backend:** `GET /ui/tax-documents/summary` — EXISTS (Python `consumer_tax_documents.py:75-90`, `_resolve_range:40-63` requires year OR date_from+date_to else 422; `TaxSpendingSummaryOut` `models.py:10719-10725`; C++ `main.cpp:154263` reg `:170029`).
- **Plan:** add `getSummary(@Query year)` + DTOs — **PASS a year** (default current), do NOT copy iOS no-arg call; domain + mappers (reuse `TaxMoney`); `summary(year)` repo (tolerant); add to UiState + fetch concurrently (mirror iOS tolerance); summary card above list; strings ("Earnings summary" per FIN-004).
- **Edge/risks:** **422 on missing param (primary risk)** — always send year, maybe seed from newest history doc; earnings not spend semantics → all-zero graceful; integer cents+currency; never fail whole screen if only summary fails.
- **Test plan:** **Unit** mapper (empty/zero); VM (summary ok; summary fail/list ok→Content null; both fail→Error); repo asserts `?year=`. **UI** section when present, hidden when null. **Manual** creator w/ earnings→summary; consumer none→graceful. **Backend** `?year=2026` 200; no-param 422.
- **Size:** M (raised — DTO+domain+mapper+repo+VM concurrency+section + year handling).

### PAR-25 — Admin consoles (split into 25a–f) — see Admin section below.

### PAR-26 — Webhook test-send + rotate-secret · S
- **Assumptions:** CONFIRMED — VM load-only; Api lacks both endpoints.
- **iOS ref:** `Webhooks/WebhookDetailViewModel.swift:45-59` (runTest POST /ui/webhooks/{id}/test), `:61-75` (rotateSecret, one-time reveal).
- **Android current:** `feature/webhooks/ui/WebhookDetailViewModel.kt:46-63` (load); `core-network/.../webhooks/WebhooksApi.kt:29-48` (no test/rotate); `WebhooksRepository.kt` (create strips secret `:112`).
- **Backend:** `POST /ui/webhooks/{id}/test` (C++ `h_webhooks_test_endpoint ~94357`; returns `{delivery_id,status,response_code,error,duration_ms}`; unreachable→`status:failed`) + `.../rotate-secret` (`~94397`, returns `{secret}`) — EXIST (reg `:167623/:167636`).
- **Plan:** add `test`+`rotateSecret` `@POST`+DTOs; repo methods via `call{}` (don't cache rotated secret); VM testing/testResult + rotating/rotatedSecret state (non-idempotent POSTs); "Send test"→result card + "Rotate signing secret"→one-time reveal+copy.
- **Edge/risks:** secret shown ONCE; 404 not-found; unreachable host→200 `status:failed` (surface failed not error); 401→login; double-tap guard.
- **Test plan:** **Unit** repo test/rotate (success/404/network); secret not cached. **UI** result card; secret reveal once; disable while in-flight. **Manual** test to real+unreachable URL; rotate+copy. **Backend** failed-vs-success by reachability; rotate returns new secret.
- **Size:** S.

### PAR-27 — Safety Center hub · S
- **Assumptions:** CONFIRMED — all 4 pieces already exist + wired; pure aggregation.
- **iOS ref:** `Safety/SafetyCenterScreen.swift:12-46` (Your data/Safety/Delete sections).
- **Android current (all exist):** `feature/blocking/BlockedUsersScreen.kt` (route `BLOCKED_USERS`), `feature/privacy/PrivacyExportScreen.kt` (`PRIVACY_EXPORT`), DMCA (`MoreRoutes.DMCA`), `feature/privacy/deletion/AccountDeletionScreen.kt`.
- **Backend:** N/A (each screen already wired).
- **Plan:** CREATE `feature/safety/SafetyCenterScreen.kt` (grouped list → 4 existing routes, sections mirroring iOS w/ destructive deletion + grace footer); add `MoreRoutes.SAFETY_CENTER` + register + one MoreCatalog entry.
- **Edge/risks:** avoid duplicate nav destinations; keep deep-links working; destructive styling; back-stack behavior.
- **Test plan:** **Unit** none. **UI** each row→correct existing screen; hub renders 4. **Manual** visit each of 4 flows + return. **Backend** N/A.
- **Size:** S.

### PAR-28 — Report categories 6→10 · M  ⚠ BACKEND-BLOCKED
- **Assumptions:** CORRECTED significantly. Android's 6 = spam/harassment/hate/sexual/violence_threats/other; iOS 10 uses a SINGLE `nudity` (v1 "split nudity" is WRONG). CRITICAL: content-report backend enforces a fixed allow-list `{sexual,extortion,criminal,spam,racist}` (C++ `main.cpp:155580` 422 at `:155616`; Python `moderation.py:31/55`) — web ref `ReportContentModal.tsx:15` uses those 5. **Android's own current codes (harassment/hate/violence_threats/other) already mismatch and would 422 on the content path today.** iOS's 10 would also 422. Message-report path is different (`reason_code` free string 2..64, `main.cpp:145345`).
- **iOS ref:** `Safety/SafetyModels.swift:88-99` (10 topics).
- **Android current:** `data/messaging/report/ReportDomain.kt:10-26` (6 enum); labels `feature/report/ReportSheet.kt:62-69`; strings `res/values/strings.xml:1154-1163`; offered set `data/report/ReportFlow.kt:70-79`; content path `data/report/ReportFlowRepository.kt:117`.
- **Backend:** `POST moderation/reports` — EXISTS but topic-ALLOW-LISTED; `POST .../messages/{id}/report` — free-string.
- **Plan (backend + web + Android):** (1) EDIT `CONT_ALLOWED_TOPICS` (`main.cpp:155580`) + `ALLOWED_TOPICS` (`moderation.py:31`) to add codes; update `cont_mod_priority` (`main.cpp:155585`). (2) EDIT web `ReportContentModal.tsx:15`. (3) EDIT Android enum + strings + `ReportSheet.kt:62-69`. (4) reconcile taxonomy with iOS (single `nudity`, add self_harm/misinformation/impersonation; decide `copyright` topic vs existing DMCA route `ReportSheet.kt:84-86`).
- **Edge/risks:** **latent 422 mismatch (primary)** — verify on-device whether current content reports already 422; message-vs-content path divergence; backend deploy (both stacks) before Android ships; localization.
- **Test plan:** **Unit** exhaustive enum/label `when`. **UI** all topics selectable+submit maps codes. **Manual** file content report w/ each NEW code → 200 after deploy; each OLD code → expose current mismatch. **Backend** allow-list accepts new codes; priority correct; message path unaffected.
- **Size:** M (raised — coordinated backend+web+Android + pre-existing mismatch).

### PAR-29 — Legal screens · S
- **Assumptions:** CONFIRMED — `about` comingSoon, no screen; Terms/Guidelines/Contact/AgeGate absent; no DOB/age-gate in auth/onboarding.
- **iOS ref:** `Legal/LegalConstants.swift:9-33` (termsVersion, minimumAge=18, supportEmail); `Legal/AgeGateView.swift:5-21` (`AgeCheck` whole-year DOB), `:29-50` (reusable DOB picker rejecting <18); About/Terms/Guidelines/Contact screens.
- **Android current:** `MoreRoutes.kt:503` (ABOUT route), `MoreCatalog.kt:1691-1698` (about comingSoon; help comingSoon `:1683`); no legal screens.
- **Backend:** N/A (static; terms-version acceptance client-local DataStore).
- **Plan:** CREATE `feature/legal/LegalConstants.kt` (termsVersion, minimumAge=18, supportEmail, DataStore keys) + `{About,Terms,CommunityGuidelines,Contact}Screen.kt` (About reads BuildConfig; Contact ACTION_SENDTO) + `AgeGate.kt` (AgeCheck + DOB picker rejecting <18) folded into registration/onboarding submit; add routes + flip `about` comingSoon=false + 3 SUPPORT entries.
- **Edge/risks:** UGC compliance — age gate blocks <18 and not pre-satisfied by default date; Terms re-accept on version bump; localize; consistent support email.
- **Test plan:** **Unit** `AgeCheck.isAdult` boundary (17y364d vs 18y); terms re-prompt; alreadyVerifiedAdult. **UI** each screen renders; age gate blocks <18; Contact opens mail. **Manual** open all 4 from More; register w/ <18 DOB blocked. **Backend** N/A.
- **Size:** S (M if age-gate wired into registration).

### PAR-30 — SEO interactive lookup · M  ⚠ C++ gap
- **Assumptions:** CONFIRMED — Android read-only nav-arg; iOS interactive form.
- **iOS ref:** `Seo/SeoScreen.swift:25-58` (mode toggle, type picker `:35`, id/secondary `:38`, path `:42`, submit `:52`); `SeoViewModel.swift:36-74` (canLookup, lookup branches resource vs path).
- **Android current:** `feature/seo/ui/SeoViewModel.kt:33-35` (args-only); `SeoScreen.kt:82-97` ("READ-ONLY diagnostic"); `feature/seo/data/SeoApi.kt:27-38` (already has both `metadata` + `metadataForPath` — API ready).
- **Backend:** `GET /seo/metadata` — EXISTS (`seo_metadata.py:69-91`, params type/id/secondary_id/path/url). No POST; **C++ does NOT implement SEO (Python-only — cutover flag).**
- **Plan:** add form state (mode/type/id/secondary/path) + canLookup + lookup branching (reuse existing SeoApi); build form Composable (segmented mode, conditional picker + fields, submit); pre-populate from nav arg; bump request-gen guard (`SeoViewModel.kt:49`).
- **Edge/risks:** URI-decode path (≤512 chars); secondary_id only for event types; stale-response guard.
- **Test plan:** **Unit** canLookup per mode; branch logic. **UI** conditional picker/inputs; submit uses right params. **Manual** resource (profile/alice) + path (/u/alice); mode toggle. **Backend** `?type=&id=` and `?path=` both 200.
- **Size:** M (raised — form state+validation+branching; API present).

### PAR-31 — Projects: tracked-files list + Drive disconnect · M  ⚠ C++ gap
- **Assumptions:** PARTLY — Drive-disconnect backend + repo `isDriveConnected` hook exist (no `disconnect()` method); tracked-files entirely absent (repo fetches, VM drops per AND-336).
- **iOS ref:** `Projects/ProjectDetailScreen.swift:22-24` (tracked files), `:48-50` (Disconnect); `ProjectDetailViewModel.swift:66-70` (loadDriveStatus), `:139-153` (disconnectDrive).
- **Android current:** `feature/projects/ui/detail/ProjectDetailScreen.kt:160-200/225-264` (header + Drive Connect only); VM `:79-101` (drops files), `:125-149` (connect only); repo `ProjectsRepository.kt:82` (isDriveConnected, no disconnect).
- **Backend:** `GET /v1/projects/{id}/detail` (`projects.py:278-298`, returns project+files+cursor); `GET/DELETE /v1/projects/providers/google_drive/credentials` (`:352/:365`); OAuth `:380` — EXIST. **Python-only (not C++).**
- **Plan:** repo `disconnectGoogleDrive()` (DELETE credentials); VM `disconnectGoogleDrive()` (→driveConnected=false, 401→login); Disconnect (destructive) button when connected; tracked-files: propagate `files[]` into Content state + render list (reuse iOS `ProjectFileRow`) — can defer as separate AND-336.
- **Edge/risks:** destructive confirm; reconnect needs fresh OAuth; 404 on credential read is normal; tracked-files is scope-creep beyond disconnect.
- **Test plan:** **Unit** VM connected→disconnecting→not-connected; 401. **UI** Disconnect when connected→flips to Connect; files render. **Manual** connect→Disconnect→reverts. **Backend** DELETE 200/204 then GET 404.
- **Size:** M (disconnect alone S; +tracked-files).

### PAR-32 — Bots "Send test" · S
- **Assumptions:** CORRECTED — bots feature NOT absent (full CRUD exists); only `sendTest` missing.
- **iOS ref:** `Bots/BotsListScreen.swift:57-61` (send-test sheet), `:109` (row menu→sendTest).
- **Android current:** `feature/bots/BotsListScreen.kt:262-330` (menu, no send-test); `BotsListViewModel.kt` (create/toggle/delete); `data/bots/BotsApi.kt:21-91`+`BotsRepository.kt:15-73` (no sendTest).
- **Backend:** `POST /bots/{id}/send` — EXISTS (`chat_bot.py:210-225`, `SendBotMessageIn{text,conversation_id}` `:71`; 409 inactive/404 not-found).
- **Plan:** add `@POST("ui/bots/{botId}/send") sendTest`; repo method; VM `onSendTest`; `BotSendTestSheet` (conversationId+text); menu item + sheet state in BotCard; reuse `SendBotMessageIn` as req DTO.
- **Edge/risks:** 409 inactive→snackbar; validate conversationId/text; sheet state at Route level.
- **Test plan:** **Unit** repo 409/404/network. **UI** menu→sheet→submit→result. **Manual** active bot echoes in conversation. **Backend** 409 on paused bot.
- **Size:** S.

### PAR-33 — Activity feed rows tappable · S
- **Assumptions:** CONFIRMED — rows clickless though DTO carries ids.
- **iOS ref:** `Activity/ActivityScreen.swift:51-72` (NavigationLink by targetType→PostDetail else profile).
- **Android current:** `feature/activity/ActivityFeedScreen.kt:204-245` (no onClick); `data/activity/ActivityDomain.kt:58-71` (actorId/targetType/targetId present); routes exist `TlDestinations.kt:357-363` (PostDetailDest), `:272-279` (PublicProfileDest).
- **Backend:** N/A (DTO fields present).
- **Plan:** add `onNavigate` through Route→Screen→row; derive target (targetType contains "post" && targetId→PostDetail; else actorId→PublicProfile; else none); wrap row `Modifier.clickable`.
- **Edge/risks:** null/empty ids→display-only; normalize case; malformed id still navigates (error in detail).
- **Test plan:** **Unit** target derivation post/profile/none. **UI** tap post→PostDetail, follow→profile, none→no-op. **Manual** like/comment→post; follow→profile. **Backend** DTO carries fields (confirmed).
- **Size:** S.

---

## ADMIN CONSOLES (PAR-25 split)

### PAR-25a — Admin Impersonation console · P2 · L
- **Assumptions:** CONFIRMED — no Android impersonation screen.
- **iOS ref:** `Admin/AdminImpersonationScreen.swift:1-174` (audit `:load`, start `:36`, stop `:51`; cards `:112-128`, start sheet `:133-173`).
- **Android current:** none.
- **Backend:** `POST /admin/impersonation/start` (`admin_impersonation.py:68`), `/stop` (`:152`), `GET /audit` (`:192`); gated `require_impersonation_operator:28`, 403, TTL-capped; C++ present. **Prefix `/admin/impersonation` (no `/v1`).**
- **Plan:** CREATE `data/adminimpersonation/AdminImpersonationApi.kt`+DTOs+Repository+Hilt (copy `data/kycadmin/KycBusinessAdminApi.kt` scaffolding); CREATE `feature/adminimpersonation/AdminImpersonationScreen.kt`+VM (mirror `KycBusinessAdminViewModel`; reuse `feature/adminops/AdminOpsCommon.kt` scaffold + error map; start ModalBottomSheet); CREATE `navigation/AdminImpersonationNavigation.kt` (clone `KycReviewNavigation.kt:24-33`) + register in `MainActivity.kt`; MoreCatalog admin-gated entry.
- **Edge/risks:** role gating (client pre-check + backend 403 final); opens real sessions → confirm before start + destructive Stop; server-side audit; privileged-target 403.
- **Test plan:** **Unit** VM (audit→content/empty; start; stop refresh; 401→AUTH/403→Forbidden/IO→NETWORK). **UI** active-vs-past; Stop only active; start validation; Forbidden for non-admin. **Manual** admin start+stop→audit; non-admin deep-link→Forbidden. **Backend** paths/bodies (no /v1); 403/expired.
- **Size:** L.

### PAR-25b — Admin Entitlements console · P2 · M
- **Assumptions:** CONFIRMED — no Android screen.
- **iOS ref:** `Admin/AdminEntitlementsScreen.swift:1-142` (revoke/extend/credits `:63-68`; bounds extendHours 1–8760, creditUnits 1–1,000,000 `:48/108`; reason-code Picker `:117`).
- **Android current:** none.
- **Backend:** `POST /v1/admin/entitlements/{id}/{revoke,extend,credits}` (`admin_entitlements.py:48/85/124`, prefix `/v1/admin/entitlements`); bodies reason_code+audit_comment(+extend_hours/credit_units); C++ present.
- **Plan:** CREATE `data/adminentitlements/AdminEntitlementsApi.kt`+DTOs (+`reasonCodes`) reusing KYB scaffolding; CREATE `feature/adminentitlements/AdminEntitlementsScreen.kt` (single form: id field + action SegmentedButton + conditional numeric + reason dropdown + comment + Apply; reuse `AdminOpsCommon.kt`); nav + register + MoreCatalog.
- **Edge/risks:** mirror iOS bounds before submit; reason required; credits money-adjacent→double-submit guard; 403→Forbidden; unknown id→server error.
- **Test plan:** **Unit** canSubmit per action/bounds; correct endpoint+body; error map. **UI** action switch shows/hides numeric; Apply gated; picker; Forbidden. **Manual** revoke+extend+credit seeded entitlement + audit. **Backend** three paths/bodies; reason enum.
- **Size:** M.

### PAR-25c — Admin Usage leaderboard · P3 · M  ⚠ flag-gated
- **Assumptions:** CONFIRMED missing; backend **LATENT** (404 unless `open_bank_project_enabled` && `metrics_leaderboard_enabled`).
- **iOS ref:** `Admin/AdminUsageScreen.swift:1-88` (dimension consumers/endpoints `:47`, metric cost/calls/units `:52`, `leaderboard(...,topN:20)` `:24`, rows `:70-79`, disabled→friendly 404).
- **Android current:** none.
- **Backend:** `GET /v1/admin/api-usage/leaderboard` (`admin_usage.py:475`, 404 `:485-486` unless both flags; max_top_n default 100); C++ present. Read-only.
- **Plan:** CREATE `data/adminusage/AdminUsageApi.kt`+`UsageLeaderboardDto` (map 404→distinct "not available" state); CREATE `feature/adminusage/AdminUsageScreen.kt`+VM (dimension+metric, reload on change, two SegmentedButtonRows, LazyColumn rows, micros→$ formatter — check adminops for existing helper); nav + register + MoreCatalog.
- **Edge/risks:** flag-gated 404 expected on DEV_MODE box → informational empty, NOT error; 403→Forbidden; top_n clamped; micros formatting.
- **Test plan:** **Unit** dimension/metric change→reload query; 404→disabled/403→Forbidden/200→content. **UI** picker toggles reload; disabled message; rows show metrics. **Manual** flags off→friendly; (if on) Top-N. **Backend** params+shape; confirm 404 detail.
- **Size:** M.

### PAR-25d — Admin Notification templates · P3 · M
- **Assumptions:** CONFIRMED — no Android screen.
- **iOS ref:** `Admin/AdminNotificationsScreen.swift:1-152` (templates `:24`, toggle setActive `:38`, testSend `:53`; card `:93-97`; TestSendSheet `:121-150`).
- **Android current:** none.
- **Backend:** `GET /ui/admin/notifications/templates` (`admin_notifications.py:29`), `GET /templates/{id}` (`:38`), `PATCH /templates/{id}` (`:50`), `POST /templates/{id}/test-send` (`:87`); C++ present. **Prefix `/ui/`.**
- **Plan:** CREATE `data/adminnotifications/AdminNotificationsApi.kt`+`NotificationTemplateDto` reusing KYB scaffolding; CREATE `feature/adminnotifications/AdminNotificationsScreen.kt` (list VM, per-row toggle optimistic/refetch, ModalBottomSheet test-send + validation; reuse `AdminOpsCommon.kt`); nav + register + catalog.
- **Edge/risks:** toggle/test-send may 403→surface; recipient validation; double-toggle; empty state.
- **Test plan:** **Unit** list; toggle flips+403; testSend. **UI** toggle updates row; sheet validation; Forbidden. **Manual** toggle template + test send. **Backend** PATCH+test-send paths (`/ui/` prefix + body keys).
- **Size:** M.

### PAR-25e — Admin KYB review · S  (FALSE GAP — already done)
- **Assumptions:** CORRECTED — fully implemented (385-line screen), arguably ahead of iOS (has optimistic-lock `expected_version`).
- **Android current:** `feature/kycadmin/KycBusinessAdmin.kt:1-385` (VM fetch/setStatus/refresh `:113-176`, screen `:164`, decide approve/reject w/ `version` `:180-197`; statuses/reason-codes `:74`; test tags `:200-213`; route `:216+`); `data/kycadmin/KycBusinessAdminApi.kt`; nav `KycReviewNavigation.kt:24` (`ROUTE="admin/kyc/business"`).
- **Backend:** `/v1/kyc/business-cases/admin/{queue,{id},screen,approve,reject}` (`kyc_business.py:297-351`); C++ present. Paths match.
- **Action:** CLOSE as done. Optional: confirm reason-code parity; add a 409/stale-version "case changed, reload" message + instrumented coverage.
- **Size:** S (verification only).

### PAR-25f — Admin Email unsuppress + SMS send-test · P2 · M
- **Assumptions:** CONFIRMED — Android folds Email+SMS into read-only `feature/admin/MessagingDashboardScreen.kt` ("read-only - AC2" `:95/139/164/382`). iOS has full dashboards PLUS the mutations → gap is only the 2 mutations.
- **iOS ref:** `Admin/AdminEmailScreen.swift:43-47/106-110` (unsuppress DELETE); `Admin/AdminSmsScreen.swift:43-47/122-166` (sendTest + SmsSendTestSheet phone+body).
- **Android current:** `feature/admin/MessagingDashboardScreen.kt:98/111` (Email/Sms routes read-only, inert rows `:382-384`); nav `MessagingDashboardNavigation.kt`.
- **Backend:** Email `GET /ui/admin/email/suppressed` (`admin_email.py:85`), `DELETE /suppressed/{email:path}` (`:94`); SMS `GET /ui/admin/sms/suppressed` (`admin_sms.py:67`), `POST /send-test` (`:105`); C++ present.
- **Plan:** add suppressed GET + email `@DELETE .../suppressed/{email}` (encoded path) + sms `@POST .../send-test` to a MessagingAdminActions Api (reuse dashboard repo io{}); VM channel-specific fetch + `unsuppress(address)` (email) + `sendTest(phone,body)` (sms) — update the read-only AC comment; screen suppression section w/ per-row Unsuppress (email) + paperplane→send-test ModalBottomSheet (sms); keep read-only tiles.
- **Edge/risks:** `{email:path}`/phone URL-encoding; mutations 403→Forbidden; send-test may hit real pipeline (confirm + E.164 validate); unsuppress destructive→confirm; shared VM diverges per channel (guard to avoid send-test on email tab).
- **Test plan:** **Unit** unsuppress removes/403; sendTest validation+dispatch; channel-gating. **UI** email rows show Unsuppress; sms paperplane→sheet validation; Forbidden hides actions. **Manual** unsuppress seeded email; send test SMS. **Backend** DELETE {email:path} encoding + POST body; 403/404.
- **Size:** M.

---

## PLATFORM CATCH-UPS

### PAR-P1 — Home-screen widgets (Glance) · M
- **Assumptions:** CONFIRMED — `testlogon://` + DeepLinkRouter reusable; no Glance/AppWidget; incoming-call notifier exists but no ongoing-call MediaStyle.
- **iOS ref:** `Widgets/QuickActionsWidget.swift:4-6/49/51` (4 actions, `testlogon://widget/<action>`); `Widgets/{Call,Broadcast,RentalCountdown}LiveActivity.swift`; `RootView.swift:245-258` (widget URL handler).
- **Android current:** `AndroidManifest.xml:51-62/140-416` (no widget host); `navigation/applink/DeepLinkRouter.kt:1-137`; `feature/call/incoming/IncomingCallNotifier.kt:22`; no glance/appwidget in gradle.
- **Backend:** N/A.
- **Plan:** add `androidx.glance:glance-appwidget`; CREATE `res/xml/quick_actions_widget_provider.xml` (static) + `res/layout/quick_actions_widget.xml` + `feature/widgets/QuickActionsWidgetReceiver.kt` (4 PendingIntents→`testlogon://widget/{newPost,messages,discover,home}`); manifest receiver + intent-filter; extend DeepLinkParser widget host→tab nav; OPTIONAL `notifications/OngoingCallNotification.kt` (MediaStyle FGS) + CALL_ONGOING channel.
- **Edge/risks:** responsive small/medium; keep static (battery); deep-link buffering before nav ready; glance API 24+.
- **Test plan:** **Unit** DeepLinkParser widget host. **UI** onUpdate sets PendingIntents. **Manual** place widget, tap each→correct tab/action. **Backend** N/A.
- **Size:** M (+~1d if ongoing-call notif).

### PAR-P2 — App Shortcuts / assistant · S
- **Assumptions:** CONFIRMED — no shortcuts.xml/ShortcutManager/meta-data; scheme + androidx.core present.
- **iOS ref:** `AppIntents/TestLogonAppIntents.swift:6-56` (4 intents), `:61-88` (AppShortcuts provider); `AppRouteCoordinator.swift:1-31`.
- **Android current:** `AndroidManifest.xml:51-62/140-416`; DeepLinkParser reusable; no shortcuts artifacts.
- **Backend:** N/A.
- **Plan:** CREATE `res/xml/shortcuts.xml` (4 static→`testlogon://shortcut/{action}`); manifest meta-data + shortcut intent-filter; extend DeepLinkParser shortcut host→tab+action; icons; OPTIONAL Phase 2 dynamic via ShortcutManagerCompat; Phase 3 `<capability>` App Actions.
- **Edge/risks:** vector drawables all API levels; distinct hosts (shortcut vs widget); static XML fine on minSdk 24.
- **Test plan:** **Unit** DeepLinkParser shortcut host. **UI** launcher shortcuts resolve label/icon→URI. **Manual** long-press icon→4 shortcuts→navigate. **Backend** N/A.
- **Size:** S.

### PAR-P3 — Rich push (preview + image + direct-reply) · M  (== existing task #77)
- **Assumptions:** CORRECTED — PushPayload too minimal (title/body only); needs senderName/imageUrl/conversationId; Coil already a dep; backend send supports `client_request_id`.
- **iOS ref:** `NotificationService/NotificationService.swift:47-61` (mutable-content NSE: sender title, decrypted body, image attachment 8s), `:126-137` (fallback "📷 Photo").
- **Android current:** `notifications/PushPayload.kt:12-18` (+parser `:36-49`); `NotificationPresenter.kt:56` (BigTextStyle only); `push/TlFirebaseMessagingService.kt:36` (no image download); Coil `libs.versions.toml:18/113-115`.
- **Backend:** `POST /conversations/{id}/messages` (`messaging.py:8285`); `client_request_id` (`:1886-1892`) for idempotent reply.
- **Plan:** extend PushPayload (senderName/imageUrl/conversationId/threadId)+parser; replace BigTextStyle with `MessagingStyle` (MESSAGE kind) + `BigPictureStyle` when image + `RemoteInput` reply Action; CREATE `notifications/DirectReplyReceiver.kt` (RemoteInput→`MessagingRepository.sendOutbox(conversationId,clientId=UUID,text,replyTo=messageId)`); pre-download image via Coil (~4s) in FCM service; pass `clientRequestId` through sendOutbox.
- **Edge/risks:** image download must not block display (~15s deadline); offline reply→fail-toast now (durable queue = PAR-P4); fresh UUID per reply; parser tolerates missing fields (degrade to BigText).
- **Test plan:** **Unit** MessagingStyle builder; DirectReplyReceiver→sendOutbox args. **UI** mock RemoteMessage w/ image→thumbnail + reply action. **Manual** cross-device message w/ sender+image→lock-screen sender title+thumbnail; direct-reply posts. **Backend** client_request_id dedup on retry.
- **Size:** M.

### PAR-P4 — Offline mutation queue · L
- **Assumptions:** CONFIRMED w/ find — a messaging-scoped `OutboxMessageEntity`+`OutboxDao` already exist and are wired into `MessagingRepository`, but NO drain worker/retry/connectivity trigger/banner/dead-letter, and `sendOutbox` omits `client_request_id`. Not fully greenfield.
- **iOS ref:** `Sync/MutationQueueRunner.swift:1-101` (durable FIFO `:13-18`, cancel-before-send `:50-55`, drain `:57-87` [2xx/404/409 remove; retry backoff; maxRetries=5 `:22`→dead-letter; transport error→stop], retry() `:89-94`).
- **Android current:** `core-data/.../messaging/MessagingEntities.kt:255-279` (OutboxMessageEntity); `MessagingDao.kt:131-148` (OutboxDao, no drain ops); `data/messaging/MessagingRepository.kt:83-100+` (sendOutbox, no client_request_id/drain); reuse `core-network/.../csrf/CsrfInterceptor.kt` + `auth/SessionAuthenticator.kt` (single-flight 401); no ConnectivityObserver.
- **Backend:** `POST /conversations/{id}/messages` (`messaging.py:8285`); `client_request_id` (`:1886-1892`, ≤128 chars) — reuses existing endpoints.
- **Plan:** add getAllPending(FIFO)/markFailed/bumpRetry/reset to OutboxDao; `drainOutbox()` + pass clientRequestId in `MessagingRepository`; CREATE `data/messaging/OutboxDrainWorker.kt` (CoroutineWorker, CONNECTED, backoff, success on 2xx/404/409, dead-letter after 5) + `data/sync/ConnectivityObserver.kt` (NetworkCallback→enqueue) + `data/sync/SyncStateRepository.kt` (pending/failed/isDraining) + `feature/messaging/ui/SyncBanner.kt`; register observer + worker in app module.
- **Edge/risks:** dup enqueue→rely on client_request_id dedupe; maxRetries=5→dead-letter+manual retry; single-flight 401 via SessionAuthenticator; process-death safe (Room); decide generalize cross-domain vs messaging-scoped (scope risk driving L).
- **Test plan:** **Unit** worker FIFO/outcomes/backoff; SyncStateRepository counts; observer triggers; drain 2xx/404/409/retry/markFailed. **UI** SyncBanner visibility/text/retry; enqueue offline→online. **Manual** airplane send→enqueue→reconnect drains; 6 offline sends→5 ok+1 dead-letter→retry; CSRF rotation mid-drain. **Backend** client_request_id dedupe; 404/409 as already-applied.
- **Size:** L.

### PAR-P5 — Broadcast host ongoing notification · S
- **Assumptions:** CONFIRMED — no FGS/ongoing notification for host; `feature/call/service/CallForegroundService.kt` is the model; backgrounded-publish reliability IS at risk.
- **iOS ref:** `Broadcast/LiveActivity/BroadcastActivityController.swift:14-36` (start/update viewer count/end).
- **Android current:** host publish real (`data/webrtc/RealBroadcastPublisher.kt`, `feature/broadcast/host/IngestViewModel.kt`); NO FGS in `feature/broadcast/**`; model `feature/call/service/CallForegroundService.kt` + `CallForegroundController.kt:40`; manifest already has `FOREGROUND_SERVICE_CAMERA/MICROPHONE` (`AndroidManifest.xml:33-35,566-568`).
- **Backend:** N/A (viewer count via `data/broadcast/BroadcastViewerCountApi.kt`).
- **Plan:** CREATE `feature/broadcast/host/service/BroadcastHostForegroundService.kt` (near-copy of CallForegroundService, FGS type camera|microphone, START_STICKY, "You're live"+viewer count+tap-to-return) + `BroadcastHostForegroundController.kt` (edge-triggered on publish active/stop); manifest register; wire from host publish lifecycle.
- **Edge/risks:** Android 14 FGS type enforcement; don't double-hold w/ call FGS (distinct IDs/channels); stop reliably on crash; OEM background limits; audio-only room→microphone-only type.
- **Test plan:** **Unit** controller edge-trigger. **UI** service posts ongoing notif w/ correct FGS type. **Manual** go live A15, Home 60s+, return→stream stayed up + notification present→tap returns. **Backend** viewer-count feeds text if wired.
- **Size:** S.

---

## FOLLOW-UP RECOMMENDED (new)
An **ads-admin / tenants / roles / subscription-tiers parity sweep**: iOS has `Admin/AdminTenantsScreen`, `AdminRolesScreen`, `AdminSubscriptionTiersScreen`, `AdminAdPlatformScreen`, `AdminAdCreativeReviewScreen`, `AdminAdFraudScreen` — some mirrored on Android (`adplatform/AdPlatformScreen.kt` exists), several apparently not. Worth a scoped diff before committing to build. (Android is AHEAD on ops: `adminops/{AuditExports,Risk,PaymentHealth,Financials}Screen` have no iOS equivalent.)

## NOT DOING — iOS-platform-only
- CallKit → Android Telecom `TestLogonConnectionService.kt` (parity).
- VoIP/PushKit → FCM + full-screen intent (`CallPushHandler.kt`/`IncomingCallNotifier`).
- StoreKit/Apple IAP (digital goods, subs, tips) → Android card rail (`BillingAuthorizer`). Do NOT copy.
- PDFKit viewer → Chrome Custom Tabs.
- Edition SFW/EU build lanes → App-Store construct; low priority on Android.

---

## BACKEND FOLLOW-UP BACKLOG (deferred; each needs a backend change + prod cpp redeploy)
The LIVE prod API is the C++ backend (testlogon-cpp); these are gaps that block the corresponding Android parity tickets until the backend ships.

- **BE-1 — /moderation/reports content_type allow-list** (unblocks PAR-18 story report): accepts `feed_post/feed_comment/feed_media/profile_photo`; REJECTS `story/clip/catalog_item/user` (422). Add `story` (+ `clip`) to the content_type allow-list in cpp `main.cpp` + Python `moderation.py`. Small.
- **BE-2 — report TOPIC allow-list** (PAR-28): topic allow-list is `{sexual,extortion,criminal,spam,racist}`; add self_harm/misinformation/impersonation/copyright etc. cpp + Python + web reference (`ReportContentModal.tsx`). Android's current 6 codes already partly mismatch — reconcile.
- **BE-3 — cart purchase payment_method_id** (PAR-08): `CartPurchaseIn` + `ui_purchase_cart`/`purchase_cart` (cpp `h_shoppingcart_purchase` + Python) do not accept a chosen payment method → checkout picker is cosmetic. Add the param end-to-end.
- **BE-4 — port SEO metadata to cpp** (PAR-30): `GET /seo/metadata` is Python-only → 404 on prod cpp. Port the handler.
- **BE-5 — port Projects + Google-Drive endpoints to cpp** (PAR-31): `/v1/projects/*` (detail w/ files, credentials get/delete, OAuth) Python-only → 404 on prod cpp.
- **BE-6 — port product variants to cpp** (PAR-09): variant enrichment + `/items/{id}/variants` Python-only + flag-gated `product_depth_enabled`.
- **BE-7 — group-call signal drain endpoint** (PAR-02): `relay_signal` writes an in-memory queue with NO read/drain path (blocks group-call media on BOTH platforms). Add a drain (GET) or fan onto messaging events poll, cpp + Python.
