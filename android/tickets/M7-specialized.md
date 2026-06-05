# M7 — Specialized (high-complexity) — Tickets

Decomposition of milestone **M7** (epics **E39–E46**). Format: **Type · Priority · Dependencies**,
**Scope**, **Acceptance Criteria**. This is the heaviest milestone (WebRTC + KYC).

**Milestone exit criteria:** 1:1 call works; KYC document capture + tier status; sign a packet;
files/share-links; questionnaire respondent; org/collaboration graph.

---

## Epic E39 — WebRTC foundation

### AND-288 — webrtc-android integration + permissions
**Type:** Feature · **Priority:** P0 · **Deps:** AND-004
**Scope:** Add `webrtc-android`; camera/mic runtime permissions; build wiring.
**Acceptance:** Library links; permissions requested; sample loopback renders.

### AND-289 — PeerConnection wrapper + lifecycle
**Type:** Feature · **Priority:** P0 · **Deps:** AND-288
**Scope:** PeerConnection factory/wrapper, SDP/ICE handling, teardown.
**Acceptance:** Offer/answer/ICE cycle completes in a test harness.

### AND-290 — Signaling transport
**Type:** Feature · **Priority:** P0 · **Deps:** AND-289, AND-143
**Scope:** Signaling over backend (`/signal`), SSE/poll for remote SDP/ICE.
**Acceptance:** Two peers exchange signaling via backend (tested/staged).

### AND-291 — TURN/STUN credentials
**Type:** Feature · **Priority:** P0 · **Deps:** AND-289
**Scope:** Fetch `turn-credentials`; configure ICE servers.
**Acceptance:** ICE uses provided TURN; relay path works behind NAT.

### AND-292 — Media capture + device selection
**Type:** Feature · **Priority:** P1 · **Deps:** AND-288
**Scope:** Camera/mic capture, switch camera, mute, resolution.
**Acceptance:** Capture toggles + camera switch work.

### AND-293 — Video renderer composables
**Type:** Feature · **Priority:** P1 · **Deps:** AND-288
**Scope:** Local/remote `SurfaceViewRenderer` Compose wrappers; scaling.
**Acceptance:** Local + remote video render.

### AND-294 — WebRTC foundation tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-290
**Scope:** Signaling + lifecycle tests (mocked transport).
**Acceptance:** Pass.

---

## Epic E40 — Calls (1:1 + group)

### AND-295 — Call API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `/messaging/messages/calls/*` DTOs (invite/accept/decline/end/signal/timeout/heartbeat).
**Acceptance:** Call payloads map (tested).

### AND-296 — Outgoing call flow
**Type:** Feature · **Priority:** P0 · **Deps:** AND-295, AND-290
**Scope:** Invite, ringing, connect, end; call UI entry from thread/profile.
**Acceptance:** Outgoing 1:1 call connects + ends.

### AND-297 — Incoming call (push + full-screen)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-296, AND-108
**Scope:** FCM call invite → full-screen incoming UI; accept/decline; timeout.
**Acceptance:** Incoming call rings (even backgrounded) and connects on accept.

### AND-298 — In-call UI (1:1)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-296, AND-293
**Scope:** Controls (mute/cam/speaker/flip/end), connection quality, duration.
**Acceptance:** Controls function during a call.

### AND-299 — Group calls
**Type:** Feature · **Priority:** P1 · **Deps:** AND-298
**Scope:** `/ui/calls/group/*`; multi-party signaling/media.
**Acceptance:** 3+ party call connects.

### AND-300 — Group call grid
**Type:** Feature · **Priority:** P1 · **Deps:** AND-299
**Scope:** Adaptive grid, active-speaker, pin.
**Acceptance:** Grid adapts to participant count.

### AND-301 — Call billing
**Type:** Feature · **Priority:** P2 · **Deps:** AND-296, AND-031
**Scope:** `callBilling`/per-minute billing display + auth.
**Acceptance:** Billed call shows cost/auth.

### AND-302 — Call recording consent + upload
**Type:** Feature · **Priority:** P2 · **Deps:** AND-296, AND-129
**Scope:** Consent/decline/request, recording upload presign/complete.
**Acceptance:** Consent flow + upload work.

### AND-303 — Call history
**Type:** Feature · **Priority:** P1 · **Deps:** AND-295
**Scope:** `callHistory.ts` list + detail; callback.
**Acceptance:** History renders; callback initiates.

### AND-304 — ConnectionService / Telecom
**Type:** Feature · **Priority:** P1 · **Deps:** AND-297
**Scope:** Telecom integration for system call UX, audio focus, headset.
**Acceptance:** Calls integrate with system telecom (where supported).

### AND-305 — Calls ViewModels + state machine
**Type:** Feature · **Priority:** P0 · **Deps:** AND-296
**Scope:** Call lifecycle state machine.
**Acceptance:** Unit-tested.

### AND-306 — Calls tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-305
**Scope:** State machine + signaling tests.
**Acceptance:** Pass.

---

## Epic E41 — Broadcast hosting

### AND-307 — Host session create/schedule
**Type:** Feature · **Priority:** P1 · **Deps:** AND-278
**Scope:** Create/schedule/cancel-schedule session.
**Acceptance:** Host can create + schedule a session.

### AND-308 — WebRTC ingest
**Type:** Feature · **Priority:** P0 · **Deps:** AND-307, AND-290
**Scope:** `inputs` + `webrtc-offer` publish camera/mic to the broadcast.
**Acceptance:** Host stream is ingested + viewable.

### AND-309 — Host controls
**Type:** Feature · **Priority:** P0 · **Deps:** AND-308
**Scope:** start/stop/resume/reschedule, health report.
**Acceptance:** Lifecycle controls work live.

### AND-310 — Inputs management
**Type:** Feature · **Priority:** P1 · **Deps:** AND-308
**Scope:** Activate/deactivate inputs; multiple sources.
**Acceptance:** Inputs switch live.

### AND-311 — Layout management
**Type:** Feature · **Priority:** P2 · **Deps:** AND-310
**Scope:** `layout` get/set scenes.
**Acceptance:** Layout changes apply.

### AND-312 — Guest invites & management
**Type:** Feature · **Priority:** P2 · **Deps:** AND-308
**Scope:** guest-invites accept/revoke; promote/mute/remove guests.
**Acceptance:** Guest join + manage work.

### AND-313 — Moderation
**Type:** Feature · **Priority:** P1 · **Deps:** AND-281
**Scope:** chat mute/ban, delete/pin, moderation-log; delegate moderation routes.
**Acceptance:** Moderation actions apply + log.

### AND-314 — Goals & products management
**Type:** Feature · **Priority:** P2 · **Deps:** AND-282, AND-283
**Scope:** Manage goals + products/reorder/price.
**Acceptance:** Goals/products CRUD live.

### AND-315 — Tips config & private shows
**Type:** Feature · **Priority:** P2 · **Deps:** AND-282
**Scope:** tips config; private-chat/private show request/accept/end.
**Acceptance:** Private show lifecycle works.

### AND-316 — Ad breaks / ad config
**Type:** Feature · **Priority:** P2 · **Deps:** AND-309
**Scope:** ad-break start/end, ad-config.
**Acceptance:** Ad break triggers.

### AND-317 — Broadcast host ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-308
**Scope:** Host session state machine.
**Acceptance:** Unit-tested.

### AND-318 — Broadcast host tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-317
**Scope:** State + control tests.
**Acceptance:** Pass.

---

## Epic E42 — KYC / identity verification

### AND-319 — KYC API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `/v1/kyc/*` DTOs (tiers/me, requirements, evaluate, cases).
**Acceptance:** KYC payloads map (tested).

### AND-320 — Tier status & requirements
**Type:** Feature · **Priority:** P0 · **Deps:** AND-319
**Scope:** Current tier, requirements for target tier, evaluate.
**Acceptance:** Tier + requirements render; evaluate updates state.

### AND-321 — Document capture + upload
**Type:** Feature · **Priority:** P0 · **Deps:** AND-319, AND-129
**Scope:** CameraX capture; `kycDocuments` upload via presign; templates.
**Acceptance:** Capture + upload a document (tested).

### AND-322 — ID scanner
**Type:** Feature · **Priority:** P1 · **Deps:** AND-321
**Scope:** `kycIdScanner`; guided ID capture (front/back/MRZ).
**Acceptance:** ID scan captures + submits.

### AND-323 — Facial comparison
**Type:** Feature · **Priority:** P1 · **Deps:** AND-321
**Scope:** `kycFacialComparison`; selfie capture + compare.
**Acceptance:** Selfie compare submits + returns result.

### AND-324 — Liveness call
**Type:** Feature · **Priority:** P2 · **Deps:** AND-290, AND-323
**Scope:** `kycLivenessCall`; live agent/automated liveness (WebRTC).
**Acceptance:** Liveness session connects + completes.

### AND-325 — eIDV
**Type:** Feature · **Priority:** P2 · **Deps:** AND-319
**Scope:** `kycEidv` electronic identity verification flow.
**Acceptance:** eIDV submits + status returns.

### AND-326 — Residency / address verification
**Type:** Feature · **Priority:** P2 · **Deps:** AND-321
**Scope:** `kycResidency`/`kycAddressVerification` proof upload + verify.
**Acceptance:** Address proof submits + verifies.

### AND-327 — Proof of funds
**Type:** Feature · **Priority:** P2 · **Deps:** AND-321
**Scope:** `kycProofOfFunds` document submission.
**Acceptance:** Proof submits + status.

### AND-328 — Screening
**Type:** Feature · **Priority:** P2 · **Deps:** AND-319
**Scope:** `kycScreening` status display.
**Acceptance:** Screening status renders.

### AND-329 — Case status + monitoring
**Type:** Feature · **Priority:** P1 · **Deps:** AND-319
**Scope:** `kyc-cases`/`kycMonitoring`; case timeline/status.
**Acceptance:** Case status + history render.

### AND-330 — KYC tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-320, AND-321
**Scope:** Repo + capture-flow tests.
**Acceptance:** Pass.

---

## Epic E43 — Files, gallery mgmt & share links

### AND-331 — Files API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `files.ts` (browse/CRUD/search) DTOs.
**Acceptance:** File payloads map (tested).

### AND-332 — File manager browse
**Type:** Feature · **Priority:** P1 · **Deps:** AND-331
**Scope:** Folder/file browse, search, sort.
**Acceptance:** Browse + search work.

### AND-333 — Upload via presign
**Type:** Feature · **Priority:** P1 · **Deps:** AND-331, AND-129
**Scope:** Upload with progress; folder placement.
**Acceptance:** Upload completes (tested).

### AND-334 — Download / open
**Type:** Feature · **Priority:** P1 · **Deps:** AND-331
**Scope:** Download + open-with; cache.
**Acceptance:** Download + open work.

### AND-335 — Share links (+ public download)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-331, AND-022
**Scope:** `fileShareLinks.ts`; create/revoke; public `/share/:linkId`.
**Acceptance:** Share link works; public page downloads.

### AND-336 — Google Drive integration
**Type:** Feature · **Priority:** P2 · **Deps:** AND-331
**Scope:** `googleDrive.ts` OAuth + import.
**Acceptance:** Connect + import a Drive file.

### AND-337 — Files ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-331
**Scope:** State + paging.
**Acceptance:** Unit-tested.

### AND-338 — Files tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-337
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E44 — E-signing

### AND-339 — Signing API + DTOs
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `signaturePackets.ts`, `signatureTemplates.ts` DTOs.
**Acceptance:** Signing payloads map (tested).

### AND-340 — Packet list + detail
**Type:** Feature · **Priority:** P1 · **Deps:** AND-339
**Scope:** Packets list, detail, status.
**Acceptance:** Packets render; detail opens.

### AND-341 — PDF rendering
**Type:** Feature · **Priority:** P1 · **Deps:** AND-340
**Scope:** Render document pages (PdfRenderer/lib).
**Acceptance:** Multi-page doc renders + scrolls.

### AND-342 — Signature capture + placement
**Type:** Feature · **Priority:** P1 · **Deps:** AND-341
**Scope:** Draw/adopt signature; place fields.
**Acceptance:** Signature placed on doc.

### AND-343 — Submit / sign + licenses
**Type:** Feature · **Priority:** P1 · **Deps:** AND-342
**Scope:** Submit signed packet; `licenseAgreements.ts`.
**Acceptance:** Signed packet submits + confirms.

### AND-344 — Signing ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-339
**Scope:** State machine.
**Acceptance:** Unit-tested.

### AND-345 — Signing tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-344
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

## Epic E45 — Questionnaires (respondent)

### AND-346 — Questionnaire API + DTOs
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `questionnaires.ts` + published respondent sessions DTOs.
**Acceptance:** Questionnaire schema maps (tested).

### AND-347 — Dynamic form renderer
**Type:** Feature · **Priority:** P1 · **Deps:** AND-346, AND-020
**Scope:** Render field types (text/choice/scale/date/upload/etc.) from schema.
**Acceptance:** All field types render + capture input.

### AND-348 — Respondent session
**Type:** Feature · **Priority:** P1 · **Deps:** AND-347
**Scope:** start/save/validate session (`/questionnaires/published/{slug}/sessions/*`).
**Acceptance:** Save + resume a session.

### AND-349 — Submit + PDF (public respond)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-348, AND-022
**Scope:** submit, PDF export; public `/questionnaires/published/:slug/respond` App Link.
**Acceptance:** Submit completes; public link opens respondent.

### AND-350 — Conditional logic / validation
**Type:** Feature · **Priority:** P2 · **Deps:** AND-347
**Scope:** Branching/visibility rules + validation.
**Acceptance:** Conditional fields show/hide; validation blocks invalid submit.

### AND-351 — Questionnaire ViewModels
**Type:** Feature · **Priority:** P1 · **Deps:** AND-346
**Scope:** Form state machine.
**Acceptance:** Unit-tested.

### AND-352 — Questionnaire tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-351
**Scope:** Renderer + validation tests.
**Acceptance:** Pass.

---

## Epic E46 — Orgs, groups, syndicates, collaborations, delegates

### AND-353 — Orgs API + members/roles
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `/ui/orgs/*` members/invite/role.
**Acceptance:** Org members + roles manage (tested).

### AND-354 — Org management screens
**Type:** Feature · **Priority:** P1 · **Deps:** AND-353
**Scope:** Org overview, members, invites.
**Acceptance:** Org screens render + manage.

### AND-355 — Groups (social)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `/ui/groups/*` membership/roles.
**Acceptance:** Group membership renders + manages.

### AND-356 — Syndicates
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `/ui/syndicates/*` (feed, treasury, revenue-split) views.
**Acceptance:** Syndicate overview renders.

### AND-357 — Syndicate open licensing
**Type:** Feature · **Priority:** P2 · **Deps:** AND-356
**Scope:** open-licensing register/list.
**Acceptance:** Licensing flow works.

### AND-358 — Collaborations + revenue
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `collaborations.ts` + revenue split.
**Acceptance:** Collaboration + revenue render.

### AND-359 — Delegates / delegation API
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `delegates.ts`/delegation API; manage-as-creator mode (auth store managingCreator).
**Acceptance:** Enter delegate mode; scoped actions apply.

### AND-360 — Delegate feed/broadcast/messaging
**Type:** Feature · **Priority:** P2 · **Deps:** AND-359
**Scope:** Delegate feed/broadcast/messaging routes.
**Acceptance:** Delegate can act in delegated surfaces.

### AND-361 — Orgs/syndicates ViewModels
**Type:** Feature · **Priority:** P2 · **Deps:** AND-353
**Scope:** State.
**Acceptance:** Unit-tested.

### AND-362 — Orgs/syndicates tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-361
**Scope:** Repo + UI tests.
**Acceptance:** Pass.

---

### M7 ticket count: 75 (E39:7, E40:12, E41:12, E42:12, E43:8, E44:7, E45:7, E46:10)
**Running total through M7:** 362 tickets (AND-001…AND-362).
