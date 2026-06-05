# TestLogon — Native Android Port: Engineering Plan

**Status:** Draft v1 · **Date:** 2026-06-05 · **Author:** Android port working group
**Target repo location:** `testlogon/android/` (monorepo subfolder)
**Backend (dev):** `http://18.222.237.167:8000` (us-east-2 EC2 `i-08f937fc705ebea75`). *Dev host — treat as intermittently available.*
**Build host:** Ubuntu 26.04 server (`andrioiddev`, 8-core, KVM emulator available) — JDK 17, Android SDK 35, Kotlin 2.x, Gradle 8.9.

---

## 0. How to read this document

This plan is organized so we can start narrow (auth) and widen safely. Sections 1–6 are the
foundation everything else depends on; read them first. Section 7 is the feature-by-feature
catalog — every screen area in the existing web app, with endpoints, Android screens, complexity,
dependencies, and risks. Section 8 sequences the work into shippable milestones. Sections 9–11
cover estimation, risks, and the definition of done.

Complexity scale used throughout: **S** (≤2 days), **M** (3–5 days), **L** (1–2 weeks),
**XL** (3+ weeks), per engineer, including UI, data layer, and tests.

---

## 1. Goals, non-goals, and guiding principles

### 1.1 Goals
- Ship a **native Kotlin/Jetpack Compose** Android client for the TestLogon platform that reuses the
  existing FastAPI backend with **no backend changes required** for the initial milestones.
- Reach **feature parity incrementally**, prioritized by user value, starting with authentication.
- Establish an architecture that scales to ~59 feature areas without collapsing into a monolith.
- Be resilient to a **flaky dev backend**: configurable base URL, timeouts, retries, offline cache,
  and honest error states.

### 1.2 Non-goals (initially)
- No reimplementation of **admin/ops-only** surfaces (admin dashboards, dev-tools, agent fleet
  management, compute/k8s/EC2 consoles) in the first several milestones — these are desktop-oriented
  and low-value on mobile.
- No backend/protocol redesign. Where the web app relies on browser-only mechanisms (cookies, SSE,
  WebRTC in-browser), we adapt on the client rather than change the server.
- No tablet/foldable-optimized layouts in v1 (responsive-friendly but phone-first).

### 1.3 Principles
1. **Contract-first.** The backend's OpenAPI (`/openapi.json`, ~3.3 MB) and the web app's
   `src/api/endpoints/*.ts` are the source of truth for request/response shapes.
2. **Thin, typed data layer.** One Retrofit service per domain, Moshi DTOs mirroring the TS types,
   repositories that expose domain models + `Result`-style outcomes.
3. **Unidirectional UI.** Compose screens render immutable UI state from a ViewModel; events flow up.
4. **Parity, not pixel-copy.** Match behavior and information architecture; use Material 3 idioms
   instead of literally porting Tailwind/Radix markup.
5. **Ship vertical slices.** Each milestone is an end-to-end, testable, demoable capability.

---

## 2. Current system overview (what we are porting)

### 2.1 Backend
- **FastAPI + DynamoDB**, ~1,370 Python modules, routers under `app/routers`, services under
  `app/services`. Public OpenAPI doc at `/docs`, machine spec at `/openapi.json`.
- Endpoint families observed (non-exhaustive): `/ui/*` (the primary app API), `/messaging/*`,
  `/broadcast/*`, `/api/billing/*`, `/v1/kyc/*`, `/questionnaires/*`, `/tickets/*`, `/saml/*`,
  `/auth/root/login`, plus provider **mocks** under `/mock/*` (CCBill, PayPal, UPS, Google Calendar,
  Jira) used in dev.
- **Auth is cookie-based.** The browser holds a session cookie plus a `ui_csrf` cookie that is echoed
  back as the `X-CSRF-Token` header on mutating requests. A short-lived bearer token field exists in
  the web auth store but is effectively empty for normal users — **the session cookie is the real
  credential.** On `401`, the web client calls `POST /ui/session/refresh` once and retries.

### 2.2 Frontend (reference implementation)
- **Vite + React 18 + TypeScript**, Tailwind 4, Radix UI, TanStack Query, Zustand stores, i18next,
  Leaflet (maps), hls.js (video), framer-motion.
- ~59 route groups under `src/pages/*`, a typed API layer under `src/api/endpoints/*.ts`
  (~230 endpoint modules) and shared types in `src/api/types.ts`.
- Real-time features use **Server-Sent Events** (e.g. `/messaging/events/stream`,
  `/broadcast/.../chat/stream`) and **WebRTC** (calls, broadcast guest inputs).

### 2.3 Authentication flow (confirmed from `Login.tsx` + `auth.ts` + `types.ts`)
```
POST /ui/session/start   body: { challenge_context: { username, password } }
   → { auth_required, challenge_id?, required_factors[], session_id? }
If auth_required:
   per factor in required_factors:
     TOTP:  POST /ui/mfa/totp/verify   { challenge_id, totp_code }
     SMS:   POST /ui/mfa/sms/begin     { challenge_id }  then  /ui/mfa/sms/verify { challenge_id, code }
     EMAIL: POST /ui/mfa/email/begin   { challenge_id }  then  /ui/mfa/email/verify { challenge_id, code }
     RECOVERY: POST /ui/mfa/recovery/{factor} { challenge_id, recovery_code }
   POST /ui/session/finalize { challenge_id, remember_device } → { status, session_id }
GET /ui/me → { user_sub, session_id, ip }
```
Adjacent flows: **register** (`/ui/register/start|confirm|resend|check`), **password recovery**
(`/ui/password-recovery/start|confirm` + challenge variants), **passwordless/magic-link**
(`/ui/passwordless/start|verify`), **WebAuthn** (`/ui/webauthn/*`), **SSO/SAML** (`/sso`, `/saml/*`),
and **session management** (`/ui/sessions`, `/ui/session/refresh|logout`, revoke).

---

## 3. Target Android architecture

### 3.1 Tech stack
| Concern | Choice | Rationale |
|---|---|---|
| Language | Kotlin 2.0.x | Modern, coroutines, null-safety |
| UI | Jetpack Compose + Material 3 | Declarative, maps cleanly to React component model |
| Navigation | Navigation-Compose (typed routes) | Single-activity, deep-link friendly |
| DI | Hilt | Standard, scales to many feature modules |
| Async | Coroutines + Flow | Structured concurrency, reactive UI state |
| Networking | Retrofit + OkHttp + Moshi | Typed, interceptor-friendly, codegen adapters |
| Persistence | Room (cache) + DataStore (prefs/settings) | Offline cache + small key/value config |
| Images | Coil | Compose-native image loading |
| Video | Media3/ExoPlayer (+ HLS) | Native HLS playback to replace hls.js |
| Real-time | OkHttp SSE / OkHttp WebSocket | Match server's SSE; WS where applicable |
| Paging | Paging 3 | Infinite feeds/messages/search |
| Testing | JUnit, Turbine, MockWebServer, Compose UI test | Unit + contract + UI |

### 3.2 Module structure (Gradle, grow into this)
```
android/
  app/                      # application module, DI wiring, navigation host, theme
  core/
    core-network/           # OkHttp, cookie jar, CSRF, base-URL, error mapping, SSE
    core-model/             # shared domain models, Result/ApiError types
    core-ui/                # design system: Material3 theme, shared composables
    core-data/              # Room, DataStore, base repository utilities
    core-testing/           # test fixtures, MockWebServer helpers
  feature/
    feature-auth/           # login, MFA, register, recovery, passwordless, sessions
    feature-feed/           # content feed
    feature-messaging/      # conversations, threads, search, calls entry points
    feature-...             # one module per domain (added per milestone)
```
We start with a single `app` module + a few `core` modules, and **split features into modules as
they land** to keep build times and ownership manageable.

### 3.3 Layering (per feature)
- **data**: Retrofit `*Api` interface, Moshi DTOs, `*RepositoryImpl`, mappers, cache DAOs.
- **domain** (where logic is non-trivial): models, use-cases, the auth state machine.
- **ui**: Compose screens, `*ViewModel` exposing `StateFlow<UiState>`, one-shot events via `Channel`.

### 3.4 Navigation map (v1 shell)
- **Unauthenticated graph:** Login → MFA → (Register / Password Recovery / Magic-Link / WebAuthn).
- **Authenticated graph:** bottom nav with Feed, Messages, Notifications, Search, Profile/Settings;
  the long tail of features reachable via a "More" hub and deep links.

---

## 4. Cross-cutting concerns (foundation that every feature relies on)

### 4.1 Session & auth transport (highest priority foundation)
- **Persistent cookie jar.** OkHttp `CookieJar` backed by DataStore/encrypted prefs so the session
  survives process death and app restarts. This *is* the login state.
- **CSRF interceptor.** Read `ui_csrf` from the jar; set `X-CSRF-Token` on every mutating request,
  mirroring the web client.
- **401 refresh authenticator.** On `401` for an authenticated user, call `/ui/session/refresh` once,
  then retry; on failure, transition to logged-out. Use OkHttp `Authenticator` to avoid retry storms.
- **Base-URL selection.** A `HostSelectionInterceptor` rewrites scheme/host/port from a user-editable
  setting (default = dev host). Lets us switch between dev/hosted/local without rebuilds and survive
  the dev host going down.

### 4.2 Resilience for a flaky dev backend (explicit user requirement)
- Connect/read/write timeouts ~20s; **bounded retry with backoff** for idempotent GETs only.
- Distinguish *network unavailable* vs *server 5xx* vs *auth expired* in UI; never show a blank screen.
- **Offline-first reads** where reasonable: cache last-good responses (Room) and show them with a
  "stale / reconnecting" affordance.
- A lightweight **/health probe + banner** so the user knows when the backend is unreachable.

### 4.3 Error model
- Map FastAPI error bodies (`{detail: string | [{msg}] | {code,...}}`) to a typed `ApiError` and
  port the web client's `normalizeErrorDetail` + authorization-code messages (e.g. `role_required`,
  `geo_blocked`, helpdesk claim codes).

### 4.4 Real-time
- **SSE** via OkHttp `EventSource` for messaging events, presence, broadcast chat, live Q&A.
  Lifecycle-aware (subscribe in `onStart`, cancel in `onStop`), with reconnect/backoff.
- **WebRTC** (calls, broadcast guest input) is a large, specialized effort — deferred to a dedicated
  milestone using `webrtc-android`; first pass may be view-only/HLS where possible.

### 4.5 Media
- **HLS playback** with Media3/ExoPlayer for VOD, clips, broadcast playback (replaces hls.js).
- Image/file uploads use the server's **presign → PUT → confirm** pattern already present in
  messaging/files/KYC endpoints; build one reusable uploader.

### 4.6 Push notifications (FCM)
- Backend supports `PUSH_*`/FCM and exposes `POST /ui/push/register`. Implement FCM, register the
  token post-login, route notification taps to deep links (messages, broadcasts, alerts).

### 4.7 Internationalization
- Server exposes i18n (`/v1/kyc/i18n`, locale endpoints) and the web app ships i18next locale files.
  Port string catalogs into Android resources / Compose; respect device locale + server locale.

### 4.8 Security
- Encrypted storage for cookies/tokens (Jetpack Security / EncryptedSharedPreferences).
- Certificate handling: dev host is plaintext HTTP → scoped cleartext permission via
  `network_security_config` for the dev host only; **enforce HTTPS for any production host.**
- Optional biometric gate (BiometricPrompt) for app re-entry; respect "remember device" semantics.

### 4.9 Theming & design system
- Build `core-ui` Material 3 theme (light/dark, dynamic color) early; provide shared composables
  (buttons, inputs, OTP field, cards, list items, empty/error/loading states) so feature teams move
  fast and stay consistent.

### 4.10 Testing & CI
- Unit tests for repositories (MockWebServer contract tests against captured OpenAPI examples).
- Compose UI tests for critical flows (login, MFA).
- **CI on the build server** (`andrioiddev`): `./gradlew assembleDebug testDebugUnitTest` and
  instrumented tests on the headless KVM emulator (`connectedDebugAndroidTest`).

### 4.11 API client generation strategy
- **Decision point (see §9):** hand-write DTOs/services for the auth slice (small, precise), and
  evaluate **OpenAPI Generator** (kotlin + moshi) for the long tail to avoid hand-porting 230 endpoint
  modules. Likely hybrid: generate models, hand-write thin repositories.

---

## 5. Backend touch-points & assumptions

- **No backend changes** assumed for milestones 1–4. Items that may *eventually* need backend help:
  - A non-cookie (token) auth option would simplify mobile, but is **not required** — cookies work.
  - Push payload/deep-link contract may need minor additions.
  - Some browser-mock provider flows (CCBill/PayPal redirects) need mobile-friendly return URLs.
- **Open questions for the owner** are collected in §10.

---

## 6. Phasing strategy (overview; detail in §8)
1. **M1 Auth foundation** — networking core + login/MFA/session. *(in scope now)*
2. **M2 App shell + read-only core** — navigation, profile/me, notifications, feed (read).
3. **M3 Messaging** — conversations, threads, search, send (text/media), SSE live updates.
4. **M4 Content consumption** — feed interactions, VOD/clips/videos (HLS), discover/search.
5. **M5 Commerce** — shop/cart/checkout, purchases, subscriptions, fan-club, billing basics.
6. **M6 Creator tools** — earnings/payouts, content calendar/scheduler, broadcasts (view→host).
7. **M7 Specialized** — calls (WebRTC), KYC, files/signing, questionnaires, groups/orgs/syndicates.
8. **M8 Long tail & admin-lite** — ads, agents, helpdesk, webhooks, remote, analytics (as needed).

---

## 7. Feature-by-feature port catalog

> Each entry lists: purpose · key endpoints (representative) · Android screens · notable client work ·
> complexity · dependencies · risks. Grouped by domain; every `src/pages/*` area is covered.

### 7.1 Authentication & account security  *(M1)*
**Areas:** `login`, `register`, `password-recovery`, `magic-link-verify`, `security`, `settings`(auth).
- **Endpoints:** `/ui/session/start|finalize|refresh|logout`, `/ui/me`, `/ui/sessions(/revoke|revoke_others)`,
  `/ui/mfa/totp|sms|email/*`, `/ui/mfa/recovery/{factor}`, `/ui/register/*`, `/ui/password-recovery/*`,
  `/ui/passwordless/*`, `/ui/webauthn/*`, `/sso`, `/saml/*`.
- **Screens:** Login, MFA (TOTP/SMS/Email/recovery), Register (+confirm/resend), Password recovery
  (start/challenge/confirm), Magic-link handoff, Active sessions list (revoke), MFA device management.
- **Client work:** cookie jar, CSRF, 401-refresh, OTP input, deep link for magic link, WebAuthn via
  Credential Manager / FIDO2 (later sub-task), SSO via Custom Tabs.
- **Complexity:** L (the foundation). **Deps:** §4.1–4.3. **Risks:** cookie/CSRF correctness; WebAuthn
  and SAML/SSO redirects on mobile.

### 7.2 App shell, profile & settings  *(M2)*
**Areas:** `dashboard`, `profile`, `settings`, `preferences`, `notifications`, `activity`, `saved`, `achievements`.
- **Endpoints:** `/ui/me`, `/ui/profile/meta/{identifier}`, `profile.ts`, `preferences.ts`,
  `notifications.ts`, `activityFeed.ts`, `bookmarks.ts`/`saved`, `achievements.ts`.
- **Screens:** Home/dashboard, Public + own profile, Settings hub, Notification center, Activity feed,
  Saved/bookmarks, Achievements/leaderboard.
- **Complexity:** M. **Deps:** M1. **Risks:** breadth of settings surface — port incrementally.

### 7.3 Messaging & contacts  *(M3 — large)*
**Areas:** `messages`, `contacts`, `helpdesk`, `groups`.
- **Endpoints:** `/messaging/conversations*` (DM/group, drafts, search, gallery, pins, reactions,
  scheduled, tips, unlock, polls, find-datetime), `/messaging/events/stream` (SSE), `/messaging/presence*`,
  `/messaging/contacts/search`, mass-messages, helpdesk queue/claim.
- **Screens:** Conversation list, Thread (rich messages: text/image/video/file/voice/gif/sticker/poll/
  countdown/calendar), Composer with attachments + presign upload, Search (in-convo + global),
  Contacts, Group management, Helpdesk inbox.
- **Client work:** SSE live updates, Paging 3 history, typing/read receipts, presence heartbeat,
  attachment pipeline, optimistic send.
- **Complexity:** XL. **Deps:** M1, §4.4–4.5. **Risks:** message-type breadth; real-time reliability.

### 7.4 Content feed, discovery & search  *(M2 read / M4 interact)*
**Areas:** `feed`, `discover`, `search`, `stories`, `polls`, `gallery`, `clips`.
- **Endpoints:** `newsfeed.ts`, `discovery.ts`, `search.ts`, `recommendations.ts`, `stories.ts`,
  `polls.ts`, `postHide.ts`/`postInteresting.ts`, `gallery.ts`, `clips.ts`.
- **Screens:** Feed (posts, media, unlock/paywall), Post detail, Discover/tags, Global search, Stories
  viewer, Clip viewer, Gallery.
- **Complexity:** L. **Deps:** M1, media (§4.5). **Risks:** paywall/unlock + entitlement logic.

### 7.5 Video: VOD, videos, watch-parties  *(M4)*
**Areas:** `videos`, `vod`, `watch-parties`, `clips`.
- **Endpoints:** `vod.ts` (+ rental/purchase-tiers/ad-supported/watermark-download), `videos.ts`,
  `watchParties.ts`, broadcast clips.
- **Screens:** Video library, VOD detail + player (HLS, DRM/watermark considerations), Purchase/rental
  flow, Watch-party room (sync playback + chat).
- **Complexity:** L–XL. **Deps:** Media3/ExoPlayer, commerce (M5 for purchase). **Risks:** DRM/watermark,
  watch-party sync.

### 7.6 Live broadcasting  *(M6 view → host)*
**Areas:** `broadcast`, `calls`(live), `live-qa`.
- **Endpoints:** the large `/broadcast/sessions/*` surface (chat SSE, tips, goals, products, Q&A,
  privacy, guests/inputs via WebRTC, playback-url, schedule/start/stop, viewers/heartbeat),
  `/ui/live-qa/*`.
- **Screens (viewer first):** Browse/scheduled broadcasts, Viewer (HLS playback + live chat + tips +
  shelf/products + Q&A), then **host** (camera/mic via WebRTC, controls, moderation).
- **Complexity:** XL (host side). **Deps:** SSE, WebRTC, media, payments. **Risks:** WebRTC ingest is
  the single biggest technical risk; stage viewer-only first.

### 7.7 Calls (1:1 and group)  *(M7)*
**Areas:** `calls`.
- **Endpoints:** `/messaging/messages/calls/*` (invite/accept/decline/end/signal/turn-credentials/
  heartbeat), `/ui/calls/group/*`, call recording consent/upload.
- **Screens:** Incoming/outgoing call UI, in-call controls, group call grid, settings (mic/cam),
  call history, recording consent.
- **Complexity:** XL. **Deps:** WebRTC, push (call invites), §4.4. **Risks:** background call handling,
  ConnectionService integration, TURN reliability.

### 7.8 Commerce: shop, cart, purchases  *(M5)*
**Areas:** `shop`, `purchases`, `saved`(wishlist).
- **Endpoints:** `cart.ts`, catalog/`shop`, `purchases.ts`, `/ui/checkout/session*`, carrier tracking,
  cart-abandonment.
- **Screens:** Catalog/category, Product detail, Cart, Checkout, Purchase history + tracking.
- **Complexity:** L. **Deps:** billing (§7.9). **Risks:** payment redirect handling on mobile.

### 7.9 Billing & payments  *(M5)*
**Areas:** `billing`, `earnings`(payout side in 7.11), `invoices`, `disputes`, `refunds`, `tax`.
- **Endpoints:** `/api/billing/*` and `/ui/billing/*` (Stripe/PayPal/CCBill/us-bank/microdeposits),
  `invoices.ts`, `billingDisputes.ts`, `refundRequests.ts`, `taxDocuments.ts`, `taxForm1099.ts`.
- **Screens:** Payment methods, Add card (Stripe SDK / hosted), Invoices, Disputes, Refund requests,
  Tax documents.
- **Client work:** integrate **Stripe Android SDK**; PayPal/CCBill via Custom Tabs with deep-link
  return; handle us-bank microdeposit verification.
- **Complexity:** L–XL. **Deps:** M1. **Risks:** PCI scope, provider redirect/return URLs, mock vs real.

### 7.10 Subscriptions, fan-club, groups, orgs, syndicates, collaborations  *(M5–M7)*
**Areas:** `subscriptions`, `fan-club`, `groups`, `orgs`, `syndicates`, `collaborations`, `delegates`.
- **Endpoints:** `subscriptions.ts`, `/ui/fan-club/*`, `/ui/groups/*`, `/ui/orgs/*`, `/ui/syndicates/*`,
  `collaborations.ts`/revenue, `delegates.ts`/delegation API.
- **Screens:** Subscription tiers + manage, Fan-club channels (chat-like), Group/org/syndicate
  membership & roles, Collaboration deals, Delegate (manage-as-creator) mode.
- **Complexity:** L (per area). **Deps:** M1, messaging patterns. **Risks:** role/permission matrices.

### 7.11 Earnings & monetization for creators  *(M6)*
**Areas:** `earnings`, `payouts`, `referrals`, `affiliates`, `promo`.
- **Endpoints:** `earnings.ts`, `payouts.ts` (+ bulk tools), `referrals.ts`, `affiliates.ts`,
  `promoCodes.ts`, per-content-revenue, engagement-rate.
- **Screens:** Earnings dashboard + charts, Payout setup/history, Referrals, Affiliate links,
  Promo codes.
- **Complexity:** M–L. **Deps:** charts lib, KYC (payouts may gate on KYC). **Risks:** financial
  accuracy/display.

### 7.12 Scheduling & calendar  *(M6)*
**Areas:** `calendar`, `content-calendar`, `scheduler`.
- **Endpoints:** `calendar.ts` (+ Google Calendar mock/integration), `content-calendar.ts`, `scheduler.ts`,
  broadcast schedule, message scheduling.
- **Screens:** Calendar views, Content calendar, Scheduler; ICS/Google sync.
- **Complexity:** M–L. **Deps:** date/recurrence handling. **Risks:** timezone + recurrence correctness.

### 7.13 Files, gallery, sharing & e-signing  *(M7)*
**Areas:** `files`, `gallery`, `signing`, share-links.
- **Endpoints:** `files.ts`, `fileShareLinks.ts`, `googleDrive.ts`, `signaturePackets.ts`,
  `signatureTemplates.ts`, `licenseAgreements.ts`.
- **Screens:** File manager (browse/upload/download via presign), Share links, Gallery, Signing
  (view packet, place signature, submit), Templates.
- **Complexity:** L. **Deps:** uploader (§4.5), PDF rendering. **Risks:** signature capture + legal flow.

### 7.14 KYC / identity verification  *(M7 — large, specialized)*
**Areas:** `kyc` (30+ endpoint modules: documents, eIDV, facial comparison, liveness call, residency,
proof-of-funds, screening, tiers, business, address).
- **Endpoints:** `/v1/kyc/*`, `kyc*.ts`.
- **Screens:** KYC tier status & requirements, Document capture (camera), ID scanner, Liveness
  (camera/video call), Address/residency, Proof of funds, Case status.
- **Complexity:** XL. **Deps:** CameraX, possibly a 3rd-party SDK for liveness/ID; gates payouts/tiers.
- **Risks:** device camera variance, vendor SDK, compliance correctness.

### 7.15 Projects, questionnaires, tickets, helpdesk  *(M7–M8)*
**Areas:** `projects`, `questionnaires`, `tickets`, `helpdesk`.
- **Endpoints:** `projects.ts`, `questionnaires.ts` (+ published respondent sessions), `tickets.ts`,
  helpdesk queue/claim.
- **Screens:** Project list/detail, Questionnaire builder (low priority on mobile) + **respondent**
  (high priority), Ticket spaces/threads, Helpdesk agent inbox.
- **Complexity:** L. **Deps:** M1, messaging patterns. **Risks:** dynamic form rendering for questionnaires.

### 7.16 Advertising platform  *(M8 — mostly desktop/creator-advanced)*
**Areas:** `ads` (campaigns, targeting, creatives, analytics, scheduling, optimization, boost,
sponsorships, billing, fraud).
- **Endpoints:** `/ui/ads/*`, `ads*.ts`, `contentBoost.ts`, `sponsorshipDeals.ts`.
- **Screens:** Advertiser dashboard, Campaigns, Creatives, Targeting, Analytics, Boost, Sponsorship inbox.
- **Complexity:** XL (full), but **mobile scope can be read/light-manage**. **Deps:** charts, billing.
- **Risks:** large surface; prioritize boost + sponsorship inbox, defer full campaign editor.

### 7.17 Trust, safety, privacy & moderation  *(threaded through; M2+)*
**Areas:** `dmca`, moderation, privacy/account-deletion, blocking, risk-scoring.
- **Endpoints:** `dmca.ts`, `moderation.ts`, `/ui/privacy/account-deletion/*`, `blocking.ts`,
  `/ui/account/*` (suspend/reactivate/closure).
- **Screens:** Block/report flows (embedded in content/messages), DMCA submit, Privacy & data export,
  Account deletion/closure, Account status.
- **Complexity:** M. **Deps:** M1. **Risks:** legal/irreversible actions — strong confirmations.

### 7.18 Admin, agents, infra, devtools  *(M8+ / likely out-of-scope for mobile)*
**Areas:** `admin`, `agents`/`bots`, `remote`, `webhooks`, `analytics`, `licenses`, devtools, compute/
k8s/ec2/instance monitoring, SSH bastion, VNC.
- **Endpoints:** `/ui/admin/*`, `/ui/agents/*`, `/ui/agent/memory/*`, `webhooks.ts`, `analytics.ts`,
  license modules, `sshBastion.ts`, `vnc.ts`.
- **Recommendation:** **De-scope for mobile v1.** If needed, ship read-only dashboards/alerts only.
- **Complexity:** XL if fully ported. **Risks:** these are operator tools poorly suited to phones.

### 7.19 Public / unauthenticated surfaces  *(M2/M4)*
**Areas:** public profile `/u/:id`, public event, share link, donation, public clip, public
questionnaire respond.
- **Screens:** Public profile, Public event, Shared download, Donation flow, Public clip, Respondent.
- **Complexity:** M. **Deps:** deep links (App Links), media. **Risks:** unauthenticated entitlement.

---

## 8. Milestone roadmap (sequenced, demoable slices)

**M1 — Auth foundation** *(scope of the upcoming first PR)*
- core-network (cookie jar, CSRF, 401-refresh, base-URL selection, error mapping, timeouts/retry),
  core-model, core-ui theme skeleton.
- feature-auth: Login + MFA (TOTP/SMS/Email/recovery) + finalize + `/ui/me` + logout + active sessions.
- Configurable server URL screen; health banner.
- **Done =** real login against the dev host on the emulator, MFA, session persists across restart,
  logout; unit + UI tests; builds in CI on the server.

**M2 — App shell & read-only core:** navigation, dashboard, profile (own+public), settings hub,
notifications, activity, saved, achievements; feed (read-only).

**M3 — Messaging:** conversations, threads (core message types), search, send text+image, SSE live,
presence, contacts.

**M4 — Content consumption:** feed interactions, discover/search, VOD/clips/videos (HLS), stories.

**M5 — Commerce:** shop/cart/checkout, purchases, subscriptions, fan-club, billing (Stripe + redirect
providers), invoices.

**M6 — Creator tools:** earnings/payouts, calendar/scheduler/content-calendar, broadcasts (viewer),
referrals/affiliates/promo.

**M7 — Specialized:** calls (WebRTC), KYC, files/gallery/signing, questionnaires (respondent),
groups/orgs/syndicates/collaborations, broadcasts (host).

**M8 — Long tail & admin-lite:** ads (boost/sponsorship first), helpdesk, tickets, projects,
webhooks/analytics (read), public surfaces polish.

---

## 9. Effort & sequencing notes
- **Rough order-of-magnitude** (1 engineer): M1 ~2 wks · M2 ~3 wks · M3 ~4–5 wks · M4 ~3–4 wks ·
  M5 ~4 wks · M6 ~4 wks · M7 ~6–8 wks (WebRTC+KYC heavy) · M8 ~ongoing. Parallelizable across 2–3
  engineers once module boundaries exist (after M1–M2).
- **API client generation decision (do during M1):** prototype OpenAPI Generator (kotlin/moshi)
  against `/openapi.json`; if the generated models are clean, adopt **generated models + hand-written
  repositories** to avoid hand-porting ~230 endpoint modules. Keep auth hand-written regardless.
- **Module split:** keep M1–M2 in `app` + `core`, then extract `feature-*` modules starting M3.

---

## 10. Risks & open questions (for the owner)
1. **WebRTC scope** (calls + broadcast host) is the biggest risk — confirm priority vs viewer-only.
2. **KYC vendor** — is identity/liveness a 3rd-party SDK or fully in-house? Affects M7 heavily.
3. **Payments** — which providers must work on mobile first (Stripe vs CCBill/PayPal)? Real vs mock in
   dev? Return-URL/deep-link contract for redirect providers.
4. **Push** — confirm FCM is provisioned; define notification → deep-link payload contract.
5. **Auth token option** — staying cookie-only is fine; confirm no appetite for a mobile bearer-token
   grant (would simplify but needs backend work).
6. **Admin/agent/infra surfaces** — confirm these are **out of scope** for mobile.
7. **Min Android version** — proposing `minSdk 24` (Android 7, ~99% devices); confirm.
8. **Branding/design** — any existing brand kit, colors, typography, app icon to match?
9. **Distribution** — Play Store, internal track, or sideload during development?
10. **Backend stability** — given the dev host is intermittent, can we get a more stable staging URL,
    or should we rely on the configurable base URL + offline cache as planned?

---

## 11. Definition of done (per feature, applied every milestone)
- Screens match web behavior/IA (not pixels); loading/empty/error/offline states implemented.
- Data layer typed against the contract; errors mapped to user-friendly messages.
- Works against the dev backend on the **headless emulator** end-to-end.
- Unit tests (repository/contract) + UI tests for primary flows; lint/format clean.
- Builds green in CI on the build server; demoed on the milestone review.
- Accessibility pass (content descriptions, touch targets, dynamic type) and i18n-ready strings.

---

## Appendix A — Confirmed auth contract (DTO shapes)
```
SessionStartReq    { challenge_context?: { username, password, ... } }
SessionStartResp   { auth_required, challenge_id?, required_factors[], session_id? }
SessionFinalizeReq { challenge_id, remember_device? }
SessionFinalizeResp{ status: "ok"|"pending", session_id?, required_factors[], passed{} }
MeResp             { user_sub, session_id, ip }
SessionInfo        { session_id, is_current, created_at, last_seen_at, ip, user_agent, revoked, revoked_at? }
TotpVerifyReq      { challenge_id, totp_code }
Sms/EmailBeginReq  { challenge_id }      ChallengeResp { challenge_id, sent_to? }
Sms/EmailVerifyReq { challenge_id, code }
RecoveryReq        { challenge_id, recovery_code, factor? }
MfaVerifyResp      { status, session_id?, required_factors[], passed{}, remaining_factors[] }
Register*/PasswordRecovery*/Passwordless*  — see §2.3 and src/api/types.ts
```
Transport: cookies (`credentials: include`) + `X-CSRF-Token` from `ui_csrf` cookie; `401 →
/ui/session/refresh` once → retry.

## Appendix B — Source-of-truth references
- Backend OpenAPI: `http://18.222.237.167:8000/openapi.json` (and `/docs`).
- Web API layer: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/client.ts`, `frontend/src/api/types.ts`.
- Web routes: `frontend/src/App.tsx`; screens under `frontend/src/pages/*`.
- Web auth screen: `frontend/src/pages/Login.tsx`; store: `frontend/src/stores/authStore.ts`.
