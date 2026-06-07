# M2 — App Shell & Read-Only Core — Tickets

Decomposition of milestone **M2** (epics **E08–E17**). Same conventions as
[`M1-auth-foundation.md`](./M1-auth-foundation.md). Ticket format: **Type · Priority · Dependencies**,
**Scope**, **Acceptance Criteria**. Priority: P0 blocks milestone · P1 important · P2 nice-to-have.

**Milestone exit criteria:** a logged-in user lands in the real app shell and can browse profile,
settings, notifications, activity, and a read-only feed; push token registered; locale-aware strings;
offline/stale states work against the flaky dev host.

---

## Epic E08 — Auth extras

### AND-053 — Registration: start
**Type:** Feature · **Priority:** P1 · **Deps:** AND-030
**Scope:** Register screen (full_name/email/password/confirm, delivery method, optional SMS/TOTP MFA
opt-in); `POST /ui/register/start`; map `RegisterStartResp` (verification_required/delivery).
**Acceptance:** Valid form starts registration and routes to confirm; validation + errors surfaced.

### AND-054 — Registration: confirm + resend
**Type:** Feature · **Priority:** P1 · **Deps:** AND-053
**Scope:** Confirm code screen; `/ui/register/confirm`; resend via `/ui/register/resend`.
**Acceptance:** Correct code confirms account; resend works; wrong code shows error.

### AND-055 — Registration: email availability check
**Type:** Feature · **Priority:** P2 · **Deps:** AND-053
**Scope:** Debounced `/ui/register/check` to flag taken emails inline.
**Acceptance:** Taken email surfaces before submit (tested).

### AND-056 — Registration → MFA setup handoff
**Type:** Feature · **Priority:** P1 · **Deps:** AND-054, AND-064
**Scope:** Use `RegisterConfirmResp.mfa_setup`/`sms_phone` to route into MFA enrollment after signup.
**Acceptance:** New user with MFA setup is guided into device enrollment.

### AND-057 — Password recovery: start
**Type:** Feature · **Priority:** P1 · **Deps:** AND-030
**Scope:** Recovery screen; `/ui/password-recovery/start`; render delivery medium/destination + factors.
**Acceptance:** Start returns challenge/delivery and advances UI (tested).

### AND-058 — Password recovery: challenge verification
**Type:** Feature · **Priority:** P1 · **Deps:** AND-057
**Scope:** Challenge variants: `/ui/password-recovery/challenge/{email|sms}/begin|verify`,
`/totp/verify`, `/recovery`.
**Acceptance:** Each challenge path passes/fails correctly (tested).

### AND-059 — Password recovery: confirm new password
**Type:** Feature · **Priority:** P1 · **Deps:** AND-058
**Scope:** `/ui/password-recovery/confirm` (username, code, new_password, challenge_id); strength rules.
**Acceptance:** New password set; user can log in with it (tested).

### AND-060 — Passwordless / magic-link: start
**Type:** Feature · **Priority:** P2 · **Deps:** AND-030
**Scope:** `/ui/passwordless/start`; "check your email" UI with `sent_to`.
**Acceptance:** Start triggers send and shows confirmation state.

### AND-061 — Magic-link deep-link verify
**Type:** Feature · **Priority:** P2 · **Deps:** AND-060, AND-022
**Scope:** App Link for `/magic-link-verify`; `/ui/passwordless/verify`; branch to MFA vs authenticated.
**Acceptance:** Tapping the link in email opens the app and completes/branches auth (tested).

### AND-062 — WebAuthn (passkeys)
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** Credential Manager / FIDO2 for `/ui/webauthn/register|authenticate/begin|finish`.
**Acceptance:** Register + authenticate with a platform passkey on a supported device.

### AND-063 — SSO / SAML login
**Type:** Feature · **Priority:** P2 · **Deps:** AND-030
**Scope:** `getSsoInfo`; Custom Tabs flow for `/sso` and `/saml/login`; return via deep link.
**Acceptance:** SSO-only tenant can sign in via the browser tab and return authenticated.

### AND-064 — MFA device management
**Type:** Feature · **Priority:** P1 · **Deps:** AND-033, AND-077
**Scope:** List/add/remove devices: totp (`devices/begin|confirm|{id}/remove`), sms/email device
variants (begin/confirm/remove).
**Acceptance:** User can enroll a TOTP device (QR/secret), add/remove SMS+email devices (tested).

---

## Epic E09 — Home / dashboard

### AND-065 — Dashboard data layer
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `DashboardApi` + DTOs from `dashboard.ts`; repository.
**Acceptance:** Dashboard payload loads + maps to domain (tested).

### AND-066 — Dashboard screen + widgets
**Type:** Feature · **Priority:** P0 · **Deps:** AND-065, AND-024
**Scope:** Landing with key widgets/cards + quick links; pull-to-refresh.
**Acceptance:** Renders real data; refresh works.

### AND-067 — "More" hub (feature directory)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-024
**Scope:** Grid/list entry point to the long tail of features (deep links), gated by availability.
**Acceptance:** Hub navigates to existing destinations; unavailable items hidden/disabled.

### AND-068 — Dashboard ViewModel + state
**Type:** Feature · **Priority:** P0 · **Deps:** AND-065
**Scope:** `StateFlow` state, loading/error/offline, refresh events.
**Acceptance:** State transitions unit-tested.

### AND-069 — Dashboard states + tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-066, AND-068
**Scope:** Empty/error/offline composables; UI test.
**Acceptance:** All states render; UI test passes headlessly.

---

## Epic E10 — Profile (own + public)

### AND-070 — Profile API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `ProfileApi` from `profile.ts` + `/ui/profile/meta/{identifier}`; DTOs.
**Acceptance:** Own + public profile payloads load/map (tested).

### AND-071 — Own profile screen
**Type:** Feature · **Priority:** P0 · **Deps:** AND-070
**Scope:** View own profile (avatar, bio, stats, links).
**Acceptance:** Renders authenticated user's profile.

### AND-072 — Edit profile (basics)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-071
**Scope:** Edit core fields (name/bio/links) with validation + save.
**Acceptance:** Edits persist and reflect on reload (tested).

### AND-073 — Public profile (`/u/:identifier`)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-070, AND-022
**Scope:** Public profile screen + App Link; handle not-found/private.
**Acceptance:** Public link opens the profile; private/missing handled.

### AND-074 — Profile media upload
**Type:** Feature · **Priority:** P2 · **Deps:** AND-072, AND-117
**Scope:** Avatar/cover upload via presign→PUT→confirm; image crop.
**Acceptance:** New avatar uploads and displays (tested).

### AND-075 — Profile ViewModels
**Type:** Feature · **Priority:** P0 · **Deps:** AND-070
**Scope:** Own/public/edit view models with state + events.
**Acceptance:** Unit-tested state transitions.

### AND-076 — Profile tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-071, AND-073
**Scope:** Repository + UI tests for view/edit/public.
**Acceptance:** Tests pass headlessly.

---

## Epic E11 — Settings & preferences

### AND-077 — Settings hub IA
**Type:** Feature · **Priority:** P0 · **Deps:** AND-024
**Scope:** Settings landing with sections (account, security, notifications, media, appearance, privacy).
**Acceptance:** Hub navigates to each subsection.

### AND-078 — Preferences API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `preferences.ts` endpoints/DTOs; repository.
**Acceptance:** Preferences load/save (tested).

### AND-079 — Media preferences
**Type:** Feature · **Priority:** P1 · **Deps:** AND-078
**Scope:** `/ui/media/preferences` (autoplay, data saver, quality).
**Acceptance:** Toggles persist and apply.

### AND-080 — Notification preferences UI
**Type:** Feature · **Priority:** P1 · **Deps:** AND-078, AND-088
**Scope:** Per-category push/email/SMS toggles surface.
**Acceptance:** Changes persist (tested).

### AND-081 — Appearance/theme settings
**Type:** Feature · **Priority:** P1 · **Deps:** AND-019
**Scope:** Light/dark/system + dynamic color toggle; persisted.
**Acceptance:** Theme switch applies immediately and persists.

### AND-082 — Account settings & status entry
**Type:** Feature · **Priority:** P1 · **Deps:** AND-077, AND-043
**Scope:** Links to sessions, account status (`/ui/account/status`), closure/reactivate entry (handoff
to E50), privacy/data-export entry.
**Acceptance:** Account status shows; destructive actions deep-link with strong confirms (handoff).

### AND-083 — Settings tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-078
**Scope:** Repo + UI tests for preferences round-trip.
**Acceptance:** Tests pass.

---

## Epic E12 — Notifications & alerts

### AND-084 — Notifications API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `notifications.ts` endpoints/DTOs; repository (list, mark read, unread count).
**Acceptance:** List + mark-read map correctly (tested).

### AND-085 — Notification center screen
**Type:** Feature · **Priority:** P0 · **Deps:** AND-084, AND-098
**Scope:** Paged list, read/unread, tap→deep-link, mark-all-read.
**Acceptance:** Renders + paginates; tap routes correctly.

### AND-086 — Alert prefs: email
**Type:** Feature · **Priority:** P1 · **Deps:** AND-078
**Scope:** `/ui/alerts/emails/begin|confirm|remove`, `/ui/alerts/email_prefs`.
**Acceptance:** Add/verify/remove email alert target (tested).

### AND-087 — Alert prefs: SMS
**Type:** Feature · **Priority:** P1 · **Deps:** AND-078
**Scope:** `/ui/alerts/sms/begin|confirm|remove`, `/ui/alerts/sms_prefs`.
**Acceptance:** Add/verify/remove SMS alert target (tested).

### AND-088 — Alert preferences screen
**Type:** Feature · **Priority:** P1 · **Deps:** AND-086, AND-087
**Scope:** Unified alert prefs UI (channels + categories).
**Acceptance:** Prefs render and persist.

### AND-089 — Notifications ViewModel + paging
**Type:** Feature · **Priority:** P0 · **Deps:** AND-084
**Scope:** Paging 3 source, unread badge state.
**Acceptance:** Paging + badge unit-tested.

### AND-090 — Notifications tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-085, AND-089
**Scope:** Repo + UI tests.
**Acceptance:** Tests pass headlessly.

---

## Epic E13 — Activity, saved & achievements

### AND-091 — Activity feed
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027, AND-098
**Scope:** `activityFeed.ts` API + paged screen.
**Acceptance:** Activity renders + paginates.

### AND-092 — Saved / bookmarks
**Type:** Feature · **Priority:** P1 · **Deps:** AND-027
**Scope:** `bookmarks.ts`/saved API + screen; unsave.
**Acceptance:** Saved items list; unsave updates (tested).

### AND-093 — Achievements
**Type:** Feature · **Priority:** P2 · **Deps:** AND-027
**Scope:** `achievements.ts` API + screen (earned/locked).
**Acceptance:** Achievements render with progress.

### AND-094 — Achievements leaderboard
**Type:** Feature · **Priority:** P2 · **Deps:** AND-093
**Scope:** `/ui/achievements/leaderboard/me` view.
**Acceptance:** Leaderboard + own rank render.

### AND-095 — ViewModels (activity/saved/achievements)
**Type:** Feature · **Priority:** P1 · **Deps:** AND-091, AND-092, AND-093
**Scope:** State/paging for the three screens.
**Acceptance:** Unit-tested.

### AND-096 — Tests
**Type:** Test · **Priority:** P2 · **Deps:** AND-095
**Scope:** Repo + UI smoke tests.
**Acceptance:** Tests pass.

---

## Epic E14 — Feed (read-only)

### AND-097 — Feed API + DTOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-027
**Scope:** `newsfeed.ts` endpoints/DTOs (posts, media, paywall flags); repository.
**Acceptance:** Feed page maps incl. locked/paywall metadata (tested).

### AND-098 — Feed list (Paging 3)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-097
**Scope:** Paging 3 source + UI list, refresh, pagination loading/error footers.
**Acceptance:** Infinite scroll + refresh work against backend.

### AND-099 — Post item composable
**Type:** Feature · **Priority:** P0 · **Deps:** AND-098, AND-103
**Scope:** Render text, media grid, author header, timestamps, link previews.
**Acceptance:** Common post shapes render correctly.

### AND-100 — Post detail screen
**Type:** Feature · **Priority:** P1 · **Deps:** AND-099
**Scope:** Full post view (no interactions yet); deep link.
**Acceptance:** Opens a post by id; renders media.

### AND-101 — Paywall / locked display
**Type:** Feature · **Priority:** P1 · **Deps:** AND-099
**Scope:** Locked-content placeholder + price/CTA (unlock deferred to M4 E24).
**Acceptance:** Locked posts show paywall affordance, not content.

### AND-102 — Feed ViewModel + state
**Type:** Feature · **Priority:** P0 · **Deps:** AND-097
**Scope:** Paging state, refresh, error/offline.
**Acceptance:** State unit-tested.

### AND-103 — Feed media thumbnails
**Type:** Feature · **Priority:** P1 · **Deps:** AND-019
**Scope:** Coil image loading, placeholders, aspect handling, data-saver respect.
**Acceptance:** Images load with placeholders; cancelled on scroll.

### AND-104 — Feed tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-098, AND-102
**Scope:** Paging + UI tests.
**Acceptance:** Tests pass headlessly.

---

## Epic E15 — Push notifications (FCM)

### AND-105 — FCM integration + Firebase config
**Type:** Feature · **Priority:** P0 · **Deps:** AND-004
**Scope:** Add Firebase, `google-services` config per flavor, `FirebaseMessagingService`.
**Acceptance:** App receives a test FCM message in foreground/background.

### AND-106 — Push token registration
**Type:** Feature · **Priority:** P0 · **Deps:** AND-105, AND-029
**Scope:** Register token via `POST /ui/push/register` after login; store mapping.
**Acceptance:** Token registered post-login; verified server-side (tested w/ MockWebServer).

### AND-107 — Notification channels + display
**Type:** Feature · **Priority:** P1 · **Deps:** AND-105
**Scope:** Channels (messages, broadcasts, alerts), POST_NOTIFICATIONS runtime permission (Android 13+).
**Acceptance:** Notifications display on proper channels; permission requested.

### AND-108 — Deep-link routing from taps
**Type:** Feature · **Priority:** P0 · **Deps:** AND-107, AND-022
**Scope:** Map payload → in-app destination (message/broadcast/alert).
**Acceptance:** Tapping a notification opens the right screen (tested).

### AND-109 — Token refresh + logout deregister
**Type:** Feature · **Priority:** P1 · **Deps:** AND-106, AND-032
**Scope:** Handle `onNewToken`; deregister/clear on logout.
**Acceptance:** Token rotates; logout stops delivery to the device.

### AND-110 — Push tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-106, AND-108
**Scope:** Registration + routing unit/integration tests.
**Acceptance:** Tests pass.

---

## Epic E16 — Localization framework

### AND-111 — i18n plumbing + string structure
**Type:** Chore · **Priority:** P1 · **Deps:** AND-003
**Scope:** String resource conventions, plurals, formatting; lint for hardcoded strings.
**Acceptance:** Hardcoded-string lint enabled; baseline strings externalized.

### AND-112 — Port locale catalogs
**Type:** Chore · **Priority:** P2 · **Deps:** AND-111
**Scope:** Convert i18next locale files (`src/i18n/locales`) into Android resource qualifiers.
**Acceptance:** At least 2 locales load; missing keys fall back to default.

### AND-113 — Server-locale sync
**Type:** Feature · **Priority:** P2 · **Deps:** AND-111, AND-027
**Scope:** `i18n.ts` + locale endpoints; honor server/user locale preference.
**Acceptance:** Server locale preference reflected in UI (tested).

### AND-114 — Locale switch + RTL readiness
**Type:** Test · **Priority:** P2 · **Deps:** AND-112
**Scope:** In-app locale override; RTL layout audit.
**Acceptance:** Switching locale updates UI; key screens pass RTL check.

---

## Epic E17 — Offline cache framework

### AND-115 — Room database + base DAOs
**Type:** Feature · **Priority:** P0 · **Deps:** AND-003
**Scope:** Room setup, migrations strategy, base entity/DAO patterns in `core-data`.
**Acceptance:** Room builds; a sample entity round-trips (tested).

### AND-116 — Cache repository pattern (SWR)
**Type:** Feature · **Priority:** P0 · **Deps:** AND-115, AND-018
**Scope:** Stale-while-revalidate base repository (emit cache → fetch → update), reused by features.
**Acceptance:** Cached-then-fresh emission verified (tested).

### AND-117 — Stale/reconnect UX hooks
**Type:** Feature · **Priority:** P1 · **Deps:** AND-116, AND-042
**Scope:** Standard "showing cached / reconnecting" affordances tied to backend health.
**Acceptance:** With host down, cached data shows with stale indicator (UI-tested).

### AND-118 — Cache eviction / TTL
**Type:** Feature · **Priority:** P2 · **Deps:** AND-115
**Scope:** TTL + size-based eviction; per-user cache clear on logout (reuse AND-032).
**Acceptance:** Expired entries refetch; logout clears user cache (tested).

### AND-119 — Offline cache tests
**Type:** Test · **Priority:** P1 · **Deps:** AND-116
**Scope:** SWR + eviction unit tests; flaky-host simulation.
**Acceptance:** Tests pass deterministically.

---

### M2 ticket count: 67 (E08:12, E09:5, E10:7, E11:7, E12:7, E13:6, E14:8, E15:6, E16:4, E17:5)
**Running total through M2:** 119 tickets (AND-001…AND-119).
