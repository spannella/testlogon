# TestLogon Android Port — Milestones & Epics

Companion to [`PORT_PLAN.md`](./PORT_PLAN.md). This breaks the port into **milestones** (shippable
slices) and **epics** (coherent bodies of work inside a milestone). The next step is to decompose each
epic into `AND-###` tickets (Type / Priority / Dependencies / Scope / Deliverables / Acceptance
Criteria), matching the repo's existing `TKT-###` convention.

**Conventions**
- Milestone IDs: `M1`–`M8`. Epic IDs: `E01`–`E50`. Ticket IDs (next pass): `AND-001`…
- Size: **S** ≤2d · **M** 3–5d · **L** 1–2w · **XL** 3w+ (per engineer; includes UI, data, tests).
- “Tickets (est.)” is a rough count to expect when we decompose the epic.

---

## M1 — Auth Foundation
**Goal:** A user can log in (password + MFA) against the dev backend on the emulator, the session
persists across restarts, and they can view `/ui/me` and log out. Build + CI green on the build server.
**Exit criteria:** real end-to-end login/MFA/logout; session survives process death; configurable
server URL; unit + UI tests; `assembleDebug` + tests pass in CI; runs on headless KVM emulator.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E01** | Project scaffolding & build tooling | Gradle (KTS), module skeleton (`app`,`core-*`), versions catalog, lint/format, wrapper | M | — | 6–8 |
| **E02** | Core networking & session transport | OkHttp/Retrofit/Moshi, **persistent cookie jar**, **CSRF interceptor**, **401→refresh authenticator**, base-URL selection, error mapping | L | E01 | 8–10 |
| **E03** | Design system & navigation shell | Material 3 theme (light/dark), shared composables (buttons/inputs/OTP/states), single-activity nav host, unauth/auth graphs | M | E01 | 6–8 |
| **E04** | Login (password) & session bootstrap | `POST /ui/session/start` with `challenge_context`, branch to MFA vs authenticated, `GET /ui/me`, auth state store | M | E02,E03 | 5–7 |
| **E05** | Multi-factor authentication | TOTP verify; SMS/email begin+verify; recovery code; `session/finalize`; multi-factor sequencing | L | E04 | 7–9 |
| **E06** | Session management & resilience | `session/refresh`/`logout`, active sessions list + revoke/revoke-others, **flaky-host handling** (timeouts/retry/offline state), health banner, server-URL settings screen | M | E02,E04 | 6–8 |
| **E07** | Auth QA, CI & test harness | MockWebServer contract tests, Compose UI tests (login/MFA), CI job on build server, headless-emulator instrumented run | M | E04,E05 | 5–6 |

---

## M2 — App Shell & Read-Only Core
**Goal:** A logged-in user lands in the real app shell and can browse their profile, settings,
notifications, activity, and a read-only feed. Cross-cutting foundations (push, i18n, offline cache)
land here.
**Exit criteria:** bottom-nav shell; profile/settings/notifications/feed read flows; push token
registered; locale-aware strings.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E08** | Auth extras | Registration (`/ui/register/*`), password recovery, passwordless/magic-link (deep link), WebAuthn (Credential Manager), SSO/SAML (Custom Tabs), MFA device management | L | M1 | 10–12 |
| **E09** | Home / dashboard | Authenticated landing aggregating quick links + key widgets | M | M1 | 4–6 |
| **E10** | Profile (own + public) | Own profile + public `/u/:identifier`, profile meta, edit basics | M | M1 | 6–8 |
| **E11** | Settings & preferences hub | Settings IA, preferences endpoints, media/notification prefs, theme toggle | M | M1 | 6–8 |
| **E12** | Notifications & alerts | Notification center, alert prefs (email/SMS begin/confirm/remove) | M | M1 | 5–7 |
| **E13** | Activity, saved & achievements | Activity feed, bookmarks/saved, achievements + leaderboard | M | M1 | 5–6 |
| **E14** | Feed (read-only) | Content feed list + post detail (no interactions yet), paywall display | L | M1,E22(media later) | 6–8 |
| **E15** | Push notifications (FCM) | FCM integration, `POST /ui/push/register`, tap→deep-link routing | M | M1 | 5–6 |
| **E16** | Localization framework | i18n plumbing, locale resources, server-locale sync | S–M | M1 | 3–4 |
| **E17** | Offline cache framework | Room cache layer + stale/reconnect UX baseline reused by features | M | E02 | 4–5 |

---

## M3 — Messaging
**Goal:** Full conversational messaging: list, threads with the common message types, send (text +
media), live updates, search, contacts.
**Exit criteria:** real-time send/receive against dev backend; attachments via presign; search works.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E18** | Messaging core | Conversation list, thread view, send text, read/mark, pagination | L | M2 | 8–10 |
| **E19** | Rich messages & attachments | Image/video/file/voice/gif/sticker/poll/countdown/calendar; **presign→upload→confirm** pipeline | XL | E18,E17 | 10–14 |
| **E20** | Real-time messaging | SSE `/messaging/events/stream`, presence heartbeat, typing, receipts, reconnect/backoff | L | E18 | 6–8 |
| **E21** | Messaging search & contacts | In-conversation + global search, contact search/tokenization | M | E18 | 5–6 |
| **E22** | Groups & helpdesk threads | Group create/manage, participants/roles, helpdesk queue/claim | L | E18 | 7–9 |

---

## M4 — Content Consumption
**Goal:** Rich content browsing — interactive feed, discovery/search, and native video (VOD/clips).
**Exit criteria:** HLS playback working; feed interactions + unlock; discover/search.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E23** | Media playback foundation | Media3/ExoPlayer + HLS, reusable player UI, watermark hooks | L | M2 | 6–8 |
| **E24** | Feed interactions | Like/hide/interesting/comment, paywall **unlock/entitlement** flow | L | E14 | 7–9 |
| **E25** | Discovery & global search | Discover, tags, recommendations, global search | M | M2 | 6–8 |
| **E26** | VOD / videos / clips | Library, VOD detail + player, clip viewer, rental/purchase entry points | L | E23,M5(billing) | 8–10 |
| **E27** | Stories & gallery | Stories viewer, gallery browsing | M | E23 | 4–6 |

---

## M5 — Commerce
**Goal:** Buy things and manage money-in: shop/cart/checkout, purchases, subscriptions, fan-club,
billing, invoices.
**Exit criteria:** end-to-end purchase (incl. one payment provider) and subscription manage.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E28** | Catalog & product | Catalog/category browse, product detail, search | M | M2 | 5–7 |
| **E29** | Cart & checkout | Cart, checkout session, address, carrier tracking, abandonment | L | E28,E31 | 7–9 |
| **E30** | Purchases & order history | Purchase history, detail, tracking | M | E29 | 4–6 |
| **E31** | Billing & payment methods | Payment methods, **Stripe Android SDK**, PayPal/CCBill/us-bank via Custom Tabs + deep-link return | XL | M1 | 8–12 |
| **E32** | Subscriptions & fan-club | Tiers, subscribe/manage, fan-club channels | L | E31 | 7–9 |
| **E33** | Invoices, refunds, disputes, tax | Invoices, refund requests, disputes, tax docs/1099 | M | E31 | 6–8 |

---

## M6 — Creator Tools
**Goal:** Creator-side monetization & planning: earnings, payouts, referrals/affiliates/promo,
scheduling, and broadcast **viewing**.
**Exit criteria:** earnings/payout views; calendar/scheduler; watch a live broadcast with chat.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E34** | Earnings dashboard | Earnings, per-content revenue, engagement, charts | L | M5 | 6–8 |
| **E35** | Payouts | Payout setup/history (+ KYC gating hooks), bulk tools (read) | M | E34,E45(KYC) | 5–7 |
| **E36** | Referrals, affiliates, promo | Referral links, affiliate dashboard, promo codes | M | M2 | 5–6 |
| **E37** | Calendar & scheduling | Calendar views, content-calendar, scheduler, ICS/Google sync | L | M2 | 7–9 |
| **E38** | Broadcast viewer | Browse/scheduled, viewer (HLS + live chat SSE + tips + products + Q&A) | XL | E23,E20 | 9–12 |

---

## M7 — Specialized (high-complexity)
**Goal:** The hard, specialized capabilities: real-time A/V (calls, broadcast hosting), KYC, files &
signing, questionnaires, and the org/collaboration graph.
**Exit criteria:** 1:1 call works; KYC document capture + tier status; sign a packet.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E39** | WebRTC foundation | `webrtc-android` integration, signaling, TURN credentials, permissions | XL | M3 | 6–8 |
| **E40** | Calls (1:1 + group) | Invite/accept/decline/end, in-call UI, group grid, history, recording consent, ConnectionService | XL | E39,E15 | 10–14 |
| **E41** | Broadcast hosting | WebRTC ingest, host controls, guests/inputs, moderation, goals/products | XL | E39,E38 | 10–14 |
| **E42** | KYC / identity verification | Tiers/requirements, document capture (CameraX), ID scan, liveness, residency, proof-of-funds, case status | XL | M2 | 10–14 |
| **E43** | Files, gallery mgmt & share links | File manager (presign up/download), share links, Google Drive | L | E17,E19 | 7–9 |
| **E44** | E-signing | Signature packets/templates, signature capture, submit, license agreements | L | E43 | 6–8 |
| **E45** | Questionnaires (respondent) | Dynamic form rendering, published respondent sessions, submit/validate/PDF | L | M2 | 6–8 |
| **E46** | Orgs, groups, syndicates, collaborations, delegates | Membership/roles, syndicate flows, collaboration revenue, delegate (manage-as-creator) mode | L | E22 | 8–10 |

---

## M8 — Long Tail & Admin-Lite
**Goal:** Remaining surfaces prioritized by mobile value; admin/infra mostly de-scoped to read-only.
**Exit criteria:** boost/sponsorship usable; tickets/projects; trust & safety flows; public surfaces.

| Epic | Name | Goal | Size | Deps | Tickets (est.) |
|---|---|---|---|---|---|
| **E47** | Ads (mobile subset) | Content boost, sponsorship inbox/manage, ad billing/analytics (read); defer full campaign editor | L | M5 | 7–9 |
| **E48** | Tickets & projects | Ticket spaces/threads, project list/detail | M | M3 | 5–7 |
| **E49** | Helpdesk agent tools | Helpdesk inbox, claim/assignment, reply | M | E22 | 4–6 |
| **E50** | Trust, safety & privacy | Block/report (embedded), DMCA submit, privacy/data export, account deletion/closure/status | M | M2 | 6–8 |
| **E51** | Public / unauthenticated surfaces | Public profile/event/share/donation/clip, App Links/deep links | M | E23 | 6–8 |
| **E52** | Webhooks & analytics (read) | Webhook config (light), analytics dashboards (read-only) | M | M2 | 4–6 |
| **E53** | Admin-lite (optional) | Read-only admin alerts/dashboards only; full admin/agents/infra/devtools **out of scope** for mobile | M | M2 | 0–6 |

---

## Cross-cutting epics (threaded through all milestones)
These are tracked as standing epics; tickets attach to the milestone where work actually happens.
| Epic | Name | Notes |
|---|---|---|
| **X1** | Accessibility | Content descriptions, touch targets, dynamic type — DoD on every feature |
| **X2** | Observability | Crash/ANR reporting, structured logging, network diagnostics for the flaky dev host |
| **X3** | Release & distribution | Signing config, build flavors (dev/staging/prod base URLs), CI artifacts, internal track |
| **X4** | Performance & offline polish | Paging tuning, image/memory budgets, cache eviction, cold-start |

---

## Summary
- **8 milestones**, **~53 feature epics** + **4 cross-cutting epics**.
- Rough ticket volume when decomposed: **~330–400 tickets** total; **M1 ≈ 43–56 tickets**.
- **Next step:** decompose **M1 (E01–E07)** into `AND-###` tickets first so we can start building,
  then decompose later milestones just-in-time.
