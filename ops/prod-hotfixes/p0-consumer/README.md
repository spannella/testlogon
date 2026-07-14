# P0 consumer-feature gaps — consolidated build-gate + on-device verify

Program: bookmarks, global search, user block, public repost, web push.
App commit: `2567453a` (android-impl). Backend commits: block `fa595080`;
search `76a5f873` and webpush `618aec2e` (verify/fold records only — routers
were already live). Bookmarks + repost needed NO backend change (routes already
present + api-key-modeled), hence no fold under this dir.

## Build gate
`./gradlew :app:assembleDebug` -> BUILD SUCCESSFUL (all 5 features compile
together). APK installed to A15 (R5CX821TA9R / .238); launch crash-free; crash
buffer empty throughout. Backend = PROD (tl-api.bitbazaar.cc).

## On-device verify matrix (A15, prod backend, acct Ben Buyer unless noted)
- BOOKMARKS — PASS. Composed a public post; feed bookmark toggle fills blue +
  persists; item appears in Saved (Shop hub) with title + type "Post" + the
  collection filter chips ("All"/"+ New") + per-row move/remove actions.
- GLOBAL SEARCH — PASS. Discover -> Search "test" -> debounced
  GET /ui/search -> "17 results", tabs All/Posts(7)/Videos(8)/Catalog with real
  cards; search history persisted ("Recent searches"); result deep-link ->
  Post detail (subscription-gate render is correct for a non-subscriber).
- USER BLOCK — PASS. Public profile "Block @…" -> confirm dialog -> action
  toggles to "Unblock"; More -> Account & Settings -> Blocked users lists the
  user; per-row Unblock (confirm) -> "No blocked users" empty state.
- REPOST — PASS (core round-trip). Against a 2nd seeded account (Mia Maker)
  public post: overflow Repost menu (Repost / Quote repost) -> Repost fills the
  icon blue + count 1 + reposted_by_me true (menu now offers "Undo repost");
  Undo -> icon outline + count cleared. Own-post repost correctly DISABLED
  (greyed) per the self-repost guard. Reposted-by attribution HEADER is
  code-complete + backend-serialized (newsfeed reposted_by) but its in-feed
  visual was not captured on-device (needs a follow-graph where a followed
  reposter surfaces into the viewer feed; not constructable with the available
  accounts this session).
- WEB PUSH — backend send path live on PROD (7 /ui/push routes; vapid-key 200).
  Frontend SPA code-complete; web build DEFERRED (node/npm absent on host).

## Residual / operator follow-ups
- Repost attribution-header on-device visual (see above).
- Web-push frontend build + prod enablement runbook: see webpush/README.md.
- Fleet: the A15 + Pixel Ben Buyer sessions were logged out during the repost
  2nd-account setup; ben.buyer.1783715432@testlogon.example no longer accepts
  the seed password (changed in a prior session) so it could not be
  re-authenticated from here. A15 currently signed in as Mia Maker; Pixel at
  the login screen. Operator with email/admin access should reset Ben and
  restore the primary session.
