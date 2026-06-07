---
id: AND-397
title: Public surfaces tests
milestone: M8
epic: E51
priority: P2
size: M
depends_on: [AND-396]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-397 — Public surfaces tests

## 1. Overview & Goal

This ticket delivers the automated test suite that guards the application's
**public surfaces** — the externally addressable entry points into the TestLogon
Android app. In practice, the only public surfaces this app exposes are **deep
links** (verified Android App Links over `https`, plus custom-scheme links) that
resolve to in-app destinations through the central deep-link router introduced
in AND-396. There is no exported `ContentProvider`, no public `Service`, and no
exported `BroadcastReceiver`; the sole exported `Activity` is `MainActivity`,
whose intent filters define the public surface.

The goal is a deterministic, fast, CI-enforced test layer that proves: (a) every
supported `https://app.testlogon.com/...` and `testlogon://...` URI maps to the
correct `NavController` route with correctly typed/decoded arguments; (b)
malformed, unknown, or hostile URIs fail closed to a safe fallback rather than
crashing or navigating to an unintended destination; (c) links that target
auth-gated destinations are gated correctly (redirect to login, then resume the
original destination after authentication); and (d) the `AndroidManifest`
intent-filter surface matches the router's declared route table (no orphan
filters, no unrouted patterns). "Acceptance: Pass" means the entire suite is
green in CI on `branch android-port` and is wired into the existing Gradle check
pipeline.

This is a **Test** ticket (Type: Test, Priority: P2). It writes no production
behavior; it only adds tests (and, if a thin test seam is required, a minimal
non-behavioral refactor of the AND-396 router to make it unit-testable).

## 2. Context & References

- **Depends on:** AND-396 (App Links verification + central deep-link router) —
  owns `assetlinks.json`, the manifest intent filters, and the
  `DeepLinkRouter`/route table this ticket exercises. AND-397 must not be started
  until AND-396's router API is stable.
- **Transitively:** AND-022 (Navigation-Compose scaffold / `MainActivity` +
  `NavHost`) via AND-396.
- **Module:** Tests live in `app/` (instrumented + manifest-coupled assertions)
  and `core-ui` or wherever `DeepLinkRouter` lands from AND-396 (pure-Kotlin unit
  tests). Shared fakes/builders come from `core-testing`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP). Tests use JUnit4, Robolectric (JVM-side
  manifest + URI parsing), Compose UI test (`createAndroidComposeRule`),
  `androidx.navigation:navigation-testing` (`TestNavHostController`), Espresso
  intents (`Intents.intended`), and Truth assertions.
- **Package base (exact):** `com.testlogon.android`. Tests sit under
  `com.testlogon.android.deeplink` and `com.testlogon.android.app`.
- **Public host:** verified App Links use `https://app.testlogon.com`; the custom
  scheme is `testlogon://`. (If AND-396 finalizes different literals, this spec's
  constants defer to the AND-396 manifest as the single source of truth — the
  manifest-parity test in §4 will catch any drift.)
- **Backend:** No direct backend interaction in this ticket; auth-gated routing
  tests stub the session state, they do not call `http://18.222.237.167:8000`.

## 3. Functional Requirements

FR-1. **Route mapping coverage.** For every entry in the AND-396 route table,
there is at least one positive test asserting that the canonical `https` URI and,
where defined, the `testlogon://` equivalent resolve to the expected route id and
argument bundle.

FR-2. **Argument decoding.** Path and query arguments are extracted with correct
types and URL-decoding (e.g. `%20`, `+`, unicode, slashes in encoded segments).
Numeric ids that overflow `Long`, or are non-numeric where a number is required,
are treated as invalid (FR-4), not silently coerced.

FR-3. **Trailing/edge normalization.** Trailing slashes, mixed case in host,
duplicate query keys, and empty query values resolve identically to their
canonical form (or are explicitly rejected) — behavior is asserted, not assumed.

FR-4. **Fail-closed for invalid input.** Unknown paths, wrong host, wrong scheme,
missing required args, and oversized/malformed URIs route to the documented
fallback (Home or a "link not found" destination) and never crash, never throw
out of the router, and never navigate to an auth-gated screen.

FR-5. **Auth-gating.** A deep link to an auth-gated destination while
unauthenticated resolves to the login route carrying the original destination as
a pending redirect; after a simulated successful session, the pending destination
is consumed exactly once. An identical link while authenticated resolves directly.

FR-6. **Manifest ↔ router parity.** A test parses `AndroidManifest.xml` (merged)
and asserts the set of `<data>` host/scheme/pathPattern entries on `MainActivity`
is consistent with the router's declared patterns — no exported intent filter that
the router cannot handle, and no router pattern lacking a manifest filter.

FR-7. **Single exported surface.** A test asserts `MainActivity` is the only
component with `android:exported="true"` carrying a `BROWSABLE`/`VIEW` filter, and
that no `ContentProvider`/`Service`/`Receiver` is exported.

FR-8. **CI enforcement.** The suite runs under `./gradlew check` (JVM tests) and a
named instrumented task; failures fail the build.

## 4. Technical Design

Two test layers:

**Layer A — Pure/Robolectric unit tests of the router** (fast, JVM, run on every
PR). The AND-396 router is expected to expose a pure mapping function that can be
exercised without an `Activity`:

```kotlin
// Owned by AND-396; consumed here. Exact names defer to AND-396.
sealed interface DeepLinkTarget {
    data class Route(val routeId: String, val args: Map<String, String>) : DeepLinkTarget
    data class AuthGated(val pending: Route) : DeepLinkTarget
    data object Fallback : DeepLinkTarget   // unknown/invalid -> safe home
}

interface DeepLinkRouter {
    fun resolve(uri: Uri, isAuthenticated: Boolean): DeepLinkTarget
}
```

If AND-396 only exposes `NavController`-coupled navigation, AND-397 requires a
**minimal test seam**: extract the pure `resolve(Uri, Boolean): DeepLinkTarget`
out of the side-effecting `navigate(...)` so it is unit-testable. This is the only
production change permitted by this ticket and must be behavior-preserving.

Unit test class skeleton (Robolectric for `android.net.Uri` parsing):

```kotlin
@RunWith(RobolectricTestRunner::class)
class DeepLinkRouterTest {
    private val router: DeepLinkRouter = RealDeepLinkRouter(/* test route table */)

    private fun resolve(s: String, auth: Boolean = true) =
        router.resolve(Uri.parse(s), isAuthenticated = auth)

    @Test fun `https run detail maps to run route with id`() {
        val t = resolve("https://app.testlogon.com/runs/4815") as DeepLinkTarget.Route
        assertThat(t.routeId).isEqualTo("run_detail")
        assertThat(t.args["runId"]).isEqualTo("4815")
    }

    @Test fun `unknown path falls back`() {
        assertThat(resolve("https://app.testlogon.com/zzz/nope"))
            .isEqualTo(DeepLinkTarget.Fallback)
    }
}
```

Data-driven matrix via JUnit `@Parameterized` (or a Kotlin `listOf` table run in a
single `@Test` with soft assertions) so adding a route is a one-line table edit:

```kotlin
data class Case(val uri: String, val auth: Boolean, val expected: DeepLinkTarget)
```

**Layer B — Instrumented end-to-end intent tests** (Espresso + Compose, run on
the instrumented task / emulator API 24 & 35). These prove the manifest filter +
`MainActivity` + `NavHost` actually land on the right Compose destination:

```kotlin
@RunWith(AndroidJUnit4::class)
class DeepLinkIntentTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    private fun launch(uri: String) {
        val i = Intent(Intent.ACTION_VIEW, Uri.parse(uri))
            .setPackage("com.testlogon.android")
        ApplicationProvider.getApplicationContext<Context>().startActivity(i)
    }

    @Test fun runDetail_opensRunScreen() {
        launch("https://app.testlogon.com/runs/4815")
        compose.onNodeWithTag("run_detail_screen").assertIsDisplayed()
    }
}
```

`TestNavHostController` is used in a lighter Compose test to assert
`navController.currentBackStackEntry?.destination?.route` and arguments without a
full Activity relaunch, giving a middle tier between A and B.

**Manifest parity test** (FR-6/FR-7) reads the merged manifest from the test
APK/resources via `PackageManager.getPackageInfo(..., GET_ACTIVITIES or
MATCH_ALL)` on instrumented side, or parses the merged `AndroidManifest.xml`
resource on the Robolectric side, and diffs `<data>` entries against
`router.declaredPatterns()`.

## 5. API Contract

No backend API is consumed by this ticket. The dev backend
(`http://18.222.237.167:8000`) is **not** contacted; auth state for FR-5 is
injected through a fake session provider from `core-testing`.

The relevant "contract" here is the **deep-link route table** (a UI contract owned
by AND-396, asserted by this ticket). Representative surface under test:

| Public URI (https + custom) | Route id | Args | Auth-gated |
|---|---|---|---|
| `/` , `testlogon://home` | `home` | — | no |
| `/login` | `login` | — | no |
| `/runs/{runId}` | `run_detail` | `runId: String(Long)` | yes |
| `/runs/{runId}/logs?tail={n}` | `run_logs` | `runId`, `tail: Int?` | yes |
| `/profile` | `profile` | — | yes |
| anything else | `home` (Fallback) | — | n/a |

The exact table is read from AND-396; the parity test fails the build if this
spec and the shipped table diverge, which is the intended early-warning signal.

> **Review note (2026-06-06):** The `/runs/{runId}` → `run_detail` and
> `/runs/{runId}/logs` → `run_logs` rows above are **illustrative placeholders**,
> not paths taken from the reference web client. The web app (`reference/src/App.tsx`)
> has **no** `/runs/...` route; the only authoritative public-facing paths it
> defines that correspond to this table are `/` (index → Dashboard), `/login`,
> and `/profile` (under `ProtectedRoute`/`AppShell`). Backend `runs` paths
> (`/ui/agents/runs/{run_id}`, `/ui/admin/jobs/runs/{job_name}`) exist but are
> internal agent/job APIs with **string** `run_id`/`job_name`, not a user-facing
> deep-link surface — so the "`runId: String(Long)`" typing and the `run_detail`
> screen are assumptions, not verified web routes. The route table is owned by
> AND-396 and the §4 parity test is the binding source of truth; the §16 audit
> records this. Examples here are kept verbatim only to illustrate the test shape.

## 6. Data & State Management

This ticket produces no persisted data and no DataStore/Room writes. State under
test is the in-memory navigation back stack and the **pending deep-link
redirect** held during auth-gating (FR-5).

Test fixtures:
- `FakeSessionState(authenticated: Boolean)` from `core-testing`, exposing the
  same `StateFlow<SessionState>` shape the real app's `SessionRepository` exposes,
  so the router/gate logic sees a realistic `StateFlow<UiState>`-style source.
- A canonical URI fixture object `DeepLinkFixtures` (single source of test URIs,
  reused across Layer A/B) to avoid string drift.
- The pending-redirect consumption is asserted to be **single-use**: after the
  fake session flips to authenticated and the redirect is consumed, a second
  collection yields null/no navigation (asserts no double-navigation on
  configuration change / recomposition).

No threading concerns beyond standard `runTest` with the Coroutines test
dispatcher for any `Flow`-based gating.

> **Review note (2026-06-06):** The "resume the original destination after
> authentication" behavior (FR-5) is an **Android-side design choice that goes
> beyond the current web client.** In the reference web app, `ProtectedRoute`
> (`reference/src/components/ProtectedRoute.tsx`) redirects unauthenticated users
> to `/login` and *records* the origin via React Router `state={{ from: location }}`,
> but `reference/src/pages/Login.tsx` always navigates to `/` after a successful
> login (`navigate("/", { replace: true })`) and does **not** read `state.from`.
> So the web app captures the origin but does not actually resume it. The Android
> single-use pending-redirect resumption is therefore a deliberate improvement,
> tested here against the AND-396 router contract — not a port of verified web
> behavior. Recorded in §16.

## 7. Error Handling & Resilience

The tests *are* the resilience guarantee for this surface. Explicit negative
cases (all must resolve to `Fallback`, never throw):

- Wrong scheme: `ftp://app.testlogon.com/runs/1`, `javascript:alert(1)`.
- Wrong/spoofed host: `https://evil.testlogon.com.attacker.com/runs/1`,
  `https://app.testlogon.com.evil.com/profile`.
- Missing/empty required arg: `https://app.testlogon.com/runs/`,
  `https://app.testlogon.com/runs/%20`.
- Wrong type: `https://app.testlogon.com/runs/notanumber`,
  overflow `.../runs/99999999999999999999`.
- Malformed/oversized: empty URI, opaque URI (`testlogon:`), 8 KB path,
  null-byte/control-char injection, double-encoded `%252e%252e`.
- Path traversal: `https://app.testlogon.com/runs/../profile`.

Resilience assertions: `resolve` is total (never throws) — enforced by a
fuzz-style test that feeds a corpus (the curated hostile list plus a few hundred
random strings) and asserts no exception escapes and the result is always a valid
`DeepLinkTarget`. Backend timeouts/retries are out of scope (no network).

## 8. Security & Privacy

Deep links are an attack surface; these tests are a security control:

- **Host allow-listing:** assert only `app.testlogon.com` (and configured custom
  scheme) is honored; look-alike/subdomain-confusion hosts fall back (§7).
- **No privilege escalation via link:** an unauthenticated deep link to an
  auth-gated route must *never* render gated content; it must land on `login`
  (FR-5). A regression here is a security failure, so this case is marked
  `@Test` + tagged `security` for visibility.
- **Open-redirect hygiene:** the pending-redirect value carried into `login` must
  only ever be an internal route (not an arbitrary external URL); test asserts a
  hostile redirect payload cannot smuggle an external destination.
- **No secrets in links/logs:** assert the router does not log full URIs at
  `INFO`+ (tokens could ride in query strings); §10 covers the redaction check.
- **Exported-surface minimization:** FR-7 test enforces a single exported VIEW
  filter. `assetlinks.json` content correctness is owned/tested by AND-396; this
  ticket asserts the *runtime routing* outcome only.

No PII is read or stored by these tests.

## 9. Accessibility & i18n

Largely N/A for a routing test ticket — a11y of destination screens is owned by
each feature ticket and their own tests. Two cross-cutting checks are included
because they are cheap and routing-adjacent:

- **i18n-safe URIs:** decoding tests include a non-ASCII/unicode path/query value
  (e.g. `?q=caf%C3%A9`, RTL marks) to prove decoding is locale-independent and
  not corrupted; URIs are never lowercased except the host.
- **Fallback discoverability:** the instrumented test asserts the fallback
  destination it lands on is a real, focusable screen (`assertIsDisplayed`) so a
  bad link never leaves the user on an empty/undescribed screen — a minimal a11y
  smoke check, not a full audit.

## 10. Telemetry & Logging

This ticket adds no production telemetry. It adds **tests that constrain**
deep-link logging/analytics behavior, assuming AND-396 emits a deep-link
resolution event:

- Assert that when a link resolves, exactly one resolution outcome
  (`route` | `fallback` | `auth_gated`) is reported to the (faked) analytics sink,
  with the route id but **without** the raw query string (PII/secret hygiene,
  §8).
- Assert fallback events carry a coarse reason enum (`unknown_path`,
  `bad_host`, `bad_scheme`, `bad_args`) and not the raw URI.
- Logging redaction: assert any logged URI is host+path only with the query
  redacted (`?…`), using a fake `Logger` from `core-testing` capturing emitted
  lines.

If AND-396 emits no such event, these assertions are skipped with a `@Ignore`
referencing the follow-up rather than failing — but the redaction test still
applies if any logging exists.

## 11. Testing Strategy

This ticket *is* the testing strategy; below is the concrete structure.

- **Unit (Layer A, Robolectric, `test/`):** `DeepLinkRouterTest`,
  `DeepLinkRouterNegativeTest`, `DeepLinkRouterFuzzTest`,
  `DeepLinkAuthGateTest`. Run via `./gradlew :app:testDebugUnitTest` (or the
  module owning the router). Target: full route-table coverage + the §7 negative
  corpus. Fast (<10s), gate every PR.
- **Navigation (Layer middle, Compose + `TestNavHostController`):**
  `DeepLinkNavGraphTest` asserts route + args on the back stack without launching
  `MainActivity`.
- **Instrumented E2E (Layer B, `androidTest/`):** `DeepLinkIntentTest` using
  `ACTION_VIEW` intents and `createAndroidComposeRule<MainActivity>()`; verifies
  manifest filters actually route to Compose destinations. Run via
  `./gradlew :app:connectedDebugAndroidTest` on emulators API 24 and API 35.
- **Manifest parity (`androidTest/` + Robolectric variant):**
  `ManifestSurfaceTest` (FR-6/FR-7).
- **Determinism:** no real network, no sleeps; coroutines via `runTest`. URIs
  centralized in `DeepLinkFixtures`. A parameterized table drives positive cases
  so coverage scales with the route table.
- **Coverage gate:** the router class must hit ≥90% line/branch (JaCoCo) — a
  reasonable, enforceable bar for a pure mapping function. CI fails below it.
- **Exit criteria ("Pass"):** all four test classes green on both API levels in
  CI; coverage gate met; manifest-parity test green.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-396 must merge first and expose a resolvable router
  surface (`resolve(Uri, Boolean): DeepLinkTarget` or the test seam described in
  §4). Coordinate the seam extraction inside AND-396's PR if possible to avoid a
  separate production change here.
- **Transitive:** AND-022 (Nav scaffold), needed for the instrumented Compose
  destinations to exist.
- **Tooling deps to add** (test-only, if not already present):
  `org.robolectric:robolectric`, `androidx.navigation:navigation-testing`,
  `androidx.test.espresso:espresso-intents`,
  `androidx.compose.ui:ui-test-junit4`, `com.google.truth:truth`,
  `org.jetbrains.kotlinx:kotlinx-coroutines-test`. All scoped `testImplementation`
  / `androidTestImplementation`, pinned via the version catalog.
- **Sequencing:** Layer A first (unblocks the router contract), then the parity
  test (catches manifest drift early), then Layer B instrumented.
- **Blocks:** nothing downstream depends on this ticket (`blocks: []`); it is a
  quality gate, not a feature enabler.

## 13. Risks & Open Questions

- **R1 — Router not unit-testable.** If AND-396 ships routing tightly coupled to
  `NavController`, Layer A needs the §4 seam. Mitigation: agree the
  `resolve(...)` signature with AND-396 before coding; treat the seam as a
  blocking pre-req.
- **R2 — Manifest `pathPattern` vs router regex mismatch.** Android
  `pathPattern`/`pathAdvancedPattern` semantics differ from arbitrary Kotlin
  matching; parity (FR-6) is non-trivial. Mitigation: parity test compares
  normalized pattern sets and is allowed to assert a documented mapping rather
  than byte-equality.
- **R3 — Instrumented flakiness / emulator availability.** App Links auto-verify
  cannot be asserted on a bare emulator (no Digital Asset Links fetch).
  Mitigation: Layer B uses explicit `ACTION_VIEW` intents with
  `setPackage(...)`, not verified-link auto-open; actual `autoVerify` status is
  AND-396's concern.
- **Open Q1:** Final literal host/scheme and full route table — confirm against
  AND-396's merged manifest. Open Q2: does AND-396 emit a deep-link analytics
  event (decides §10 active vs `@Ignore`)? Open Q3: is the fallback destination
  `home` or a dedicated "link not found" screen?

## 14. Acceptance Criteria

AC-1. Every route in the AND-396 table has ≥1 passing positive test for its
`https` form (and custom-scheme form where defined) asserting route id + decoded
args (FR-1, FR-2).
AC-2. Edge-normalization cases (trailing slash, host case, encoded unicode,
duplicate query keys) behave as documented and are asserted (FR-3).
AC-3. The full §7 negative corpus (wrong scheme/host, bad/missing/overflow args,
traversal, oversized, control chars) resolves to `Fallback`; the fuzz test proves
`resolve` never throws (FR-4).
AC-4. Unauthenticated access to an auth-gated link lands on `login` with the
original destination as a single-use pending redirect; authenticated access
resolves directly (FR-5).
AC-5. `ManifestSurfaceTest` passes: manifest VIEW/BROWSABLE filters and router
patterns are consistent, and `MainActivity` is the only exported public surface
(FR-6, FR-7).
AC-6. Instrumented `DeepLinkIntentTest` lands on the correct Compose destination
for representative links on emulator API 24 and API 35.
AC-7. Router coverage ≥90% line/branch (JaCoCo); CI fails below the gate.
AC-8. Whole suite green in CI on `android-port` via `./gradlew check` (JVM) and
the instrumented task; no real network calls; no `Thread.sleep`. ("Pass".)

## 15. Definition of Done

- All §14 acceptance criteria met; suite green on `android-port` in CI on API 24
  and API 35.
- Test classes added under the documented packages
  (`com.testlogon.android.deeplink`, `com.testlogon.android.app`); shared fixtures
  (`DeepLinkFixtures`, `FakeSessionState`, fake `Logger`/analytics) placed in
  `core-testing` for reuse.
- Any required AND-396 test seam is the minimal, behavior-preserving extraction
  described in §4 and is reviewed/approved by the AND-396 owner; no other
  production behavior changed.
- New test dependencies added to the version catalog and wired into the correct
  configurations; `./gradlew check` and the connected/instrumented task both run
  the new tests.
- JaCoCo coverage gate configured and enforced for the router.
- Open questions Q1–Q3 resolved or explicitly deferred with a tracked follow-up;
  parity test reflects the final route table.
- Code reviewed and merged to `android-port`; CI badge green.

## 16. Citations & Assumption Audit

Each key technical claim in this spec, with a verdict and an exact source
pointer. Sources: `reference/src/...` (frontend reference app), the OpenAPI
index/spec, or Android framework docs (labelled "framework ref"). This is a
**Test** ticket that contacts no backend, so most "API" claims are negative
claims (that nothing is contacted) plus UI/routing-contract claims.

1. **Claim:** The app's public surfaces are deep links resolving through a router;
   no backend API is consumed by this ticket (§1, §5).
   **VERDICT:** Verified (as a scope statement). The reference web client routes
   are pure client-side React Router routes; deep-link routing is a UI concern.
   **SOURCE:** `reference/src/App.tsx` (`<Routes>`/`<Route>` table — all routing
   is client-side, no per-route backend call to resolve a route).

2. **Claim:** Auth-gated destinations redirect unauthenticated users to a `login`
   route carrying the original destination as a pending redirect (FR-5, §1c, §6).
   **VERDICT:** Corrected / partially verified. The web client **does** redirect
   to `/login` and **does record** the origin, but it does **not** resume it —
   `Login.tsx` always navigates to `/` after auth and ignores `state.from`. The
   Android "resume original destination, single-use" behavior is an
   Android-side improvement, not a port of verified web behavior. Marked inline
   in §6 and §5.
   **SOURCE:** `reference/src/components/ProtectedRoute.tsx`
   (`<Navigate to="/login" state={{ from: location }} replace />`) and
   `reference/src/pages/Login.tsx` (`navigate("/", { replace: true })`, no read
   of `location.state.from`).

3. **Claim:** Representative public route table includes `/runs/{runId}` →
   `run_detail` and `/runs/{runId}/logs` → `run_logs` with `runId: String(Long)`
   (§4 examples, §5 table).
   **VERDICT:** Corrected → Unverified-assumption (illustrative placeholder). The
   reference web app has **no** `/runs/...` route. The only authoritative routes
   matching the table are `/` (index → Dashboard), `/login`, and `/profile`.
   Backend `runs` paths exist but are internal agent/job APIs, not a user-facing
   deep-link surface, and their ids are strings, not `Long`. Corrected inline in
   §5; examples retained only to illustrate test shape.
   **SOURCE:** `reference/src/App.tsx` (no `path="runs/..."`; `<Route index ... Dashboard>`,
   `path="/login"`, `path="profile"`); OpenAPI index
   `GET /ui/agents/runs/{run_id}` and `GET /ui/admin/jobs/runs/{job_name}`
   (string params, internal `/ui/agents` + `/ui/admin` scope).

4. **Claim:** `/login` is a public (non-auth) route and `/profile` is auth-gated
   (§5 table).
   **VERDICT:** Verified. `/login` is declared outside the `ProtectedRoute`
   block; `profile` is inside `<Route element={<ProtectedRoute><AppShell/></ProtectedRoute>}>`.
   **SOURCE:** `reference/src/App.tsx` (`<Route path="/login" .../>` in the public
   block; `<Route path="profile" element={<ProfilePage />} />` inside the
   protected block).

5. **Claim:** The home/index destination corresponds to `/` (Dashboard), used as
   the fallback target (§5, §7, §13 Open Q3).
   **VERDICT:** Verified (for `/` = Dashboard). Whether the Android fallback is
   `home` or a dedicated "link not found" screen remains an open question owned by
   AND-396 (Q3); the web app's `/` maps to Dashboard and unmatched routes render a
   404 `ErrorPage`.
   **SOURCE:** `reference/src/App.tsx` (`<Route index element={<Dashboard />} />`;
   `<Route path="*" element={<ErrorPage status={404} />} />`).

6. **Claim:** The dev backend `http://18.222.237.167:8000` is **not** contacted by
   this ticket (§2, §5).
   **VERDICT:** Verified (negative claim) / Unverified-assumption for the literal
   host. The reference client derives its base URL from `VITE_API_BASE_URL`
   (env-configured), not a hard-coded `18.222.237.167`; that literal does not
   appear in the reference source or the OpenAPI servers block. The "not
   contacted" claim is correct because no test in this ticket performs network I/O.
   **SOURCE:** `reference/src/api/client.ts`
   (`API_BASE_URL = import.meta.env?.VITE_API_BASE_URL ...`); grep for
   `18.222.237.167` in `reference/` and `openapi.pretty.json` → no match.

7. **Claim:** Web client auth uses a CSRF token from the `ui_csrf` cookie sent as
   `X-CSRF-Token` (background context, §8 secret-hygiene rationale).
   **VERDICT:** Verified (as background; not exercised by this ticket).
   **SOURCE:** `reference/src/api/client.ts`
   (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`).

8. **Claim:** Public host literal is `https://app.testlogon.com` and custom scheme
   is `testlogon://` (§2, §5, §7).
   **VERDICT:** Unverified-assumption. These literals do not appear in the
   reference web source or OpenAPI; they are AND-396-owned Android manifest
   constants. The spec already defers to the AND-396 manifest as the single source
   of truth, and the §4 manifest-parity test is designed to catch drift.
   **SOURCE:** grep for `app.testlogon.com` / `testlogon://` in `reference/` → no
   match; spec §2 self-declares the deferral to AND-396.

9. **Claim:** The only exported component with a BROWSABLE/VIEW filter is
   `MainActivity`; no exported `ContentProvider`/`Service`/`Receiver` (FR-7, §8).
   **VERDICT:** Unverified-assumption (depends on AND-396/AND-022 manifest, which
   is not in these sources). This is exactly what the FR-7 `ManifestSurfaceTest`
   is written to assert, so it is a test target rather than a pre-verified fact.
   **SOURCE:** Android manifest semantics — `android:exported`, intent-filter
   `VIEW`/`BROWSABLE`, App Links `autoVerify` (framework ref:
   https://developer.android.com/training/app-links and
   https://developer.android.com/guide/topics/manifest/activity-element#exported).

10. **Claim:** App Links auto-verify (Digital Asset Links) cannot be asserted on a
    bare emulator; Layer B uses explicit `ACTION_VIEW` + `setPackage(...)` (§13 R3,
    §4 Layer B).
    **VERDICT:** Verified (framework behavior). Verified App Links require a
    network fetch of `assetlinks.json` and OEM verification that a CI emulator does
    not perform; an explicit `ACTION_VIEW` intent with `setPackage` bypasses
    verification and is the correct test approach.
    **SOURCE:** framework ref —
    https://developer.android.com/training/app-links/verify-android-applinks .

11. **Claim:** `TestNavHostController` / `navigation-testing` allows asserting the
    current back-stack route and arguments without launching `MainActivity` (§4,
    §11).
    **VERDICT:** Verified (framework capability).
    **SOURCE:** framework ref —
    https://developer.android.com/guide/navigation/testing .

12. **Claim:** `Uri.parse` of malformed/opaque/oversized strings can be resolved
    totally (never throws) by the router (§7 fuzz, FR-4).
    **VERDICT:** Unverified-assumption about the AND-396 implementation; the fuzz
    test is precisely what proves totality. `android.net.Uri.parse` itself is
    lenient/total for most inputs, but router-internal decoding is the risk the
    test guards.
    **SOURCE:** framework ref — `android.net.Uri`
    https://developer.android.com/reference/android/net/Uri ; totality is enforced
    by TC-AND-397 fuzz case below, not pre-verified.

### Corrections made

- **§5 route table:** Added a review note clarifying that `/runs/{runId}` →
  `run_detail` and `/runs/{runId}/logs` → `run_logs` are illustrative placeholders
  with no counterpart in the reference web client; the authoritative web routes
  matching the table are `/` (Dashboard), `/login`, and `/profile`. Flagged the
  `runId: String(Long)` typing as an assumption (backend run ids are strings).
- **§6 / FR-5 auth-resume:** Added a review note that the web client records the
  origin (`ProtectedRoute` `state.from`) but does **not** resume it after login
  (`Login.tsx` always goes to `/`); the Android single-use pending-redirect
  resumption is a deliberate Android improvement, not a verified web port.
- **§16 audit (item 6):** Noted the dev host `18.222.237.167:8000` is not a
  hard-coded literal in the reference client (base URL is env-driven via
  `VITE_API_BASE_URL`); the "not contacted" scope claim stands.

### Open assumptions

- **Host/scheme literals** (`app.testlogon.com`, `testlogon://`): not present in
  the reference sources; owned by AND-396's manifest. Cannot be verified here —
  the parity test (FR-6) is the guard. (Item 8.)
- **Final route table, route ids, and arg types** (`run_detail`, `run_logs`,
  `runId` typing): owned by AND-396; the reference web app does not define a
  `/runs` surface, so these cannot be verified from the provided sources. (Item 3.)
- **Fallback destination** (Home vs dedicated "link not found"): unresolved Open
  Q3; web app uses Dashboard for `/` and a 404 `ErrorPage` for unmatched routes,
  but the Android choice is AND-396's. (Item 5.)
- **Exported-surface manifest shape** (FR-7): depends on the merged AND-396/AND-022
  manifest, not in scope of provided sources; asserted by `ManifestSurfaceTest`.
  (Item 9.)
- **Router totality / `DeepLinkTarget` shape**: the `resolve(Uri, Boolean)` seam
  and `DeepLinkTarget` sealed type are AND-396-owned; their existence/signature is
  a coordinated pre-req (R1), not verifiable from these sources. (Item 12.)
- **Analytics deep-link event** (§10): existence of an AND-396 resolution event is
  Open Q2; assertions are `@Ignore`-gated until confirmed.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device);
**emu35** = headless emulator AVD `test35` (x86_64, Android 15 / API 35, KVM on the
Ubuntu build server); **device** = physical Samsung Galaxy A15 5G (SM-A156U, serial
R5CX821TA9R, Android 14 / API 34, arm64-v8a) on the build host via adb. Deep-link
routing is not hardware-dependent, so most cases run on **JVM** or **emu35**; the
ABI/API-parity case (TC-13) **must** run on the physical **device** to cover
arm64-v8a / API 34 vs the emulator's x86_64 / API 35.

- **TC-AND-397-01** — Happy path: canonical `https` route mapping
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** `RealDeepLinkRouter` built with the AND-396 route table;
  `isAuthenticated = true`.
  **Steps:** `resolve(Uri.parse("https://app.testlogon.com/profile"), auth=true)`
  for each authoritative route (`/`, `/login`, `/profile`) plus any AND-396 table
  rows, driven by the `@Parameterized` `Case` table.
  **Expected:** Each resolves to `DeepLinkTarget.Route` with the expected route id
  and decoded arg bundle; no exception. (Placeholder `/runs/...` rows are only
  asserted if AND-396 actually ships them — see §5 note.)
  **Traces:** AC-1.

- **TC-AND-397-02** — Custom-scheme parity (`testlogon://`)
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** route table with custom-scheme equivalents (e.g.
  `testlogon://home`).
  **Steps:** Resolve each `testlogon://...` form and its `https` twin; compare.
  **Expected:** Custom-scheme URI resolves to the same `Route`/args as the `https`
  canonical form where the scheme is defined.
  **Traces:** AC-1.

- **TC-AND-397-03** — Argument decoding & typing
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** a route with a path arg and an optional query arg.
  **Steps:** Resolve URIs containing `%20`, `+`, encoded unicode (`caf%C3%A9`),
  encoded slash in a segment, and a numeric query (`?tail=50`); assert decoded
  values and types.
  **Expected:** Args are URL-decoded correctly and typed per the table; host is
  the only segment lowercased; path/query case preserved.
  **Traces:** AC-1, AC-2.

- **TC-AND-397-04** — Edge normalization
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** route table loaded.
  **Steps:** Resolve trailing-slash variants, mixed-case host
  (`HTTPS://APP.TestLogon.COM/profile`), duplicate query keys, empty query value.
  **Expected:** Each resolves identically to its canonical form or is explicitly
  rejected to `Fallback`, exactly as documented (§3 FR-3); behavior asserted.
  **Traces:** AC-2.

- **TC-AND-397-05** — Negative corpus → Fallback (validation/error shapes)
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** curated hostile URI list from §7 in `DeepLinkFixtures`.
  **Steps:** Resolve wrong scheme (`ftp:`, `javascript:`), spoofed host
  (`https://app.testlogon.com.evil.com/profile`), missing/empty arg
  (`/runs/`, `/runs/%20`), wrong type (`/runs/notanumber`), overflow
  (`/runs/99999999999999999999`), traversal (`/runs/../profile`), opaque
  (`testlogon:`), control-char and double-encoded (`%252e%252e`) inputs.
  **Expected:** Every input resolves to `DeepLinkTarget.Fallback`; none resolves to
  an auth-gated `Route`; no exception.
  **Traces:** AC-3.

- **TC-AND-397-06** — Fuzz totality: `resolve` never throws
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** hostile corpus + a few hundred random/8 KB/null-byte strings.
  **Steps:** Feed every input to `resolve(...)`; collect outcomes.
  **Expected:** No exception escapes; every result is a valid `DeepLinkTarget`
  (`Route`/`AuthGated`/`Fallback`). Asserted with soft assertions over the corpus.
  **Traces:** AC-3.

- **TC-AND-397-07** — Auth-gating: unauthenticated → login with pending redirect
  **Type:** unit (Robolectric, `runTest`) · **Target:** JVM
  **Preconditions:** `FakeSessionState(authenticated = false)`; an auth-gated link
  (e.g. `https://app.testlogon.com/profile`).
  **Steps:** Resolve while unauthenticated; flip `FakeSessionState` to
  authenticated; consume the pending redirect; attempt a second consumption.
  **Expected:** First resolve → `AuthGated(pending = Route(profile))` landing on
  `login`; after auth, pending consumed exactly once and routes to `profile`; the
  second consumption yields null/no navigation (single-use). Note: this exceeds
  current web behavior (see §6 note / §16 item 2).
  **Traces:** AC-4.

- **TC-AND-397-08** — Auth-gating: authenticated resolves directly + open-redirect
  hygiene
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** `FakeSessionState(authenticated = true)`.
  **Steps:** Resolve the same auth-gated link directly; then attempt to smuggle an
  external destination as the pending redirect value (e.g. a payload encoding
  `https://evil.com`).
  **Expected:** Authenticated resolve → `Route(profile)` directly; the pending
  redirect can only ever carry an internal route id, never an external URL — a
  hostile external redirect payload is rejected/normalized to `Fallback`.
  **Traces:** AC-4 (security: open-redirect, §8).

- **TC-AND-397-09** — Manifest ↔ router parity & single exported surface
  **Type:** contract/instrumented (also Robolectric variant) · **Target:** emu35
  (Robolectric variant runs on JVM)
  **Preconditions:** merged `AndroidManifest.xml` available;
  `router.declaredPatterns()` exposed by AND-396.
  **Steps:** Parse merged manifest `<data>` host/scheme/pathPattern entries on
  `MainActivity`; diff against the router's declared patterns; enumerate exported
  components.
  **Expected:** No manifest VIEW/BROWSABLE filter unhandled by the router and no
  router pattern lacking a filter; `MainActivity` is the only exported component
  with a BROWSABLE/VIEW filter; no exported `ContentProvider`/`Service`/`Receiver`.
  **Traces:** AC-5.

- **TC-AND-397-10** — NavGraph route + args without Activity relaunch
  **Type:** Compose-UI (TestNavHostController) · **Target:** emu35 (or Robolectric)
  **Preconditions:** `TestNavHostController` wired to the app NavGraph.
  **Steps:** Drive a deep-link navigation for a representative route; read
  `navController.currentBackStackEntry?.destination?.route` and the argument bundle.
  **Expected:** Current destination route id and arguments match the resolved
  `DeepLinkTarget` for the same URI.
  **Traces:** AC-1, AC-6.

- **TC-AND-397-11** — Instrumented E2E: `ACTION_VIEW` lands on Compose destination
  **Type:** instrumented/e2e (Espresso intents + Compose) · **Target:** emu35
  (also run on an API-24 AVD per §11/AC-6)
  **Preconditions:** `createAndroidComposeRule<MainActivity>()`; app installed.
  **Steps:** Fire `Intent(ACTION_VIEW, Uri.parse("https://app.testlogon.com/profile"))`
  with `setPackage("com.testlogon.android")` (not relying on verified-link
  auto-open — see §16 item 10); assert the destination.
  **Expected:** `compose.onNodeWithTag("profile_screen").assertIsDisplayed()`; the
  manifest filter + `MainActivity` + `NavHost` route to the correct Compose screen.
  **Traces:** AC-6.

- **TC-AND-397-12** — Fallback destination is a real, focusable screen (a11y smoke)
  **Type:** Compose-UI / instrumented · **Target:** emu35
  **Preconditions:** a known-bad deep link (unknown path).
  **Steps:** Launch the bad link via `ACTION_VIEW`; assert the landed screen.
  **Expected:** Lands on the fallback (Home/"link not found") which is displayed
  and focusable (`assertIsDisplayed()` + non-empty content description); a bad link
  never leaves the user on an empty/undescribed screen.
  **Traces:** AC-3 (a11y/discoverability, §9).

- **TC-AND-397-13** — ABI/API parity on physical device (arm64 / API 34)
  **Type:** instrumented/e2e · **Target:** **device (required)** — Samsung Galaxy
  A15 5G, arm64-v8a, API 34
  **Preconditions:** physical device connected via adb; app installed.
  **Why device:** the CI emulator is x86_64 / API 35; this case covers the
  arm64-v8a / API-34 differences (`Uri` parsing, intent dispatch) that the
  emulator cannot represent.
  **Steps:** Run the representative `ACTION_VIEW` deep-link set (happy path +
  one negative + one auth-gated) on the device.
  **Expected:** Identical routing outcomes to emu35; no ABI/API-specific
  divergence.
  **Traces:** AC-6, AC-8.

- **TC-AND-397-14** — Logging redaction & analytics outcome (secret hygiene)
  **Type:** unit (Robolectric) · **Target:** JVM
  **Preconditions:** fake `Logger` and fake analytics sink from `core-testing`; a
  link with a sensitive query string (e.g. `?token=abc`).
  **Steps:** Resolve the link; capture logged lines and analytics events. If
  AND-396 emits no resolution event, the analytics assertion is `@Ignore`-gated
  (§10 / §16 open assumption); the redaction assertion still runs if any logging
  exists.
  **Expected:** Exactly one resolution outcome (`route`/`fallback`/`auth_gated`)
  reported with the route id but **without** the raw query; any logged URI is
  host+path only with the query redacted (`?…`); fallback events carry a coarse
  reason enum, not the raw URI.
  **Traces:** AC-3, AC-8 (security/telemetry, §8/§10).

- **TC-AND-397-15** — CI wiring & determinism gate
  **Type:** manual (CI config review) + JVM · **Target:** JVM / CI
  **Preconditions:** Gradle `check` pipeline and the named instrumented task on
  `android-port`.
  **Steps:** Run `./gradlew check` (JVM/Robolectric) and the connected/instrumented
  task on emu35 + API-24 AVD; inspect for network calls and `Thread.sleep`; verify
  JaCoCo router coverage gate.
  **Expected:** Whole suite green on both API levels; router coverage ≥90%
  line/branch with CI failing below the gate; no real network calls; no
  `Thread.sleep`.
  **Traces:** AC-7, AC-8.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|---|---|
| AC-1 (positive route + args, https + custom) | TC-01, TC-02, TC-03, TC-10 |
| AC-2 (edge normalization) | TC-03, TC-04 |
| AC-3 (negative corpus → Fallback; fuzz never throws) | TC-05, TC-06, TC-12, TC-14 |
| AC-4 (auth-gating single-use redirect; security) | TC-07, TC-08 |
| AC-5 (manifest↔router parity; single exported surface) | TC-09 |
| AC-6 (instrumented lands on correct Compose dest, API 24 & 35) | TC-10, TC-11, TC-13 |
| AC-7 (router coverage ≥90% JaCoCo) | TC-15 |
| AC-8 (suite green in CI; no network; no sleep) | TC-13, TC-14, TC-15 |
