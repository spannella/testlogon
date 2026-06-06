---
id: AND-397
title: Public surfaces tests
milestone: M8
epic: E51
priority: P2
size: M
status: draft
depends_on: [AND-396]
blocks: []
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
