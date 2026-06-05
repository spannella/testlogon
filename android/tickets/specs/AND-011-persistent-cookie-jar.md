---
id: AND-011
title: Persistent cookie jar
milestone: M1
epic: E02
priority: P0
size: M
status: draft
depends_on: [AND-009]
blocks: [AND-012]
---

# AND-011 — Persistent cookie jar

## 1. Overview & Goal

TestLogon authenticates entirely through server-set cookies. The web reference
app relies on the browser cookie store to keep `POST /ui/session/start`,
the MFA exchange, `POST /ui/session/finalize`, and every authenticated request
on the same session. Android has no implicit cookie store, so OkHttp must be
given an explicit `CookieJar`. The default `okhttp3.CookieJar.NO_COOKIES`
discards every `Set-Cookie`, which would break the session immediately after the
first hop.

The goal of this ticket is to implement a production-grade, persistent,
encrypted `CookieJar` that:

- captures cookies from every response (`saveFromResponse`) and replays the
  correct subset on every matching request (`loadForRequest`);
- honors RFC 6265 domain matching, path matching, `Secure`, `HttpOnly`,
  `Max-Age`/`Expires`, and host-only flags;
- persists non-session (durable) cookies to encrypted storage so that the
  authenticated session **survives a full process death and cold start**;
- exposes a `clear()` API for logout that wipes both the in-memory cache and the
  encrypted persistence layer;
- is provided through Hilt and wired into the shared `OkHttpClient` from
  AND-009.

This jar is the foundation for the CSRF interceptor (AND-012), which reads the
`ui_csrf` cookie this jar stores, and for the entire cookie-based auth flow
(AND-013+). Without it, no authenticated screen can function.

## 2. Context & References

- **Module:** `core-network` (`com.testlogon.android.core.network`). The jar
  lives at `com.testlogon.android.core.network.cookie`.
- **Depends on AND-009** — `OkHttpClient + timeouts + logging`. AND-009 builds
  the singleton `OkHttpClient`; this ticket adds `.cookieJar(persistentCookieJar)`
  to that builder. The two tickets touch the same Hilt `NetworkModule`.
- **Blocks AND-012** — the CSRF interceptor reads the `ui_csrf` cookie value out
  of this jar (or via the jar's helper) to set the `X-CSRF-Token` header.
- **Auth flow (downstream, AND-013+):** `POST /ui/session/start` →
  `{auth_required, challenge_id, required_factors[]}` → MFA
  `/ui/mfa/{totp|sms|email}/begin|verify` → `POST /ui/session/finalize` →
  `GET /ui/me`. On `401`, the client calls `POST /ui/session/refresh` once and
  retries. Every step depends on cookies surviving between calls.
- **Web reference:** browser-managed cookies; `frontend/src/api/*` sends
  `credentials: 'include'` and echoes `ui_csrf`. This jar reproduces that
  behavior natively.
- **Backend:** dev host `http://18.222.237.167:8000` is **plaintext HTTP**.
  Cookies arriving over HTTP will typically lack the `Secure` attribute; the jar
  must not require `Secure` to persist a cookie. Production will be HTTPS.
- **Library:** OkHttp 4.12 `okhttp3.CookieJar`, `okhttp3.Cookie`,
  `okhttp3.HttpUrl`. Encrypted storage via `androidx.security:security-crypto`
  (`EncryptedSharedPreferences`) backed by the Android Keystore.

## 3. Functional Requirements

FR-1. **Capture.** On every response, `saveFromResponse(url, cookies)` stores all
returned cookies keyed by their effective identity (name + domain + path).

FR-2. **Replay.** On every request, `loadForRequest(url)` returns exactly the
cookies whose domain, path, and scheme match the target URL per RFC 6265.

FR-3. **Persistence.** Cookies with a `persistent` lifetime (an explicit
`Max-Age`/`Expires`) are written to `EncryptedSharedPreferences`. Session
cookies (no expiry) are kept in memory only and dropped on process death — this
matches browser semantics. (See Open Question OQ-1: the backend session cookie
may be a session cookie; if so it must NOT survive restart and the auth
restoration relies on the persistent refresh cookie. Behavior is configurable
via `PersistSessionCookies` flag, default `false`.)

FR-4. **Restore on startup.** On first construction (lazy), the jar loads all
non-expired persisted cookies from encrypted storage into the in-memory cache.

FR-5. **Expiry enforcement.** Expired cookies are never returned from
`loadForRequest` and are evicted from both memory and storage when encountered.

FR-6. **Overwrite semantics.** A new cookie with the same (name, domain, path)
replaces the previous one. A cookie returned with an already-passed expiry is a
deletion and removes the matching entry.

FR-7. **Clear-on-logout.** `clear()` removes every cookie from memory and
encrypted storage synchronously and is callable from the logout path
(AND-013+).

FR-8. **CSRF helper.** Expose `currentCookie(name: String, url: HttpUrl): Cookie?`
so AND-012 can fetch `ui_csrf` without re-implementing matching.

FR-9. **Thread safety.** `saveFromResponse`/`loadForRequest` are called from
OkHttp dispatcher threads concurrently; all mutations must be safe.

## 4. Technical Design

Package `com.testlogon.android.core.network.cookie`.

```kotlin
/** Persistence boundary; swappable for tests. */
interface CookieStore {
    fun loadAll(): List<Cookie>
    fun saveAll(cookies: Collection<Cookie>)
    fun removeAll(cookies: Collection<Cookie>)
    fun clear()
}

/** EncryptedSharedPreferences-backed implementation. */
@Singleton
class EncryptedCookieStore @Inject constructor(
    @ApplicationContext context: Context,
) : CookieStore {

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "tl_cookie_jar",
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    override fun loadAll(): List<Cookie> { /* deserialize, drop expired */ }
    override fun saveAll(cookies: Collection<Cookie>) { /* serialize persistent only */ }
    override fun removeAll(cookies: Collection<Cookie>) { /* remove by key */ }
    override fun clear() { prefs.edit().clear().commit() }

    companion object { fun keyFor(c: Cookie) = "${c.name}|${c.domain}|${c.path}" }
}
```

```kotlin
@Singleton
class PersistentCookieJar @Inject constructor(
    private val store: CookieStore,
) : CookieJar {

    // Keyed by name|domain|path; guarded by the lock.
    private val cache = LinkedHashMap<String, Cookie>()
    private val lock = Any()
    @Volatile private var restored = false

    private fun ensureRestored() {
        if (restored) return
        synchronized(lock) {
            if (restored) return
            store.loadAll()
                .filterNot { it.expired() }
                .forEach { cache[EncryptedCookieStore.keyFor(it)] = it }
            restored = true
        }
    }

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        ensureRestored()
        val persistable = mutableListOf<Cookie>()
        val deletable = mutableListOf<Cookie>()
        synchronized(lock) {
            for (c in cookies) {
                val key = EncryptedCookieStore.keyFor(c)
                if (c.expired()) {
                    cache.remove(key)?.let { deletable += it }
                } else {
                    cache[key] = c
                    if (c.persistent) persistable += c
                }
            }
        }
        if (persistable.isNotEmpty()) store.saveAll(persistable)
        if (deletable.isNotEmpty()) store.removeAll(deletable)
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        ensureRestored()
        val now = System.currentTimeMillis()
        val expired = mutableListOf<Cookie>()
        val matches: List<Cookie>
        synchronized(lock) {
            val it = cache.values.iterator()
            val out = ArrayList<Cookie>()
            while (it.hasNext()) {
                val c = it.next()
                if (c.expiresAt <= now) { it.remove(); expired += c; continue }
                if (c.matches(url)) out += c
            }
            matches = out
        }
        if (expired.isNotEmpty()) store.removeAll(expired)
        return matches
    }

    fun currentCookie(name: String, url: HttpUrl): Cookie? =
        loadForRequest(url).firstOrNull { it.name == name }

    fun clear() {
        synchronized(lock) { cache.clear() }
        store.clear()
    }

    private fun Cookie.expired() = expiresAt <= System.currentTimeMillis()
}
```

Domain/path/secure matching is delegated to OkHttp's `Cookie.matches(HttpUrl)`,
which already implements RFC 6265 host-only, domain-suffix, path-prefix, and
`Secure` rules. The jar must not bypass it. `Cookie.parse(url, header)` is used
implicitly by OkHttp before `saveFromResponse`, so attributes are already
normalized when they reach the jar.

**Serialization.** Each persistent cookie is encoded as a single JSON object
(via Moshi, AND-006) capturing all eight RFC fields so it can be rebuilt with
`Cookie.Builder`:

```json
{
  "name": "tl_session",
  "value": "<opaque>",
  "expiresAt": 1780000000000,
  "domain": "18.222.237.167",
  "path": "/",
  "secure": false,
  "httpOnly": true,
  "hostOnly": true
}
```

Reconstruction: `Cookie.Builder().name(..).value(..).expiresAt(..).domain(..)`
(use `hostOnlyDomain(..)` when `hostOnly` is true).path(..)`, conditionally
`.secure()` / `.httpOnly()`.

**Hilt wiring** (extends AND-009's `NetworkModule`):

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class CookieModule {
    @Binds @Singleton abstract fun bindStore(impl: EncryptedCookieStore): CookieStore
    @Binds @Singleton abstract fun bindJar(impl: PersistentCookieJar): CookieJar
}
```

AND-009's `OkHttpClient` provider gains `.cookieJar(cookieJar)` where
`cookieJar: CookieJar` is injected. A separate `@Named("cookieJar")` qualifier
exposing the concrete `PersistentCookieJar` (for `clear()`/`currentCookie`) is
provided so logout and AND-012 can reach the helpers without a downcast.

## 5. API Contract

This ticket implements no new backend endpoints; it is a network-infrastructure
component. It interacts with the wire only through HTTP `Set-Cookie` response
headers and `Cookie` request headers, which the framework handles. The relevant
contract is the cookie set the backend issues during the auth flow owned by
AND-013+:

- `Set-Cookie: tl_session=...; HttpOnly; Path=/` — session/auth cookie.
- `Set-Cookie: ui_csrf=...; Path=/` — CSRF token cookie, readable by AND-012
  via `currentCookie("ui_csrf", url)`.
- `Set-Cookie: tl_refresh=...; Max-Age=...; HttpOnly; Path=/` — persistent
  refresh cookie used by `POST /ui/session/refresh`; this is the cookie that
  must survive process restart.

Over the dev host these arrive without `Secure` (plaintext HTTP) and must still
be stored. No request body or JSON contract is owned here.

## 6. Data & State Management

- **In-memory:** `LinkedHashMap<String, Cookie>` keyed by `name|domain|path`,
  guarded by a single monitor lock. Insertion order is preserved for stable
  iteration but is not semantically significant.
- **At rest:** `EncryptedSharedPreferences` file `tl_cookie_jar`, one preference
  entry per persistent cookie keyed by `keyFor(cookie)`, value = Moshi JSON.
  Only `persistent` cookies are written; session cookies stay in memory.
- **Lifecycle:** the jar is a Hilt `@Singleton`; restoration is lazy on first
  jar access and idempotent (`restored` double-checked flag). No `Application`
  init work is required, keeping cold-start cost off the main thread.
- **No Room / no DataStore Proto.** Encrypted prefs are chosen over DataStore
  here because the security-crypto library targets `SharedPreferences` directly
  and the dataset is tiny (single-digit cookies). DataStore remains the choice
  for non-secret app prefs elsewhere.
- **Memory ↔ disk consistency:** writes update memory first, then disk; expiry
  eviction during `loadForRequest` removes from both. `clear()` wipes both.

## 7. Error Handling & Resilience

- **Keystore/crypto failure on read** (corrupt file, key rotation, restored
  backup): `loadAll()` catches `GeneralSecurityException`/`IOException`, clears
  the prefs file, returns an empty list, and logs a redacted warning. The app
  degrades to "logged out" rather than crashing — the user re-authenticates.
- **Deserialization failure** of a single entry: skip that entry, continue;
  never let one bad cookie poison the whole jar.
- **Disk write failure** in `saveAll`: log and continue; the cookie remains in
  memory for the current process so the active session still works, it simply
  won't survive restart. No exception is propagated to the OkHttp call.
- **Concurrency:** all cache mutation is inside `synchronized(lock)`; disk I/O is
  performed outside the lock to avoid blocking the dispatcher under contention.
- **Expiry skew:** comparisons use `System.currentTimeMillis()`; OkHttp clamps
  `expiresAt` to a max sentinel, so far-future cookies behave correctly.

## 8. Security & Privacy

- Cookies are bearer credentials. At rest they are encrypted with
  `EncryptedSharedPreferences` (AES256-SIV keys, AES256-GCM values) under a
  Keystore-held `MasterKey`; key material never leaves the secure hardware where
  available.
- Cookie names and values MUST NOT appear in logs. The AND-009
  `HttpLoggingInterceptor` already redacts `Cookie`/`Set-Cookie` headers; this
  ticket adds no plaintext logging of cookie values. Diagnostic logs use cookie
  name + domain only.
- `clear()` on logout is mandatory to prevent credential leakage to a
  subsequent user on a shared device; it must `commit()` (synchronous) not
  `apply()` so the wipe is durable before the logout flow proceeds.
- `allowBackup` for the cookie prefs file should be excluded from auto-backup
  (`backup_rules.xml`) so credentials are not exfiltrated via cloud backup.
- The jar does not require `Secure`; on the plaintext dev host this is
  unavoidable. A debug-build assertion logs (without values) when a credential
  cookie is received over a non-HTTPS scheme, to flag production misconfig.

## 9. Accessibility & i18n

Not applicable. This is a headless network component with no UI surface, no
user-visible strings, and no locale-dependent behavior. Any user-facing
"session expired, please sign in" messaging is owned by the auth feature
(AND-013+) and the global UI states.

## 10. Telemetry & Logging

- Debug-only, value-redacted logs at jar boundaries: `cookie.saved name=ui_csrf
  domain=...`, `cookie.restored count=N`, `cookie.cleared`, `cookie.evicted
  reason=expired`.
- Optional counters (if an analytics sink exists in `core-data`): number of
  cookies restored at cold start, count of crypto-failure resets. These are
  metadata only — never names beyond a fixed allowlist (`ui_csrf`) and never
  values.
- No PII and no credential material is ever emitted to any telemetry channel.

## 11. Testing Strategy

Unit tests (`core-network` test source set, JUnit + MockWebServer + Truth):

- **TC-1 round-trip:** server returns `Set-Cookie: a=1`; a subsequent request to
  a matching URL includes `Cookie: a=1`. (Acceptance #1, in-process half.)
- **TC-2 process-restart survival:** drive `saveFromResponse` with a persistent
  cookie, construct a **new** `PersistentCookieJar` over the **same**
  `CookieStore`, assert `loadForRequest` returns it. With MockWebServer and a
  shared file-backed store, this proves the cookie survives a simulated cold
  start. (Acceptance #1, persistence half.)
- **TC-3 session cookie not persisted:** cookie without expiry is returned in the
  same process but absent after a fresh jar over the same store (default flag).
- **TC-4 domain mismatch:** cookie for `host-a` is not sent to `host-b`.
- **TC-5 path matching:** cookie with `Path=/api` not sent to `/`.
- **TC-6 expiry:** cookie past `expiresAt` is neither returned nor persisted, and
  is evicted from the store.
- **TC-7 overwrite/delete:** same (name,domain,path) replaces; expired-overwrite
  deletes.
- **TC-8 clear():** after `clear()`, store and a fresh jar are empty.
- **TC-9 crypto resilience:** corrupt the prefs blob; jar resets cleanly and
  returns empty rather than throwing.
- **TC-10 concurrency:** parallel `saveFromResponse`/`loadForRequest` over many
  threads completes without `ConcurrentModificationException`.
- **TC-11 currentCookie helper:** returns `ui_csrf` for a matching URL (supports
  AND-012).

Instrumented test (`androidTest`): real `EncryptedCookieStore` on a device/
emulator, save then re-create the Hilt graph (or new store instance) to confirm
real Keystore-backed persistence; covers the on-device process-restart claim.

`core-testing` provides an in-memory `FakeCookieStore` for fast unit tests.

## 12. Dependencies & Sequencing

- **Blocked by AND-009** (`OkHttpClient + timeouts + logging`): the client
  builder must exist before `.cookieJar(...)` can be attached. Coordinate the
  `NetworkModule` edit.
- **Blocks AND-012** (`CSRF interceptor`): it consumes `currentCookie("ui_csrf",
  url)`. Land this first.
- **Blocks AND-013+** (cookie auth flow): start/MFA/finalize/me/refresh all
  require a persistent session.
- **Transitive:** AND-003/AND-004 (module + DI scaffolding) via AND-009;
  AND-006 (Moshi) for cookie serialization.
- New dependency: `androidx.security:security-crypto:1.1.0-alpha06` (or latest
  stable 1.0.0 if alpha is disallowed by policy — see OQ-2). Add to the
  `core-network` build and version catalog.

## 13. Risks & Open Questions

- **OQ-1:** Is the backend auth cookie a *session* cookie (no `Max-Age`) or
  *persistent*? If session-scoped, restart survival depends on `tl_refresh` +
  `POST /ui/session/refresh`, not the session cookie. Confirm against
  `/openapi.json` and observed `Set-Cookie` headers; `PersistSessionCookies`
  defaults to `false` to match browser behavior.
- **OQ-2:** `security-crypto` 1.1.0 is alpha; 1.0.0 is stable but older. Choose
  per project dependency policy.
- **Risk:** Keystore key invalidation (device PIN change, app restore) can make
  stored cookies undecryptable. Mitigated by TC-9 reset-on-failure → user
  re-auth.
- **Risk:** plaintext dev host means cookies are stored without `Secure`; safe
  for dev, must be re-validated for production HTTPS.
- **Risk:** clock skew between device and server affecting expiry; accepted, uses
  device time as OkHttp does.

## 14. Acceptance Criteria

AC-1 (from backlog): A cookie set by a server response is automatically attached
to the next matching request (verified by TC-1 against MockWebServer).

AC-2 (from backlog): A persistent cookie **survives process restart** —
verified by TC-2 (fresh jar over the same store) and the instrumented
real-Keystore test.

AC-3: Domain, path, scheme, and expiry matching follow RFC 6265 (TC-4..TC-7),
delegating to `Cookie.matches`.

AC-4: `clear()` wipes memory and encrypted storage; a fresh jar afterwards is
empty (TC-8).

AC-5: Cookie names/values never appear in logs; AND-009 redaction verified to
still hold with the jar attached.

AC-6: `currentCookie("ui_csrf", url)` returns the stored CSRF cookie for AND-012
(TC-11).

AC-7: Crypto/deserialization failures degrade to empty (logged-out) without
crashing (TC-9).

## 15. Definition of Done

- `PersistentCookieJar`, `CookieStore`, `EncryptedCookieStore`, and `CookieModule`
  implemented in `com.testlogon.android.core.network.cookie` and attached to the
  AND-009 `OkHttpClient`.
- `security-crypto` added to the version catalog and `core-network` build; backup
  rules exclude the cookie prefs file.
- All TC-1..TC-11 unit tests plus the instrumented persistence test pass in CI.
- `FakeCookieStore` added to `core-testing`.
- No cookie values in logs (manual + redaction test).
- `currentCookie` helper exported for AND-012; logout `clear()` entry point
  available for AND-013+.
- Code reviewed, ktlint/detekt clean, merged to `android-port`.
