---
id: AND-011
title: Persistent cookie jar
milestone: M1
epic: E02
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-009]
blocks: [AND-012]
---

# AND-011 — Persistent cookie jar

## 1. Overview & Goal

TestLogon's web reference app authenticates with a **hybrid** scheme: it relies
on the browser cookie store *and* a persisted bearer `accessToken`. Verified in
`src/api/client.ts`, every request both sends `credentials: "include"` (cookies)
and, when an `accessToken` is present in the persisted auth store, an
`Authorization: Bearer <accessToken>` header. The cookie half keeps
`POST /ui/session/start`, the MFA exchange, `POST /ui/session/finalize`, the
`ui_csrf` CSRF cookie, and the `POST /ui/session/refresh` 401-recovery flow on
the same session. (Correction: the original draft claimed authentication is
"entirely through server-set cookies"; the source shows a bearer token is also
in play. The cookie jar this ticket builds is necessary but not by itself
sufficient — bearer-token storage is owned by the auth feature, AND-013+.)
Android has no implicit cookie store, so OkHttp must be given an explicit
`CookieJar`. The default `okhttp3.CookieJar.NO_COOKIES`
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
  `UiSessionStartResp {auth_required: bool, challenge_id?: string,
  required_factors: string[], session_id?: string}` (verified against OpenAPI
  schema `UiSessionStartResp` and `src/api/types.ts: SessionStartResp`) → MFA
  verify endpoints `POST /ui/mfa/totp/verify`, `POST /ui/mfa/sms/begin` +
  `POST /ui/mfa/sms/verify`, `POST /ui/mfa/email/begin` +
  `POST /ui/mfa/email/verify` → `POST /ui/session/finalize` (req
  `UiSessionFinalizeReq`) → `GET /ui/me`. (Correction: the original draft wrote
  `/ui/mfa/{totp|sms|email}/begin|verify`; TOTP has **no** `begin` endpoint in
  the OpenAPI index — only `/ui/mfa/totp/verify` exists. SMS and email have both
  begin and verify.) On `401`, the client calls `POST /ui/session/refresh` once
  and retries (verified in `src/api/client.ts: refreshSession`/`api`). Every step
  depends on cookies surviving between calls.
- **Web reference:** browser-managed cookies; `src/api/client.ts` sends
  `credentials: 'include'` on every call and echoes the `ui_csrf` cookie value
  into an `X-CSRF-Token` header. (Correction: the original draft pointed at a
  nonexistent `frontend/src/api/*` path; the reference source root is `src/`.)
  This jar reproduces the cookie-transport behavior natively.
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
  "name": "ui_csrf",
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

- `ui_csrf` — CSRF token cookie. **Verified**: `src/api/client.ts` and
  `src/stores/offlineStore.ts` read `ui_csrf` from `document.cookie` and copy it
  into the `X-CSRF-Token` request header. Because the web client reads it from
  `document.cookie`, this cookie is **not** `HttpOnly`. Exposed to AND-012 via
  `currentCookie("ui_csrf", url)`.
- A server-set **session cookie** (`HttpOnly`) — its existence is implied by the
  cookie-auth flow (`require_ui_session` server guard, `credentials: "include"`,
  the `POST /ui/session/refresh` recovery path). **Unverified assumption:** the
  original draft named it `tl_session`; that exact name does **not** appear
  anywhere in the reference source or OpenAPI (expected, since an `HttpOnly`
  cookie is invisible to JS). The jar must treat the name as opaque and store
  whatever the server sends — it must not hard-code `tl_session`.
- A persistent **refresh cookie** consumed by `POST /ui/session/refresh`
  (which takes no request body — verified `resp=200`, `req=` empty in the
  OpenAPI index). **Unverified assumption:** the original draft named it
  `tl_refresh` and assumed it is a separate, long-lived `Max-Age` cookie; no such
  name or attribute is observable in the sources. The refresh mechanism is real;
  whether it rides on the same `HttpOnly` session cookie or a distinct refresh
  cookie cannot be confirmed from these references (see OQ-1). The jar must not
  depend on a specific refresh-cookie name.

Cookie names other than `ui_csrf` are therefore treated as opaque. Over the dev
host these arrive without `Secure` (plaintext HTTP) and must still be stored. No
request body or JSON contract is owned here.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **CSRF: web client reads `ui_csrf` cookie and sends it as `X-CSRF-Token`.**
   VERDICT: Verified. SOURCE: `src/api/client.ts: api` (`getCookie("ui_csrf")`
   → `headers.set("X-CSRF-Token", csrf)`); corroborated in
   `src/stores/offlineStore.ts: getCsrfFromCookie` and
   `src/api/endpoints/profile.ts` / `src/api/endpoints/kycCompliance.ts`.
2. **`ui_csrf` is NOT `HttpOnly`.** VERDICT: Verified (by inference from
   behavior). SOURCE: `src/api/client.ts` reads it from `document.cookie`, which
   is impossible for an `HttpOnly` cookie. The original draft's `Set-Cookie:
   ui_csrf=...; Path=/` (no HttpOnly) is consistent and retained.
3. **401 recovery: client calls `POST /ui/session/refresh` once, then retries.**
   VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` (`fetch("/ui/
   session/refresh", { method: "POST", credentials: "include" })`) and the 401
   branch of `api` (single-flight `refreshPromise`, retry).
4. **`POST /ui/session/refresh` takes no request body and returns 200.**
   VERDICT: Verified. SOURCE: OpenAPI index `POST /ui/session/refresh | req= |
   resp=200:` (op `ui_session_refresh_ui_session_refresh_post`).
5. **`POST /ui/session/start` request/response shape
   `{auth_required, challenge_id?, required_factors[], session_id?}`.**
   VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/start`
   (`req=UiSessionStartReq, resp=200:UiSessionStartResp`) + schema
   `components.schemas.UiSessionStartResp` (required: `auth_required`); frontend
   `src/api/types.ts: SessionStartResp` and `src/api/endpoints/auth.ts:
   sessionStart`.
6. **`POST /ui/session/finalize` exists (req `UiSessionFinalizeReq`).**
   VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/finalize`
   (`req=UiSessionFinalizeReq`); `src/api/endpoints/auth.ts: sessionFinalize`.
7. **`GET /ui/me` exists.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/me`
   (op `ui_me_ui_me_get`); `src/api/endpoints/auth.ts: getMe`.
8. **MFA verify endpoints.** VERDICT: Corrected. SOURCE: OpenAPI index —
   `POST /ui/mfa/totp/verify`, `POST /ui/mfa/sms/begin`,
   `POST /ui/mfa/sms/verify`, `POST /ui/mfa/email/begin`,
   `POST /ui/mfa/email/verify`; `src/api/endpoints/auth.ts` (`verifyTotp`,
   `beginSms`/`verifySms`, `beginEmail`/`verifyEmail`). The draft's
   `/ui/mfa/{totp|sms|email}/begin|verify` falsely implied a `totp/begin`
   endpoint — none exists; TOTP is verify-only.
9. **Web app authenticates "entirely through server-set cookies".**
   VERDICT: Corrected. SOURCE: `src/api/client.ts: api` also sends
   `Authorization: Bearer <accessToken>` from `src/stores/authStore.ts`
   (persisted zustand store, `accessToken` field). Auth is hybrid (cookie session
   + bearer token), not cookie-only. The cookie jar remains required but is not
   the whole auth story.
10. **Cookie name `tl_session` for the session/auth cookie.**
    VERDICT: Unverified-assumption. SOURCE: no occurrence of `tl_session` in
    `reference/src/**` or `openapi.pretty.json`. An `HttpOnly` session cookie is
    invisible to JS, so absence is expected; the name itself is unconfirmed.
    Spec now treats the name as opaque.
11. **Cookie name `tl_refresh` and a distinct long-lived `Max-Age` refresh
    cookie.** VERDICT: Unverified-assumption. SOURCE: no occurrence of
    `tl_refresh` in the sources; only the `/ui/session/refresh` *endpoint* is
    observable. Whether refresh rides the session cookie or a separate cookie is
    unknown (see OQ-1). Spec no longer hard-codes this name.
12. **Reference frontend source path.** VERDICT: Corrected. SOURCE: actual root
    is `reference/src/` (e.g. `src/api/client.ts`); the draft's
    `frontend/src/api/*` path does not exist in the reference tree.
13. **Dev host `http://18.222.237.167:8000` is plaintext HTTP; cookies arrive
    without `Secure`.** VERDICT: Unverified-assumption. SOURCE: not derivable
    from the reference source or OpenAPI (no base-URL constant; the web client
    uses `VITE_API_BASE_URL` from env in `src/api/client.ts: withApiBase`).
    Carried over from the ticket/environment context; treated as a config-time
    assumption, not a contract.
14. **OkHttp `Cookie.matches(HttpUrl)` implements RFC 6265 domain/path/secure
    matching, and `CookieJar.NO_COOKIES` discards cookies.**
    VERDICT: Verified (framework ref). SOURCE: OkHttp 4.x API —
    https://square.github.io/okhttp/4.x/okhttp/okhttp3/-cookie/ and
    https://square.github.io/okhttp/4.x/okhttp/okhttp3/-cookie-jar/.
15. **`EncryptedSharedPreferences` / `MasterKey` (AES256-SIV keys, AES256-GCM
    values) from `androidx.security:security-crypto`, Keystore-backed.**
    VERDICT: Verified (framework ref). SOURCE:
    https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences
    and .../crypto/MasterKey. Note: `security-crypto` is deprecated as of
    Jetpack (2024); 1.1.0-alpha06 remains the last published artifact — relevant
    to OQ-2.
16. **Auto-backup exclusion via `backup_rules.xml` / `allowBackup`.**
    VERDICT: Verified (framework ref). SOURCE:
    https://developer.android.com/guide/topics/data/autobackup#IncludingFiles.

### Corrections made

- Overview/§2: changed "authenticates entirely through server-set cookies" to a
  hybrid cookie + bearer-token description (claim 9).
- §2 auth-flow line: removed the nonexistent `/ui/mfa/totp/begin`; listed the
  real verify/begin endpoints and added verified request/response schema names
  (claims 5, 8).
- §2 web-reference line: fixed `frontend/src/api/*` → `src/api/client.ts`, and
  named the `X-CSRF-Token` header explicitly (claims 1, 12).
- §5 API Contract: replaced hard-coded `tl_session`/`tl_refresh` cookie names
  with opaque-name handling, marked them unverified, and corrected `ui_csrf` to
  non-`HttpOnly` with verified sources (claims 2, 10, 11).
- §4 serialization JSON example: changed the illustrative `name` from
  `tl_session` to `ui_csrf` (the only confirmed cookie name).

### Open assumptions

- **Session/refresh cookie names and attributes** (claims 10, 11): unverifiable
  because the session cookie is `HttpOnly` (never exposed to the reference JS)
  and the OpenAPI spec documents endpoints, not `Set-Cookie` headers. Resolution
  requires observing live `Set-Cookie` responses from the backend (OQ-1).
- **Whether the backend session cookie is session-scoped vs persistent**
  (OQ-1): same reason; drives the `PersistSessionCookies` default and the
  restart-survival path.
- **Plaintext dev host / missing `Secure` attribute** (claim 13): an
  environment fact, not in the verifiable sources; revalidate for production
  HTTPS.
- **Exact bearer-token lifecycle** (where `accessToken` is minted/refreshed for
  Android): owned by AND-013+; out of scope here but noted because it changes
  the "cookies alone restore the session" premise.

## 17. Test Plan

Test types: unit (JUnit + Truth), contract/MockWebServer, integration,
Compose-UI (n/a — headless), instrumented/e2e, manual. IDs trace to the
section-14 Acceptance Criteria (AC-1..AC-7).

- **TC-AND-011-01 — Capture + replay round-trip.**
  Type: contract/MockWebServer.
  Preconditions: `PersistentCookieJar` over a `FakeCookieStore`, OkHttp client
  with the jar attached; MockWebServer enqueues a response with
  `Set-Cookie: a=1; Path=/`.
  Steps: (1) GET `/x` (server sets cookie); (2) GET `/y` on the same host.
  Expected: request 2 carries `Cookie: a=1`. Traces: AC-1.

- **TC-AND-011-02 — Persistent cookie survives simulated process restart.**
  Type: unit + instrumented.
  Preconditions: a file/real-Keystore-backed `CookieStore`.
  Steps: (1) `saveFromResponse` with a cookie carrying `Max-Age`/`Expires`
  (persistent); (2) construct a **new** `PersistentCookieJar` over the **same**
  store; (3) `loadForRequest` for a matching URL. Instrumented variant: real
  `EncryptedCookieStore` on device, recreate the store/Hilt graph.
  Expected: the persistent cookie is returned after the fresh construction.
  Traces: AC-2.

- **TC-AND-011-03 — Session (no-expiry) cookie not persisted by default.**
  Type: unit.
  Preconditions: `PersistSessionCookies=false`.
  Steps: (1) `saveFromResponse` with a cookie that has no `Max-Age`/`Expires`;
  (2) confirm it is returned in-process; (3) new jar over the same store.
  Expected: present in the first process, absent after the fresh jar.
  Traces: AC-2, AC-3.

- **TC-AND-011-04 — Domain matching (RFC 6265).** Type: unit.
  Preconditions: cookie stored for `host-a`.
  Steps: `loadForRequest` for `host-b`.
  Expected: cookie is not returned (delegates to `Cookie.matches`).
  Traces: AC-3.

- **TC-AND-011-05 — Path + scheme matching.** Type: unit.
  Preconditions: cookie with `Path=/api`; a `Secure` cookie stored.
  Steps: `loadForRequest` for `/` (path miss) and for `http://` vs `https://`
  (scheme check on the `Secure` cookie).
  Expected: `Path=/api` cookie absent at `/`; `Secure` cookie withheld over
  `http`. Traces: AC-3.

- **TC-AND-011-06 — Expiry enforcement + eviction.** Type: unit.
  Preconditions: cookie with `expiresAt` in the past placed in the store.
  Steps: `loadForRequest` for a matching URL.
  Expected: cookie not returned and removed from both memory and store.
  Traces: AC-3.

- **TC-AND-011-07 — Overwrite + delete semantics.** Type: unit.
  Steps: (1) save `(name,domain,path)=a` value v1; (2) save same key value v2;
  (3) save same key with a past expiry.
  Expected: v2 replaces v1; the past-expiry write deletes the entry from memory
  and store. Traces: AC-3.

- **TC-AND-011-08 — `clear()` wipes memory and storage.** Type: unit +
  instrumented.
  Steps: save persistent cookies; call `clear()`; construct a fresh jar over the
  same store. Instrumented: assert the `EncryptedSharedPreferences` file is empty
  (synchronous `commit()`).
  Expected: store empty and the fresh jar returns nothing. Traces: AC-4.

- **TC-AND-011-09 — Logging redaction (no cookie values in logs).**
  Type: contract/MockWebServer + manual.
  Preconditions: AND-009 `HttpLoggingInterceptor` + the jar both attached; a log
  capture sink.
  Steps: drive a request/response that sets and sends a cookie; inspect captured
  logs.
  Expected: no `Cookie`/`Set-Cookie` values appear; only name+domain diagnostics.
  Traces: AC-5.

- **TC-AND-011-10 — `currentCookie("ui_csrf", url)` helper.** Type: unit.
  Preconditions: a `ui_csrf` cookie stored for the host.
  Steps: call `currentCookie("ui_csrf", url)` for a matching and a
  non-matching URL.
  Expected: returns the cookie for the match, `null` otherwise (supports the
  AND-012 CSRF interceptor). Traces: AC-6.

- **TC-AND-011-11 — Crypto/deserialization resilience.** Type: unit +
  instrumented.
  Preconditions: corrupt the persisted blob (truncate/garble) or inject one
  undecodable entry alongside a valid one.
  Steps: construct a jar / call `loadAll`.
  Expected: `GeneralSecurityException`/`IOException` and per-entry decode errors
  are caught; the jar resets to empty (full corruption) or skips the bad entry
  (single), never throwing into the OkHttp call. Traces: AC-7.

- **TC-AND-011-12 — Concurrency safety.** Type: unit (stress).
  Steps: run many threads invoking `saveFromResponse`/`loadForRequest`
  concurrently.
  Expected: no `ConcurrentModificationException`, no lost writes; disk I/O occurs
  outside the lock. Traces: AC-2, AC-3.

- **TC-AND-011-13 — Plaintext-host / no-`Secure` storage (dev) + offline path.**
  Type: contract/MockWebServer.
  Preconditions: server (HTTP) returns a credential cookie without `Secure`;
  then simulate a network failure on the next call.
  Steps: (1) capture the non-`Secure` cookie; (2) trigger an offline/transport
  error on a later request.
  Expected: the cookie is still stored and replayed (jar does not require
  `Secure`); a transport failure does not corrupt or clear the jar (cookies
  persist for retry). Traces: AC-1, AC-2.

- **TC-AND-011-14 — Disk-write failure tolerance + backup exclusion.**
  Type: unit + manual.
  Steps: (unit) stub `store.saveAll` to throw; save a persistent cookie. (manual)
  verify `backup_rules.xml` excludes the `tl_cookie_jar` prefs file.
  Expected: the cookie stays usable in-memory for the live session; no exception
  propagates to OkHttp; the cookie prefs file is excluded from auto-backup.
  Traces: AC-2, AC-5.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (response cookie attached to next request) | TC-01, TC-13 |
| AC-2 (persistent cookie survives process restart) | TC-02, TC-03, TC-12, TC-13, TC-14 |
| AC-3 (RFC 6265 domain/path/scheme/expiry matching) | TC-03, TC-04, TC-05, TC-06, TC-07, TC-12 |
| AC-4 (`clear()` wipes memory + storage) | TC-08 |
| AC-5 (no cookie names/values in logs) | TC-09, TC-14 |
| AC-6 (`currentCookie("ui_csrf", url)` for AND-012) | TC-10 |
| AC-7 (crypto/deser failure degrades to empty, no crash) | TC-11 |
