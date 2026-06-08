package com.testlogon.android.core.testing.net

import com.squareup.moshi.Moshi
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.junit.rules.TestRule
import org.junit.runner.Description
import org.junit.runners.model.Statement
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.util.concurrent.TimeUnit

/**
 * AND-046 — reusable MockWebServer harness for hermetic networking tests.
 *
 * JUnit4 [TestRule] that starts a [MockWebServer] on an ephemeral loopback port before each test and
 * shuts it down (in `finally`) after, so ports are never leaked across the suite. Exposes [baseUrl],
 * [enqueue], and [takeRequest], plus a [retrofit] builder that points the production converter config
 * at the mock server. Lives in `src/main` so it is visible to `testImplementation` dependents.
 */
class MockBackendRule(
    private val dispatcherFactory: (() -> Dispatcher)? = null,
) : TestRule {

    lateinit var server: MockWebServer
        private set

    val baseUrl: HttpUrl get() = server.url("/")

    val requestCount: Int get() = server.requestCount

    override fun apply(base: Statement, description: Description): Statement = object : Statement() {
        override fun evaluate() {
            server = MockWebServer().also { s ->
                dispatcherFactory?.let { s.dispatcher = it() }
                s.start()
            }
            try {
                base.evaluate()
            } finally {
                server.shutdown()
            }
        }
    }

    fun enqueue(response: MockResponse) = server.enqueue(response)

    fun enqueueFixture(name: String, code: Int = 200) = server.enqueue(Fixtures.ok(name, code))

    /** Bounded wait so a missing expected request fails the test rather than hanging the suite. */
    fun takeRequest(timeoutMs: Long = 5_000): RecordedRequest =
        requireNotNull(server.takeRequest(timeoutMs, TimeUnit.MILLISECONDS)) {
            "Expected a request within ${timeoutMs}ms but none arrived."
        }
}

/** Builds Retrofit against the mock server using the production-style Moshi converter config. */
fun MockBackendRule.retrofit(
    moshi: Moshi,
    client: OkHttpClient = defaultTestClient(),
): Retrofit = Retrofit.Builder()
    .baseUrl(baseUrl)
    .client(client)
    .addConverterFactory(MoshiConverterFactory.create(moshi))
    .build()

/** Short timeouts so timeout tests run in ~2s instead of the production 20s budget. */
fun defaultTestClient(cookieJar: CookieJar = InMemoryCookieJar()): OkHttpClient =
    OkHttpClient.Builder()
        .connectTimeout(2, TimeUnit.SECONDS)
        .readTimeout(2, TimeUnit.SECONDS)
        .writeTimeout(2, TimeUnit.SECONDS)
        .cookieJar(cookieJar)
        .build()

/**
 * Loads JSON fixtures from the `core-testing/src/main/resources/fixtures/` dir and builds [MockResponse]s
 * for success, the three FastAPI `detail` error variants, timeout, and malformed-body cases.
 */
object Fixtures {

    /** Reads `fixtures/<name>.json` from the classpath; throws with a clear message if missing. */
    fun json(name: String): String =
        requireNotNull(javaClass.classLoader?.getResourceAsStream("fixtures/$name.json")) {
            "Missing fixture: fixtures/$name.json"
        }.bufferedReader().use { it.readText() }

    fun ok(name: String, code: Int = 200): MockResponse =
        MockResponse()
            .setResponseCode(code)
            .setHeader("Content-Type", "application/json")
            .setBody(json(name))

    /** Success body supplied inline (e.g. a `{}` body) rather than from a fixture file. */
    fun okBody(body: String, code: Int = 200): MockResponse =
        MockResponse()
            .setResponseCode(code)
            .setHeader("Content-Type", "application/json")
            .setBody(body)

    /** A success response that also issues `Set-Cookie` for the session + ui_csrf cookies. */
    fun okWithSessionCookies(name: String, csrf: String = DEFAULT_CSRF, code: Int = 200): MockResponse =
        ok(name, code)
            .addHeader("Set-Cookie", "tl_session=sess-1; Path=/; HttpOnly")
            .addHeader("Set-Cookie", "ui_csrf=$csrf; Path=/")

    /** Raw `detail` error; [detailJson] is the JSON value of `detail` (string/array/object literal). */
    fun error(detailJson: String, code: Int): MockResponse =
        MockResponse()
            .setResponseCode(code)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"detail":$detailJson}""")

    /** A no-response socket; with the 2s test read timeout this surfaces as SocketTimeoutException. */
    fun timeout(): MockResponse = MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE)

    fun disconnect(): MockResponse = MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START)

    fun malformed(code: Int = 200): MockResponse =
        MockResponse().setResponseCode(code).setBody("{not json")

    /** A valid body delivered after [delayMs] (slow-but-eventual). */
    fun delayed(name: String, delayMs: Long): MockResponse =
        ok(name).setBodyDelay(delayMs, TimeUnit.MILLISECONDS)

    const val DEFAULT_CSRF = "csrf-test-token"
}

/** Typed fixture-name constants to avoid stringly-typed drift across tests. */
object FixtureName {
    const val SESSION_START_NO_MFA = "session_start_no_mfa"
    const val SESSION_START_MFA = "session_start_mfa_required"
    const val SESSION_START_MFA_TOTP_SMS = "session_start_mfa_totp_sms"
    const val MFA_TOTP_VERIFY_OK = "mfa_totp_verify_ok"
    const val MFA_TOTP_VERIFY_REMAINING_SMS = "mfa_totp_verify_remaining_sms"
    const val MFA_SMS_BEGIN_OK = "mfa_sms_begin_ok"
    const val MFA_SMS_VERIFY_OK = "mfa_sms_verify_ok"
    const val MFA_VERIFY_INVALID = "mfa_verify_invalid"
    const val MFA_VERIFY_INVALID_ARRAY = "mfa_verify_invalid_array"
    const val MFA_VERIFY_INVALID_OBJECT = "mfa_verify_invalid_object"
    const val SESSION_FINALIZE_OK = "session_finalize_ok"
    const val SESSION_REFRESH_OK = "session_refresh_ok"
    const val ME = "me"
    const val SESSIONS = "sessions"
    const val ERROR_DETAIL_STRING = "error_detail_string"
    const val ERROR_DETAIL_LIST = "error_detail_list"
    const val ERROR_DETAIL_OBJECT = "error_detail_object"
}

/**
 * Minimal in-memory [CookieJar] for cookie-roundtrip tests; delegates RFC 6265 matching to OkHttp's
 * [Cookie.matches]. The production persistent jar is validated separately.
 */
class InMemoryCookieJar : CookieJar {
    private val store = mutableListOf<Cookie>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        synchronized(store) {
            for (c in cookies) {
                store.removeAll { it.name == c.name && it.domain == c.domain && it.path == c.path }
                store += c
            }
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> =
        synchronized(store) { store.filter { it.matches(url) } }

    fun cookieValue(name: String): String? =
        synchronized(store) { store.firstOrNull { it.name == name }?.value }

    fun clear() = synchronized(store) { store.clear() }
}
