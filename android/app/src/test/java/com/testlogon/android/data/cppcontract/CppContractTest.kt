package com.testlogon.android.data.cppcontract

import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.di.NetworkModule
import com.testlogon.android.data.activity.ActivityApi
import com.testlogon.android.data.analytics.AnalyticsDashboardApi
import com.testlogon.android.data.auth.AuthApi
import com.testlogon.android.data.dashboard.DashboardApi
import com.testlogon.android.data.feed.CurrentUserApi
import com.testlogon.android.data.messaging.MessagingApi
import com.testlogon.android.data.preferences.MediaPreferencesApi
import com.testlogon.android.data.preferences.NotificationPreferencesApi
import com.testlogon.android.data.profile.ProfileApi
import kotlinx.coroutines.runBlocking
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * A1 — Android client-contract test against the cpp backend (live).
 *
 * Exercises the app's REAL network layer (the production Retrofit API interfaces + the production
 * Moshi from [NetworkModule.provideMoshi]) against the running C++ backend on https://192.168.0.82:8443
 * (self-signed cert -> trust-all SSLSocketFactory here). For each of ~10 core GET endpoints it asserts:
 *   (a) HTTP 2xx from the live server, and
 *   (b) the JSON body deserializes into the app's own DTO type without throwing.
 * A field/shape/type mismatch surfaces as a Moshi JsonDataException = a real app<->cpp contract bug.
 *
 * OPT-IN / LIVE: this is NOT a hermetic unit test. It hits a real server, so it is gated behind the
 * env var CPP_E2E=1 (assumeTrue -> the test is SKIPPED, not failed, when unset) so it never runs or
 * flakes in the normal hermetic `testDebugUnitTest` CI lane. Run it explicitly:
 *
 *   CPP_E2E=1 CPP_BASE_URL=https://192.168.0.82:8443/ \
 *     ./gradlew :app:testDebugUnitTest --tests "*CppContractTest*"
 *
 * Auth: cookie-based per the cpp AUTH CONTRACT — POST /ui/session/start with
 * {challenge_context:{username,password}} sets ui_session + ui_access_token(JWT) + ui_csrf cookies,
 * which our in-memory CookieJar then replays on every subsequent call (exactly as the app's
 * PersistentCookieJar does on-device). Read-only GETs need no X-CSRF-Token.
 */
class CppContractTest {

    companion object {
        private val ENABLED = System.getenv("CPP_E2E") == "1"
        private val BASE_URL =
            System.getenv("CPP_BASE_URL")?.takeIf { it.isNotBlank() } ?: "https://192.168.0.82:8443/"
        private const val USERNAME = "e2e_bob@test.local"
        private const val PASSWORD = "Passw0rd!123"

        // Production Moshi, reused verbatim (BigDecimal/lenient-number/enum adapters + Kotlin reflect).
        private val moshi: Moshi = NetworkModule.provideMoshi()

        private lateinit var retrofit: Retrofit

        /** In-memory cookie jar so the session cookies from /ui/session/start ride subsequent calls. */
        private val cookieJar = object : CookieJar {
            private val store = mutableMapOf<String, Cookie>()
            override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                cookies.forEach { store[it.name] = it }
            }
            override fun loadForRequest(url: HttpUrl): List<Cookie> = store.values.toList()
        }

        @JvmStatic
        @BeforeClass
        fun setUpClass() {
            // Heavy live setup (SSL + login + retrofit) only when enabled. The per-test @Before
            // assumeTrue is what marks the individual tests SKIPPED (not the whole class "no tests
            // found") when CPP_E2E is unset — so the hermetic CI lane stays green.
            if (!ENABLED) return

            // Trust-all SSL for the self-signed SAN cert on the cpp box (test-only).
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
            val sslContext = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustAll), SecureRandom())
            }
            val client = OkHttpClient.Builder()
                .cookieJar(cookieJar)
                .sslSocketFactory(sslContext.socketFactory, trustAll)
                .hostnameVerifier { _, _ -> true }
                .build()

            // Log in via the app's real auth contract; capture cookies into the jar.
            val loginBody =
                """{"challenge_context":{"username":"$USERNAME","password":"$PASSWORD"}}"""
                    .toRequestBody("application/json".toMediaType())
            val loginReq = Request.Builder()
                .url(BASE_URL.trimEnd('/') + "/ui/session/start")
                .post(loginBody)
                .build()
            client.newCall(loginReq).execute().use { resp ->
                check(resp.isSuccessful) { "cpp /ui/session/start failed: HTTP ${resp.code}" }
            }
            check(cookieJar.loadForRequest(BASE_URL.toHttpUrl()).any { it.name == "ui_access_token" }) {
                "no ui_access_token cookie captured after login"
            }

            retrofit = Retrofit.Builder()
                .baseUrl(BASE_URL)
                .callFactory(client)
                .addConverterFactory(MoshiConverterFactory.create(moshi))
                .build()
        }
    }

    @Before
    fun requireLiveServer() {
        assumeTrue(
            "CppContractTest is a LIVE integration test; set CPP_E2E=1 to run it (skipped otherwise).",
            ENABLED,
        )
    }

    // ── Each test calls a real app API interface and asserts a successful deserialize. ──

    @Test fun me_authApi() = runBlocking {
        val r = retrofit.create(AuthApi::class.java).me()
        assertTrue(r.userSub.isNotBlank())
    }

    @Test fun me_currentUserApi() = runBlocking {
        val r = retrofit.create(CurrentUserApi::class.java).me()
        assertNotNull(r.userSub)
    }

    @Test fun profile_getMyProfile() = runBlocking {
        val r = retrofit.create(ProfileApi::class.java).getMyProfile()
        assertNotNull(r.profile)
    }

    @Test fun dashboard_summary() = runBlocking {
        val r = retrofit.create(DashboardApi::class.java).getDashboard()
        assertNotNull(r.currency)
    }

    @Test fun activity_feed() = runBlocking {
        val r = retrofit.create(ActivityApi::class.java).getActivity(limit = 20)
        assertNotNull(r.items)
    }

    @Test fun messaging_conversations() = runBlocking {
        val r = retrofit.create(MessagingApi::class.java).listConversations()
        assertNotNull(r)
    }

    @Test fun media_preferences() = runBlocking {
        val r = retrofit.create(MediaPreferencesApi::class.java).getMediaPreferences()
        assertNotNull(r)
    }

    @Test fun alert_type_preferences() = runBlocking {
        val r = retrofit.create(NotificationPreferencesApi::class.java).getTypePreferences()
        assertNotNull(r)
    }

    @Test fun sessions_list() = runBlocking {
        val r = retrofit.create(AuthApi::class.java).listSessions()
        assertNotNull(r.sessions)
    }

    @Test fun analytics_overview() = runBlocking {
        val r = retrofit.create(AnalyticsDashboardApi::class.java)
            .getOverview(fromDate = "2026-06-01", toDate = "2026-06-30")
        assertNotNull(r.currency)
    }
}

