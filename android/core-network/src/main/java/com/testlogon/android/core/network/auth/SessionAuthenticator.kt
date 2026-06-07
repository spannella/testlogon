package com.testlogon.android.core.network.auth

import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.core.network.cookie.PersistentCookieJar
import okhttp3.Authenticator
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.Route
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.io.IOException
import javax.inject.Provider

/**
 * Notified when the authenticator gives up on a 401 (refresh failed or the user was never
 * authenticated). The app/feature layer observes this to clear state and route to login.
 */
fun interface AuthEventSink {
    fun onLoggedOut()

    companion object {
        val NONE = AuthEventSink { /* no-op default */ }
    }
}

/**
 * On a `401` for an authenticated session, calls `POST /ui/session/refresh` once (single-flight)
 * and retries the original request; gives up after a single refresh-driven retry.
 *
 * - A `401` on the refresh request itself, or a re-`401` after one retry, ends the flow.
 * - If no session cookie exists, no refresh is attempted.
 * - On give-up, the cookie jar is cleared and [AuthEventSink.onLoggedOut] is fired once.
 *
 * The refresh call uses a derived client with the authenticator removed (loop-safe) while keeping
 * the cookie jar + interceptors, supplied lazily via [refreshClient] to avoid a provider cycle.
 */
class SessionAuthenticator(
    private val refreshClient: Provider<OkHttpClient>,
    private val cookieJar: PersistentCookieJar,
    private val settingsStore: SettingsStore,
    private val authEventSink: AuthEventSink,
) : Authenticator {

    private val lock = Any()

    override fun authenticate(route: Route?, response: Response): Request? {
        // Never refresh in response to the refresh call itself.
        if (response.request.header(REFRESH_HEADER) != null) {
            failLogout()
            return null
        }
        // At most one refresh-driven retry per request.
        if (response.priorResponse != null) {
            failLogout()
            return null
        }
        // No session => nothing to refresh.
        if (!hasSession(response.request)) {
            failLogout()
            return null
        }

        val refreshed = synchronized(lock) {
            // If another concurrent 401 already refreshed and re-established a session, reuse it.
            if (hasSession(response.request) && refreshSucceededSince) {
                true
            } else {
                refreshSucceededSince = false
                refresh().also { ok -> if (ok) refreshSucceededSince = true }
            }
        }
        if (!refreshed) {
            failLogout()
            return null
        }
        // Retry the original request; the cookie jar + CSRF interceptor reattach fresh session/CSRF.
        return response.request.newBuilder().build()
    }

    @Volatile
    private var refreshSucceededSince = false

    private fun hasSession(request: Request): Boolean =
        cookieJar.loadForRequest(request.url).isNotEmpty()

    private fun refresh(): Boolean {
        val base = settingsStore.baseUrl.toHttpUrlOrNull() ?: return false
        val url = base.newBuilder().addPathSegments("ui/session/refresh").build()
        val request = Request.Builder()
            .url(url)
            .post(ByteArray(0).toRequestBody(null))
            .header(REFRESH_HEADER, "1")
            .build()
        return try {
            refreshClient.get().newCall(request).execute().use { it.isSuccessful }
        } catch (_: IOException) {
            false
        }
    }

    private fun failLogout() {
        cookieJar.clear()
        authEventSink.onLoggedOut()
    }

    companion object {
        const val REFRESH_HEADER = "X-TL-Refresh"
    }
}
