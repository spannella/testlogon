package com.testlogon.android.core.network.csrf

import com.testlogon.android.core.network.Anonymous
import com.testlogon.android.core.network.cookie.PersistentCookieJar
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Mirrors the web client's double-submit CSRF scheme: copies the `ui_csrf` cookie value into the
 * `X-CSRF-Token` header on mutating requests.
 *
 * - Only `POST/PUT/PATCH/DELETE` are touched (the backend enforces CSRF on mutating routes only).
 * - A caller-supplied `X-CSRF-Token` header is never overwritten.
 * - If no `ui_csrf` cookie applies to the request URL, the request proceeds unchanged.
 * - The value is read per-request from the shared cookie jar, so a rotated token is picked up
 *   automatically on the next call.
 * - AND-395: a request tagged [Anonymous] is passed through untouched (no `X-CSRF-Token`); the
 *   public-respondent surface is anonymous and must not carry the authenticated CSRF token.
 */
@Singleton
class CsrfInterceptor @Inject constructor(
    private val cookieJar: PersistentCookieJar,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()

        // AND-395: anonymous public calls opt out of the CSRF header entirely.
        if (request.tag(Anonymous::class.java) != null) {
            return chain.proceed(request)
        }

        if (!isMutating(request.method) || request.header(CSRF_HEADER) != null) {
            return chain.proceed(request)
        }

        val token = cookieJar.currentCookie(CSRF_COOKIE, request.url)?.value
        if (token.isNullOrBlank()) {
            return chain.proceed(request)
        }

        return chain.proceed(
            request.newBuilder().header(CSRF_HEADER, token).build(),
        )
    }

    private fun isMutating(method: String): Boolean = method.uppercase() in MUTATING_METHODS

    companion object {
        const val CSRF_COOKIE = "ui_csrf"
        const val CSRF_HEADER = "X-CSRF-Token"
        private val MUTATING_METHODS = setOf("POST", "PUT", "PATCH", "DELETE")
    }
}
