package com.testlogon.android.core.testing.net

import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AND-046 — request-aware dispatcher that models the cookie-based auth happy path:
 * `POST /ui/session/start` -> `POST /ui/mfa/totp/verify` -> `POST /ui/session/finalize` ->
 * `GET /ui/me`. Issues `Set-Cookie` for the session + `ui_csrf` on start/refresh, and (optionally)
 * rejects CSRF-missing mutations with a 403.
 *
 * NOTE: there is NO `/ui/mfa/totp/begin` route — TOTP posts straight to verify. Only SMS/email
 * have a begin step.
 */
class AuthFlowDispatcher(
    private val csrfToken: String = Fixtures.DEFAULT_CSRF,
    private val requireCsrfOnMutations: Boolean = true,
) : Dispatcher() {

    override fun dispatch(request: RecordedRequest): MockResponse {
        val path = request.requestUrl?.encodedPath.orEmpty()
        val method = request.method.orEmpty()

        // CSRF is required on mutations except the unauthenticated session/start (no cookie yet).
        if (requireCsrfOnMutations && method != "GET" && path != "/ui/session/start" &&
            request.getHeader("X-CSRF-Token") != csrfToken
        ) {
            return Fixtures.error("\"csrf_failed\"", 403)
        }

        return when ("$method $path") {
            "POST /ui/session/start" ->
                Fixtures.okWithSessionCookies(FixtureName.SESSION_START_MFA, csrfToken)
            "POST /ui/mfa/totp/verify" -> Fixtures.ok(FixtureName.MFA_TOTP_VERIFY_OK)
            "POST /ui/mfa/sms/begin" -> Fixtures.ok(FixtureName.MFA_SMS_BEGIN_OK)
            "POST /ui/mfa/sms/verify" -> Fixtures.ok(FixtureName.MFA_SMS_VERIFY_OK)
            "POST /ui/session/finalize" -> Fixtures.ok(FixtureName.SESSION_FINALIZE_OK)
            "POST /ui/session/refresh" ->
                Fixtures.ok(FixtureName.SESSION_REFRESH_OK)
                    .addHeader("Set-Cookie", "ui_csrf=$csrfToken; Path=/")
            "GET /ui/me" -> Fixtures.ok(FixtureName.ME)
            "GET /ui/sessions" -> Fixtures.ok(FixtureName.SESSIONS)
            else -> Fixtures.error("\"not_found\"", 404)
        }
    }
}

/**
 * Returns `401` exactly once for the first protected request seen, then a single
 * `POST /ui/session/refresh` 200 (re-echoing `ui_csrf`), then serves the retried request from
 * [delegate]. Models the verified web-client `401 -> refresh -> retry` cycle for a single refresh.
 */
class RefreshOnceDispatcher(
    private val protectedPath: String = "/ui/me",
    private val csrfToken: String = Fixtures.DEFAULT_CSRF,
    private val delegate: Dispatcher = AuthFlowDispatcher(csrfToken),
) : Dispatcher() {

    private val challenged = AtomicBoolean(false)

    override fun dispatch(request: RecordedRequest): MockResponse {
        val path = request.requestUrl?.encodedPath.orEmpty()
        if (path == "/ui/session/refresh") {
            return Fixtures.ok(FixtureName.SESSION_REFRESH_OK)
                .addHeader("Set-Cookie", "ui_csrf=$csrfToken; Path=/")
        }
        if (path == protectedPath && challenged.compareAndSet(false, true)) {
            return Fixtures.error("\"Not authenticated\"", 401)
        }
        return delegate.dispatch(request)
    }
}
