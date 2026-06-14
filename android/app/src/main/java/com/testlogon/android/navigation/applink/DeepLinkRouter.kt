package com.testlogon.android.navigation.applink

import com.testlogon.android.auth.AuthStateProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-396 — process-scoped App Link router (FR-4/5/6).
 *
 * Observes [AuthStateProvider.isAuthenticated] (the existing session seam — the spec's
 * `SessionStateProvider`) to decide between immediate navigation and buffering. It performs NO I/O;
 * it only produces a typed route and asks a [RouteNavigator] to navigate.
 *
 * Buffering is intentionally in-memory (`@Singleton`, NOT persisted): a deferred deep link must not
 * survive process death and surprise the user later (§6). Consumption is single-shot — the buffer is
 * cleared after a successful navigate so recomposition / config change never double-navigates (§6,
 * TC-07).
 *
 * Navigation is delegated through [RouteNavigator] so this class is JVM-unit-testable without a real
 * NavController. The host composable wires the NavController-backed navigator (FR-4 replaces the
 * start destination so Back behaves naturally).
 */
@Singleton
class DeepLinkRouter @Inject constructor(
    private val parser: DeepLinkParser,
    private val session: AuthStateProvider,
    private val telemetry: DeepLinkTelemetry,
) {
    /** A buffered, resolved link awaiting either NavController readiness or authentication. */
    data class Buffered(val resolved: DeepLink.Resolved, val pathTemplate: String, val host: String?)

    private val _pending = MutableStateFlow<Buffered?>(null)
    val pending: StateFlow<Buffered?> = _pending.asStateFlow()

    /**
     * Parses an inbound VIEW intent URL (cold start or `onNewIntent`). [source] is "cold" or "warm".
     * Resolved links are buffered into [pending] for [consume] to drain once the NavController is
     * ready; Malformed/Unhandled are handled immediately (telemetry only — the actual Home fallback
     * happens in [consume] when there is no pending link and an unhandled marker was set).
     */
    fun onIntent(url: String?, host: String? = hostOf(url), source: String = SOURCE_COLD) {
        val template = parser.pathTemplate(url)
        when (val link = parser.parse(url)) {
            is DeepLink.Resolved -> {
                telemetry.received(host, template, source)
                telemetry.resolved(routeNameOf(link.route), link.requiresAuth)
                _pending.value = Buffered(link, template, host)
            }
            DeepLink.RequiresAuth -> {
                // parse() never returns RequiresAuth (that decision is the router's, made at consume
                // time against the live session). Treated defensively as unhandled.
                telemetry.unhandled(host, template)
            }
            DeepLink.Unhandled -> {
                telemetry.received(host, template, source)
                telemetry.unhandled(host, template)
                _pending.value = Buffered(
                    DeepLink.Resolved(HOME_FALLBACK_ROUTE, requiresAuth = true),
                    template,
                    host,
                )
            }
            DeepLink.Malformed -> {
                telemetry.malformed()
                // A foreign/garbage link never navigates (SEC-1); leave any prior buffer untouched.
            }
        }
    }

    /**
     * Drains a buffered link once the NavController (wrapped by [navigator]) is ready.
     *
     * - A public link, or an authed link while signed in -> navigate immediately, clear the buffer.
     * - An authed link while signed out -> KEEP the buffer (for [onAuthenticated]) and route to the
     *   auth surface; emit `deeplink_deferred_auth`.
     *
     * Idempotent: calling twice navigates at most once for the same buffered link.
     */
    fun consume(navigator: RouteNavigator) {
        val buffered = _pending.value ?: return
        val resolved = buffered.resolved
        if (resolved.requiresAuth && !session.isAuthenticated.value) {
            // Buffer survives; the user is sent to auth and the link resumes after finalize.
            telemetry.deferredAuth(buffered.pathTemplate)
            navigator.navigateToAuth()
            return
        }
        navigator.navigate(resolved.route)
        _pending.value = null
    }

    /**
     * Flushes a buffered authed link after a successful session finalize (FR-6). Exactly-once: the
     * second call is a no-op because the buffer is already null. No-op when the session is not (yet)
     * authenticated or there is no pending authed link.
     */
    fun onAuthenticated(navigator: RouteNavigator) {
        if (!session.isAuthenticated.value) return
        val buffered = _pending.value ?: return
        navigator.navigate(buffered.resolved.route)
        telemetry.resumedAfterAuth(buffered.pathTemplate)
        _pending.value = null
    }

    /** Clears any buffered link (e.g. on a fresh cold start so an abandoned auth doesn't resume). */
    fun clear() {
        _pending.value = null
    }

    private fun hostOf(url: String?): String? =
        url?.let { runCatching { java.net.URI(it.trim()).host?.lowercase() }.getOrNull() }

    /** The leading route token, for telemetry (e.g. `video` from `video/{id}`); never raw ids. */
    private fun routeNameOf(route: String): String = route.substringBefore('/').ifEmpty { route }

    private companion object {
        const val SOURCE_COLD = "cold"

        /** The authenticated shell start destination; the safe Home fallback (FR-7). */
        const val HOME_FALLBACK_ROUTE = "main/shell"
    }
}

/**
 * Navigation abstraction so [DeepLinkRouter] stays JVM-testable. The host composable supplies a
 * NavController-backed implementation; unit tests supply a recording fake.
 */
interface RouteNavigator {
    /** Navigate to [route], replacing the start destination so Back exits naturally (FR-4). */
    fun navigate(route: String)

    /** Route the user to the auth surface to satisfy a buffered authed link. */
    fun navigateToAuth()
}
