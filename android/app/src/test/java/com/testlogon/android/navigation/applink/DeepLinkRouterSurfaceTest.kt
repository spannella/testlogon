package com.testlogon.android.navigation.applink

import android.net.Uri
import com.testlogon.android.auth.AuthStateProvider
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.MockedStatic
import org.mockito.Mockito

/**
 * AND-397 — public-surface security & telemetry gap tests for [DeepLinkRouter].
 *
 * AND-396 ([DeepLinkRouterTest]) already covers immediate navigation, the auth buffer/flush
 * single-shot, public-immediate, malformed-never-navigates, and the unknown->Home fallback. This
 * class adds the AND-397-specific gaps:
 *
 * - TC-AND-397-08 — open-redirect hygiene: a buffered/pending link can only ever carry an internal
 *   NavController route id, never an external URL, even when the inbound link tries to smuggle one.
 * - TC-AND-397-14 — telemetry redaction: a [DeepLinkTelemetry] recording fake observes that every
 *   resolution reports the path TEMPLATE / route name only — never the raw query string, raw id, or
 *   full URL — and that a fallback reports a coarse outcome, not the raw URI.
 *
 * Pure JVM (no Robolectric), matching AND-396: the route `build(...)` helpers call Uri.encode, which
 * is stubbed to identity for the URL-safe ids used here.
 */
class DeepLinkRouterSurfaceTest {

    private lateinit var uriStatic: MockedStatic<Uri>

    @Before
    fun setUp() {
        uriStatic = Mockito.mockStatic(Uri::class.java)
        uriStatic.`when`<String> { Uri.encode(Mockito.anyString()) }
            .thenAnswer { it.getArgument<String>(0) }
        uriStatic.`when`<String> { Uri.decode(Mockito.anyString()) }
            .thenAnswer { it.getArgument<String>(0) }
    }

    @After
    fun tearDown() {
        uriStatic.close()
    }

    private val verifiedHosts = setOf("app.testlogon.com")
    private val parser = DeepLinkParserImpl(verifiedHosts)

    private class FakeSession(authed: Boolean) : AuthStateProvider {
        val flow = MutableStateFlow(authed)
        override val isAuthenticated: StateFlow<Boolean> get() = flow
    }

    private class RecordingNavigator : RouteNavigator {
        val navigated = mutableListOf<String>()
        var authRoutings = 0
        override fun navigate(route: String) { navigated.add(route) }
        override fun navigateToAuth() { authRoutings++ }
    }

    /** A telemetry fake that records every emitted line so redaction can be asserted (SEC-5). */
    private class RecordingTelemetry : DeepLinkTelemetry {
        val lines = mutableListOf<String>()
        override fun received(host: String?, pathTemplate: String, source: String) {
            lines.add("received host=$host template=$pathTemplate source=$source")
        }
        override fun resolved(routeName: String, requiredAuth: Boolean) {
            lines.add("resolved route=$routeName auth=$requiredAuth")
        }
        override fun deferredAuth(pathTemplate: String) { lines.add("deferred template=$pathTemplate") }
        override fun resumedAfterAuth(pathTemplate: String) { lines.add("resumed template=$pathTemplate") }
        override fun unhandled(host: String?, pathTemplate: String) {
            lines.add("unhandled host=$host template=$pathTemplate")
        }
        override fun malformed() { lines.add("malformed") }
    }

    private fun router(authed: Boolean, telemetry: DeepLinkTelemetry): Pair<DeepLinkRouter, FakeSession> {
        val session = FakeSession(authed)
        return DeepLinkRouter(parser, session, telemetry) to session
    }

    // ----- TC-AND-397-08: open-redirect hygiene -----

    @Test
    fun `a pending link only ever carries an internal route never an external url`() {
        val (router, _) = router(authed = false, telemetry = RecordingTelemetry())

        // An auth-gated link buffers a Resolved whose route came from the parser (an internal route).
        router.onIntent("https://app.testlogon.com/videos/abc")
        val buffered = router.pending.value
        assertTrue("expected a buffered link", buffered != null)
        val route = buffered!!.resolved.route
        assertFalse("pending route must not be an http url: $route", route.contains("http://"))
        assertFalse("pending route must not be an https url: $route", route.contains("https://"))
        assertFalse("pending route must not carry a foreign host: $route", route.contains("evil"))
    }

    @Test
    fun `an external host smuggled in a path segment never produces a navigable external route`() {
        val (router, session) = router(authed = false, telemetry = RecordingTelemetry())
        val nav = RecordingNavigator()

        // Attempt to smuggle an external destination as an id.
        router.onIntent("https://app.testlogon.com/videos/https%3A%2F%2Fevil.com")
        router.consume(nav)
        // Auth-gated while logged out -> routed to auth, NOT to any external URL.
        assertEquals(emptyList<String>(), nav.navigated)
        assertEquals(1, nav.authRoutings)

        session.flow.value = true
        router.onAuthenticated(nav)
        // After auth it resumes onto an INTERNAL route only.
        assertEquals(1, nav.navigated.size)
        val landed = nav.navigated.single()
        assertTrue("must resume onto the internal video route: $landed", landed.startsWith("video"))
        assertFalse("must never navigate to an external url: $landed", landed.contains("://"))
    }

    @Test
    fun `a foreign host link leaves no pending and never navigates`() {
        val (router, _) = router(authed = true, telemetry = RecordingTelemetry())
        val nav = RecordingNavigator()

        router.onIntent("https://evil.example.com/u/sean")
        router.consume(nav)

        assertEquals(emptyList<String>(), nav.navigated)
        assertNull(router.pending.value)
    }

    // ----- TC-AND-397-14: telemetry redaction (no raw ids / query / full url) -----

    @Test
    fun `resolution telemetry reports templates and route names only never raw id or query`() {
        val telemetry = RecordingTelemetry()
        val (router, _) = router(authed = true, telemetry = telemetry)

        router.onIntent("https://app.testlogon.com/videos/secretId123?token=abc123secret")

        assertTrue("expected telemetry to be emitted", telemetry.lines.isNotEmpty())
        for (line in telemetry.lines) {
            assertFalse("telemetry leaked the raw id: $line", line.contains("secretId123"))
            assertFalse("telemetry leaked the token value: $line", line.contains("abc123secret"))
            assertFalse("telemetry leaked the raw query: $line", line.contains("token="))
            assertFalse("telemetry leaked the full url: $line", line.contains("https://"))
        }
        // The path template is present, redacted to {videoId}.
        assertTrue(
            "expected a redacted template in telemetry: ${telemetry.lines}",
            telemetry.lines.any { it.contains("/videos/{videoId}") },
        )
    }

    @Test
    fun `an unknown path reports an unhandled outcome without the raw id or query`() {
        val telemetry = RecordingTelemetry()
        val (router, _) = router(authed = true, telemetry = telemetry)

        // For an unknown route the template is the coarse first path segment (the route category),
        // never the trailing raw id segment and never the query string (SEC-5).
        router.onIntent("https://app.testlogon.com/unknownsection/rawSecretId?token=leakme")

        assertTrue(
            "expected an unhandled telemetry outcome: ${telemetry.lines}",
            telemetry.lines.any { it.startsWith("unhandled") },
        )
        for (line in telemetry.lines) {
            assertFalse("unhandled telemetry leaked the raw id: $line", line.contains("rawSecretId"))
            assertFalse("unhandled telemetry leaked the token value: $line", line.contains("leakme"))
            assertFalse("unhandled telemetry leaked the raw query: $line", line.contains("token="))
            assertFalse("unhandled telemetry leaked the full url: $line", line.contains("https://"))
        }
    }

    @Test
    fun `a malformed link reports a coarse malformed outcome with no host or path`() {
        val telemetry = RecordingTelemetry()
        val (router, _) = router(authed = true, telemetry = telemetry)

        router.onIntent("https://evil.example.com/u/private-handle")

        assertEquals(listOf("malformed"), telemetry.lines)
    }

    @Test
    fun `deferred-auth then resume telemetry carries only the path template`() {
        val telemetry = RecordingTelemetry()
        val (router, session) = router(authed = false, telemetry = telemetry)
        val nav = RecordingNavigator()

        router.onIntent("https://app.testlogon.com/videos/secretId123")
        router.consume(nav)
        session.flow.value = true
        router.onAuthenticated(nav)

        val gating = telemetry.lines.filter { it.startsWith("deferred") || it.startsWith("resumed") }
        assertTrue("expected deferred + resumed telemetry: ${telemetry.lines}", gating.size >= 2)
        for (line in gating) {
            assertFalse("gating telemetry leaked the raw id: $line", line.contains("secretId123"))
            assertTrue("gating telemetry should carry the template: $line", line.contains("/videos/{videoId}"))
        }
    }
}
