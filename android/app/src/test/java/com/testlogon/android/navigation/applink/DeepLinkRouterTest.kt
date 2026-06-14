package com.testlogon.android.navigation.applink

import android.net.Uri
import com.testlogon.android.auth.AuthStateProvider
import com.testlogon.android.navigation.VideoDetailDest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.MockedStatic
import org.mockito.Mockito

/**
 * AND-396 — [DeepLinkRouter] state tests (TC-AND-396-05, -06, -07) with fake collaborators.
 *
 * The route `build(...)` helpers call android.net.Uri.encode; URL-safe test ids encode to themselves,
 * so we stub Uri.encode/decode as identity for each test.
 */
class DeepLinkRouterTest {

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

    private class NoopTelemetry : DeepLinkTelemetry {
        override fun received(host: String?, pathTemplate: String, source: String) = Unit
        override fun resolved(routeName: String, requiredAuth: Boolean) = Unit
        override fun deferredAuth(pathTemplate: String) = Unit
        override fun resumedAfterAuth(pathTemplate: String) = Unit
        override fun unhandled(host: String?, pathTemplate: String) = Unit
        override fun malformed() = Unit
    }

    private fun router(authed: Boolean): Pair<DeepLinkRouter, FakeSession> {
        val session = FakeSession(authed)
        return DeepLinkRouter(parser, session, NoopTelemetry()) to session
    }

    private val videosUrl = "https://app.testlogon.com/videos/abc"

    // Lazy so it is computed under the Uri.encode static stub (set in @Before), not at construction.
    private val videoRoute: String get() = VideoDetailDest.build("abc")

    // TC-AND-396-05 — navigate immediately when authenticated.
    @Test
    fun `authed link while logged in navigates once and clears pending`() {
        val (router, _) = router(authed = true)
        val nav = RecordingNavigator()

        router.onIntent(videosUrl)
        router.consume(nav)

        assertEquals(listOf(videoRoute), nav.navigated)
        assertNull(router.pending.value)
        assertEquals(0, nav.authRoutings)
    }

    // TC-AND-396-06 — buffer while logged out, flush exactly once after auth.
    @Test
    fun `authed link while logged out buffers then flushes once after auth`() {
        val (router, session) = router(authed = false)
        val nav = RecordingNavigator()

        router.onIntent(videosUrl)
        router.consume(nav)

        // Routed to auth, NOT to the destination; buffer survives.
        assertEquals(emptyList<String>(), nav.navigated)
        assertEquals(1, nav.authRoutings)
        assertTrue(router.pending.value != null)

        // Authenticate, flush.
        session.flow.value = true
        router.onAuthenticated(nav)
        assertEquals(listOf(videoRoute), nav.navigated)
        assertNull(router.pending.value)

        // Second onAuthenticated is a no-op (single-shot).
        router.onAuthenticated(nav)
        assertEquals(listOf(videoRoute), nav.navigated)
    }

    // TC-AND-396-07 — single-shot consumption survives recomposition (consume twice -> navigate once).
    @Test
    fun `consume twice navigates exactly once`() {
        val (router, _) = router(authed = true)
        val nav = RecordingNavigator()

        router.onIntent(videosUrl)
        router.consume(nav)
        router.consume(nav)

        assertEquals(listOf(videoRoute), nav.navigated)
        assertNull(router.pending.value)
    }

    @Test
    fun `public link navigates immediately even when logged out`() {
        val (router, _) = router(authed = false)
        val nav = RecordingNavigator()

        router.onIntent("https://app.testlogon.com/u/sean")
        router.consume(nav)

        assertEquals(1, nav.navigated.size)
        assertEquals(0, nav.authRoutings)
        assertNull(router.pending.value)
    }

    @Test
    fun `malformed link never buffers and never navigates`() {
        val (router, _) = router(authed = true)
        val nav = RecordingNavigator()

        router.onIntent("https://evil.example.com/videos/abc")
        router.consume(nav)

        assertEquals(emptyList<String>(), nav.navigated)
        assertNull(router.pending.value)
    }

    @Test
    fun `unknown path buffers a home fallback and navigates home`() {
        val (router, _) = router(authed = true)
        val nav = RecordingNavigator()

        router.onIntent("https://app.testlogon.com/library")
        router.consume(nav)

        assertEquals(listOf("main/shell"), nav.navigated)
        assertNull(router.pending.value)
    }

    @Test
    fun `onAuthenticated is a no-op when not authenticated`() {
        val (router, _) = router(authed = false)
        val nav = RecordingNavigator()

        router.onIntent(videosUrl)
        router.onAuthenticated(nav)

        assertEquals(emptyList<String>(), nav.navigated)
        assertTrue(router.pending.value != null)
    }
}
