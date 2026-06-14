package com.testlogon.android.navigation.applink

import android.net.Uri
import com.testlogon.android.navigation.PublicProfileDest
import com.testlogon.android.navigation.VideoDetailDest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.MockedStatic
import org.mockito.Mockito

/**
 * AND-397 — public-surface gap tests for [DeepLinkParserImpl].
 *
 * AND-396 already covers the happy paths, unknown paths, foreign/look-alike hosts, the custom-scheme
 * rejection, and path-template redaction (see [DeepLinkParserImplTest]). This class adds the
 * AND-397-specific gaps that were NOT already asserted:
 *
 * - TC-AND-397-03 — argument decoding & typing (`%20`, `+`, encoded unicode, encoded `..`).
 * - TC-AND-397-04 — edge normalization (trailing slash, mixed-case host, duplicate `//`, empty arg).
 * - TC-AND-397-05 — the §7 negative corpus that AND-396 did not enumerate (ftp/javascript scheme,
 *   opaque URI, path traversal, oversized/control-char/whitespace input).
 * - TC-AND-397-06 — fuzz totality: `parse` is total — it never throws and always yields a valid
 *   [DeepLink] variant, and a hostile/garbage input never resolves to an authenticated route.
 *
 * Pure JVM (no Robolectric, matching the established AND-396 pattern): the parser maps URL strings
 * via java.net.URI. The route `build(...)` helpers call android.net.Uri.encode (unavailable on the
 * JVM); the URL-safe ids used here encode to themselves, so Uri.encode/decode are stubbed as
 * identity for the duration of each test.
 */
class DeepLinkParserSurfaceTest {

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

    private val parser = DeepLinkParserImpl(verifiedHosts = setOf("app.testlogon.com"))

    // ----- TC-AND-397-03: argument decoding & typing -----

    @Test
    fun `percent-encoded space in a path segment is decoded`() {
        // java.net.URI decodes %20 -> ' '; the parser's URLDecoder pass leaves the space intact.
        val result = parser.parse("https://app.testlogon.com/videos/abc%20123")
        assertEquals(DeepLink.Resolved(VideoDetailDest.build("abc 123"), requiresAuth = true), result)
    }

    @Test
    fun `plus in a path segment decodes to a space`() {
        // URI does NOT decode '+'; the parser's URLDecoder pass turns it into a space (form decoding).
        val result = parser.parse("https://app.testlogon.com/u/a+b")
        assertEquals(DeepLink.Resolved(PublicProfileDest.build("a b"), requiresAuth = false), result)
    }

    @Test
    fun `encoded unicode is decoded locale-independently`() {
        // caf%C3%A9 -> café; decoding must not be corrupted and the host is the only lowercased part.
        val result = parser.parse("https://app.testlogon.com/u/caf%C3%A9")
        assertEquals(DeepLink.Resolved(PublicProfileDest.build("café"), requiresAuth = false), result)
    }

    @Test
    fun `path case is preserved while only the host is lowercased`() {
        val result = parser.parse("https://app.testlogon.com/u/SeanMixedCase")
        assertEquals(
            DeepLink.Resolved(PublicProfileDest.build("SeanMixedCase"), requiresAuth = false),
            result,
        )
    }

    // ----- TC-AND-397-04: edge normalization -----

    @Test
    fun `mixed-case host resolves identically to the canonical lower-case host`() {
        val mixed = parser.parse("https://APP.TestLogon.COM/u/sean")
        val canonical = parser.parse("https://app.testlogon.com/u/sean")
        assertEquals(canonical, mixed)
        assertEquals(DeepLink.Resolved(PublicProfileDest.build("sean"), requiresAuth = false), mixed)
    }

    @Test
    fun `trailing slash resolves identically to the canonical form`() {
        val trailing = parser.parse("https://app.testlogon.com/u/sean/")
        val canonical = parser.parse("https://app.testlogon.com/u/sean")
        assertEquals(canonical, trailing)
    }

    @Test
    fun `duplicate slashes collapse to the same canonical route`() {
        val doubled = parser.parse("https://app.testlogon.com//u//sean")
        val canonical = parser.parse("https://app.testlogon.com/u/sean")
        assertEquals(canonical, doubled)
    }

    @Test
    fun `a query string never changes the resolved route`() {
        val withQuery = parser.parse("https://app.testlogon.com/u/sean?ref=x&ref=y&empty=")
        val canonical = parser.parse("https://app.testlogon.com/u/sean")
        assertEquals(canonical, withQuery)
    }

    @Test
    fun `an empty required segment that decodes to blank is malformed`() {
        // /u/%20 -> segment is a single space, which trims to empty -> rejected (SEC-3), never a route.
        assertEquals(DeepLink.Malformed, parser.parse("https://app.testlogon.com/u/%20"))
    }

    // ----- TC-AND-397-05: negative corpus -> never an auth route, never throws -----

    @Test
    fun `ftp scheme is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse("ftp://app.testlogon.com/videos/1"))
    }

    @Test
    fun `javascript pseudo-scheme is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse("javascript:alert(1)"))
    }

    @Test
    fun `opaque custom-scheme uri is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse("testlogon:"))
    }

    @Test
    fun `empty string is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse(""))
    }

    @Test
    fun `whitespace inside the raw uri is malformed`() {
        // java.net.URI rejects a raw space -> URISyntaxException -> Malformed (never throws).
        assertEquals(DeepLink.Malformed, parser.parse("https://app.testlogon.com/u/se an"))
    }

    @Test
    fun `subdomain-confusion host is malformed`() {
        assertEquals(
            DeepLink.Malformed,
            parser.parse("https://app.testlogon.com.attacker.com/u/sean"),
        )
    }

    @Test
    fun `path traversal never escapes to a different route`() {
        // The parser treats `..` as an opaque segment; `/videos/../profile` stays on the videos
        // route (id="..") and can NEVER smuggle the user onto the profile route. Behavior asserted,
        // not assumed (FR-3): the security guarantee is that traversal never reaches /profile.
        val result = parser.parse("https://app.testlogon.com/videos/../profile")
        assertTrue("traversal must not throw or escape: $result", result is DeepLink.Resolved)
        val route = (result as DeepLink.Resolved).route
        assertFalse("traversal leaked into the profile route: $route", route.contains("profile/public"))
        assertTrue("traversal must stay on the videos route: $route", route.startsWith("video"))
    }

    @Test
    fun `double-encoded traversal is decoded but still does not escape`() {
        // %252e%252e -> URI decodes once to %2e%2e, URLDecoder decodes again to "..".
        val result = parser.parse("https://app.testlogon.com/videos/%252e%252e")
        assertTrue(result is DeepLink.Resolved)
        assertFalse((result as DeepLink.Resolved).route.contains("profile"))
    }

    @Test
    fun `an oversized path does not throw and never reaches an auth route`() {
        val huge = "https://app.testlogon.com/" + "a".repeat(8 * 1024)
        val result = parser.parse(huge)
        // Single unknown head segment on a verified host -> Unhandled; must not throw.
        assertEquals(DeepLink.Unhandled, result)
    }

    // ----- TC-AND-397-06: fuzz totality -----

    @Test
    fun `parse is total over a hostile and random corpus`() {
        val curated = listOf(
            null,
            "",
            "   ",
            "notaurl",
            "://",
            "https://",
            "https:///",
            "http://",
            "ftp://app.testlogon.com/videos/1",
            "javascript:alert(1)",
            "data:text/html,<script>1</script>",
            "file:///etc/passwd",
            "testlogon:",
            "mailto:a@b.com",
            "https://app.testlogon.com",
            "https://app.testlogon.com/",
            "https://app.testlogon.com/videos",
            "https://app.testlogon.com/videos/",
            "https://app.testlogon.com/videos/%20",
            "https://app.testlogon.com/videos/../../profile",
            "https://app.testlogon.com/videos/%252e%252e%252f",
            "https://app.testlogon.com.evil.com/profile",
            "https://evil.example.com/videos/1",
            "https://app.testlogon.com/" + "x".repeat(8 * 1024),
            "https://app.testlogon.com/videos/a b",
            "https://app.testlogon.com/videos/‮evil",
            "%00%01%02",
            "https://app.testlogon.com/event",
            "https://app.testlogon.com/event/only-one",
        )
        val random = buildRandomCorpus(seed = 4815, count = 400)

        for (input in curated + random) {
            val result = runCatching { parser.parse(input) }
            assertTrue("parse threw on input=[$input]: ${result.exceptionOrNull()}", result.isSuccess)
            val link = result.getOrNull()
            assertTrue("parse returned a non-DeepLink for input=[$input]", link is DeepLink)
            // A garbage/hostile input must NEVER resolve to an authenticated route.
            if (link is DeepLink.Resolved) {
                assertFalse(
                    "hostile input resolved to an auth route: input=[$input] route=${link.route}",
                    link.requiresAuth && isHostile(input),
                )
            }
        }
    }

    @Test
    fun `path template is total and never leaks a query string`() {
        val inputs = listOf(
            null, "", "notaurl", "testlogon:",
            "https://app.testlogon.com/videos/secret?token=abc",
            "https://app.testlogon.com/u/sean#frag",
            "https://evil.example.com/x?y=z",
        )
        for (input in inputs) {
            val template = runCatching { parser.pathTemplate(input) }
            assertTrue("pathTemplate threw on [$input]", template.isSuccess)
            val t = template.getOrNull().orEmpty()
            assertFalse("template leaked a query for [$input]: $t", t.contains("token"))
            assertFalse("template leaked a fragment for [$input]: $t", t.contains("#"))
            assertFalse("template leaked a raw id for [$input]: $t", t.contains("secret"))
        }
    }

    private fun isHostile(input: String?): Boolean {
        if (input == null) return true
        val lower = input.lowercase()
        return !lower.startsWith("https://app.testlogon.com") &&
            !lower.startsWith("http://app.testlogon.com")
    }

    private fun buildRandomCorpus(seed: Long, count: Int): List<String> {
        val rng = java.util.Random(seed)
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
            "/:.?#&=%+-_~ \t\n ‮<>\"'\\|{}[]"
        return List(count) {
            val len = rng.nextInt(64)
            buildString {
                repeat(len) { append(alphabet[rng.nextInt(alphabet.length)]) }
            }
        }
    }
}
