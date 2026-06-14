package com.testlogon.android.navigation.applink

import com.testlogon.android.navigation.DonationDest
import com.testlogon.android.navigation.EventDetailDest
import com.testlogon.android.navigation.MainDest
import com.testlogon.android.navigation.PostDetailDest
import com.testlogon.android.navigation.PublicClipDest
import com.testlogon.android.navigation.PublicProfileDest
import com.testlogon.android.navigation.PublicShareDest
import com.testlogon.android.navigation.VideoDetailDest
import android.net.Uri
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.MockedStatic
import org.mockito.Mockito

/**
 * AND-396 — table tests for [DeepLinkParserImpl] (TC-AND-396-01..04, -12).
 *
 * Pure JVM (no Robolectric): the parser maps URL strings via java.net.URI. The route `build(...)`
 * helpers call android.net.Uri.encode (not available on the JVM); the URL-safe test ids encode to
 * themselves, so we stub Uri.encode/decode as identity for the duration of each test.
 */
class DeepLinkParserImplTest {

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

    // TC-AND-396-01 — verified content path -> typed authed route, correct segment extraction.
    @Test
    fun `videos path resolves to video detail route requiring auth`() {
        val result = parser.parse("https://app.testlogon.com/videos/abc123")
        assertEquals(DeepLink.Resolved(VideoDetailDest.build("abc123"), requiresAuth = true), result)
    }

    @Test
    fun `gallery path resolves to the same video detail route`() {
        val result = parser.parse("https://app.testlogon.com/gallery/v_9")
        assertEquals(DeepLink.Resolved(VideoDetailDest.build("v_9"), requiresAuth = true), result)
    }

    @Test
    fun `posts path resolves to post detail requiring auth`() {
        val result = parser.parse("https://app.testlogon.com/posts/p1")
        assertEquals(DeepLink.Resolved(PostDetailDest.build("p1"), requiresAuth = true), result)
    }

    // TC-AND-396-02 — public paths resolve with requiresAuth=false + correct segment extraction.
    @Test
    fun `public profile path resolves without auth`() {
        val result = parser.parse("https://app.testlogon.com/u/sean")
        assertEquals(DeepLink.Resolved(PublicProfileDest.build("sean"), requiresAuth = false), result)
    }

    @Test
    fun `public share path resolves without auth`() {
        val result = parser.parse("https://app.testlogon.com/share/lnk_9")
        assertEquals(DeepLink.Resolved(PublicShareDest.build("lnk_9"), requiresAuth = false), result)
    }

    @Test
    fun `public clip path resolves without auth`() {
        val result = parser.parse("https://app.testlogon.com/c/clip1")
        assertEquals(DeepLink.Resolved(PublicClipDest.build("clip1"), requiresAuth = false), result)
    }

    @Test
    fun `donate path resolves without auth`() {
        val result = parser.parse("https://app.testlogon.com/donate/fund_5")
        assertEquals(DeepLink.Resolved(DonationDest.build("fund_5"), requiresAuth = false), result)
    }

    @Test
    fun `event path resolves to public event detail`() {
        val result = parser.parse("https://app.testlogon.com/event/cal_1/ev_2")
        assertEquals(
            DeepLink.Resolved(EventDetailDest.build("cal_1", "ev_2", isPublic = true), requiresAuth = false),
            result,
        )
    }

    @Test
    fun `root path resolves to home shell`() {
        val result = parser.parse("https://app.testlogon.com/")
        assertEquals(DeepLink.Resolved(MainDest.Shell.route, requiresAuth = true), result)
    }

    @Test
    fun `settings privacy resolves to the native privacy route`() {
        val result = parser.parse("https://app.testlogon.com/settings/privacy")
        assertEquals(DeepLink.Resolved(MainDest.SettingsPrivacy.route, requiresAuth = true), result)
    }

    @Test
    fun `settings theme maps to the appearance route`() {
        val result = parser.parse("https://app.testlogon.com/settings/theme")
        assertEquals(DeepLink.Resolved(MainDest.SettingsAppearance.route, requiresAuth = true), result)
    }

    // TC-AND-396-03 — unknown path on a verified host -> Unhandled.
    @Test
    fun `unknown library path is unhandled`() {
        assertEquals(DeepLink.Unhandled, parser.parse("https://app.testlogon.com/library"))
    }

    @Test
    fun `unknown nested path is unhandled`() {
        assertEquals(DeepLink.Unhandled, parser.parse("https://app.testlogon.com/nonsense/x"))
    }

    @Test
    fun `unmapped settings sub-path is unhandled`() {
        assertEquals(DeepLink.Unhandled, parser.parse("https://app.testlogon.com/settings/blocked"))
    }

    // TC-AND-396-04 — non-allowlisted host -> Malformed; never a route.
    @Test
    fun `foreign host is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse("https://evil.example.com/videos/abc"))
    }

    @Test
    fun `look-alike host suffix is malformed`() {
        // The URI host IS the full attacker domain, which is not in the allowlist.
        assertEquals(DeepLink.Malformed, parser.parse("https://app.testlogon.com.evil.com/videos/abc"))
    }

    @Test
    fun `garbage non-url is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse("notaurl"))
    }

    @Test
    fun `null url is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse(null))
    }

    @Test
    fun `custom scheme is out of scope and malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse("testlogon://videos/abc"))
    }

    @Test
    fun `missing required segment is malformed`() {
        assertEquals(DeepLink.Malformed, parser.parse("https://app.testlogon.com/videos"))
        assertEquals(DeepLink.Malformed, parser.parse("https://app.testlogon.com/event/cal_1"))
    }

    // TC-AND-396-12 — path templates strip raw ids + query string (no PII).
    @Test
    fun `path template strips raw id and query string`() {
        assertEquals(
            "/videos/{videoId}",
            parser.pathTemplate("https://app.testlogon.com/videos/secretId123?token=xyz"),
        )
        assertEquals("/u/{identifier}", parser.pathTemplate("https://app.testlogon.com/u/sean"))
        assertEquals("/", parser.pathTemplate("https://app.testlogon.com/"))
    }

    @Test
    fun `path template never contains the raw id`() {
        val template = parser.pathTemplate("https://app.testlogon.com/videos/secretId123?token=xyz")
        assertTrue("template leaked raw id: $template", !template.contains("secretId123"))
        assertTrue("template leaked query: $template", !template.contains("token"))
    }

    @Test
    fun `dev host in the allowlist resolves`() {
        val devParser = DeepLinkParserImpl(verifiedHosts = setOf("18.222.237.167"))
        assertEquals(
            DeepLink.Resolved(VideoDetailDest.build("v1"), requiresAuth = true),
            devParser.parse("http://18.222.237.167/videos/v1"),
        )
    }
}
