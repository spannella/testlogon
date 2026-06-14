package com.testlogon.android.feature.share

import com.testlogon.android.navigation.PublicShareDest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-392 - the public-download landing must be reachable three ways (FR-2 / §8): a verified HTTPS App
 * Link on the production host, a plaintext HTTP tap-through on the dev host, and the custom-scheme
 * fallback on all builds. These are JVM assertions on [PublicShareDest.deepLinks] uriPatterns (the
 * manifest autoVerify is exercised by the instrumented App Link test, not here). The route id field is
 * `linkId` and the `/share/` segment is shared by all three. Uses the unmocked android.net.Uri behaviour
 * is NOT needed - we only read the uriPattern strings the builder records.
 */
class PublicShareDeepLinkTest {

    private fun patterns(): List<String> =
        PublicShareDest.deepLinks().mapNotNull { it.uriPattern }

    @Test
    fun registersHttpsAppLink_httpDevHost_andCustomScheme() {
        val arg = "{linkId}"
        val patterns = patterns()
        assertEquals(3, patterns.size)
        assertTrue(patterns.any { it == "https://{host}/share/$arg" })
        assertTrue(patterns.any { it == "http://18.222.237.167/share/$arg" })
        assertTrue(patterns.any { it == "testlogon://share/$arg" })
    }

    @Test
    fun everyPattern_carriesLinkIdArgAndSharePath() {
        patterns().forEach { pattern ->
            assertTrue("missing linkId arg in $pattern", pattern.contains("{linkId}"))
            assertTrue("missing /share path in $pattern", pattern.contains("share/"))
        }
    }
}
