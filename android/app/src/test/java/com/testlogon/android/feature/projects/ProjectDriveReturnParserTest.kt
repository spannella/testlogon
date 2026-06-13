package com.testlogon.android.feature.projects

import com.testlogon.android.feature.projects.provider.ProjectDriveReturnParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-374 - JVM tests for the PURE [ProjectDriveReturnParser] (java.net.URI, no android.net.Uri). Recognizes
 * the custom-scheme + App Link project-Drive callback shapes and extracts {projectId, code, state, error};
 * returns null for any unrelated URL; flags a cancel/access_denied return.
 */
class ProjectDriveReturnParserTest {

    private val parser = ProjectDriveReturnParser()

    @Test
    fun customScheme_success_parsesProjectIdCodeState() {
        val ret = parser.parse(
            "testlogon://projects/p1/providers/google_drive/callback?code=4%2Fabc&state=st_1",
        )
        assertEquals("p1", ret?.projectId)
        assertEquals("4/abc", ret?.code)
        assertEquals("st_1", ret?.state)
        assertNull(ret?.error)
        assertFalse(ret!!.cancelled)
    }

    @Test
    fun customScheme_accessDenied_isCancelled_noCode() {
        val ret = parser.parse(
            "testlogon://projects/p1/providers/google_drive/callback?error=access_denied",
        )
        assertEquals("p1", ret?.projectId)
        assertEquals("access_denied", ret?.error)
        assertTrue(ret!!.cancelled)
        assertNull(ret.code)
    }

    @Test
    fun appLink_success_parsesProjectId() {
        val ret = parser.parse(
            "https://app.testlogon.example/app/projects/p9/providers/google_drive/callback?code=c&state=s",
        )
        assertEquals("p9", ret?.projectId)
        assertEquals("c", ret?.code)
        assertEquals("s", ret?.state)
    }

    @Test
    fun unrelatedUrl_returnsNull() {
        assertNull(parser.parse("testlogon://calendar-integrations/google/callback?code=x"))
        assertNull(parser.parse("https://example.com/whatever"))
        assertNull(parser.parse("testlogon://projects/p1/something/else"))
        assertNull(parser.parse("not a url at all"))
    }

    @Test
    fun customScheme_wrongProvider_returnsNull() {
        assertNull(parser.parse("testlogon://projects/p1/providers/dropbox/callback?code=x&state=y"))
    }
}
