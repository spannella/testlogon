package com.testlogon.android.feature.feed

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-176 — pure tests for the share artifacts: URL shape + no auth material leaks. */
class PostShareTest {

    @Test
    fun urlFor_usesVerifiedPostsPathSegment() {
        val url = PostShare.urlFor("post_42")
        assertTrue(url.endsWith("/posts/post_42"))
        assertFalse(url.contains("/p/")) // NOT the wrong /p/{id} segment
    }

    @Test
    fun urlAndSubject_containNoAuthMaterial() {
        val url = PostShare.urlFor("post_42")
        val subject = PostShare.subjectFor("Sunset Studio")
        val haystack = "$url ${subject.orEmpty()}".lowercase()
        listOf("cookie", "ui_csrf", "csrf", "bearer", "session", "authorization", "token").forEach {
            assertFalse("share payload must not contain '$it'", haystack.contains(it))
        }
    }

    @Test
    fun subjectFor_nullWhenNoName() {
        assertNull(PostShare.subjectFor(null))
        assertNull(PostShare.subjectFor(" "))
    }
}
