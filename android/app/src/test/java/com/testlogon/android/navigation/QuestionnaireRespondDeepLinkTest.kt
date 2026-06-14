package com.testlogon.android.navigation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-349 - JVM unit test for the pure respond App Link slug parse (no android.net.Uri). Verifies the
 * .../questionnaires/published/{slug}/respond extraction across schemes/hosts, URL decoding, and the
 * reject cases (wrong path, missing /respond, blank slug, extra segments).
 */
class QuestionnaireRespondDeepLinkTest {

    @Test
    fun slugFromUrl_extractsSlug_httpsProdHost() {
        assertEquals(
            "customer-intake",
            QuestionnaireRespondDest.slugFromUrl(
                "https://app.testlogon.example.com/questionnaires/published/customer-intake/respond",
            ),
        )
    }

    @Test
    fun slugFromUrl_extractsSlug_devHttpHost() {
        assertEquals(
            "my-survey",
            QuestionnaireRespondDest.slugFromUrl(
                "http://18.222.237.167/questionnaires/published/my-survey/respond",
            ),
        )
    }

    @Test
    fun slugFromUrl_urlDecodesSlug() {
        assertEquals(
            "a b",
            QuestionnaireRespondDest.slugFromUrl(
                "https://host/questionnaires/published/a%20b/respond",
            ),
        )
    }

    @Test
    fun slugFromUrl_rejectsWrongPath() {
        assertNull(QuestionnaireRespondDest.slugFromUrl("https://host/u/someone"))
    }

    @Test
    fun slugFromUrl_rejectsMissingRespondSuffix() {
        assertNull(
            QuestionnaireRespondDest.slugFromUrl("https://host/questionnaires/published/my-survey"),
        )
    }

    @Test
    fun slugFromUrl_rejectsExtraSegments() {
        assertNull(
            QuestionnaireRespondDest.slugFromUrl(
                "https://host/questionnaires/published/my-survey/sections/1/respond",
            ),
        )
    }

    @Test
    fun slugFromUrl_rejectsBlankAndNull() {
        assertNull(QuestionnaireRespondDest.slugFromUrl(null))
        assertNull(QuestionnaireRespondDest.slugFromUrl(""))
        assertNull(
            QuestionnaireRespondDest.slugFromUrl("https://host/questionnaires/published//respond"),
        )
    }
}
