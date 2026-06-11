package com.testlogon.android.data.gcal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-273 — pure return-URL parser tests (java.net.URI; no android.net.Uri). */
class GoogleCalendarReturnParserTest {

    private val parser = GoogleCalendarReturnParser()

    @Test
    fun customScheme_parsesCodeAndState() {
        val ret = parser.parse(
            "testlogon://calendar-integrations/google/callback?code=abc&state=s1",
        )
        assertEquals("abc", ret?.code)
        assertEquals("s1", ret?.state)
        assertFalse(ret!!.cancelled)
    }

    @Test
    fun appLink_parsesCodeAndState() {
        val ret = parser.parse(
            "https://app.testlogon.example.com/app/calendar/integrations/google/callback?code=c&state=s",
        )
        assertEquals("c", ret?.code)
        assertEquals("s", ret?.state)
    }

    @Test
    fun accessDenied_isCancelled() {
        val ret = parser.parse(
            "testlogon://calendar-integrations/google/callback?error=access_denied&state=s1",
        )
        assertTrue(ret!!.cancelled)
        assertEquals("access_denied", ret.error)
    }

    @Test
    fun nonGcalUrl_returnsNull() {
        assertNull(parser.parse("testlogon://payments/return?provider=paypal"))
        assertNull(parser.parse("https://app.testlogon.example.com/u/sam"))
        assertNull(parser.parse("not a url at all ::::"))
    }
}
