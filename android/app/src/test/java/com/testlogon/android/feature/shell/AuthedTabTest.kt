package com.testlogon.android.feature.shell

import org.junit.Assert.assertEquals
import org.junit.Test

class AuthedTabTest {

    @Test fun fromRoute_mapsKnownRoutes() {
        assertEquals(AuthedTab.HOME, AuthedTab.fromRoute("authed/home"))
        assertEquals(AuthedTab.ME, AuthedTab.fromRoute("authed/me"))
    }

    @Test fun fromRoute_fallsBackToStartForNullOrUnknown() {
        assertEquals(AuthedTab.START, AuthedTab.fromRoute(null))
        assertEquals(AuthedTab.START, AuthedTab.fromRoute("garbage/route"))
    }
}
