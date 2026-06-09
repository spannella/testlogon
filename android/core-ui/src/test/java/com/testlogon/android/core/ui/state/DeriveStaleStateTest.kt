package com.testlogon.android.core.ui.state

import com.testlogon.android.core.model.BackendStatus
import com.testlogon.android.core.model.Freshness
import com.testlogon.android.core.ui.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-117 / AND-119 — pure JVM truth-table tests for [deriveStaleState]. No Compose, no device:
 * compares against the generated R.string int constants (equality holds regardless of resolved
 * value).
 */
class DeriveStaleStateTest {

    private fun freshness(
        hasCachedValue: Boolean = true,
        isStale: Boolean = false,
        isRefreshing: Boolean = false,
        lastRefreshFailed: Boolean = false,
    ) = Freshness(hasCachedValue, isStale, isRefreshing, lastRefreshFailed)

    @Test
    fun `no cached value hides the bar regardless of other flags`() {
        for (backend in listOf(BackendStatus.Unknown, BackendStatus.Up, BackendStatus.Down)) {
            val s = deriveStaleState(
                freshness(hasCachedValue = false, isStale = true, isRefreshing = true, lastRefreshFailed = true),
                backend,
            )
            assertFalse(s.showBar)
            assertEquals(StaleState.Mode.None, s.mode)
        }
    }

    @Test
    fun `refreshing takes precedence and disables retry`() {
        val s = deriveStaleState(freshness(isRefreshing = true, lastRefreshFailed = true), BackendStatus.Down)
        assertTrue(s.showBar)
        assertEquals(StaleState.Mode.Reconnecting, s.mode)
        assertEquals(R.string.stale_reconnecting, s.messageRes)
        assertFalse(s.retryEnabled)
    }

    @Test
    fun `refresh failed while host down shows offline copy with retry`() {
        val s = deriveStaleState(freshness(lastRefreshFailed = true), BackendStatus.Down)
        assertEquals(StaleState.Mode.RefreshFailed, s.mode)
        assertEquals(R.string.stale_offline_saved, s.messageRes)
        assertTrue(s.retryEnabled)
    }

    @Test
    fun `refresh failed while host up shows generic refresh-failed copy`() {
        val s = deriveStaleState(freshness(lastRefreshFailed = true), BackendStatus.Up)
        assertEquals(StaleState.Mode.RefreshFailed, s.mode)
        assertEquals(R.string.stale_refresh_failed, s.messageRes)
        assertTrue(s.retryEnabled)
    }

    @Test
    fun `ttl stale only shows showing-saved copy`() {
        val s = deriveStaleState(freshness(isStale = true), BackendStatus.Up)
        assertEquals(StaleState.Mode.Stale, s.mode)
        assertEquals(R.string.stale_showing_saved, s.messageRes)
        assertTrue(s.retryEnabled)
    }

    @Test
    fun `fresh data hides the bar`() {
        val s = deriveStaleState(freshness(), BackendStatus.Up)
        assertFalse(s.showBar)
        assertEquals(StaleState.Mode.None, s.mode)
    }
}
