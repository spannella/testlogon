package com.testlogon.android.core.data.swr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-117 — Resource.toFreshness() is total over the sealed hierarchy. */
class ResourceFreshnessTest {

    @Test
    fun `loading with data is refreshing with cached value`() {
        val f = (Resource.Loading("A") as Resource<*>).toFreshness()
        assertTrue(f.hasCachedValue)
        assertTrue(f.isRefreshing)
        assertFalse(f.lastRefreshFailed)
        assertFalse(f.isStale)
    }

    @Test
    fun `loading without data has no cached value`() {
        val f = (Resource.Loading<String>(null) as Resource<*>).toFreshness()
        assertFalse(f.hasCachedValue)
        assertTrue(f.isRefreshing)
    }

    @Test
    fun `success is fresh - no bar`() {
        val f = (Resource.Success("A") as Resource<*>).toFreshness()
        assertFalse(f.hasCachedValue)
        assertFalse(f.isRefreshing)
        assertFalse(f.lastRefreshFailed)
        assertFalse(f.isStale)
    }

    @Test
    fun `error with cached value is stale and failed`() {
        val f = (Resource.Error(RuntimeException(), "A") as Resource<*>).toFreshness()
        assertTrue(f.hasCachedValue)
        assertTrue(f.isStale)
        assertTrue(f.lastRefreshFailed)
        assertFalse(f.isRefreshing)
    }

    @Test
    fun `error without cached value has no cached value`() {
        val f = (Resource.Error<String>(RuntimeException(), null) as Resource<*>).toFreshness()
        assertFalse(f.hasCachedValue)
        assertTrue(f.lastRefreshFailed)
    }

    @Test
    fun `asThrowable maps failure and network error`() {
        val net = RuntimeException("n")
        assertEquals(
            net,
            (com.testlogon.android.core.model.ApiResult.NetworkError(net) as com.testlogon.android.core.model.ApiResult<*>).asThrowable(),
        )
    }
}
