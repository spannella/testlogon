package com.testlogon.android.core.data.swr

import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-116 — the SwrRepository base lets a subclass override only the four/five hooks. */
@OptIn(ExperimentalCoroutinesApi::class)
class SwrRepositoryTest {

    private class TestRepo(
        private val cache: MutableStateFlow<String?>,
        private val fresh: Boolean = false,
        private val fetcher: suspend () -> ApiResult<String>,
    ) : SwrRepository<String, String, String>() {
        var fetchCount = 0
        override fun cacheFlow(key: String): Flow<String?> = cache
        override suspend fun fetch(key: String): ApiResult<String> {
            fetchCount++
            return fetcher()
        }
        override suspend fun persist(key: String, dto: String) {
            cache.value = dto
        }
        override fun isFresh(cached: String?): Boolean = fresh
    }

    @Test
    fun `stream drives cached-then-fresh through base wiring`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        val repo = TestRepo(cache) { ApiResult.Success("B") }
        val emissions = repo.stream("k").take(2).toList()
        assertEquals(Resource.Loading("A"), emissions[0])
        assertEquals(Resource.Success("B"), emissions[1])
        assertEquals(1, repo.fetchCount)
    }

    @Test
    fun `fresh cache skips network`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        val repo = TestRepo(cache, fresh = true) { ApiResult.Success("B") }
        val emissions = repo.stream("k").take(1).toList()
        assertEquals(Resource.Success("A"), emissions[0])
        assertEquals(0, repo.fetchCount)
    }

    @Test
    fun `forceRefresh overrides freshness`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        val repo = TestRepo(cache, fresh = true) { ApiResult.Success("B") }
        val emissions = repo.stream("k", forceRefresh = true).take(2).toList()
        assertEquals(Resource.Loading("A"), emissions[0])
        assertEquals(Resource.Success("B"), emissions[1])
        assertEquals(1, repo.fetchCount)
    }

    @Test
    fun `default isFresh is false so revalidation always runs`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        // A repo that does NOT override isFresh.
        val repo = object : SwrRepository<String, String, String>() {
            var fetched = false
            override fun cacheFlow(key: String): Flow<String?> = cache
            override suspend fun fetch(key: String): ApiResult<String> {
                fetched = true
                return ApiResult.Success("B")
            }
            override suspend fun persist(key: String, dto: String) { cache.value = dto }
        }
        repo.stream("k").take(2).toList()
        assertTrue(repo.fetched)
    }

    @Test
    fun `isFresh helper boundaries`() {
        assertFalse(isFresh(fetchedAt = null, now = 1_000, ttlMs = 100))
        assertTrue(isFresh(fetchedAt = 950, now = 1_000, ttlMs = 100)) // age 50 < 100
        assertTrue(isFresh(fetchedAt = 901, now = 1_000, ttlMs = 100)) // age 99 < 100
        assertFalse(isFresh(fetchedAt = 900, now = 1_000, ttlMs = 100)) // age 100 == ttl (exclusive)
        assertFalse(isFresh(fetchedAt = 800, now = 1_000, ttlMs = 100)) // age 200 > ttl
        assertEquals(60_000L, CachePolicyDefaults.DEFAULT_TTL_MS)
    }
}
