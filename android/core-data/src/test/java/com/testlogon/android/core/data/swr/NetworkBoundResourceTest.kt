package com.testlogon.android.core.data.swr

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-116 / AND-119 — JVM unit tests for the SWR [networkBoundResource] builder. Pure logic, no
 * Android, no real network, no Room: the query Flow and fetch seam are fakes.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class NetworkBoundResourceTest {

    @Test
    fun `cached then fresh emits Loading(cached) then Success(fresh)`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        var saved = 0
        val flow = networkBoundResource(
            query = { cache },
            fetch = { ApiResult.Success("B") },
            saveFetchResult = { dto -> saved++; cache.value = dto },
        )
        val emissions = flow.take(2).toList()
        assertEquals(Resource.Loading("A"), emissions[0])
        assertEquals(Resource.Success("B"), emissions[1])
        assertEquals(1, saved)
    }

    @Test
    fun `empty cache success emits Loading(null) then Success`() = runTest {
        val cache = MutableStateFlow<String?>(null)
        val flow = networkBoundResource(
            query = { cache },
            fetch = { ApiResult.Success("B") },
            saveFetchResult = { dto -> cache.value = dto },
        )
        val emissions = flow.take(2).toList()
        assertEquals(Resource.Loading<String>(null), emissions[0])
        assertEquals(Resource.Success("B"), emissions[1])
    }

    @Test
    fun `network failure keeps stale data and does not save`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        var saved = false
        val cause = IOException("timeout")
        val flow = networkBoundResource(
            query = { cache },
            fetch = { ApiResult.NetworkError(cause, isTimeout = true) },
            saveFetchResult = { saved = true },
        )
        val emissions = flow.take(2).toList()
        assertEquals(Resource.Loading("A"), emissions[0])
        assertEquals(Resource.Error(cause, "A"), emissions[1])
        assertFalse(saved)
    }

    @Test
    fun `server failure carries cached value via ApiErrorException`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        val flow = networkBoundResource(
            query = { cache },
            fetch = { ApiResult.Failure(ApiError(status = 422, message = "bad")) },
            saveFetchResult = { },
        )
        val emissions = flow.take(2).toList()
        assertEquals(Resource.Loading("A"), emissions[0])
        val err = emissions[1] as Resource.Error
        assertEquals("A", err.data)
        assertTrue(err.throwable is ApiErrorException)
        assertEquals(422, (err.throwable as ApiErrorException).error.status)
    }

    @Test
    fun `failure with empty cache yields Error(null)`() = runTest {
        val cache = MutableStateFlow<String?>(null)
        val flow = networkBoundResource(
            query = { cache },
            fetch = { ApiResult.NetworkError(IOException("x")) },
            saveFetchResult = { },
        )
        val emissions = flow.take(2).toList()
        assertEquals(Resource.Loading<String>(null), emissions[0])
        val err = emissions[1] as Resource.Error
        assertEquals(null, err.data)
    }

    @Test
    fun `shouldFetch false serves cached Success only and never fetches`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        var fetched = false
        val flow = networkBoundResource(
            query = { cache },
            fetch = { fetched = true; ApiResult.Success("B") },
            saveFetchResult = { },
            shouldFetch = { false },
        )
        val emissions = flow.take(1).toList()
        assertEquals(Resource.Success("A"), emissions[0])
        assertFalse(fetched)
    }

    @Test
    fun `thrown exception in fetch is caught as Error not crash`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        val boom = IllegalStateException("boom")
        val flow = networkBoundResource<String, String>(
            query = { cache },
            fetch = { throw boom },
            saveFetchResult = { },
        )
        val emissions = flow.toList()
        // Loading(A) then a terminal Error carrying the cached value.
        assertEquals(Resource.Loading("A"), emissions.first())
        val err = emissions.last() as Resource.Error
        assertSame(boom, err.throwable)
        assertEquals("A", err.data)
    }

    @Test
    fun `onFetchFailed fires once with the carried throwable`() = runTest {
        val cause = IOException("net")
        val failures = mutableListOf<Throwable>()
        val flow = networkBoundResource(
            query = { flowOf<String?>("A") },
            fetch = { ApiResult.NetworkError(cause) },
            saveFetchResult = { },
            onFetchFailed = { failures.add(it) },
        )
        flow.take(2).toList()
        assertEquals(1, failures.size)
        assertSame(cause, failures.first())
    }

    @Test
    fun `db is single source of truth - net dto never emitted directly`() = runTest {
        // NET is an Int; DB/domain is a String. Success must carry the DB value, not the raw NET.
        val cache = MutableStateFlow<String?>(null)
        val flow: Flow<Resource<String>> = networkBoundResource(
            query = { cache },
            fetch = { ApiResult.Success(7) },
            saveFetchResult = { dto -> cache.value = "mapped:$dto" },
        )
        val emissions = flow.take(2).toList()
        assertEquals(Resource.Success("mapped:7"), emissions[1])
    }

    @Test
    fun `collector cancellation cancels in-flight fetch`() = runTest {
        val cache = MutableStateFlow<String?>("A")
        val started = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Unit>()
        val gate = CompletableDeferred<Unit>() // never completed
        val flow = networkBoundResource<String, String>(
            query = { cache },
            fetch = {
                started.complete(Unit)
                try {
                    gate.await() // suspends forever until cancelled
                    ApiResult.Success("B")
                } catch (e: kotlinx.coroutines.CancellationException) {
                    cancelled.complete(Unit)
                    throw e
                }
            },
            saveFetchResult = { },
        )
        val job = launch { flow.toList() }
        started.await() // deterministic: wait until fetch is in flight (dispatcher-agnostic)
        job.cancel()
        cancelled.await() // deterministic: fetch coroutine observed cancellation
        assertTrue(cancelled.isCompleted)
    }
}
