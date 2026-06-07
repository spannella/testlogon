package com.testlogon.android.core.model

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.net.SocketTimeoutException

class ApiResultTest {

    private val error = ApiError(status = 403, message = "nope")

    @Test
    fun `map transforms success`() {
        val result = ApiResult.Success(2).map { it * 3 }
        assertEquals(ApiResult.Success(6), result)
    }

    @Test
    fun `map over failure is identity`() {
        val failure: ApiResult<Int> = ApiResult.Failure(error)
        assertSame(failure, failure.map { it + 1 })
    }

    @Test
    fun `flatMap short-circuits on network error`() {
        val net: ApiResult<Int> = ApiResult.NetworkError(IOException())
        assertSame(net, net.flatMap { ApiResult.Success(it) })
    }

    @Test
    fun `fold dispatches to the right branch`() {
        val out = ApiResult.Failure(error).fold(
            onSuccess = { "s" },
            onFailure = { "f:${it.status}" },
            onNetworkError = { "n" },
        )
        assertEquals("f:403", out)
    }

    @Test
    fun `predicates and accessors`() {
        val success: ApiResult<String> = ApiResult.Success("x")
        assertTrue(success.isSuccess)
        assertEquals("x", success.getOrNull())
        assertEquals(error, ApiResult.Failure(error).errorOrNull())
    }

    @Test
    fun `apiCall wraps success`() = runTest {
        assertEquals(ApiResult.Success(42), apiCall { 42 })
    }

    @Test
    fun `apiCall maps timeout to network error with flag`() = runTest {
        val result = apiCall<Int> { throw SocketTimeoutException() }
        assertTrue(result is ApiResult.NetworkError && result.isTimeout)
    }

    @Test
    fun `apiCall maps generic IOException without timeout flag`() = runTest {
        val result = apiCall<Int> { throw IOException("reset") }
        assertTrue(result is ApiResult.NetworkError && !result.isTimeout)
    }

    @Test
    fun `apiCall rethrows cancellation`() = runTest {
        try {
            apiCall<Int> { throw CancellationException() }
            fail("expected CancellationException")
        } catch (_: CancellationException) {
            // expected
        }
    }
}
