package com.testlogon.android.core.network.retry

import okhttp3.Interceptor
import okhttp3.Response
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import kotlin.random.Random

/**
 * Bounded exponential-backoff (full-jitter) retry for **safe, idempotent GETs only**.
 *
 * Mutating requests (`POST/PUT/PATCH/DELETE`) are executed exactly once and never replayed.
 * A GET is retried when [proceed][Interceptor.Chain.proceed] either throws a retryable
 * [IOException] or returns a retryable 5xx/throttle status. At most [RetryConfig.maxAttempts]
 * `proceed()` calls occur; the terminal response/exception is surfaced unchanged.
 *
 * The inter-attempt sleep aborts promptly if the call is cancelled.
 */
class RetryInterceptor(
    private val config: RetryConfig = RetryConfig(),
    private val random: Random = Random.Default,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.method != "GET" || config.maxAttempts <= 1) {
            return chain.proceed(request)
        }

        var lastError: IOException? = null
        for (attempt in 0 until config.maxAttempts) {
            if (chain.call().isCanceled()) throw IOException("canceled")
            val lastAttempt = attempt == config.maxAttempts - 1
            try {
                val response = chain.proceed(request)
                if (response.code !in config.retryableStatuses || lastAttempt) {
                    return response
                }
                response.close() // release body/connection before retrying
            } catch (e: IOException) {
                lastError = e
                if (!e.isRetryable() || lastAttempt) throw e
            }
            sleep(delayMsFor(attempt), chain)
        }
        throw lastError ?: IOException("retry exhausted")
    }

    /** Full-jitter exponential backoff: random in [0, min(maxDelay, base * 2^attempt)]. */
    internal fun delayMsFor(attempt: Int): Long {
        val exp = config.baseDelayMs shl attempt
        val ceiling = minOf(config.maxDelayMs, exp.coerceAtLeast(config.baseDelayMs))
        return random.nextLong(0, ceiling + 1)
    }

    private fun sleep(ms: Long, chain: Interceptor.Chain) {
        val deadline = System.nanoTime() + ms * 1_000_000
        while (System.nanoTime() < deadline) {
            if (chain.call().isCanceled()) throw IOException("canceled during backoff")
            Thread.sleep(minOf(POLL_MS, ms).coerceAtLeast(1L))
        }
    }

    private fun IOException.isRetryable(): Boolean = when (this) {
        is UnknownHostException -> false // DNS/offline -> fail fast
        is SocketTimeoutException, is ConnectException -> true
        else -> true // connection reset / generic transport
    }

    private companion object {
        const val POLL_MS = 50L
    }
}

/** Configuration for [RetryInterceptor]. Defaults: 1 initial + up to 2 retries. */
data class RetryConfig(
    val maxAttempts: Int = 3,
    val baseDelayMs: Long = 250L,
    val maxDelayMs: Long = 4_000L,
    val retryableStatuses: Set<Int> = setOf(502, 503, 504, 408, 429),
)
