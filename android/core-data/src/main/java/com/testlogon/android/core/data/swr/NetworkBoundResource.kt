package com.testlogon.android.core.data.swr

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map

/**
 * AND-116 — a Throwable wrapper for a non-transport [ApiError] so SWR can carry it through
 * [Resource.Error] uniformly with [ApiResult.NetworkError] causes.
 */
class ApiErrorException(val error: ApiError) : Exception(error.message)

/** Converts a completed [ApiResult] failure into a [Throwable] for [Resource.Error]. */
fun ApiResult<*>.asThrowable(): Throwable = when (this) {
    is ApiResult.Failure -> ApiErrorException(error)
    is ApiResult.NetworkError -> cause
    is ApiResult.Success -> IllegalStateException("Success is not a failure")
}

/**
 * AND-116 — generic stale-while-revalidate Flow builder.
 *
 * Sequence:
 * 1. Read the cached value once. If [shouldFetch] is true, emit [Resource.Loading] with it.
 * 2. Fetch over the network.
 *    - On [ApiResult.Success]: persist via [saveFetchResult], then re-emit the freshly persisted
 *      value read back from [query] as [Resource.Success] (DB is the single source of truth — the
 *      raw [NET] DTO is NEVER emitted directly).
 *    - On failure: emit [Resource.Error] carrying the last cached value; the cache is not cleared.
 * 3. If [shouldFetch] is false (fresh cache), emit cached [Resource.Success] only.
 *
 * Flow-cold and lifecycle-safe: nothing runs until collected; collector cancellation cancels the
 * in-flight [fetch]. A trailing `.catch` converts any exception escaping [fetch] mapping into a
 * [Resource.Error] so the collector never crashes.
 *
 * @param DB  the domain/cache type emitted to consumers.
 * @param NET the network DTO wrapped in [ApiResult].
 */
fun <DB, NET> networkBoundResource(
    query: () -> Flow<DB?>,
    fetch: suspend () -> ApiResult<NET>,
    saveFetchResult: suspend (NET) -> Unit,
    shouldFetch: (DB?) -> Boolean = { true },
    onFetchFailed: (Throwable) -> Unit = {},
): Flow<Resource<DB>> = flow {
    val cached: DB? = query().first()
    if (shouldFetch(cached)) {
        emit(Resource.Loading(cached))
        when (val result = fetch()) {
            is ApiResult.Success -> {
                saveFetchResult(result.data)
                emitAll(query().filterNotNull().map { Resource.Success(it) })
            }
            is ApiResult.Failure -> {
                val t = result.asThrowable()
                onFetchFailed(t)
                emitAll(query().map { Resource.Error(t, it) })
            }
            is ApiResult.NetworkError -> {
                val t = result.cause
                onFetchFailed(t)
                emitAll(query().map { Resource.Error(t, it) })
            }
        }
    } else {
        emitAll(query().filterNotNull().map { Resource.Success(it) })
    }
}
    .catch { t ->
        // Unexpected exception escaping fetch/mapping — surface stale-with-error, never crash.
        onFetchFailed(t)
        val last = runCatching { query().first() }.getOrNull()
        emit(Resource.Error(t, last))
    }
    .flowOn(Dispatchers.Default)
