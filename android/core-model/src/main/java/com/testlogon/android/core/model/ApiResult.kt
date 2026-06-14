package com.testlogon.android.core.model

import kotlinx.coroutines.CancellationException
import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException

/**
 * Canonical result-carrying type returned by every repository / data source.
 *
 * Models only *completed* outcomes (no `Loading` — that belongs to per-feature UiState):
 *  - [Success] — a domain value.
 *  - [Failure] — the server answered but the response is an error ([ApiError]).
 *  - [NetworkError] — the request never produced an HTTP response (DNS, connect, timeout, offline).
 *
 * The Failure/NetworkError split is deliberate: only [NetworkError] is safe to retry on
 * idempotent GETs, and it drives a distinct offline/retry UI affordance.
 */
sealed interface ApiResult<out T> {
    data class Success<out T>(val data: T) : ApiResult<T>
    data class Failure(val error: ApiError) : ApiResult<Nothing>
    data class NetworkError(
        val cause: Throwable,
        val isTimeout: Boolean = false,
    ) : ApiResult<Nothing>
}

// ---- Transformations (failure variants pass through unchanged) ----

inline fun <T, R> ApiResult<T>.map(transform: (T) -> R): ApiResult<R> = when (this) {
    is ApiResult.Success -> ApiResult.Success(transform(data))
    is ApiResult.Failure -> this
    is ApiResult.NetworkError -> this
}

inline fun <T, R> ApiResult<T>.flatMap(transform: (T) -> ApiResult<R>): ApiResult<R> = when (this) {
    is ApiResult.Success -> transform(data)
    is ApiResult.Failure -> this
    is ApiResult.NetworkError -> this
}

inline fun <T, R> ApiResult<T>.fold(
    onSuccess: (T) -> R,
    onFailure: (ApiError) -> R,
    onNetworkError: (ApiResult.NetworkError) -> R,
): R = when (this) {
    is ApiResult.Success -> onSuccess(data)
    is ApiResult.Failure -> onFailure(error)
    is ApiResult.NetworkError -> onNetworkError(this)
}

// ---- Accessors ----

fun <T> ApiResult<T>.getOrNull(): T? = (this as? ApiResult.Success)?.data

inline fun <T> ApiResult<T>.getOrElse(default: (ApiResult<T>) -> T): T =
    if (this is ApiResult.Success) data else default(this)

fun ApiResult<*>.errorOrNull(): ApiError? = (this as? ApiResult.Failure)?.error

fun ApiResult<*>.exceptionOrNull(): Throwable? = (this as? ApiResult.NetworkError)?.cause

val ApiResult<*>.isSuccess: Boolean get() = this is ApiResult.Success
val ApiResult<*>.isFailure: Boolean get() = this is ApiResult.Failure
val ApiResult<*>.isNetworkError: Boolean get() = this is ApiResult.NetworkError

// ---- Side-effects (return the receiver for fluent chaining) ----

inline fun <T> ApiResult<T>.onSuccess(action: (T) -> Unit): ApiResult<T> =
    apply { if (this is ApiResult.Success) action(data) }

inline fun <T> ApiResult<T>.onFailure(action: (ApiError) -> Unit): ApiResult<T> =
    apply { if (this is ApiResult.Failure) action(error) }

inline fun <T> ApiResult<T>.onNetworkError(action: (ApiResult.NetworkError) -> Unit): ApiResult<T> =
    apply { if (this is ApiResult.NetworkError) action(this) }

@PublishedApi
internal fun Throwable.isTimeout(): Boolean =
    this is SocketTimeoutException || this is InterruptedIOException

/**
 * Runs [block], folding thrown exceptions into the correct variant. [IOException] subtypes become
 * [ApiResult.NetworkError] (timeout flag set for [SocketTimeoutException]/[InterruptedIOException]);
 * [CancellationException] is re-thrown, never swallowed.
 *
 * HTTP-error → [ApiResult.Failure] mapping is layered on by the network module (it needs Retrofit).
 */
suspend inline fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
    ApiResult.Success(block())
} catch (e: CancellationException) {
    throw e
} catch (e: IOException) {
    ApiResult.NetworkError(e, isTimeout = e.isTimeout())
}
