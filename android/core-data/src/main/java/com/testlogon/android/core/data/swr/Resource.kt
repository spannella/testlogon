package com.testlogon.android.core.data.swr

/**
 * AND-116 — result of a stale-while-revalidate stream.
 *
 * Emission contract (see [networkBoundResource]):
 * - [Loading] carries the cached value (if any) while a revalidation is in flight.
 * - [Success] always carries a value read back from the cache (the DB is the single source of
 *   truth — the raw network DTO is never emitted directly to consumers).
 * - [Error] carries the throwable AND the last-known cached value (if any), so the UI can show
 *   stale content with an error banner rather than clearing the screen.
 *
 * [data] exposes the value uniformly across states (null when there is nothing cached yet).
 */
sealed interface Resource<out T> {
    val data: T?

    data class Loading<out T>(override val data: T? = null) : Resource<T>

    data class Success<out T>(override val data: T) : Resource<T>

    data class Error<out T>(
        val throwable: Throwable,
        override val data: T? = null,
    ) : Resource<T>
}
