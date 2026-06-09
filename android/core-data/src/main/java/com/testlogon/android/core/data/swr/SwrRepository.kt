package com.testlogon.android.core.data.swr

import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.flow.Flow

/**
 * AND-116 — abstract stale-while-revalidate base every data-backed feature repository extends.
 *
 * A subclass implements only [cacheFlow], [fetch], [persist], and (optionally) [isFresh]; the
 * [stream] helper wires them through [networkBoundResource] so the emission contract
 * (cache → fetch → DB-read-back) is uniform and DB stays the single source of truth.
 *
 * @param Key    the cache key type.
 * @param Domain the domain/cache type emitted to consumers (read back from the DB).
 * @param Dto    the network DTO persisted by [persist].
 */
abstract class SwrRepository<Key, Domain, Dto> {
    /** Room-backed `Flow` for the cached value at [key]; stays hot so later writes re-emit. */
    protected abstract fun cacheFlow(key: Key): Flow<Domain?>

    /** Network fetch for [key]. */
    protected abstract suspend fun fetch(key: Key): ApiResult<Dto>

    /** Maps + writes [dto] to the cache (stamping fetchedAt = now), through the AND-115 DAO. */
    protected abstract suspend fun persist(key: Key, dto: Dto)

    /** TTL/freshness gate; default never-fresh so revalidation always runs. */
    protected open fun isFresh(cached: Domain?): Boolean = false

    /** Telemetry seam; called once per revalidation failure. */
    protected open fun onFetchFailed(throwable: Throwable) {}

    /**
     * Cache-first stream for [key]. When [forceRefresh] is true the freshness gate is bypassed and
     * the network is always hit.
     */
    fun stream(key: Key, forceRefresh: Boolean = false): Flow<Resource<Domain>> =
        networkBoundResource(
            query = { cacheFlow(key) },
            fetch = { fetch(key) },
            saveFetchResult = { dto -> persist(key, dto) },
            shouldFetch = { cached -> forceRefresh || !isFresh(cached) },
            onFetchFailed = ::onFetchFailed,
        )
}
