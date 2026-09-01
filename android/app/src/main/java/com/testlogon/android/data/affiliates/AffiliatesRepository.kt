package com.testlogon.android.data.affiliates

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.referrals.DEFAULT_CURRENCY_USD
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-265 — affiliates dashboard data layer over [AffiliatesApi].
 *
 * loadDashboard() issues the idempotent GET ui/affiliates/links, maps to domain, and computes the
 * aggregated earnings client-side. createLink()/deleteLink() are the two mutations the web dashboard
 * exposes (POST/DELETE ui/affiliates/links); both optimistically fold the result into the in-memory
 * snapshot so the UI reflects the change without a full reload. Everything is wrapped in [ApiResult]
 * (CancellationException re-thrown, HTTP -> Failure, JsonDataException -> Failure, transport ->
 * NetworkError). Reads degrade honestly (empty/stale); mutations surface the error. [clear] empties the
 * snapshot (logout cleanup).
 */
interface AffiliatesRepository {

    suspend fun loadDashboard(): ApiResult<AffiliateDashboard>

    /** Create a link; on success returns the fresh dashboard (new link folded into the snapshot). */
    suspend fun createLink(request: AffiliateLinkCreateRequest): ApiResult<AffiliateLink>

    /** Revoke a link; on success returns the id removed (also dropped from the snapshot). */
    suspend fun deleteLink(linkId: String): ApiResult<String>

    fun cached(): AffiliateDashboard?

    fun clear()
}

@Singleton
class AffiliatesRepositoryImpl @Inject constructor(
    private val api: AffiliatesApi,
    private val errorParser: ApiErrorParser,
) : AffiliatesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: AffiliateDashboard? = null

    override suspend fun loadDashboard(): ApiResult<AffiliateDashboard> = withContext(io) {
        call { api.getLinks().toDomain(DEFAULT_CURRENCY_USD) }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun createLink(request: AffiliateLinkCreateRequest): ApiResult<AffiliateLink> =
        withContext(io) {
            call { api.createLink(request).toDomain(DEFAULT_CURRENCY_USD) }
                .also { if (it is ApiResult.Success) foldIn(it.data) }
        }

    override suspend fun deleteLink(linkId: String): ApiResult<String> = withContext(io) {
        call { api.deleteLink(linkId).linkId.ifEmpty { linkId } }
            .also { if (it is ApiResult.Success) foldOut(it.data) }
    }

    override fun cached(): AffiliateDashboard? = snapshot

    override fun clear() {
        snapshot = null
    }

    /** Adds/updates [link] in the snapshot and re-aggregates earnings (integer cents, no Double). */
    @Synchronized
    private fun foldIn(link: AffiliateLink) {
        val existing = snapshot?.links.orEmpty()
        val merged = existing.filterNot { it.id == link.id } + link
        snapshot = AffiliateDashboard(merged, merged.aggregateEarnings(DEFAULT_CURRENCY_USD))
    }

    /** Removes [linkId] from the snapshot and re-aggregates earnings. */
    @Synchronized
    private fun foldOut(linkId: String) {
        val existing = snapshot?.links ?: return
        val merged = existing.filterNot { it.id == linkId }
        snapshot = AffiliateDashboard(merged, merged.aggregateEarnings(DEFAULT_CURRENCY_USD))
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
