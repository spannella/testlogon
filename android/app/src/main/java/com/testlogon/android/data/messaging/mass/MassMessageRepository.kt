package com.testlogon.android.data.messaging.mass

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** AND-160 — one page of campaigns + the cursor for the next page. */
data class MassCampaignPage(
    val items: List<MassCampaign>,
    val nextCursor: String?,
)

/**
 * AND-160 — data layer for mass-message campaigns.
 *
 * Network-backed (no Room): campaign volume is small and freshness matters. The list is paged via a
 * cursor-keyed [PagingSource]; create/cancel are one-shot mutations. CancellationException is always
 * re-thrown; HTTP errors fold to [ApiResult.Failure] and IO to [ApiResult.NetworkError].
 *
 * No message text or recipient ids are logged.
 */
interface MassMessageRepository {

    /** A paged flow of campaigns, newest first. Optional server-side status/mode filters. */
    fun campaignsPager(status: String? = null, mode: String? = null): Flow<PagingData<MassCampaign>>

    /** Fetch one page directly (used by the [PagingSource] and by tests). */
    suspend fun listPage(cursor: String?, limit: Int, status: String?, mode: String?): ApiResult<MassCampaignPage>

    /** Create a campaign. Returns the new campaign plus accepted/rejected detail. */
    suspend fun create(request: CreateCampaignDraft): ApiResult<MassCampaignCreateResult>

    /** Cancel a non-terminal campaign. [prior] supplies fields the cancel response omits. */
    suspend fun cancel(id: String, prior: MassCampaign? = null): ApiResult<MassCampaign>
}

/**
 * AND-160 — validated create input (the ViewModel's draft maps into this). Kept in the data layer so
 * the repository owns the request build (content payload, mode, send_at, idempotency_key).
 */
data class CreateCampaignDraft(
    val text: String,
    val conversationIds: List<String>,
    val mode: CampaignMode = CampaignMode.IMMEDIATE,
    val sendAtEpochSeconds: Long? = null,
    val idempotencyKey: String? = null,
)

@Singleton
class MassMessageRepositoryImpl @Inject constructor(
    private val api: MassMessageApi,
    private val errorParser: ApiErrorParser,
) : MassMessageRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun campaignsPager(status: String?, mode: String?): Flow<PagingData<MassCampaign>> =
        Pager(
            config = PagingConfig(
                pageSize = MassMessageApi.DEFAULT_LIMIT,
                enablePlaceholders = false,
            ),
            pagingSourceFactory = { MassCampaignPagingSource(this, status, mode) },
        ).flow

    override suspend fun listPage(
        cursor: String?,
        limit: Int,
        status: String?,
        mode: String?,
    ): ApiResult<MassCampaignPage> = withContext(io) {
        when (val r = apiCall { api.listCampaigns(limit = limit, cursor = cursor, status = status, mode = mode) }) {
            is ApiResult.Success -> ApiResult.Success(
                MassCampaignPage(
                    items = r.data.items.map { it.toDomain() },
                    nextCursor = r.data.nextCursor?.takeIf { it.isNotBlank() },
                ),
            )
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun create(request: CreateCampaignDraft): ApiResult<MassCampaignCreateResult> =
        withContext(io) {
            val body = MassMessageCreateCampaignRequestDto(
                conversationIds = request.conversationIds,
                content = MassMessageContentPayloadDto(text = request.text),
                mode = request.mode.wire(),
                sendAt = if (request.mode == CampaignMode.SCHEDULED) request.sendAtEpochSeconds else null,
                idempotencyKey = request.idempotencyKey?.takeIf { it.isNotBlank() },
            )
            when (val r = apiCall { api.createCampaign(body) }) {
                is ApiResult.Success -> ApiResult.Success(r.data.toResult())
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override suspend fun cancel(id: String, prior: MassCampaign?): ApiResult<MassCampaign> =
        withContext(io) {
            when (val r = apiCall { api.cancelCampaign(id) }) {
                is ApiResult.Success -> ApiResult.Success(r.data.toDomain(prior))
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/**
 * AND-160 — cursor-keyed Paging 3 source over [MassMessageRepository.listPage]. Forward-only,
 * newest-first; [getRefreshKey] returns null so refresh re-anchors at page 1. Repository failures
 * become [LoadResult.Error].
 */
class MassCampaignPagingSource(
    private val repository: MassMessageRepository,
    private val status: String?,
    private val mode: String?,
) : PagingSource<String, MassCampaign>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, MassCampaign> =
        when (
            val result = repository.listPage(
                cursor = params.key,
                limit = params.loadSize,
                status = status,
                mode = mode,
            )
        ) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.nextCursor,
            )
            is ApiResult.Failure -> LoadResult.Error(MassCampaignLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, MassCampaign>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx page load failure. */
class MassCampaignLoadException(message: String) : Exception(message)
