package com.testlogon.android.feature.seo.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-400 - the data layer over [SeoApi] for the read-only SEO inspector.
 *
 * Wraps each call in [ApiResult] via the established call{} pattern (CancellationException re-thrown,
 * HttpException -&gt; Failure, transport -&gt; NetworkError); the DTO never leaks past this layer. The GET
 * is idempotent, so transient transport / 5xx backoff is applied globally by the shared core-network
 * RetryInterceptor - the repository adds no retry loop of its own. A null / empty (204) body decodes to
 * an empty [SeoMetadata] (available=false) which the ViewModel renders as the empty state.
 *
 * The endpoint is PUBLIC (no auth); there is no 401/403/404 handling here. A 422 surfaces as a
 * non-retryable [ApiResult.Failure] (its message is parsed by [ApiErrorParser]).
 */
interface SeoRepository {

    /** Resource-addressed metadata lookup (secondaryId is used for events). */
    suspend fun metadata(type: ResourceType, id: String, secondaryId: String? = null): ApiResult<SeoMetadata>

    /** Path-addressed metadata lookup (mirrors the web getSeoMetadataForPath). */
    suspend fun metadataForPath(path: String): ApiResult<SeoMetadata>
}

@Singleton
class SeoRepositoryImpl @Inject constructor(
    private val api: SeoApi,
    private val mapper: SeoMetadataMapper,
    private val errorParser: ApiErrorParser,
) : SeoRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun metadata(
        type: ResourceType,
        id: String,
        secondaryId: String?,
    ): ApiResult<SeoMetadata> = withContext(io) {
        call { api.getSeoMetadata(type.wire, id, secondaryId?.takeIf { it.isNotBlank() }) }
    }

    override suspend fun metadataForPath(path: String): ApiResult<SeoMetadata> = withContext(io) {
        call { api.getSeoMetadataForPath(path) }
    }

    /** Runs the suspending API call, mapping the body to domain and folding failures into [ApiResult]. */
    private suspend fun call(block: suspend () -> Response<SeoMetadataDto>): ApiResult<SeoMetadata> = try {
        val response = block()
        if (response.isSuccessful) {
            // A null / 204 body yields an empty payload (available=false) -> the empty state.
            val dto = response.body() ?: SeoMetadataDto()
            ApiResult.Success(mapper.toDomain(dto))
        } else {
            ApiResult.Failure(errorParser.from(HttpException(response)))
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
