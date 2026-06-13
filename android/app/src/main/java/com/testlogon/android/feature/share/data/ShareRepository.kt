package com.testlogon.android.feature.share.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.CreateShareLinkRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.share.FileShareLinksApi
import com.testlogon.android.core.network.share.PublicShareApi
import com.testlogon.android.feature.share.model.PublicShare
import com.testlogon.android.feature.share.model.ShareLink
import com.testlogon.android.feature.share.model.ShareLinkOptions
import com.testlogon.android.feature.share.model.toDomain
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
 * AND-335 - data layer over [FileShareLinksApi] (owner, authenticated) + [PublicShareApi] (public,
 * session-free). Each network call is wrapped in [ApiResult] and the wire DTO is mapped to the domain
 * BEFORE the typed result. Never throws (Cancellation is re-thrown).
 *
 * OWNER vs PUBLIC SPLIT: the two apis come from two different Retrofit clients (see ShareNetworkModule) -
 * the owner api on the shared authenticated Retrofit (cookie + CSRF + Bearer) and the public api on a
 * cookieless Retrofit. This repository simply consumes both; it never attaches headers itself.
 *
 * LIST is a single GET of ALL the caller's links, FILTERED to a file CLIENT-SIDE (the wire has no
 * per-file list). The actual public byte download is handled by [ShareDownloader] (streamed to
 * MediaStore), not here. Both apis are NEW interfaces with no existing fakes, so no shared fake is
 * touched.
 */
interface ShareRepository {

    /** List the caller's links for a single file (all-links GET filtered by file_node_id client-side). */
    suspend fun listLinks(fileId: String): ApiResult<List<ShareLink>>

    /** Create a new share link for [fileId] with the chosen [options] (201 -> the created link). */
    suspend fun createLink(fileId: String, options: ShareLinkOptions): ApiResult<ShareLink>

    /** Revoke the link identified by [linkId]. */
    suspend fun revokeLink(linkId: String): ApiResult<Unit>

    /** Resolve a public link's metadata + state (session-free; [password] optionally re-checked). */
    suspend fun resolvePublic(linkId: String, password: String?): ApiResult<PublicShare>
}

@Singleton
class ShareRepositoryImpl @Inject constructor(
    private val ownerApi: FileShareLinksApi,
    private val publicApi: PublicShareApi,
    private val errorParser: ApiErrorParser,
) : ShareRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listLinks(fileId: String): ApiResult<List<ShareLink>> = withContext(io) {
        when (val result = call { ownerApi.listLinks() }) {
            is ApiResult.Success ->
                ApiResult.Success(
                    result.data.links
                        .filter { it.file_node_id == fileId }
                        .map { it.toDomain() },
                )
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun createLink(
        fileId: String,
        options: ShareLinkOptions,
    ): ApiResult<ShareLink> = withContext(io) {
        val body = CreateShareLinkRequest(
            file_node_id = fileId,
            expiry_hours = options.expiryHours,
            max_downloads = options.maxDownloads,
            password = options.password?.takeIf { it.isNotEmpty() },
        )
        when (val result = call { ownerApi.createLink(body) }) {
            is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun revokeLink(linkId: String): ApiResult<Unit> = withContext(io) {
        when (val result = call { ownerApi.revokeLink(linkId) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun resolvePublic(
        linkId: String,
        password: String?,
    ): ApiResult<PublicShare> = withContext(io) {
        when (val result = call { publicApi.resolvePublic(linkId) }) {
            is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport
     * failures -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch precedes
     * the IOException catch (it is an IOException subtype). Cancellation is re-thrown.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
