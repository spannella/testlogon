package com.testlogon.android.data.profile

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.profile.MediaUploadResult
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.core.network.error.ApiErrorParser
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
 * AND-070 / AND-071 / AND-072 / AND-074 — profile data layer over [ProfileApi].
 *
 *  - getOwnProfile: GET /ui/profile, unwraps the { profile } envelope, maps to domain, and caches
 *    the last-known-good profile in memory for stale-while-error rendering (no Room in scope).
 *  - getPublicProfile: GET /ui/profile/public/{identifier}, classifying 404 -> NotFound and
 *    429 -> RateLimited (typed) so the public screen can render dedicated surfaces.
 *  - getCrossUserProfile: GET /ui/profiles/{identifier} (audience-aware), exposed for completeness.
 *  - updateProfile: PATCH /ui/profile (partial), unwraps the envelope, write-through to cache.
 *  - uploadPhoto: POST /ui/profile/photos/{kind}/upload; never auto-retried.
 */
interface ProfileRepository {

    suspend fun getOwnProfile(forceRefresh: Boolean = false): ApiResult<Profile>

    /** Last cached own profile for stale-while-error rendering, or null. */
    fun cachedOwnProfile(): Profile?

    suspend fun getPublicProfile(identifier: String): ProfileResult

    suspend fun updateProfile(patch: ProfilePatch): ApiResult<Profile>

    suspend fun uploadPhoto(
        kind: MediaKind,
        upload: ProfileMediaUploader.PreparedUpload,
    ): ApiResult<MediaUploadResult>
}

@Singleton
class ProfileRepositoryImpl @Inject constructor(
    private val api: ProfileApi,
    private val uploader: ProfileMediaUploader,
    private val errorParser: ApiErrorParser,
) : ProfileRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var cache: Profile? = null

    override suspend fun getOwnProfile(forceRefresh: Boolean): ApiResult<Profile> =
        withContext(io) {
            apiCall { api.getMyProfile().profile.toDomain() }
                .also { if (it is ApiResult.Success) cache = it.data }
        }

    override fun cachedOwnProfile(): Profile? = cache

    override suspend fun getPublicProfile(identifier: String): ProfileResult =
        withContext(io) {
            val trimmed = identifier.trim()
            if (trimmed.isEmpty()) return@withContext ProfileResult.NotFound
            try {
                ProfileResult.Found(api.getPublicProfile(trimmed).toDomain())
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                classifyLookup(errorParser.from(e), e)
            } catch (e: IOException) {
                ProfileResult.Offline
            }
        }

    override suspend fun updateProfile(patch: ProfilePatch): ApiResult<Profile> =
        withContext(io) {
            // PATCH is non-idempotent and never auto-retried (the OkHttp retry policy is GET-only).
            apiCall { api.patchMyProfile(patch.toReqDto()).profile.toDomain() }
                .also { if (it is ApiResult.Success) cache = it.data }
        }

    override suspend fun uploadPhoto(
        kind: MediaKind,
        upload: ProfileMediaUploader.PreparedUpload,
    ): ApiResult<MediaUploadResult> = withContext(io) {
        apiCall { uploader.upload(kind, upload) }
            .also { result ->
                // Keep the in-memory profile fresh with the uploaded photo URL.
                if (result is ApiResult.Success) result.data.profile?.let { cache = it }
            }
    }

    private fun classifyLookup(error: ApiError, http: HttpException): ProfileResult = when (error.status) {
        404 -> ProfileResult.NotFound
        429 -> ProfileResult.RateLimited(retryAfterSeconds(http, error))
        else -> ProfileResult.Error(error, retryable = error.status >= 500 || error.status == 0)
    }

    /** Reads `Retry-After` (seconds) header first, then `detail.retry_after_seconds` from the body. */
    private fun retryAfterSeconds(http: HttpException, error: ApiError): Long? {
        http.response()?.headers()?.get("Retry-After")?.trim()?.toLongOrNull()
            ?.takeIf { it > 0 }?.let { return it }
        val detail = (error.raw as? String)?.let { errorParser.parseDetail(it) }
        val raw = (detail as? Map<*, *>)?.get("retry_after_seconds")
        return when (raw) {
            is Number -> raw.toLong().takeIf { it > 0 }
            is String -> raw.toLongOrNull()?.takeIf { it > 0 }
            else -> null
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
