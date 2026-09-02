package com.testlogon.android.feature.files.mounts.data

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileMountCreateRequest
import com.testlogon.android.core.model.files.FileMountDto
import com.testlogon.android.core.model.files.FileMountUpdateRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.files.FileMountsApi
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
 * FM-MOUNTS - data layer for the file-manager S3 mount CRUD surface, over the [FileMountsApi].
 *
 * DEGRADE-ON-404 (and on the backend feature-gate 403): the mount surface is feature-flagged on the
 * backend (`filemgr_s3_mounts_enabled`) and may be absent in a given environment. [listMounts] therefore
 * folds a 404 (route absent) or 403 (feature disabled) into an EMPTY [MountList] with
 * [MountList.available] = false, so the UI shows a graceful "not available here" state instead of an
 * error. Genuine failures (422, 5xx, network) still surface as Failure / NetworkError. The mutating
 * verbs surface their errors normally (the UI only offers them once list reports the surface available).
 */
interface MountsRepository {
    suspend fun listMounts(): ApiResult<MountList>
    suspend fun createMount(body: FileMountCreateRequest): ApiResult<FileMount>
    suspend fun updateMount(mountId: String, body: FileMountUpdateRequest): ApiResult<FileMount>
    suspend fun deleteMount(mountId: String): ApiResult<Boolean>
    suspend fun validateMount(mountId: String): ApiResult<MountValidationResult>
}

/** A mount listing plus whether the surface is available in this environment (degrade-on-404/403). */
data class MountList(
    val mounts: List<FileMount>,
    val available: Boolean,
)

/** The result of a server-side mount connectivity check (POST .../validate). */
data class MountValidationResult(
    val ok: Boolean,
    val mountId: String?,
    val status: String?,
)

@Singleton
class MountsRepositoryImpl @Inject constructor(
    private val api: FileMountsApi,
    private val errorParser: ApiErrorParser,
) : MountsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listMounts(): ApiResult<MountList> = withContext(io) {
        try {
            val items = api.listMounts().items.map(FileMountDto::toDomain)
            ApiResult.Success(MountList(mounts = items, available = true))
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            val error = errorParser.from(e)
            if (error.status == HTTP_NOT_FOUND || error.status == HTTP_FORBIDDEN) {
                // Surface not enabled in this environment -> degrade to an empty, unavailable list.
                ApiResult.Success(MountList(mounts = emptyList(), available = false))
            } else {
                ApiResult.Failure(error)
            }
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    override suspend fun createMount(body: FileMountCreateRequest): ApiResult<FileMount> =
        withContext(io) { call { api.createMount(body).toDomain() } }

    override suspend fun updateMount(
        mountId: String,
        body: FileMountUpdateRequest,
    ): ApiResult<FileMount> = withContext(io) { call { api.updateMount(mountId, body).toDomain() } }

    override suspend fun deleteMount(mountId: String): ApiResult<Boolean> =
        withContext(io) { call { api.deleteMount(mountId).deleted } }

    override suspend fun validateMount(mountId: String): ApiResult<MountValidationResult> =
        withContext(io) {
            call {
                val dto = api.validateMount(mountId)
                MountValidationResult(ok = dto.ok, mountId = dto.mount_id, status = dto.status)
            }
        }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val HTTP_NOT_FOUND = 404
        const val HTTP_FORBIDDEN = 403
    }
}

/** Domain model for a single S3 file mount (the fields the Mounts UI renders). */
data class FileMount(
    val id: String,
    val provider: String,
    val mountPath: String,
    val bucket: String,
    val prefix: String?,
    val mode: String,
    val authRef: String,
    val status: String,
    val lastError: String?,
)

/** Maps a wire [FileMountDto] to its domain [FileMount]. */
fun FileMountDto.toDomain(): FileMount = FileMount(
    id = id,
    provider = provider,
    mountPath = mount_path,
    bucket = bucket,
    prefix = prefix,
    mode = mode,
    authRef = auth_ref,
    status = status,
    lastError = last_error,
)
