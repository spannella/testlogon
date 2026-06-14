package com.testlogon.android.data.vod.download

import android.content.Context
import com.testlogon.android.core.data.download.DownloadDao
import com.testlogon.android.core.data.download.DownloadEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.File
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-195 — watermarked-download orchestration over [VodWatermarkDownloadApi] + [WatermarkArtifactClient].
 *
 * REUSES the AND-170 identity (captured from [AuthStateStore.userSub] at request time and stored
 * immutably with the artifact) and the AND-074/129 streaming download approach. Entitlement is gated
 * server-side (the endpoint 403s when not entitled -> [DownloadError.NOT_ENTITLED]); the client adds a
 * defensive identity-resolved precondition (FR-3). Server-side burn-in is the only strategy: the
 * streamed file IS the watermarked copy; [DownloadError.WATERMARK_FAILED] fails closed and leaves no
 * final artifact (FR-3).
 */
interface WatermarkDownloadRepository {

    /** Per-VOD download state, derived from the Room row. */
    fun observe(videoId: String): Flow<DownloadUiState>

    /** Completed downloads (the "Downloads" list). */
    fun completed(): Flow<List<DownloadedItem>>

    /**
     * Runs the begin -> (poll) -> stream -> persist pipeline. Captures identity at call time; fails
     * closed if identity is unresolved or the render never reaches a watermarked artifact. Safe to call
     * from a WorkManager worker (suspending, cooperative cancellation deletes the temp file).
     */
    suspend fun runDownload(videoId: String): ApiResult<DownloadedItem>

    suspend fun cancel(videoId: String)
    suspend fun delete(videoId: String)
}

@Singleton
class WatermarkDownloadRepositoryImpl @Inject constructor(
    @ApplicationContext private val context: Context,
    private val api: VodWatermarkDownloadApi,
    private val artifactClient: WatermarkArtifactClient,
    private val dao: DownloadDao,
    private val authState: AuthStateStore,
) : WatermarkDownloadRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun observe(videoId: String): Flow<DownloadUiState> =
        dao.observe(videoId).map { it?.toUiState() ?: DownloadUiState.Idle }

    override fun completed(): Flow<List<DownloadedItem>> =
        dao.completed().map { rows -> rows.mapNotNull { it.toItem() } }

    override suspend fun runDownload(videoId: String): ApiResult<DownloadedItem> = withContext(io) {
        val identityId = authState.userSub.value
        if (identityId.isNullOrBlank()) {
            return@withContext fail(videoId, identityId.orEmpty(), DownloadError.IDENTITY_UNRESOLVED)
        }

        upsertStatus(videoId, identityId, status = STATUS_QUEUED, percent = 0)

        // 1. Begin (idempotent within cache window; no request body).
        val begin = try {
            api.beginWatermarkDownload(videoId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            return@withContext fail(videoId, identityId, if (e.code() == HTTP_FORBIDDEN) DownloadError.NOT_ENTITLED else DownloadError.UNKNOWN)
        } catch (e: IOException) {
            return@withContext fail(videoId, identityId, DownloadError.NETWORK)
        }

        // 2. Resolve render (poll if processing); fail closed on unknown/failed.
        val resolved = try {
            resolveToStream(videoId, begin.status, begin.downloadUrl, begin.watermarkPayload)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            return@withContext fail(videoId, identityId, DownloadError.NETWORK)
        } ?: return@withContext fail(videoId, identityId, DownloadError.WATERMARK_FAILED)

        // 3. Stream the (server-burned-in) artifact to a temp file, then promote on success.
        upsertStatus(videoId, identityId, status = STATUS_DOWNLOADING, percent = 0)
        val temp = File(context.cacheDir, "dl-tmp/$videoId.part")
        val finalFile = File(context.filesDir, "downloads/$videoId.mp4")
        var lastPct = 0
        val streamResult = try {
            artifactClient.stream(resolved.downloadUrl, temp) { read, total ->
                // Track the latest whole-percent for the final Room snapshot (no per-chunk Room writes).
                lastPct = WatermarkDownloadLogic.percent(read, total)
            }
        } catch (e: CancellationException) {
            runCatching { temp.delete() }
            throw e
        } catch (e: IOException) {
            runCatching { temp.delete() }
            return@withContext fail(videoId, identityId, DownloadError.NETWORK)
        }

        if (!streamResult.success) {
            runCatching { temp.delete() }
            // 403/404/410 => the short-lived url expired (no expires_at field; detect by status code).
            val err = if (streamResult.httpStatus in EXPIRY_CODES) DownloadError.TOKEN_EXPIRED else DownloadError.NETWORK
            return@withContext fail(videoId, identityId, err)
        }

        // 4. Watermark stage (server-burned-in): verify the stream completed, promote temp -> final.
        upsertStatus(videoId, identityId, status = STATUS_WATERMARKING, percent = lastPct.coerceAtLeast(0))
        if (resolved.downloadUrl.isBlank() || streamResult.bytes <= 0L) {
            runCatching { temp.delete() }
            return@withContext fail(videoId, identityId, DownloadError.WATERMARK_FAILED)
        }
        finalFile.parentFile?.mkdirs()
        val promoted = runCatching {
            if (finalFile.exists()) finalFile.delete()
            temp.renameTo(finalFile) || temp.copyTo(finalFile, overwrite = true).let { temp.delete() }
        }.getOrDefault(false)
        if (!promoted) {
            runCatching { temp.delete() }
            return@withContext fail(videoId, identityId, DownloadError.STORAGE_FULL)
        }

        val now = System.currentTimeMillis()
        val entity = DownloadEntity(
            videoId = videoId,
            status = STATUS_COMPLETED,
            percent = 100,
            localUri = finalFile.toURI().toString(),
            sizeBytes = streamResult.bytes,
            watermarked = true,
            strategy = WatermarkStrategy.SERVER_BURNED_IN.name,
            identityId = identityId,
            watermarkPayload = resolved.watermarkPayload,
            error = null,
            completedAtEpochMs = now,
            updatedAtEpochMs = now,
        )
        dao.upsert(entity)
        ApiResult.Success(checkNotNull(entity.toItem()))
    }

    /** Polls until the render is ready (returns the stream resolution) or fails closed (null). */
    private suspend fun resolveToStream(
        videoId: String,
        beginStatus: String,
        beginUrl: String?,
        beginPayload: String?,
    ): RenderResolution.Stream? {
        var resolution = WatermarkDownloadLogic.resolveRender(beginStatus, beginUrl, beginPayload)
        var restarts = 0
        var polls = 0
        while (true) {
            when (val r = resolution) {
                is RenderResolution.Stream -> return r
                RenderResolution.Fail -> return null
                RenderResolution.Restart -> {
                    if (restarts++ >= MAX_RESTARTS) return null
                    val begin = api.beginWatermarkDownload(videoId)
                    resolution = WatermarkDownloadLogic.resolveRender(begin.status, begin.downloadUrl, begin.watermarkPayload)
                }
                RenderResolution.Poll -> {
                    if (polls++ >= MAX_POLLS) return null // deadline -> fail closed
                    delay(POLL_INTERVAL_MS)
                    val s = api.pollWatermarkStatus(videoId)
                    resolution = WatermarkDownloadLogic.resolveRender(s.status, s.downloadUrl, beginPayload)
                }
            }
        }
    }

    override suspend fun cancel(videoId: String) = withContext(io) {
        runCatching { File(context.cacheDir, "dl-tmp/$videoId.part").delete() }
        val existing = dao.get(videoId)
        if (existing != null && existing.status != STATUS_COMPLETED) {
            dao.upsert(existing.copy(status = STATUS_CANCELLED, updatedAtEpochMs = System.currentTimeMillis()))
        }
    }

    override suspend fun delete(videoId: String) = withContext(io) {
        runCatching { File(context.filesDir, "downloads/$videoId.mp4").delete() }
        dao.delete(videoId)
    }

    private suspend fun upsertStatus(videoId: String, identityId: String, status: String, percent: Int) {
        val existing = dao.get(videoId)
        dao.upsert(
            (existing ?: DownloadEntity(videoId = videoId, status = status, identityId = identityId)).copy(
                status = status,
                percent = percent,
                identityId = identityId,
                updatedAtEpochMs = System.currentTimeMillis(),
            ),
        )
    }

    private suspend fun fail(videoId: String, identityId: String, error: DownloadError): ApiResult<DownloadedItem> {
        val existing = dao.get(videoId)
        dao.upsert(
            (existing ?: DownloadEntity(videoId = videoId, status = STATUS_FAILED, identityId = identityId)).copy(
                status = STATUS_FAILED,
                error = error.name,
                updatedAtEpochMs = System.currentTimeMillis(),
            ),
        )
        return ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 0, message = error.name, code = error.name))
    }

    private companion object {
        const val HTTP_FORBIDDEN = 403
        const val POLL_INTERVAL_MS = 2_000L
        const val MAX_POLLS = 30
        const val MAX_RESTARTS = 1
        val EXPIRY_CODES = setOf(403, 404, 410)

        const val STATUS_QUEUED = "QUEUED"
        const val STATUS_DOWNLOADING = "DOWNLOADING"
        const val STATUS_WATERMARKING = "WATERMARKING"
        const val STATUS_COMPLETED = "COMPLETED"
        const val STATUS_FAILED = "FAILED"
        const val STATUS_CANCELLED = "CANCELLED"
    }
}

// ---- entity -> domain ----

private fun DownloadEntity.toUiState(): DownloadUiState = when (status) {
    "QUEUED" -> DownloadUiState.Queued
    "DOWNLOADING" -> DownloadUiState.Downloading(percent)
    "WATERMARKING" -> DownloadUiState.Watermarking
    "COMPLETED" -> toItem()?.let { DownloadUiState.Completed(it) } ?: DownloadUiState.Idle
    "CANCELLED" -> DownloadUiState.Cancelled
    "FAILED" -> DownloadUiState.Failed(
        runCatching { DownloadError.valueOf(error ?: "UNKNOWN") }.getOrDefault(DownloadError.UNKNOWN),
    )
    else -> DownloadUiState.Idle
}

private fun DownloadEntity.toItem(): DownloadedItem? {
    val uri = localUri ?: return null
    return DownloadedItem(
        videoId = videoId,
        localUri = uri,
        sizeBytes = sizeBytes,
        watermarked = watermarked,
        strategy = runCatching { WatermarkStrategy.valueOf(strategy) }.getOrDefault(WatermarkStrategy.SERVER_BURNED_IN),
        identityId = identityId,
        watermarkPayload = watermarkPayload,
        completedAtEpochMs = completedAtEpochMs,
    )
}
