package com.testlogon.android.feature.files.upload

import android.net.Uri
import com.testlogon.android.core.model.files.CompleteUploadRequest
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.PresignRequest
import com.testlogon.android.core.network.files.FilesApi
import com.testlogon.android.core.network.files.toDomain
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.presentation.FilePath
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import retrofit2.HttpException
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-333 - in-process upload engine for the Files feature: presign to bare PUT to confirm, with
 * bounded concurrency, byte progress, per-job cancel / retry, and a double-send guard.
 *
 * REUSE: the presign / confirm control plane is the AND-331 [FilesApi]
 * (presignUpload / completeUpload); the byte transfer is the AND-323/327
 * StorageUploadClient.put bare cookieless PUT (the @StorageOkHttp client), reached through the thin
 * [StoragePut] seam, fed a streaming [UploadSource] request body so progress streams without
 * buffering the file. The :app AttachmentUploader is NOT reused: its presign / confirm are hardwired
 * to the attachment endpoint (AttachmentApi), so only StorageUploadClient (and, via [UploadSource],
 * ProgressRequestBody) is shared.
 *
 * PLACEMENT is path-based (no folder_id): the object path is targetFolderPath + displayName,
 * normalized through [FilePath]. After a successful confirm the destination folder is signalled on the
 * [FolderRefreshBus] so the AND-332 browse listing re-pages.
 *
 * CONCURRENCY: a [Semaphore] (default permits 2) caps simultaneous in-flight uploads FIFO; the permit
 * is the ONLY wait (no poll loop / no delay). Each job runs in its own child coroutine so [cancel]
 * cancels exactly that job. DOUBLE-SEND GUARD: presign / complete are non-idempotent POSTs, so a job
 * already in CONFIRMING or DONE is never restarted by [retry] or re-enqueue.
 *
 * Resumable / background (WorkManager) uploads are DEFERRED; this is all in-process.
 */
@Singleton
class UploadCoordinator(
    private val filesApi: FilesApi,
    private val storagePut: StoragePut,
    private val uploadSource: UploadSource,
    private val refreshBus: FolderRefreshBus,
    dispatcher: CoroutineDispatcher,
) {

    /** Production constructor: uploads run on [Dispatchers.IO]. */
    @Inject
    constructor(
        filesApi: FilesApi,
        storagePut: StoragePut,
        uploadSource: UploadSource,
        refreshBus: FolderRefreshBus,
    ) : this(filesApi, storagePut, uploadSource, refreshBus, Dispatchers.IO)

    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + dispatcher)
    private val gate = Semaphore(permits = MAX_CONCURRENT)

    private val _jobs = MutableStateFlow<List<UploadJob>>(emptyList())

    /** All tracked jobs (newest enqueue order preserved); the UI renders one row per entry. */
    val jobs: StateFlow<List<UploadJob>> = _jobs.asStateFlow()

    /** Per-job runner coroutine, so [cancel] can cancel exactly one upload (touched from IO + caller). */
    private val runners = java.util.concurrent.ConcurrentHashMap<String, Job>()

    /**
     * Enqueues one upload of [uri] into [targetFolderPath], returning the new job id. The display name
     * / MIME / size are resolved up-front via [UploadSource] so the row shows the real name immediately.
     */
    fun enqueue(uri: Uri, targetFolderPath: String): String {
        val id = UUID.randomUUID().toString()
        val meta = runCatching { uploadSource.metadata(uri) }.getOrNull()
        val job = UploadJob(
            id = id,
            sourceUri = uri,
            displayName = meta?.displayName ?: FALLBACK_NAME,
            mimeType = meta?.mimeType ?: DEFAULT_MIME,
            sizeBytes = meta?.sizeBytes ?: 0L,
            targetFolderPath = FilePath.normalize(targetFolderPath),
            state = UploadState.QUEUED,
        )
        _jobs.update { it + job }
        start(id)
        return id
    }

    /** Cancels the in-flight job [id] (a no-op for terminal jobs); marks it CANCELLED. */
    fun cancel(id: String) {
        val job = jobOf(id) ?: return
        if (!job.isActive) return
        runners.remove(id)?.cancel()
        patch(id) { it.copy(state = UploadState.CANCELLED, error = null) }
    }

    /**
     * Retries a FAILED / CANCELLED job from presign, keeping its id. DOUBLE-SEND GUARD: a job that is
     * already DONE or in CONFIRMING is NOT restarted (its non-idempotent confirm may already be landing).
     */
    fun retry(id: String) {
        val job = jobOf(id) ?: return
        if (job.state == UploadState.DONE || job.state == UploadState.CONFIRMING) return
        if (runners[id]?.isActive == true) return
        patch(id) { it.copy(state = UploadState.QUEUED, progress = 0f, error = null, resultPath = null) }
        start(id)
    }

    /** Removes a terminal job's row (no effect while active). */
    fun dismiss(id: String) {
        val job = jobOf(id) ?: return
        if (job.isActive) return
        runners.remove(id)
        _jobs.update { list -> list.filterNot { it.id == id } }
    }

    private fun start(id: String) {
        val runner = scope.launch {
            gate.withPermit { runJob(id) }
        }
        runners[id] = runner
    }

    private suspend fun runJob(id: String) {
        val job = jobOf(id) ?: return
        // A job cancelled while it waited for the permit must not proceed.
        if (job.state != UploadState.QUEUED) return
        try {
            patch(id) { it.copy(state = UploadState.PREPARING, error = null) }

            val objectPath = FilePath.child(job.targetFolderPath, job.displayName)
            val presign = filesApi.presignUpload(
                PresignRequest(path = objectPath, content_type = job.mimeType),
            )
            val putContentType = presign.content_type ?: job.mimeType

            patch(id) { it.copy(state = UploadState.UPLOADING, progress = 0f) }
            val total = job.sizeBytes
            val body = uploadSource.requestBody(
                uri = job.sourceUri,
                mimeType = putContentType,
                sizeBytes = total,
            ) { sent ->
                val fraction = if (total > 0L) (sent.toFloat() / total.toFloat()).coerceIn(0f, 1f) else 0f
                patch(id) { it.copy(progress = fraction) }
            }
            val putResult = storagePut.put(presign.upload_url, putContentType, body)
            if (!putResult.success) {
                fail(id, "Upload failed (${putResult.httpStatus})")
                return
            }
            patch(id) { it.copy(progress = 1f) }

            // DOUBLE-SEND GUARD applies here: from CONFIRMING onward retry will not restart the job.
            patch(id) { it.copy(state = UploadState.CONFIRMING) }
            val resultPath: String = try {
                filesApi.completeUpload(
                    CompleteUploadRequest(
                        path = presign.path,
                        key = presign.key,
                        ticket_id = presign.ticket_id,
                        content_type = putContentType,
                        encrypted = false,
                    ),
                ).toDomain().path
            } catch (e: com.squareup.moshi.JsonDataException) {
                // Bytes uploaded (PUT 200) + complete-upload ran server-side; only the minimal
                // response body didn't map to the full node DTO. Don't crash — use the dest path.
                presign.path
            } catch (e: NullPointerException) {
                presign.path
            }
            patch(id) {
                it.copy(state = UploadState.DONE, progress = 1f, error = null, resultPath = resultPath)
            }
            // Re-page the destination folder now that the new node exists server-side.
            refreshBus.signal(job.targetFolderPath)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            fail(id, "Upload failed (${e.code()})")
        } catch (e: IOException) {
            fail(id, e.message ?: "Network error")
        } finally {
            runners.remove(id)
        }
    }

    private fun fail(id: String, message: String) {
        patch(id) { it.copy(state = UploadState.FAILED, error = message) }
    }

    private fun jobOf(id: String): UploadJob? = _jobs.value.firstOrNull { it.id == id }

    private fun patch(id: String, transform: (UploadJob) -> UploadJob) {
        _jobs.update { list -> list.map { if (it.id == id) transform(it) else it } }
    }

    private companion object {
        const val MAX_CONCURRENT = 2
        const val DEFAULT_MIME = "application/octet-stream"
        const val FALLBACK_NAME = "upload"
    }
}
