package com.testlogon.android.feature.call.recording

import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.data.call.PendingRecordingDao
import com.testlogon.android.core.data.call.PendingRecordingEntity
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.recording.CaptureResult
import com.testlogon.android.data.call.recording.RecordingCapturer
import com.testlogon.android.data.call.recording.RecordingRepository
import com.testlogon.android.data.upload.StorageUploadClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.MediaType.Companion.toMediaType
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-302 — orchestrates the call-recording consent + upload sub-state on top of the active 1:1 call.
 *
 * Drives the REAL parts end-to-end: the consent protocol (request/consent/decline via [RecordingRepository]),
 * the [RecordingStateMachine] consent GATE, the durable Room queue ([PendingRecordingDao]), and the upload
 * (presign -> PUT -> complete). Capture itself is FLAGGED: on Granted it calls [RecordingCapturer.start]
 * which (StubRecordingCapturer) returns [CaptureResult.NotConfigured] -> the controller surfaces
 * "recording unavailable (media not configured)" and returns to Idle WITHOUT a fake Recording/upload.
 *
 * UPLOAD reuses the AND-129 transport: the typed presign/complete are this feature's own REST, but the
 * cookieless storage PUT is delegated to [StorageUploadClient.put] (no new HTTP client). A File-backed
 * RequestBody is used (recordings are local Files, not content Uris), so [com.testlogon.android.data.upload.ProgressRequestBody]
 * — which is Uri-based — is intentionally not reused for the PUT body; progress is derived from the typed
 * pipeline phases. Because capture is FLAGGED, the upload path runs only in tests with a fake capturer that
 * returns a temp file.
 *
 * Recording consent/stop events (RecordingConsentRequested, recording_stopped) are designed to ride the
 * FLAGGED call signaling seam ([com.testlogon.android.data.webrtc.SignalingTransport]); since that seam
 * yields no events, [onRemoteConsentRequest]/[onCallEnded] are invoked by the call orchestrator instead and
 * the state machine + REST consent are the real, testable parts.
 */
@Singleton
class RecordingController @Inject constructor(
    private val repository: RecordingRepository,
    private val capturer: RecordingCapturer,
    private val pendingDao: PendingRecordingDao,
    private val storageClient: StorageUploadClient,
    private val clock: Clock,
    private val scope: CoroutineScope,
) {

    private val _state = MutableStateFlow(RecordingUiState())
    val state: StateFlow<RecordingUiState> = _state.asStateFlow()

    private var captureFile: File? = null
    private var workJob: Job? = null

    /** Requester taps Record: POST .../request, then await consent. Caller has already ensured RECORD_AUDIO. */
    fun request(callId: String) {
        if (_state.value.phase != RecordingPhase.Idle) return
        workJob = scope.launch {
            when (val res = repository.request(callId)) {
                is ApiResult.Success ->
                    _state.update { RecordingStateMachine.onRequest(it, res.data.recordingId) }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _state.update { RecordingStateMachine.onError(it, ERROR_REQUEST) }
            }
        }
    }

    /** Callee accepts: POST .../consent; on a granted status (gate open) attempt the FLAGGED capture. */
    fun consent(callId: String) {
        workJob = scope.launch {
            when (val res = repository.consent(callId)) {
                is ApiResult.Success -> {
                    val consent = res.data
                    if (consent.isGranted) {
                        _state.update { RecordingStateMachine.onConsentGranted(it, consent.recordingId) }
                        attemptCapture(callId)
                    } else {
                        // Server did not actually grant (defensive; do NOT depend on specific codes).
                        _state.update { RecordingStateMachine.onError(it, ERROR_CONSENT) }
                    }
                }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _state.update { RecordingStateMachine.onError(it, ERROR_CONSENT) }
            }
        }
    }

    /** Either side declines: POST .../decline and settle the sub-state. */
    fun decline(callId: String) {
        workJob = scope.launch {
            repository.decline(callId)
            _state.update { RecordingStateMachine.onDeclined(it) }
        }
    }

    /** A remote consent request arrived (rides the FLAGGED signaling seam; invoked by the orchestrator). */
    fun onRemoteConsentRequest(requesterName: String?) {
        _state.update { RecordingStateMachine.onRemoteRequest(it, requesterName) }
    }

    /**
     * The requester started capture once consent was granted. GATED by [RecordingStateMachine.canStartCapture]:
     * capture is attempted ONLY from Granted. The FLAGGED capturer returns NotConfigured -> mediaUnavailable.
     */
    private suspend fun attemptCapture(callId: String) {
        if (!RecordingStateMachine.canStartCapture(_state.value.phase)) return
        val output = File.createTempFile("rec_${callId}_", ".mp4")
        when (val result = capturer.start(output)) {
            is CaptureResult.Started -> {
                captureFile = result.file
                _state.update { RecordingStateMachine.onCaptureStarted(it) }
            }
            is CaptureResult.Stopped -> {
                // Not expected from start(); treat as immediately captured.
                captureFile = result.file
                _state.update { RecordingStateMachine.onCaptureStarted(it) }
            }
            CaptureResult.NotConfigured -> {
                // FLAGGED: native media engine not wired. Never a real file; surface "unavailable", stay Idle.
                output.delete()
                captureFile = null
                capturer.discard()
                _state.update { RecordingStateMachine.onCaptureUnavailable(it) }
            }
        }
    }

    /**
     * Call ended (or user stopped): if an active capture exists, stop it and queue the artifact for upload,
     * then drive presign -> PUT -> complete. With the FLAGGED capturer there is no active capture, so this is
     * a no-op (PendingUpload is never entered without a file).
     */
    fun onCallEnded(callId: String) {
        if (_state.value.phase != RecordingPhase.Recording) {
            capturer.discard()
            return
        }
        workJob = scope.launch {
            val stopped = capturer.stop()
            val file = (stopped as? CaptureResult.Stopped)?.file ?: captureFile
            val duration = (stopped as? CaptureResult.Stopped)?.durationSeconds ?: 0f
            if (file == null || !file.exists()) {
                // No artifact: do not fabricate an upload.
                _state.update { RecordingStateMachine.onCaptureUnavailable(it) }
                return@launch
            }
            _state.update { RecordingStateMachine.onStop(it) }
            enqueueAndUpload(callId, file, duration)
        }
    }

    /**
     * Retry a FAILED upload from the durable queue: re-reads the persisted pending row for the current
     * recording and re-drives presign -> PUT -> complete. No-op if there is no recoverable artifact on disk
     * (e.g. capture was FLAGGED/unavailable, so nothing was ever queued).
     */
    fun retry(callId: String) {
        val recordingId = _state.value.recordingId ?: return
        workJob = scope.launch {
            val pending = pendingDao.get(recordingId) ?: return@launch
            val file = File(pending.filePath)
            if (!file.exists()) {
                _state.update { RecordingStateMachine.onError(it, ERROR_UPLOAD) }
                return@launch
            }
            captureFile = file
            _state.update { RecordingStateMachine.onStop(it.copy(phase = RecordingPhase.Recording)) }
            enqueueAndUpload(callId, file, pending.durationMs / 1_000f)
        }
    }

    /** User cancels an in-flight/queued upload. */
    fun cancel() {
        workJob?.cancel()
        scope.launch {
            _state.value.recordingId?.let { pendingDao.delete(it) }
            captureFile?.delete()
            captureFile = null
            _state.update { RecordingStateMachine.onCancel(it) }
        }
    }

    /** Resets the sub-state to Idle (e.g. after Uploaded/Cancelled/Failed is observed by the screen). */
    fun reset() {
        _state.value = RecordingStateMachine.reset()
    }

    private suspend fun enqueueAndUpload(callId: String, file: File, durationSeconds: Float) {
        val recordingId = _state.value.recordingId ?: return
        // Durable queue: persist BEFORE the network so an upload survives process death.
        pendingDao.upsert(
            PendingRecordingEntity(
                recordingId = recordingId,
                callId = callId,
                filePath = file.absolutePath,
                sizeBytes = file.length(),
                durationMs = (durationSeconds * 1_000f).toLong(),
                phase = RecordingPhase.PendingUpload.name,
                attempts = 0,
                createdAtEpochMs = clock.now(),
            ),
        )

        // ---- PRESIGN (this feature's typed REST) ----
        val presign = when (
            val res = repository.presign(callId, CONTENT_TYPE, file.length())
        ) {
            is ApiResult.Success -> res.data
            is ApiResult.Failure, is ApiResult.NetworkError -> {
                _state.update { RecordingStateMachine.onError(it, ERROR_UPLOAD) }
                return
            }
        }

        _state.update { RecordingStateMachine.onUploadProgress(it, 0) }

        // ---- STORAGE PUT (reused AND-129 cookieless transport) ----
        val body = file.asRequestBody(CONTENT_TYPE.toMediaType())
        val put = try {
            storageClient.put(presign.uploadUrl, CONTENT_TYPE, body)
        } catch (e: java.io.IOException) {
            _state.update { RecordingStateMachine.onError(it, ERROR_UPLOAD) }
            return
        }
        if (!put.success) {
            _state.update { RecordingStateMachine.onError(it, ERROR_UPLOAD) }
            return
        }
        _state.update { RecordingStateMachine.onUploadProgress(it, 100) }

        // ---- COMPLETE (this feature's typed REST) ----
        when (repository.complete(callId, presign.recordingId, durationSeconds)) {
            is ApiResult.Success -> {
                pendingDao.delete(recordingId)
                file.delete()
                captureFile = null
                _state.update { RecordingStateMachine.onUploaded(it) }
            }
            is ApiResult.Failure, is ApiResult.NetworkError ->
                _state.update { RecordingStateMachine.onError(it, ERROR_UPLOAD) }
        }
    }

    private companion object {
        // MediaRecorder MPEG_4 -> the presign content_type allow-list ^video/(webm|mp4)$.
        const val CONTENT_TYPE = "video/mp4"
        const val ERROR_REQUEST = "recording_request_failed"
        const val ERROR_CONSENT = "recording_consent_failed"
        const val ERROR_UPLOAD = "recording_upload_failed"
    }
}
