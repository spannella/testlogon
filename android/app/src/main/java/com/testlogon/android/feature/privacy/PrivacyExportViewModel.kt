package com.testlogon.android.feature.privacy

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.privacy.ExportCategories
import com.testlogon.android.data.privacy.ExportRequest
import com.testlogon.android.data.privacy.ExportStatus
import com.testlogon.android.data.privacy.PrivacyExportRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/** AND-385 - a UI row for one export request (formatting deferred to the composable for locale/RTL). */
data class ExportRequestUi(
    val id: String,
    val status: ExportStatus,
    val requestedAtEpochMs: Long,
    val expiresAtEpochMs: Long?,
    val sizeBytes: Long?,
    val downloadable: Boolean,
    val retryable: Boolean,
    val expired: Boolean,
)

/** AND-385 - a transient, snackbar-surfaced error with a stable code for telemetry (never PII). */
data class ExportUiError(val message: String, val code: String? = null)

/**
 * AND-385 - the screen state (FR-1..FR-6). [canRequest] is false while ANY tracked request is non-terminal,
 * to prevent duplicate-spam (FR-1). [isOffline] keeps cached rows visible with an offline banner (FR-6).
 */
data class PrivacyExportUiState(
    val requests: List<ExportRequestUi> = emptyList(),
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val requestInFlight: Boolean = false,
    val isOffline: Boolean = false,
    val downloading: Set<String> = emptySet(),
    val lastSavedName: String? = null,
    val error: ExportUiError? = null,
    val canRequest: Boolean = true,
)

/** Internal mutable signals combined with the cache flow to build [PrivacyExportUiState]. */
private data class ExportSignals(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val requestInFlight: Boolean = false,
    val isOffline: Boolean = false,
    val downloading: Set<String> = emptySet(),
    val lastSavedName: String? = null,
    val error: ExportUiError? = null,
)

/**
 * AND-385 - presentation logic for the Privacy & Data Export screen.
 *
 * The cache flow ([PrivacyExportRepository.observeRequests]) is the source of truth; it is combined with
 * internal [ExportSignals] and exposed via stateIn. An initial [refresh] runs from [load] (called by the
 * screen on first resume - NEVER an unbounded poll in init). While any tracked request is non-terminal a
 * bounded foreground poll (<= [MAX_POLLS] iterations, [POLL_INTERVAL_MS] apart, idempotent GET only) refreshes
 * status; it stops on a terminal state or when the screen is not resumed ([stopPolling]). The create POST is
 * non-idempotent and never auto-retried (a re-press while in-flight is a no-op). The clock seam is read INSIDE
 * the coroutine.
 */
@HiltViewModel
class PrivacyExportViewModel @Inject constructor(
    private val repository: PrivacyExportRepository,
) : ViewModel() {

    /** Settable seams (Hilt cannot inject a bare dispatcher / clock). */
    var io: CoroutineDispatcher = Dispatchers.IO
    var now: () -> Long = { System.currentTimeMillis() }

    private val signals = MutableStateFlow(ExportSignals())

    private var pollJob: Job? = null
    private var requestJob: Job? = null
    private var loaded = false

    val uiState: StateFlow<PrivacyExportUiState> =
        combine(repository.observeRequests(), signals) { requests, s ->
            val nowMs = now()
            val rows = requests.map { it.toUi(nowMs) }
            PrivacyExportUiState(
                requests = rows,
                isLoading = s.isLoading && rows.isEmpty(),
                isRefreshing = s.isRefreshing,
                requestInFlight = s.requestInFlight,
                isOffline = s.isOffline,
                downloading = s.downloading,
                lastSavedName = s.lastSavedName,
                error = s.error,
                canRequest = !s.requestInFlight && requests.none { !it.isTerminal },
            )
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS),
            initialValue = PrivacyExportUiState(isLoading = true),
        )

    /** First-load entry (called by the screen on resume). Idempotent: only the first call fetches. */
    fun load() {
        if (loaded) return
        loaded = true
        refresh(initial = true)
    }

    /** Pull-to-refresh / retry. Always runs the idempotent list GET; refreshes the offline flag. */
    fun onRefresh() = refresh(initial = false)

    private fun refresh(initial: Boolean) {
        viewModelScope.launch {
            signals.update {
                it.copy(isLoading = initial, isRefreshing = !initial, error = null)
            }
            when (val r = repository.refresh()) {
                is ApiResult.Success ->
                    signals.update { it.copy(isLoading = false, isRefreshing = false, isOffline = false) }
                is ApiResult.NetworkError ->
                    signals.update {
                        it.copy(isLoading = false, isRefreshing = false, isOffline = true)
                    }
                is ApiResult.Failure ->
                    signals.update {
                        it.copy(
                            isLoading = false,
                            isRefreshing = false,
                            isOffline = false,
                            error = ExportUiError(REFRESH_FAILED, r.error.code),
                        )
                    }
            }
            maybeStartPolling()
        }
    }

    /** Non-idempotent create with ALL categories selected (the default selection). */
    fun onRequestExport(categories: Map<String, Boolean> = ExportCategories.allSelected()) {
        if (requestJob?.isActive == true) return
        if (!uiState.value.canRequest) return
        requestJob = viewModelScope.launch {
            signals.update { it.copy(requestInFlight = true, error = null) }
            when (val r = repository.requestExport(categories)) {
                is ApiResult.Success ->
                    signals.update { it.copy(requestInFlight = false, isOffline = false) }
                is ApiResult.NetworkError ->
                    signals.update {
                        it.copy(requestInFlight = false, error = ExportUiError(NETWORK_MESSAGE))
                    }
                is ApiResult.Failure ->
                    signals.update {
                        it.copy(
                            requestInFlight = false,
                            error = ExportUiError(requestErrorMessage(r.error.status), r.error.code),
                        )
                    }
            }
            maybeStartPolling()
        }
    }

    /** Retry of a prior failed request == a fresh create (FR / AC). */
    fun onRetry(@Suppress("UNUSED_PARAMETER") id: String) = onRequestExport()

    /** Streams a completed export to Downloads; tracks the in-flight id in [PrivacyExportUiState.downloading]. */
    fun onDownload(id: String) {
        if (id in signals.value.downloading) return
        viewModelScope.launch {
            signals.update { it.copy(downloading = it.downloading + id, error = null) }
            val result = repository.download(id)
            signals.update { s ->
                when (result) {
                    is ApiResult.Success -> s.copy(
                        downloading = s.downloading - id,
                        lastSavedName = id,
                    )
                    is ApiResult.NetworkError -> s.copy(
                        downloading = s.downloading - id,
                        error = ExportUiError(DOWNLOAD_FAILED),
                    )
                    is ApiResult.Failure -> s.copy(
                        downloading = s.downloading - id,
                        error = ExportUiError(DOWNLOAD_FAILED, result.error.code),
                    )
                }
            }
        }
    }

    /** Clears the transient snackbar error after it is shown. */
    fun onErrorShown() = signals.update { it.copy(error = null) }

    /** Clears the saved-name signal after the "saved" snackbar is shown. */
    fun onSavedShown() = signals.update { it.copy(lastSavedName = null) }

    /** Lifecycle: pause polling when the screen is not resumed. */
    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    /**
     * Starts the bounded poll loop iff some tracked request is non-terminal and none is already running. The
     * pending decision + the poll target are read from the repository cache snapshot ([observeRequests] is the
     * source of truth) rather than the lagging [uiState] StateFlow, so the loop is correct as soon as the cache
     * updates (and is test-deterministic).
     */
    private suspend fun maybeStartPolling() {
        if (pollJob?.isActive == true) return
        val pending = repository.observeRequests().first().any { !it.isTerminal }
        if (!pending) return
        pollJob = viewModelScope.launch {
            var iterations = 0
            while (iterations < MAX_POLLS) {
                withContext(io) { delay(POLL_INTERVAL_MS) }
                iterations++
                // Poll the oldest non-terminal request's single-status GET (idempotent).
                val snapshot = repository.observeRequests().first()
                val target = snapshot.firstOrNull { !it.isTerminal } ?: break
                repository.refreshOne(target.id)
                if (repository.observeRequests().first().none { !it.isTerminal }) break
            }
            pollJob = null
        }
    }

    private fun ExportRequest.toUi(nowMs: Long): ExportRequestUi = ExportRequestUi(
        id = id,
        status = status,
        requestedAtEpochMs = createdAtEpochMs,
        expiresAtEpochMs = downloadExpiresAtEpochMs,
        sizeBytes = sizeBytes,
        downloadable = isDownloadable(nowMs),
        retryable = isRetryable,
        expired = isExpired(nowMs),
    )

    private fun requestErrorMessage(status: Int): String = when (status) {
        401, 403 -> AUTH_MESSAGE
        429 -> RATE_LIMITED_MESSAGE
        in 500..599 -> SERVER_MESSAGE
        else -> REQUEST_FAILED
    }

    companion object {
        const val POLL_INTERVAL_MS = 10_000L
        const val MAX_POLLS = 5
        const val STOP_TIMEOUT_MS = 5_000L

        const val REQUEST_FAILED = "Couldn't request your export. Please try again."
        const val REFRESH_FAILED = "Couldn't refresh your export requests. Please try again."
        const val DOWNLOAD_FAILED = "Couldn't download the export. Please try again."
        const val NETWORK_MESSAGE =
            "Couldn't reach TestLogon. Check your connection and try again."
        const val AUTH_MESSAGE = "Your session expired. Sign in again to request an export."
        const val RATE_LIMITED_MESSAGE = "Too many requests - wait a moment and try again."
        const val SERVER_MESSAGE = "Something went wrong requesting your export. Please try again."
    }
}
