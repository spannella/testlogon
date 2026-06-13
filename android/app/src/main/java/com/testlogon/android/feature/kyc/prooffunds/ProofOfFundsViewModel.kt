package com.testlogon.android.feature.kyc.prooffunds

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.capture.CaptureError
import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.prooffunds.data.ProofOfFundsRepository
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSource
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSummary
import com.testlogon.android.feature.kyc.prooffunds.model.ProofOfFunds
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

/**
 * AND-327 - presentation logic for the KYC proof-of-funds flow.
 *
 * REAL REST (NO vendor / ML / CameraX SDK, NO flagged seam):
 *   - LOAD: [load] reads the summary + submissions ONCE (single, non-looping). If a submission exists the
 *     VM lands on [ProofOfFundsUiState.Status] (latest + history); otherwise on a fresh
 *     [ProofOfFundsUiState.Form].
 *   - DOCUMENT: the SCREEN owns the dependency-free acquisition launchers (TakePicture via a FileProvider
 *     Uri / GetContent for "choose a file"), hands the VM a [File] ([onDocumentAcquired]); the VM processes
 *     it OFF-MAIN via AND-321's [CaptureImageProcessor] (REUSE) then uploads it through the repo's
 *     presign->PUT pipeline (REUSE of AND-129) and records the returned S3 key.
 *   - SUBMIT: [submit] sends source_category + declared_amount_cents + currency + document_s3_key + note.
 *     CLIENT UX gate: a document + a source + a valid amount are required before Submit enables (even though
 *     the wire treats every field as optional). On success the VM lands on Status.
 *
 * NO POLL LOOP: [uiState] is a plain (synchronous) MutableStateFlow.
 *
 * DOUBLE-SEND GUARD: the submit POST and the document upload are NON-IDEMPOTENT. A single in-flight [work]
 * Job gates BOTH — a submit/upload is a no-op while one is already running — so a double tap never fires a
 * second submission or a second upload.
 */
@HiltViewModel
class ProofOfFundsViewModel @Inject constructor(
    private val repository: ProofOfFundsRepository,
    private val processor: CaptureImageProcessor,
    @Suppress("unused") private val savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<ProofOfFundsUiState>(ProofOfFundsUiState.Loading)
    val uiState: StateFlow<ProofOfFundsUiState> = _uiState.asStateFlow()

    /** Single in-flight guard (double-send guard for the non-idempotent submit + document upload). */
    private var work: Job? = null

    init {
        load(forceRefresh = false)
    }

    /**
     * Loads the summary + submissions ONCE. Lands on [ProofOfFundsUiState.Status] when a submission exists,
     * else on a fresh [ProofOfFundsUiState.Form]. [forceRefresh] keeps the existing Status surface visible
     * (with [ProofOfFundsUiState.Status.refreshing] = true) instead of flashing the spinner.
     */
    fun load(forceRefresh: Boolean) {
        val priorStatus = _uiState.value as? ProofOfFundsUiState.Status
        if (forceRefresh && priorStatus != null) {
            _uiState.value = priorStatus.copy(refreshing = true)
        } else if (!forceRefresh) {
            _uiState.value = ProofOfFundsUiState.Loading
        }

        viewModelScope.launch {
            val summary = when (val res = repository.summary()) {
                is ApiResult.Success -> res.data
                is ApiResult.Failure -> {
                    _uiState.value = ProofOfFundsUiState.Error(res.error.message, retryable = true)
                    return@launch
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = ProofOfFundsUiState.Error(OFFLINE, retryable = true)
                    return@launch
                }
            }

            val history = when (val res = repository.submissions()) {
                is ApiResult.Success -> res.data
                is ApiResult.Failure -> {
                    _uiState.value = ProofOfFundsUiState.Error(res.error.message, retryable = true)
                    return@launch
                }
                is ApiResult.NetworkError -> {
                    _uiState.value = ProofOfFundsUiState.Error(OFFLINE, retryable = true)
                    return@launch
                }
            }

            val latest = history.maxByOrNull { it.createdAt }
            _uiState.value = if (latest != null) {
                ProofOfFundsUiState.Status(
                    summary = summary,
                    latest = latest,
                    history = history.sortedByDescending { it.createdAt },
                    canResubmit = latest.status.invitesResubmit,
                    refreshing = false,
                )
            } else if (priorStatus != null) {
                // A refresh that returns an empty list must NOT regress a just-submitted (or existing)
                // Status back to the Form — keep the prior submission, only updating the summary.
                priorStatus.copy(summary = summary, refreshing = false)
            } else {
                ProofOfFundsUiState.Form(summary = summary)
            }
        }
    }

    // ---- Form editing ----

    fun onSourceChanged(source: PoFSource) = updateForm { it.copy(source = source).revalidated() }

    fun onAmountChanged(value: String) = updateForm { it.copy(amountRaw = value).revalidated() }

    fun onCurrencyChanged(value: String) = updateForm { it.copy(currency = value).revalidated() }

    fun onNoteChanged(value: String) = updateForm { it.copy(note = value) }

    fun onRemoveDocument() = updateForm {
        it.copy(documentKey = null, documentLabel = null).revalidated()
    }

    /**
     * The screen acquired a document [file] (system-intent camera / picker output). Process it off-main
     * (REUSING AND-321's [CaptureImageProcessor]) then upload via the repo's presign->PUT pipeline (REUSE of
     * AND-129) and record the returned S3 key. DEBOUNCED by [work] (the upload is non-idempotent).
     */
    fun onDocumentAcquired(file: File) {
        val current = _uiState.value as? ProofOfFundsUiState.Form ?: return
        if (work?.isActive == true) return // double-send guard (shared with submit).

        _uiState.value = current.copy(uploading = true, inlineError = null)
        work = viewModelScope.launch {
            val processed = try {
                processor.process(file)
            } catch (e: CaptureError) {
                _uiState.value = current.copy(
                    uploading = false,
                    inlineError = e.message ?: GENERIC_PROCESS_ERROR,
                )
                return@launch
            }

            when (val result = repository.uploadDocument(processed.file)) {
                is ApiResult.Success -> _uiState.value = current.copy(
                    uploading = false,
                    documentKey = result.data,
                    documentLabel = processed.file.name,
                    inlineError = null,
                ).revalidated()
                is ApiResult.Failure -> _uiState.value = current.copy(
                    uploading = false,
                    inlineError = result.error.message,
                )
                is ApiResult.NetworkError -> _uiState.value = current.copy(
                    uploading = false,
                    inlineError = OFFLINE,
                )
            }
        }
    }

    /**
     * Submits the form: source_category + declared_amount_cents + currency + document_s3_key + note. CLIENT
     * UX gate: a document + a source + a valid amount are required (the screen also disables Submit until
     * then). DEBOUNCED by [work] (the submit POST is non-idempotent). On success lands on Status.
     */
    fun submit() {
        val current = _uiState.value as? ProofOfFundsUiState.Form ?: return
        if (work?.isActive == true) return // double-send guard (shared with upload).

        val errors = current.validate()
        if (!errors.isClear) {
            _uiState.value = current.copy(fieldErrors = errors, submitEnabled = false)
            return
        }
        val amountCents = current.amountCents ?: return
        val source = current.source ?: return

        _uiState.value = current.copy(submitting = true, inlineError = null)
        work = viewModelScope.launch {
            when (
                val result = repository.submit(
                    sourceCategory = source.token,
                    declaredAmountCents = amountCents,
                    currency = current.currency.trim().ifBlank { null },
                    documentS3Key = current.documentKey,
                    note = current.note.trim().ifBlank { null },
                )
            ) {
                is ApiResult.Success -> reloadAfterSubmit(result.data, current.summary)
                is ApiResult.Failure -> _uiState.value = current.copy(
                    submitting = false,
                    inlineError = result.error.message,
                )
                is ApiResult.NetworkError -> _uiState.value = current.copy(
                    submitting = false,
                    inlineError = OFFLINE,
                )
            }
        }
    }

    /** Moves from a Status surface back to a fresh Form prefilled from the latest submission. */
    fun onResubmit() {
        val current = _uiState.value as? ProofOfFundsUiState.Status ?: return
        if (work?.isActive == true) return
        _uiState.value = ProofOfFundsUiState.Form(
            summary = current.summary,
            source = current.latest.source?.takeIf { it != PoFSource.UNKNOWN },
            amountRaw = current.latest.declaredAmountCents?.let { centsToRaw(it) } ?: "",
            currency = current.latest.currency ?: ProofOfFundsUiState.DEFAULT_CURRENCY,
            note = current.latest.note.orEmpty(),
        ).revalidated()
    }

    /** Re-runs the initial load after a terminal error. */
    fun retry() = load(forceRefresh = false)

    /** Pull-to-refresh: re-reads summary + submissions without flashing the spinner. */
    fun refresh() = load(forceRefresh = true)

    // ---- helpers ----

    private inline fun updateForm(transform: (ProofOfFundsUiState.Form) -> ProofOfFundsUiState.Form) {
        val current = _uiState.value as? ProofOfFundsUiState.Form ?: return
        _uiState.value = transform(current.copy(inlineError = null))
    }

    /**
     * On a successful submit, surface the new submission immediately as Status (latest = the returned
     * submission) so the UI does not depend on a follow-up GET; the full history is refreshed lazily.
     */
    private fun reloadAfterSubmit(submitted: ProofOfFunds, summary: PoFSummary) {
        _uiState.value = ProofOfFundsUiState.Status(
            summary = summary,
            latest = submitted,
            history = listOf(submitted),
            canResubmit = submitted.status.invitesResubmit,
            refreshing = false,
        )
        // Refresh the authoritative summary + history (non-looping single load).
        load(forceRefresh = true)
    }

    /** Recomputes [ProofOfFundsUiState.Form.submitEnabled] from the client UX gate. */
    private fun ProofOfFundsUiState.Form.revalidated(): ProofOfFundsUiState.Form =
        copy(submitEnabled = validate().isClear)

    /** Full client-UX validation: a document + a source + a valid (>0) amount are required. */
    private fun ProofOfFundsUiState.Form.validate(): PoFFieldErrors {
        val cents = amountCents
        return PoFFieldErrors(
            sourceMissing = source == null,
            amountMissing = amountRaw.isBlank(),
            amountInvalid = amountRaw.isNotBlank() && (cents == null || cents <= 0),
            documentMissing = documentKey == null,
        )
    }

    private val ProofOfFundsUiState.Form.amountCents: Long?
        get() = parseAmountToCents(amountRaw)

    private companion object {
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val GENERIC_PROCESS_ERROR = "Could not process the document."
    }
}

/** True when no field error is set. */
val PoFFieldErrors.isClear: Boolean
    get() = !sourceMissing && !amountMissing && !amountInvalid && !documentMissing

/**
 * Parses a user-entered major-unit amount (e.g. "1,234.50" or "1234.5") into integer cents, or null when
 * it is blank / not a number. Locale-tolerant on grouping by stripping non-numeric separators except the
 * last decimal point.
 */
fun parseAmountToCents(raw: String): Long? {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return null
    // Keep digits + a single decimal separator; treat both '.' and ',' as possible decimal markers but
    // prefer '.' when both are present (then commas are grouping separators).
    val normalized = if (trimmed.contains('.')) {
        trimmed.replace(",", "")
    } else {
        trimmed.replace(",", ".")
    }
    val value = normalized.toBigDecimalOrNull() ?: return null
    return value.movePointRight(2).toBigInteger().toLong()
}

/** Renders integer cents back to a plain major-unit string for prefilling the form (no grouping). */
fun centsToRaw(cents: Long): String {
    val whole = cents / 100
    val frac = (cents % 100).let { if (it < 0) -it else it }
    return "$whole.${frac.toString().padStart(2, '0')}"
}
