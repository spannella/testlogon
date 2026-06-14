package com.testlogon.android.feature.dmca

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.dmca.DataStoreDmcaDraftStore
import com.testlogon.android.data.dmca.DmcaClaimRequest
import com.testlogon.android.data.dmca.DmcaContentType
import com.testlogon.android.data.dmca.DmcaDraft
import com.testlogon.android.data.dmca.DmcaRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-384 - the editable / attestable fields of the DMCA form, keyed for inline error mapping. */
enum class DmcaField {
    OriginalWorkDescription,
    ContentUrl,
    ContentType,
    ContentId,
    ClaimantName,
    ClaimantEmail,
    ClaimantAddress,
    ClaimantPhone,
    SwornStatement,
    GoodFaithBelief,
    Signature,
}

/** AND-384 - the distinct failure kinds the UI renders with distinct, human-readable copy (FR-6 / AC-5). */
enum class DmcaErrorKind { Validation, Auth, RateLimited, Server, Network }

/**
 * AND-384 - the DMCA form's edit state. [isSubmittable] is true only when EVERY hard rule passes: all
 * required text fields non-blank and within bounds, a valid-looking email, the description >= 20 chars, a
 * non-blank content URL, both attestation booleans true, and a non-blank signature. The signature/name
 * mismatch is a SOFT warning (surfaced in [fieldErrors]) and does NOT block submit (FR-3).
 */
data class DmcaFormState(
    val originalWorkDescription: String = "",
    val contentUrl: String = "",
    val contentType: String = DmcaContentType.OTHER,
    val contentId: String? = null,
    val claimantName: String = "",
    val claimantEmail: String = "",
    val claimantAddress: String = "",
    val claimantPhone: String = "",
    val swornStatement: Boolean = false,
    val goodFaithBelief: Boolean = false,
    val signature: String = "",
    val fieldErrors: Map<DmcaField, String> = emptyMap(),
    /** True when the content reference was supplied by a pre-targeted entry and is locked read-only. */
    val contentLocked: Boolean = false,
) {
    val isSubmittable: Boolean
        get() = originalWorkDescription.trim().length in DESC_MIN..DESC_MAX &&
            contentUrl.trim().length in URL_MIN..URL_MAX &&
            claimantName.trim().length in NAME_MIN..NAME_MAX &&
            isEmailValid(claimantEmail) &&
            claimantAddress.trim().length in ADDRESS_MIN..ADDRESS_MAX &&
            claimantPhone.trim().length <= PHONE_MAX &&
            contentId.orEmpty().length <= CONTENT_ID_MAX &&
            swornStatement && goodFaithBelief &&
            signature.trim().length in SIGNATURE_MIN..SIGNATURE_MAX

    /** A soft, non-blocking warning when the signature does not match the legal name (FR-3). */
    val signatureNameMismatch: Boolean
        get() = signature.isNotBlank() && claimantName.isNotBlank() &&
            !signature.trim().equals(claimantName.trim(), ignoreCase = true)

    fun toRequest(): DmcaClaimRequest = DmcaClaimRequest(
        claimantName = claimantName.trim(),
        claimantEmail = claimantEmail.trim(),
        claimantAddress = claimantAddress.trim(),
        claimantPhone = claimantPhone.trim().ifBlank { null },
        contentUrl = contentUrl.trim(),
        contentType = DmcaContentType.normalize(contentType),
        contentId = contentId?.trim()?.ifBlank { null },
        originalWorkDescription = originalWorkDescription.trim(),
        swornStatement = swornStatement,
        goodFaithBelief = goodFaithBelief,
        signature = signature.trim(),
    )

    /** The non-attestation draft snapshot (signature + checkboxes are deliberately excluded). */
    fun toDraft(): DmcaDraft = DmcaDraft(
        originalWorkDescription = originalWorkDescription,
        contentUrl = contentUrl,
        contentType = contentType,
        contentId = contentId,
        claimantName = claimantName,
        claimantEmail = claimantEmail,
        claimantAddress = claimantAddress,
        claimantPhone = claimantPhone,
    )

    companion object {
        const val DESC_MIN = 20
        const val DESC_MAX = 5000
        const val URL_MIN = 5
        const val URL_MAX = 2000
        const val NAME_MIN = 2
        const val NAME_MAX = 256
        const val EMAIL_MIN = 5
        const val EMAIL_MAX = 320
        const val ADDRESS_MIN = 10
        const val ADDRESS_MAX = 1000
        const val PHONE_MAX = 30
        const val CONTENT_ID_MAX = 256
        const val SIGNATURE_MIN = 2
        const val SIGNATURE_MAX = 256

        // Mirrors the web client regex /^[^\s@]+@[^\s@]+\.[^\s@]+$/.
        private val EMAIL_REGEX = Regex("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")

        fun isEmailValid(email: String): Boolean {
            val t = email.trim()
            return t.length in EMAIL_MIN..EMAIL_MAX && EMAIL_REGEX.matches(t)
        }
    }
}

/** AND-384 - the screen state machine: editing/submitting -> submitted, or editing with an error banner. */
sealed interface DmcaUiState {
    data class Editing(val form: DmcaFormState, val submitting: Boolean = false) : DmcaUiState
    data class Error(
        val form: DmcaFormState,
        val message: String,
        val kind: DmcaErrorKind,
    ) : DmcaUiState
    data class Submitted(
        val claimId: String,
        val status: String,
        val contentRemoved: Boolean,
    ) : DmcaUiState
}

/**
 * AND-384 - presentation logic for the DMCA submit form.
 *
 * Reads the optional pre-target nav args (contentType / contentId / url) from [SavedStateHandle] and (after
 * starting) restores any cached draft text - WITHOUT the signature or attestations (which are never persisted
 * and must be re-affirmed, AC-6). [submit] is non-idempotent: a re-entrant call while submitting is a no-op
 * (single repo call, AC-4); there is NO auto-retry on failure - the user taps "Try again". 422 field errors
 * are routed to [DmcaFormState.fieldErrors] by matching the loc tail; 401 (post-refresh) / 429 / 5xx /
 * transport each map to a distinct [DmcaErrorKind]. The form is preserved across any failure (FR-6).
 */
@HiltViewModel
class DmcaViewModel @Inject constructor(
    private val repository: DmcaRepository,
    private val errorParser: ApiErrorParser,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val argContentType: String? =
        savedState.get<String>(ARG_CONTENT_TYPE)?.takeIf { it.isNotBlank() }
    private val argContentId: String? =
        savedState.get<String>(ARG_CONTENT_ID)?.takeIf { it.isNotBlank() }
    private val argUrl: String? =
        savedState.get<String>(ARG_URL)?.takeIf { it.isNotBlank() }

    private val draftKey: String = DataStoreDmcaDraftStore.targetKey(argContentType, argContentId)
    private val isPreTargeted: Boolean = argContentType != null || argContentId != null || argUrl != null

    private val _uiState = MutableStateFlow<DmcaUiState>(
        DmcaUiState.Editing(
            DmcaFormState(
                contentType = DmcaContentType.normalize(argContentType),
                contentId = argContentId,
                contentUrl = argUrl.orEmpty(),
                contentLocked = isPreTargeted,
            ),
        ),
    )
    val uiState: StateFlow<DmcaUiState> = _uiState.asStateFlow()

    private var submitJob: Job? = null
    private var saveJob: Job? = null

    init {
        // Restore best-effort draft text INSIDE a coroutine (never block init); the pre-target args win for
        // the content reference, and the signature + attestations are never restored.
        viewModelScope.launch {
            val draft = repository.loadDraft(draftKey) ?: return@launch
            updateForm { current ->
                current.copy(
                    originalWorkDescription = draft.originalWorkDescription.ifBlank { current.originalWorkDescription },
                    contentUrl = if (isPreTargeted) current.contentUrl else draft.contentUrl.ifBlank { current.contentUrl },
                    contentType = if (isPreTargeted) current.contentType else DmcaContentType.normalize(draft.contentType),
                    contentId = if (isPreTargeted) current.contentId else (draft.contentId ?: current.contentId),
                    claimantName = draft.claimantName.ifBlank { current.claimantName },
                    claimantEmail = draft.claimantEmail.ifBlank { current.claimantEmail },
                    claimantAddress = draft.claimantAddress.ifBlank { current.claimantAddress },
                    claimantPhone = draft.claimantPhone.ifBlank { current.claimantPhone },
                )
            }
        }
    }

    fun onFieldChanged(field: DmcaField, value: String) {
        updateForm { form ->
            val cleared = form.fieldErrors - field
            when (field) {
                DmcaField.OriginalWorkDescription ->
                    form.copy(originalWorkDescription = value.take(DmcaFormState.DESC_MAX), fieldErrors = cleared)
                DmcaField.ContentUrl ->
                    form.copy(contentUrl = value.take(DmcaFormState.URL_MAX), fieldErrors = cleared)
                DmcaField.ContentType ->
                    form.copy(contentType = DmcaContentType.normalize(value), fieldErrors = cleared)
                DmcaField.ContentId ->
                    form.copy(contentId = value.take(DmcaFormState.CONTENT_ID_MAX), fieldErrors = cleared)
                DmcaField.ClaimantName ->
                    form.copy(claimantName = value.take(DmcaFormState.NAME_MAX), fieldErrors = cleared)
                DmcaField.ClaimantEmail ->
                    form.copy(claimantEmail = value.take(DmcaFormState.EMAIL_MAX), fieldErrors = cleared)
                DmcaField.ClaimantAddress ->
                    form.copy(claimantAddress = value.take(DmcaFormState.ADDRESS_MAX), fieldErrors = cleared)
                DmcaField.ClaimantPhone ->
                    form.copy(claimantPhone = value.take(DmcaFormState.PHONE_MAX), fieldErrors = cleared)
                DmcaField.Signature ->
                    form.copy(signature = value.take(DmcaFormState.SIGNATURE_MAX), fieldErrors = cleared)
                // Booleans are not text fields; ignore.
                DmcaField.SwornStatement, DmcaField.GoodFaithBelief -> form
            }
        }
        scheduleDraftSave()
    }

    fun onToggle(field: DmcaField, checked: Boolean) {
        updateForm { form ->
            when (field) {
                DmcaField.SwornStatement -> form.copy(swornStatement = checked)
                DmcaField.GoodFaithBelief -> form.copy(goodFaithBelief = checked)
                else -> form
            }
        }
        // Attestations are NOT persisted (AC-6) - no draft save here.
    }

    /** Non-idempotent submit: ignored while already submitting; requires the form to be submittable. */
    fun submit() {
        if (submitJob?.isActive == true) return
        val form = currentForm() ?: return
        if (!form.isSubmittable) return
        runSubmit(form)
    }

    /** User-initiated retry of the same notice (only from a failure); never auto-fired. */
    fun retry() {
        if (submitJob?.isActive == true) return
        val form = currentForm() ?: return
        if (!form.isSubmittable) return
        runSubmit(form)
    }

    private fun runSubmit(form: DmcaFormState) {
        _uiState.value = DmcaUiState.Editing(form, submitting = true)
        submitJob = viewModelScope.launch {
            try {
                when (val r = repository.submit(form.toRequest())) {
                    is ApiResult.Success -> onSuccess(r.data)
                    is ApiResult.Failure -> onFailure(form, r.error)
                    is ApiResult.NetworkError -> _uiState.value = DmcaUiState.Error(
                        form = form,
                        message = NETWORK_MESSAGE,
                        kind = DmcaErrorKind.Network,
                    )
                }
            } catch (e: CancellationException) {
                throw e
            }
        }
    }

    private suspend fun onSuccess(response: com.testlogon.android.data.dmca.DmcaClaimCreateResponse) {
        repository.clearDraft(draftKey) // FR-7: a successful notice clears the cached draft.
        _uiState.value = DmcaUiState.Submitted(
            claimId = response.claimId,
            status = response.status,
            contentRemoved = response.contentRemoved,
        )
    }

    private fun onFailure(form: DmcaFormState, error: ApiError) {
        if (error.status == HTTP_VALIDATION) {
            val mapped = mapFieldErrors(error)
            if (mapped.isNotEmpty()) {
                _uiState.value = DmcaUiState.Editing(form.copy(fieldErrors = mapped), submitting = false)
                return
            }
        }
        val (message, kind) = when (error.status) {
            401, 403 -> AUTH_MESSAGE to DmcaErrorKind.Auth
            HTTP_VALIDATION -> error.message to DmcaErrorKind.Validation
            HTTP_RATE_LIMITED -> RATE_LIMITED_MESSAGE to DmcaErrorKind.RateLimited
            in 500..599 -> SERVER_MESSAGE to DmcaErrorKind.Server
            else -> error.message.ifBlank { SERVER_MESSAGE } to DmcaErrorKind.Server
        }
        _uiState.value = DmcaUiState.Error(form = form, message = message, kind = kind)
    }

    /** Routes 422 detail items to [DmcaField]s by matching the last element of each `loc` array. */
    private fun mapFieldErrors(error: ApiError): Map<DmcaField, String> {
        val result = mutableMapOf<DmcaField, String>()
        for ((field, loc) in LOC_TAIL_TO_FIELD) {
            val msg = errorParser.fieldErrorForLocTail(error, loc)
            if (msg != null) result[field] = msg
        }
        return result
    }

    private fun scheduleDraftSave() {
        val form = currentForm() ?: return
        saveJob?.cancel()
        saveJob = viewModelScope.launch {
            delay(DRAFT_DEBOUNCE_MS)
            val draft = form.toDraft()
            if (draft.isEmpty) repository.clearDraft(draftKey) else repository.saveDraft(draftKey, draft)
        }
    }

    private fun currentForm(): DmcaFormState? = when (val s = _uiState.value) {
        is DmcaUiState.Editing -> s.form
        is DmcaUiState.Error -> s.form
        is DmcaUiState.Submitted -> null
    }

    private inline fun updateForm(transform: (DmcaFormState) -> DmcaFormState) {
        _uiState.update { state ->
            when (state) {
                is DmcaUiState.Editing -> state.copy(form = transform(state.form))
                is DmcaUiState.Error -> DmcaUiState.Editing(transform(state.form), submitting = false)
                is DmcaUiState.Submitted -> state
            }
        }
    }

    companion object {
        const val ARG_CONTENT_TYPE = "contentType"
        const val ARG_CONTENT_ID = "contentId"
        const val ARG_URL = "url"

        const val NETWORK_MESSAGE =
            "Couldn't reach TestLogon. Your notice was not submitted - check your connection and try again."
        const val AUTH_MESSAGE = "Your session expired. Sign in again to file this notice."
        const val RATE_LIMITED_MESSAGE = "Too many requests - wait a moment and try again."
        const val SERVER_MESSAGE = "Something went wrong submitting your notice. Please try again."

        private const val HTTP_VALIDATION = 422
        private const val HTTP_RATE_LIMITED = 429
        private const val DRAFT_DEBOUNCE_MS = 500L

        /** loc-tail (server field name) per editable [DmcaField], for 422 mapping. */
        private val LOC_TAIL_TO_FIELD: List<Pair<DmcaField, String>> = listOf(
            DmcaField.OriginalWorkDescription to "original_work_description",
            DmcaField.ContentUrl to "content_url",
            DmcaField.ContentType to "content_type",
            DmcaField.ContentId to "content_id",
            DmcaField.ClaimantName to "claimant_name",
            DmcaField.ClaimantEmail to "claimant_email",
            DmcaField.ClaimantAddress to "claimant_address",
            DmcaField.ClaimantPhone to "claimant_phone",
            DmcaField.SwornStatement to "sworn_statement",
            DmcaField.GoodFaithBelief to "good_faith_belief",
            DmcaField.Signature to "signature",
        )
    }
}
