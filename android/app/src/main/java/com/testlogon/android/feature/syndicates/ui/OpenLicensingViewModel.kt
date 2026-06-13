package com.testlogon.android.feature.syndicates.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-357 - drives the [OpenLicensingUiState] for the open-licensing sub-screen (a sub-surface of the AND-356
 * syndicate overview).
 *
 * syndicateId arrives as a nav arg via [SavedStateHandle] (survives process death). load() / refresh() read
 * the NOT-paginated content list ({items}) and replace it whole (NO Paging 3). The register form is a
 * mutation: submit() POSTs the register receipt and, on Success, sets lastResult = licenses_created, closes
 * the form and REFETCHES the list (it never optimistically prepends, since the receipt is NOT a list row).
 *
 * 422 handling (FastAPI detail[{loc,msg,type}]): map back to inline per-field errors by the trailing loc
 * segment (content_id / content_type), keeping the form OPEN. Any other failure keeps the form open with a
 * single retryable submitError. There is NO poll loop; register is a mutation and is NOT retry-eligible here.
 */
@HiltViewModel
class OpenLicensingViewModel @Inject constructor(
    private val repository: SyndicateRepository,
    private val errorParser: ApiErrorParser,
    savedState: SavedStateHandle,
) : ViewModel() {

    val syndicateId: String =
        checkNotNull(savedState[ARG_SYNDICATE_ID]) { "missing $ARG_SYNDICATE_ID nav arg" }

    private val _uiState = MutableStateFlow<OpenLicensingUiState>(OpenLicensingUiState.Loading())
    val uiState: StateFlow<OpenLicensingUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /** First load (no list yet): goes through Loading and may resolve to Content / Empty / Error. */
    fun load() {
        _uiState.value = OpenLicensingUiState.Loading(form = currentForm())
        viewModelScope.launch { fetch(isRefresh = false) }
    }

    fun onRetry() = load()

    /** Pull-to-refresh: re-reads and replaces the whole list (keeps the form sub-state). */
    fun refresh() {
        val form = currentForm()
        _uiState.value = when (val s = _uiState.value) {
            is OpenLicensingUiState.Content -> s.copy(isRefreshing = true)
            else -> OpenLicensingUiState.Loading(form = form)
        }
        viewModelScope.launch { fetch(isRefresh = true) }
    }

    private suspend fun fetch(isRefresh: Boolean) {
        val form = currentForm()
        _uiState.value = when (val result = repository.getOpenLicensingContent(syndicateId)) {
            is ApiResult.Success ->
                if (result.data.isEmpty()) {
                    OpenLicensingUiState.Empty(form = form)
                } else {
                    OpenLicensingUiState.Content(items = result.data, isRefreshing = false, form = form)
                }
            is ApiResult.Failure -> OpenLicensingUiState.Error(error = result.error, form = form)
            is ApiResult.NetworkError -> OpenLicensingUiState.Error(
                error = ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                form = form,
            )
        }
    }

    // ---- Register form ----

    /** Opens the register form (clearing any prior errors / result). */
    fun openForm() = updateForm {
        RegisterFormState(visible = true)
    }

    /** Dismisses the register form (drops any draft / errors). */
    fun dismissForm() = updateForm { RegisterFormState(visible = false) }

    fun onContentIdChange(value: String) = updateForm {
        it.copy(contentId = value, contentIdError = null, submitError = null)
    }

    fun onContentTypeChange(type: LicensingContentType) = updateForm {
        it.copy(contentType = type, contentTypeError = null, submitError = null)
    }

    /**
     * Submits the register form. Guarded by [RegisterFormState.isValid]. On Success: lastResult =
     * licenses_created, the form closes, and the list is REFETCHED. On 422: per-field inline errors by loc
     * tail (form stays open). On any other failure: a retryable submitError (form stays open).
     */
    fun submit() {
        val form = currentForm()
        if (!form.isValid || form.submitting) return
        val type = form.contentType ?: return
        updateForm { it.copy(submitting = true, contentIdError = null, contentTypeError = null, submitError = null) }
        viewModelScope.launch {
            when (val result = repository.registerOpenLicensing(syndicateId, form.contentId.trim(), type)) {
                is ApiResult.Success -> {
                    // Receipt, NOT a row: close the form, surface the count, and REFETCH the list.
                    updateForm {
                        RegisterFormState(visible = false, lastResult = result.data.licensesCreated)
                    }
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceSubmitFailure(result.error)
                is ApiResult.NetworkError -> updateForm {
                    it.copy(submitting = false, submitError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    /** Clears the last success result after it has been surfaced (one-shot feedback). */
    fun consumeResult() = updateForm {
        if (it.lastResult != null) it.copy(lastResult = null) else it
    }

    private fun reduceSubmitFailure(error: ApiError) {
        if (error.status == STATUS_UNPROCESSABLE) {
            val (idMsg, typeMsg) = mapFieldErrors(error)
            if (idMsg != null || typeMsg != null) {
                updateForm {
                    it.copy(submitting = false, contentIdError = idMsg, contentTypeError = typeMsg)
                }
                return
            }
        }
        updateForm { it.copy(submitting = false, submitError = error.message) }
    }

    /**
     * Routes FastAPI 422 detail[{loc,msg,type}] items to the two fields by the TRAILING loc segment
     * (content_id / content_type). Returns (contentIdError, contentTypeError); either may be null. 404 / 409
     * are not documented and fall through to the generic submitError path.
     */
    private fun mapFieldErrors(error: ApiError): Pair<String?, String?> {
        val detail = (error.raw as? String)?.let { errorParser.parseDetail(it) } as? List<*>
            ?: return null to null
        var idMsg: String? = null
        var typeMsg: String? = null
        for (item in detail) {
            val map = item as? Map<*, *> ?: continue
            val loc = (map["loc"] as? List<*>)?.lastOrNull() as? String ?: continue
            val msg = (map["msg"] as? String)?.takeIf { it.isNotBlank() }
            when (loc) {
                "content_id" -> idMsg = msg ?: idMsg
                "content_type" -> typeMsg = msg ?: typeMsg
            }
        }
        return idMsg to typeMsg
    }

    private fun currentForm(): RegisterFormState = _uiState.value.form

    private inline fun updateForm(transform: (RegisterFormState) -> RegisterFormState) {
        _uiState.update { state ->
            val next = transform(state.form)
            when (state) {
                is OpenLicensingUiState.Loading -> state.copy(form = next)
                is OpenLicensingUiState.Content -> state.copy(form = next)
                is OpenLicensingUiState.Empty -> state.copy(form = next)
                is OpenLicensingUiState.Error -> state.copy(form = next)
            }
        }
    }

    companion object {
        const val ARG_SYNDICATE_ID = "syndicateId"

        private const val STATUS_UNPROCESSABLE = 422
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Please try again."
    }
}
