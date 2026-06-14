package com.testlogon.android.feature.taxforms

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.taxforms.Form1099
import com.testlogon.android.data.taxforms.TaxForm1099Repository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-247 — 1099-NEC list state (single bounded fetch, no Paging 3 — counts are low, < 10 per user).
 *
 * Mirrors the AND-246 TaxDocsUiState shape: a list, loading/refreshing flags, and a (cache-aware) error.
 * [downloadingYear] tracks the in-flight download-URL fetch so the row's action can show progress and a
 * second tap is ignored.
 */
data class Form1099UiState(
    val forms: List<Form1099> = emptyList(),
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val downloadingYear: Int? = null,
    val error: UiText? = null,
)

/** AND-247 — one-shot effects (Channel-backed so rotation cannot replay them). */
sealed interface Form1099Event {
    /** Open the resolved 1099 PDF URL in a browser / Custom Tab (reusing InvoicePdfLauncher). */
    data class ViewPdf(val url: String) : Form1099Event

    /** The download-URL resolution failed; show [message] (the URL expired / offline / non-2xx). */
    data class DownloadError(val message: UiText) : Form1099Event
}

/**
 * AND-247 — 1099-NEC presentation logic. Loads the list on construction; [refresh] re-fetches. Tapping
 * a row's download action resolves the year's PDF URL via [TaxForm1099Repository.downloadUrl] (re-fetched
 * each time because the presigned link expires) and emits a one-shot [Form1099Event.ViewPdf] opened in a
 * Custom Tab (so session cookies / the presigned grant carry the download). Failures map through
 * [BillingErrorMapper] (AND-232), reusing the billing error dictionary.
 */
@HiltViewModel
class Form1099ListViewModel @Inject constructor(
    private val repository: TaxForm1099Repository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _uiState = MutableStateFlow(Form1099UiState(isLoading = true))
    val uiState: StateFlow<Form1099UiState> = _uiState.asStateFlow()

    private val _events = Channel<Form1099Event>(Channel.BUFFERED)
    val events: Flow<Form1099Event> = _events.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    /** Resolve + open the PDF for [form]'s tax year. A second tap while a fetch is in flight is ignored. */
    fun onDownloadClicked(form: Form1099) {
        if (_uiState.value.downloadingYear != null) return // in-flight guard
        _uiState.update { it.copy(downloadingYear = form.taxYear) }
        viewModelScope.launch {
            val result = repository.downloadUrl(form.taxYear)
            _uiState.update { it.copy(downloadingYear = null) }
            when (result) {
                is ApiResult.Success -> {
                    val url = result.data
                    if (url.isBlank()) {
                        _events.send(Form1099Event.DownloadError(errorMapper.map(emptyUrlFailure()).message))
                    } else {
                        _events.send(Form1099Event.ViewPdf(url))
                    }
                }
                else -> _events.send(Form1099Event.DownloadError(errorMapper.map(result).message))
            }
        }
    }

    private fun load(isRefresh: Boolean) {
        val hadData = _uiState.value.forms.isNotEmpty()
        _uiState.update { it.copy(isLoading = !isRefresh && !hadData, isRefreshing = isRefresh) }
        viewModelScope.launch {
            when (val result = repository.list1099s()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        forms = result.data,
                        isLoading = false,
                        isRefreshing = false,
                        error = null,
                    )
                }
                else -> _uiState.update {
                    it.copy(
                        isLoading = false,
                        isRefreshing = false,
                        // Keep cached rows; only surface a full error with no cache (offline-aware).
                        error = if (hadData) it.error else errorMapper.map(result).message,
                    )
                }
            }
        }
    }

    /** An empty/expired download_url is a server-state failure; reuse the generic billing mapping. */
    private fun emptyUrlFailure(): ApiResult<Nothing> =
        ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 502, message = ""))
}
