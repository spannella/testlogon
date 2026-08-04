package com.testlogon.android.feature.taxdocs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.taxdocs.TaxDocument
import com.testlogon.android.data.taxdocs.TaxDocsRepository
import com.testlogon.android.data.taxdocs.TaxSpendingSummary
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.Calendar
import javax.inject.Inject

/** AND-246 — tax-documents list state (single bounded fetch, no Paging 3). PAR-24 adds [summary]. */
data class TaxDocsUiState(
    val documents: List<TaxDocument> = emptyList(),
    val summary: TaxSpendingSummary? = null,
    val summaryYear: Int? = null,
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val error: UiText? = null,
)

/** AND-246 — one-shot effect: open a tax-document PDF in a Custom Tab (reusing InvoicePdfLauncher). */
sealed interface TaxDocsEvent {
    data class ViewPdf(val url: String) : TaxDocsEvent
}

/**
 * AND-246 — tax-documents presentation logic. Loads the list on construction; [refresh] re-fetches. The
 * "View / download PDF" action emits a one-shot [TaxDocsEvent.ViewPdf] with the absolute year-keyed PDF
 * URL (opened in a Custom Tab so session cookies ride along — reusing the AND-243 launcher). Failures map
 * through [BillingErrorMapper] (AND-232). Rows with a null `year` are not downloadable.
 *
 * PAR-24 — also fetches the earnings summary CONCURRENTLY with the list (via async), folded best-effort:
 * a summary failure leaves [TaxDocsUiState.summary] null and NEVER fails the screen (mirrors iOS
 * tolerance). The summary year defaults to the current calendar year; the backend requires a year param
 * (422 otherwise), so one is always sent.
 */
@HiltViewModel
class TaxDocsViewModel @Inject constructor(
    private val repository: TaxDocsRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TaxDocsUiState(isLoading = true))
    val uiState: StateFlow<TaxDocsUiState> = _uiState.asStateFlow()

    private val _events = Channel<TaxDocsEvent>(Channel.BUFFERED)
    val events: Flow<TaxDocsEvent> = _events.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    /** Open the PDF for [doc] (no-op when the document has no year — not downloadable). */
    fun onDownloadClicked(doc: TaxDocument) {
        val year = doc.year ?: return
        viewModelScope.launch {
            _events.send(TaxDocsEvent.ViewPdf(repository.pdfUrl(year)))
        }
    }

    private fun load(isRefresh: Boolean) {
        val hadData = _uiState.value.documents.isNotEmpty()
        _uiState.update {
            it.copy(isLoading = !isRefresh && !hadData, isRefreshing = isRefresh)
        }
        viewModelScope.launch {
            val year = currentYear()
            // Concurrent: the list and the summary run in parallel; the summary is best-effort.
            val listDeferred = async { repository.listTaxDocuments() }
            val summaryDeferred = async { repository.summary(year) }

            val listResult = listDeferred.await()
            val summaryResult = summaryDeferred.await()
            val summary = (summaryResult as? ApiResult.Success)?.data

            when (listResult) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        documents = listResult.data,
                        summary = summary ?: it.summary,
                        summaryYear = year,
                        isLoading = false,
                        isRefreshing = false,
                        error = null,
                    )
                }
                else -> _uiState.update {
                    it.copy(
                        summary = summary ?: it.summary,
                        summaryYear = year,
                        isLoading = false,
                        isRefreshing = false,
                        // Keep any cached rows; only surface a full error with no cache.
                        error = if (hadData) it.error else errorMapper.map(listResult).message,
                    )
                }
            }
        }
    }

    private fun currentYear(): Int = Calendar.getInstance().get(Calendar.YEAR)
}
