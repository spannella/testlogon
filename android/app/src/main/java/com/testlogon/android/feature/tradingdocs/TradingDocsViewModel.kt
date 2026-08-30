package com.testlogon.android.feature.tradingdocs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.tradingdocs.TradingDocsRepository
import com.testlogon.android.data.tradingdocs.TradingDocument
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
 * FE-170 — Trading Documents screen state. The list is ALWAYS resolvable to a grouped view; a fetch
 * failure (incl. BE-171 404) degrades to an empty list, surfaced as the honest empty state — no error
 * surface, no crash (per the acceptance criteria).
 */
data class TradingDocsUiState(
    val groups: List<TradingDocGroup> = emptyList(),
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
) {
    val isEmpty: Boolean get() = groups.isEmpty()
}

/** FE-170 — one-shot effects: open a download in a Custom Tab, or share a link. */
sealed interface TradingDocsEvent {
    /** Open a resolved (presigned) download URL in a Custom Tab. */
    data class OpenDownload(val url: String) : TradingDocsEvent

    /** Share a document via ACTION_SEND (a link when a URL is resolvable, else the title). */
    data class Share(val title: String, val url: String?) : TradingDocsEvent

    /** The document could not be downloaded (no URL resolvable). */
    data object DownloadUnavailable : TradingDocsEvent
}

/**
 * FE-170 — presentation logic for the Trading Documents area. Loads the (unfiltered) list on
 * construction; [refresh] re-fetches. Download prefers the row's inline download_url, falling back to
 * [TradingDocsRepository.getDownloadUrl]; a "generating" doc is never downloadable. Share emits a link
 * (or the title if none resolvable). Everything degrades gracefully — a failed fetch just yields the
 * empty state.
 */
@HiltViewModel
class TradingDocsViewModel @Inject constructor(
    private val repository: TradingDocsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TradingDocsUiState(isLoading = true))
    val uiState: StateFlow<TradingDocsUiState> = _uiState.asStateFlow()

    private val _events = Channel<TradingDocsEvent>(Channel.BUFFERED)
    val events: Flow<TradingDocsEvent> = _events.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    /** Download [doc]: no-op while generating; open the inline URL or resolve one, else signal unavailable. */
    fun onDownloadClicked(doc: TradingDocument) {
        if (!isDownloadable(doc)) return
        viewModelScope.launch {
            val url = doc.downloadUrl ?: repository.getDownloadUrl(doc.docId)
            if (url != null) {
                _events.send(TradingDocsEvent.OpenDownload(url))
            } else {
                _events.send(TradingDocsEvent.DownloadUnavailable)
            }
        }
    }

    /** Share [doc]: emits a link when one is inline/resolvable, else shares the title text. */
    fun onShareClicked(doc: TradingDocument) {
        viewModelScope.launch {
            val url = doc.downloadUrl ?: if (isDownloadable(doc)) repository.getDownloadUrl(doc.docId) else null
            _events.send(TradingDocsEvent.Share(title = docTitle(doc), url = url))
        }
    }

    private fun load(isRefresh: Boolean) {
        val hadData = _uiState.value.groups.isNotEmpty()
        _uiState.update { it.copy(isLoading = !isRefresh && !hadData, isRefreshing = isRefresh) }
        viewModelScope.launch {
            val docs = repository.listTradingDocuments()
            _uiState.update {
                it.copy(
                    groups = groupDocuments(docs),
                    isLoading = false,
                    isRefreshing = false,
                )
            }
        }
    }
}
