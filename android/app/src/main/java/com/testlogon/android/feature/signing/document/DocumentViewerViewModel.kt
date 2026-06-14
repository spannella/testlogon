package com.testlogon.android.feature.signing.document

import android.graphics.Bitmap
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.signing.document.data.PdfSource
import com.testlogon.android.feature.signing.document.model.DocumentRef
import com.testlogon.android.feature.signing.document.model.DocumentUiState
import com.testlogon.android.feature.signing.document.model.PageLayout
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-341 - presentation logic for the PDF document viewer.
 *
 * SINGLE READ, NO POLL: [load] downloads the PDF once (cache-first via [PdfSource]) then opens ONE
 * [PdfPageRenderer], lands on [DocumentUiState.Ready] with one [PageLayout] per page (or Error). The
 * screen lazily asks for the bitmap of each near-viewport page via [requestPage]; renders are cached +
 * deduped by [BitmapPageCache]. Zoom adjusts the target render width; the re-render is a single
 * cancellable debounced job (NOT a loop). On teardown the renderer is closed + the cache cleared.
 *
 * packetId is sourced from the [SavedStateHandle] nav arg ([ARG_PACKET_ID]).
 */
@HiltViewModel
class DocumentViewerViewModel @Inject constructor(
    private val pdfSource: PdfSource,
    private val rendererFactory: PdfPageRendererFactory,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val packetId: String =
        savedStateHandle.get<String>(ARG_PACKET_ID)?.takeIf { it.isNotBlank() }.orEmpty()

    private val _uiState = MutableStateFlow<DocumentUiState>(DocumentUiState.Loading)
    val uiState: StateFlow<DocumentUiState> = _uiState.asStateFlow()

    /** Current target render width (px); zoom multiplies the base column width into this. */
    private val _targetWidthPx = MutableStateFlow(0)
    val targetWidthPx: StateFlow<Int> = _targetWidthPx.asStateFlow()

    private val cache = BitmapPageCache()
    private var renderer: PdfPageRenderer? = null

    private var loadJob: Job? = null

    init {
        load()
    }

    /** Downloads + opens the document, landing on Ready or Error. */
    fun load() {
        if (packetId.isEmpty()) {
            _uiState.value = DocumentUiState.Error(MISSING_PACKET, retryable = false)
            return
        }
        _uiState.value = DocumentUiState.Loading
        loadJob?.cancel()
        loadJob = viewModelScope.launch {
            when (val result = pdfSource.downloadPdf(packetId)) {
                is ApiResult.Success -> openRenderer(result.data)
                is ApiResult.Failure ->
                    _uiState.value = DocumentUiState.Error(result.error.message, retryable = true)
                is ApiResult.NetworkError ->
                    _uiState.value = DocumentUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    /** Re-runs [load] after a terminal error. */
    fun retry() = load()

    private fun openRenderer(file: java.io.File) {
        closeRenderer()
        val opened = runCatching { rendererFactory.create(file) }.getOrNull()
        if (opened == null) {
            _uiState.value = DocumentUiState.Error(CORRUPT, retryable = false)
            return
        }
        renderer = opened
        val pages = (0 until opened.pageCount).map { index ->
            runCatching { opened.pageLayout(index) }
                .getOrDefault(PageLayout(index = index, widthPts = DEFAULT_PT, heightPts = DEFAULT_PT))
        }
        _uiState.value = DocumentUiState.Ready(
            ref = DocumentRef(packetId = packetId, displayName = file.name),
            pageCount = opened.pageCount,
            pages = pages,
        )
    }

    /**
     * Renders (or returns the cached) bitmap for [index] at [targetWidthPx], deduping concurrent calls.
     * The screen calls this only for near-viewport pages (windowed). Returns null if the renderer is
     * gone or rendering fails.
     */
    suspend fun requestPage(index: Int, targetWidthPx: Int): Bitmap? {
        val active = renderer ?: return null
        val key = BitmapPageCache.Key(index = index, targetWidthPx = targetWidthPx.coerceAtLeast(1))
        return runCatching {
            cache.getOrRender(key, viewModelScope) { active.renderPage(index, key.targetWidthPx) }
        }.getOrNull()
    }

    /** Marks a page composed (bitmap protected from recycle while on screen). */
    fun onPageComposed(index: Int, targetWidthPx: Int) {
        viewModelScope.launch {
            cache.retain(BitmapPageCache.Key(index, targetWidthPx.coerceAtLeast(1)))
        }
    }

    /** Releases an off-screen page so its bitmap can be recycled (lazy windowing). */
    fun onPageDisposed(index: Int, targetWidthPx: Int) {
        viewModelScope.launch {
            cache.release(BitmapPageCache.Key(index, targetWidthPx.coerceAtLeast(1)))
        }
    }

    /**
     * Updates the base on-screen page width (the LazyColumn item width) and the zoom factor, producing a
     * new integer target render width. The screen re-requests visible pages at the new width; this is a
     * single state write (the debounce of the re-render lives in the screen as one cancellable job).
     */
    fun setRenderWidth(baseWidthPx: Int, zoom: Float) {
        val width = (baseWidthPx * zoom).toInt().coerceAtLeast(1)
        if (width != _targetWidthPx.value) {
            _targetWidthPx.value = width
        }
    }

    private fun closeRenderer() {
        renderer?.let { r -> runCatching { r.close() } }
        renderer = null
    }

    override fun onCleared() {
        super.onCleared()
        closeRenderer()
        // viewModelScope is already cancelled here; clear() is synchronous + safe.
        cache.clear()
    }

    companion object {
        const val ARG_PACKET_ID = "packetId"

        private const val DEFAULT_PT = 612f // US Letter width fallback when a page read fails.
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val MISSING_PACKET = "Document not found."
        private const val CORRUPT = "This document could not be opened."
    }
}
