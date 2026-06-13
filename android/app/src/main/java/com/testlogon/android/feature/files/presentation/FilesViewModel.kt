package com.testlogon.android.feature.files.presentation

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.feature.files.data.FileSort
import com.testlogon.android.feature.files.data.FileSortBy
import com.testlogon.android.feature.files.data.FileSortDir
import com.testlogon.android.feature.files.data.FilesRepository
import com.testlogon.android.feature.files.data.SearchMode
import com.testlogon.android.feature.files.data.SortPrefs
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-332 - UI state for the file-manager browse surface (the browse listing itself is driven by the
 * Paging LoadState of [FilesViewModel.pagedItems]; this holds only the non-paging chrome).
 *
 * [breadcrumbs] is DERIVED from [currentPath]. When [isSearching] is true the screen renders the
 * single-shot [searchResults] (with [searchLoading] / [searchError]) instead of the paged listing.
 */
data class FilesUiState(
    val currentPath: String = FilePath.ROOT,
    val rootLabel: String = "",
    val sort: FileSort = FileSort(),
    val searchQuery: String = "",
    val searchMode: SearchMode = SearchMode.PREFIX,
    val isSearching: Boolean = false,
    val searchLoading: Boolean = false,
    val searchError: String? = null,
    val searchResults: List<FileNode> = emptyList(),
) {
    val breadcrumbs: List<Breadcrumb> = FilePath.breadcrumbs(currentPath, rootLabel)
}

/** AND-332 - one-shot effects consumed by the screen (a Channel, never a StateFlow). */
sealed interface FilesEvent {
    /** Up / back was pressed at the root - the host should pop the back stack. */
    data object NavigateUp : FilesEvent

    /** A file row was opened; [path] is its addressable path (preview is a later ticket). */
    data class OpenFile(val path: String) : FilesEvent
}

/**
 * AND-332 - presentation logic for the read-only file-manager browse surface.
 *
 * BROWSE: [pagedItems] is a cached [PagingData] flow that switches the underlying Pager whenever the
 * path or sort changes (flatMapLatest over [pagerKey]); the repository builds a NETWORK-backed
 * FilesPagingSource (Room SWR cache DEFERRED). SEARCH: non-paginated bounded results held in
 * [FilesUiState]. The ONLY timed wait in this VM is the 300 ms search debounce, implemented as a SINGLE
 * cancellable [searchJob] (a new keystroke cancels the pending one); there is no poll loop. Navigation
 * is path-based (no node ids): opening a folder appends a segment, a breadcrumb truncates, up pops a
 * segment (at root -> [FilesEvent.NavigateUp]). Sort changes persist via [SortPrefs] and re-page.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class FilesViewModel @Inject constructor(
    private val repository: FilesRepository,
    private val sortPrefs: SortPrefs,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        FilesUiState(currentPath = savedState.get<String>(KEY_PATH)?.let(FilePath::normalize) ?: FilePath.ROOT),
    )
    val uiState: StateFlow<FilesUiState> = _uiState.asStateFlow()

    /** Drives which Pager is active: the current (path, sort) plus a bump for explicit refresh. */
    private data class PagerKey(val path: String, val sort: FileSort, val refresh: Long)

    private val pagerKey = MutableStateFlow(
        PagerKey(path = _uiState.value.currentPath, sort = FileSort(), refresh = 0L),
    )

    val pagedItems: Flow<PagingData<FileNode>> =
        pagerKey
            .flatMapLatest { key -> repository.pagedFolder(key.path, key.sort) }
            .cachedIn(viewModelScope)

    private val _events = Channel<FilesEvent>(Channel.BUFFERED)
    val events: Flow<FilesEvent> = _events.receiveAsFlow()

    /** The single in-flight debounced search job; a new keystroke cancels it. */
    private var searchJob: Job? = null

    init {
        viewModelScope.launch {
            val sort = sortPrefs.read()
            _uiState.update { it.copy(sort = sort) }
            pagerKey.update { it.copy(sort = sort) }
        }
    }

    /** Opens a folder [node] by appending its segment to the current path and re-paging. */
    fun onOpenFolder(node: FileNode) {
        if (node.type != FileNodeType.FOLDER) return
        navigateTo(FilePath.child(_uiState.value.currentPath, node.name))
    }

    /** Navigates to the breadcrumb at [index] by truncating the current path. */
    fun onBreadcrumb(index: Int) {
        navigateTo(FilePath.truncateTo(_uiState.value.currentPath, index))
    }

    /** Pops one path segment; at the root, emits [FilesEvent.NavigateUp] instead. */
    fun onUp() {
        val path = _uiState.value.currentPath
        if (FilePath.isRoot(path)) {
            _events.trySend(FilesEvent.NavigateUp)
        } else {
            navigateTo(FilePath.parent(path))
        }
    }

    /** Alias for [onUp] - the system back press maps to the same path-pop / NavigateUp behaviour. */
    fun onBack() = onUp()

    /** A file row was opened; emits [FilesEvent.OpenFile] carrying its path (preview is a later ticket). */
    fun onOpenFile(node: FileNode) {
        if (node.type == FileNodeType.FOLDER) return
        _events.trySend(FilesEvent.OpenFile(node.path))
    }

    /**
     * Handles a search-field edit: a query of [MIN_QUERY_LENGTH]+ chars schedules a single debounced
     * search; a shorter / blank query cancels any pending job and restores the browse listing.
     */
    fun onSearchChanged(query: String) {
        _uiState.update { it.copy(searchQuery = query) }
        val trimmed = query.trim()
        searchJob?.cancel()
        if (trimmed.length < MIN_QUERY_LENGTH) {
            _uiState.update {
                it.copy(isSearching = false, searchLoading = false, searchError = null, searchResults = emptyList())
            }
            return
        }
        _uiState.update { it.copy(isSearching = true, searchLoading = true, searchError = null) }
        searchJob = viewModelScope.launch {
            delay(DEBOUNCE_MS)
            runSearch(trimmed)
        }
    }

    /** Toggles the active search surface (filename prefix vs. full text) and re-runs any live search. */
    fun onToggleSearchMode() {
        val next = if (_uiState.value.searchMode == SearchMode.PREFIX) SearchMode.TEXT else SearchMode.PREFIX
        _uiState.update { it.copy(searchMode = next) }
        val trimmed = _uiState.value.searchQuery.trim()
        if (trimmed.length >= MIN_QUERY_LENGTH) {
            searchJob?.cancel()
            _uiState.update { it.copy(searchLoading = true, searchError = null) }
            searchJob = viewModelScope.launch { runSearch(trimmed) }
        }
    }

    /** Persists [sortBy]/[sortDir] (+ optional folders-first toggle) and re-pages / re-sorts search. */
    fun onSortChanged(sortBy: FileSortBy, sortDir: FileSortDir, foldersFirst: Boolean = _uiState.value.sort.foldersFirst) {
        val sort = FileSort(sortBy = sortBy, sortDir = sortDir, foldersFirst = foldersFirst)
        _uiState.update { it.copy(sort = sort) }
        pagerKey.update { it.copy(sort = sort) }
        viewModelScope.launch { sortPrefs.write(sort) }
        val trimmed = _uiState.value.searchQuery.trim()
        if (_uiState.value.isSearching && trimmed.length >= MIN_QUERY_LENGTH) {
            searchJob?.cancel()
            searchJob = viewModelScope.launch { runSearch(trimmed) }
        }
    }

    /** Re-anchors the browse Pager at the first page (pull-to-refresh seam, shared with AND-333). */
    fun onRefresh() {
        pagerKey.update { it.copy(refresh = it.refresh + 1) }
    }

    private fun navigateTo(path: String) {
        if (path == _uiState.value.currentPath && !_uiState.value.isSearching) return
        savedState[KEY_PATH] = path
        // Leaving search when navigating folders restores the browse listing.
        searchJob?.cancel()
        _uiState.update {
            it.copy(
                currentPath = path,
                searchQuery = "",
                isSearching = false,
                searchLoading = false,
                searchError = null,
                searchResults = emptyList(),
            )
        }
        pagerKey.update { it.copy(path = path) }
    }

    private suspend fun runSearch(query: String) {
        when (val result = repository.search(query, _uiState.value.searchMode, _uiState.value.sort)) {
            is ApiResult.Success -> _uiState.update {
                it.copy(searchLoading = false, searchError = null, searchResults = result.data)
            }
            is ApiResult.Failure -> _uiState.update {
                it.copy(searchLoading = false, searchError = result.error.message, searchResults = emptyList())
            }
            is ApiResult.NetworkError -> _uiState.update {
                it.copy(searchLoading = false, searchError = OFFLINE_MESSAGE, searchResults = emptyList())
            }
        }
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LENGTH = 2
        const val KEY_PATH = "files_current_path"
        private const val OFFLINE_MESSAGE = "You appear to be offline."
    }
}
