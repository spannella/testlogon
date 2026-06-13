@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.files.ui

import android.text.format.DateUtils
import android.text.format.Formatter
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Sort
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.files.data.FileSort
import com.testlogon.android.feature.files.data.FileSortBy
import com.testlogon.android.feature.files.data.FileSortDir
import com.testlogon.android.feature.files.data.SearchMode
import com.testlogon.android.feature.files.presentation.Breadcrumb
import com.testlogon.android.feature.files.presentation.FilesUiState
import com.testlogon.android.feature.files.presentation.FilesViewModel
import java.time.Instant

/** AND-332 - stable test tags for the file-manager browse screen. */
object FilesTestTags {
    const val SCREEN = "files_screen"
    const val SEARCH = "files_search"
    const val SEARCH_CLEAR = "files_search_clear"
    const val SEARCH_MODE = "files_search_mode"
    const val SORT = "files_sort"
    const val LIST = "files_list"
    const val EMPTY = "files_empty"
    const val ERROR = "files_error"
    const val APPEND_FOOTER = "files_append_footer"
    const val APPEND_RETRY = "files_append_retry"

    /** AND-336 - the import-from-Google-Drive top-bar affordance. */
    const val DRIVE_IMPORT = "files_drive_import"

    /** Per-breadcrumb tag: files_breadcrumb_<index>. */
    fun breadcrumb(index: Int): String = "files_breadcrumb_$index"

    /** Per-row tag: file_row_<path-or-name>. */
    fun row(node: FileNode): String = "file_row_${node.path.ifBlank { node.name }}"

    /** AND-335 - per-row share affordance tag: file_share_<path-or-name>. */
    fun share(node: FileNode): String = "file_share_${node.path.ifBlank { node.name }}"
}

/**
 * AND-332 - route-level entry for the read-only file-manager browse surface. Collects the (non-paging)
 * UI state + the cached browse PagingData, wires one-shot events (NavigateUp -> [onBack];
 * OpenFile -> [onOpenFile], which carries the file path - preview is a later ticket).
 */
@Composable
fun FilesRoute(
    onBack: () -> Unit,
    onOpenFile: (String) -> Unit,
    modifier: Modifier = Modifier,
    // AND-335 - share affordance: opens the owner ShareSheet for the tapped file (defaults to no-op so
    // existing call sites/tests are unaffected). The file is keyed by its path (the backend's file id).
    onShareFile: (String) -> Unit = {},
    // AND-336 - "Import from Google Drive" affordance: opens the backend-mediated Drive picker for the
    // folder currently on screen (defaults to no-op so existing call sites/tests are unaffected).
    onImportFromDrive: (String) -> Unit = {},
    viewModel: FilesViewModel = hiltViewModel(),
    uploadViewModel: com.testlogon.android.feature.files.upload.FilesUploadViewModel = hiltViewModel(),
    downloadViewModel: com.testlogon.android.feature.files.download.FileActionsViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val items = viewModel.pagedItems.collectAsLazyPagingItems()
    val uploadJobs by uploadViewModel.uploadJobs.collectAsStateWithLifecycle()
    var uploadSheetVisible by remember { mutableStateOf(false) }

    // AND-334 - download / open-with state for the tapped file row.
    val downloadState by downloadViewModel.uiState.collectAsStateWithLifecycle()
    var downloadSheetVisible by remember { mutableStateOf(false) }
    var pendingDownloadNode by remember { mutableStateOf<FileNode?>(null) }
    val openLauncher = remember { com.testlogon.android.data.files.download.OpenWithLauncher() }

    androidx.compose.runtime.LaunchedEffect(Unit) {
        downloadViewModel.events.collect { event -> openLauncher.open(context, event.cached) }
    }

    // AND-333 - system document picker; placement is path-based, so we capture the folder on screen.
    val pickFiles = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = androidx.activity.result.contract.ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris ->
        if (uris.isNotEmpty()) {
            uploadViewModel.onFilesPicked(uris, state.currentPath)
            uploadSheetVisible = true
        }
    }

    androidx.compose.runtime.LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                com.testlogon.android.feature.files.presentation.FilesEvent.NavigateUp -> onBack()
                is com.testlogon.android.feature.files.presentation.FilesEvent.OpenFile -> onOpenFile(event.path)
            }
        }
    }

    FilesScreen(
        state = state,
        items = items,
        onUp = viewModel::onUp,
        onBreadcrumb = viewModel::onBreadcrumb,
        onOpenFolder = viewModel::onOpenFolder,
        onOpenFile = viewModel::onOpenFile,
        onSearchChanged = viewModel::onSearchChanged,
        onToggleSearchMode = viewModel::onToggleSearchMode,
        onSortChanged = viewModel::onSortChanged,
        onRefresh = viewModel::onRefresh,
        modifier = modifier,
        onUploadClick = { pickFiles.launch(arrayOf("*/*")) },
        // AND-335 - the per-row share action carries the file path to the owner ShareSheet route.
        onShareFile = { node -> onShareFile(node.path) },
        // AND-336 - the Drive-import action carries the folder on screen as the import target.
        onImportFromDrive = { onImportFromDrive(state.currentPath) },
    )

    if (uploadSheetVisible) {
        com.testlogon.android.feature.files.upload.UploadSheet(
            jobs = uploadJobs,
            onCancel = uploadViewModel::onCancel,
            onRetry = uploadViewModel::onRetry,
            onDismissJob = uploadViewModel::onDismiss,
            onDismiss = { uploadSheetVisible = false },
        )
    }
}

@Composable
fun FilesScreen(
    state: FilesUiState,
    items: LazyPagingItems<FileNode>,
    onUp: () -> Unit,
    onBreadcrumb: (Int) -> Unit,
    onOpenFolder: (FileNode) -> Unit,
    onOpenFile: (FileNode) -> Unit,
    onSearchChanged: (String) -> Unit,
    onToggleSearchMode: () -> Unit,
    onSortChanged: (FileSortBy, FileSortDir, Boolean) -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
    onUploadClick: (() -> Unit)? = null,
    // AND-335 - per-file share action (defaults to no-op so existing call sites/tests are unaffected).
    onShareFile: (FileNode) -> Unit = {},
    // AND-336 - "Import from Google Drive" action (null -> the affordance is hidden, so existing AND-332
    // FilesScreen callers / tests are unaffected).
    onImportFromDrive: (() -> Unit)? = null,
) {
    var sortSheetVisible by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(FilesTestTags.SCREEN),
        floatingActionButton = {
            // AND-333 - upload affordance; only shown when the host wires the picker (defaulted-off so
            // existing AND-332 FilesScreen callers / tests are unaffected).
            if (onUploadClick != null && !state.isSearching) {
                FloatingActionButton(
                    onClick = onUploadClick,
                    modifier = Modifier.testTag(com.testlogon.android.feature.files.upload.UploadTestTags.FAB),
                ) {
                    Icon(
                        Icons.Filled.Upload,
                        contentDescription = stringResource(R.string.files_upload_action),
                    )
                }
            }
        },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.files_title)) },
                navigationIcon = {
                    IconButton(onClick = onUp) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    // AND-336 - import-from-Drive affordance (only when the host wires it; defaulted-off
                    // so existing AND-332 callers / tests are unaffected).
                    if (onImportFromDrive != null && !state.isSearching) {
                        IconButton(
                            onClick = onImportFromDrive,
                            modifier = Modifier.testTag(FilesTestTags.DRIVE_IMPORT),
                        ) {
                            Icon(
                                Icons.Filled.CloudDownload,
                                contentDescription = stringResource(R.string.drive_title),
                            )
                        }
                    }
                    IconButton(
                        onClick = { sortSheetVisible = true },
                        modifier = Modifier.testTag(FilesTestTags.SORT),
                    ) {
                        Icon(Icons.Filled.Sort, contentDescription = stringResource(R.string.files_sort))
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            BreadcrumbRow(breadcrumbs = state.breadcrumbs, onBreadcrumb = onBreadcrumb)
            SearchField(
                query = state.searchQuery,
                mode = state.searchMode,
                onSearchChanged = onSearchChanged,
                onClear = { onSearchChanged("") },
                onToggleMode = onToggleSearchMode,
            )
            HorizontalDivider()
            Box(Modifier.fillMaxSize()) {
                if (state.isSearching) {
                    SearchContent(
                        state = state,
                        onOpenFolder = onOpenFolder,
                        onOpenFile = onOpenFile,
                        onShareFile = onShareFile,
                    )
                } else {
                    BrowseContent(
                        items = items,
                        onRefresh = onRefresh,
                        onOpenFolder = onOpenFolder,
                        onOpenFile = onOpenFile,
                        onShareFile = onShareFile,
                    )
                }
            }
        }
    }

    if (sortSheetVisible) {
        SortSheet(
            sort = state.sort,
            onSortChanged = onSortChanged,
            onDismiss = { sortSheetVisible = false },
        )
    }
}

@Composable
private fun BreadcrumbRow(
    breadcrumbs: List<Breadcrumb>,
    onBreadcrumb: (Int) -> Unit,
) {
    val goToFmt = stringResource(R.string.files_breadcrumb_cd)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        breadcrumbs.forEachIndexed { index, crumb ->
            if (index > 0) {
                Icon(
                    Icons.Filled.ChevronRight,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val cd = goToFmt.format(crumb.name)
            TextButton(
                onClick = { onBreadcrumb(index) },
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(FilesTestTags.breadcrumb(index))
                    .clearAndSetSemantics { contentDescription = cd },
            ) {
                Text(
                    text = crumb.name,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        }
    }
}

@Composable
private fun SearchField(
    query: String,
    mode: SearchMode,
    onSearchChanged: (String) -> Unit,
    onClear: () -> Unit,
    onToggleMode: () -> Unit,
) {
    val label = stringResource(R.string.files_search_label)
    val modeLabel = when (mode) {
        SearchMode.PREFIX -> stringResource(R.string.files_search_mode_prefix)
        SearchMode.TEXT -> stringResource(R.string.files_search_mode_text)
    }
    val modeToggleCd = stringResource(R.string.files_search_mode_toggle)
    OutlinedTextField(
        value = query,
        onValueChange = onSearchChanged,
        singleLine = true,
        label = { Text(label) },
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (query.isNotEmpty()) {
                    IconButton(onClick = onClear, modifier = Modifier.testTag(FilesTestTags.SEARCH_CLEAR)) {
                        Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.files_search_clear))
                    }
                }
                TextButton(
                    onClick = onToggleMode,
                    modifier = Modifier
                        .testTag(FilesTestTags.SEARCH_MODE)
                        .clearAndSetSemantics { contentDescription = "$modeToggleCd: $modeLabel" },
                ) { Text(modeLabel) }
            }
        },
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag(FilesTestTags.SEARCH),
    )
}

@Composable
private fun BrowseContent(
    items: LazyPagingItems<FileNode>,
    onRefresh: () -> Unit,
    onOpenFolder: (FileNode) -> Unit,
    onOpenFile: (FileNode) -> Unit,
    onShareFile: (FileNode) -> Unit = {},
) {
    val listState = rememberLazyListState()
    val refresh = items.loadState.refresh
    val isRefreshing = refresh is LoadState.Loading && items.itemCount > 0
    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Box(Modifier.fillMaxSize()) {
            when {
                refresh is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                refresh is LoadState.Error && items.itemCount == 0 ->
                    ErrorState(
                        message = stringResource(R.string.files_error),
                        onRetry = items::retry,
                        modifier = Modifier.testTag(FilesTestTags.ERROR),
                    )

                refresh is LoadState.NotLoading && items.itemCount == 0 ->
                    EmptyState(
                        title = stringResource(R.string.files_empty_folder),
                        modifier = Modifier.testTag(FilesTestTags.EMPTY),
                    )

                else -> LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize().testTag(FilesTestTags.LIST),
                ) {
                    items(
                        count = items.itemCount,
                        key = { index -> items.peek(index)?.path ?: index },
                    ) { index ->
                        val node = items[index]
                        if (node != null) {
                            FileRow(
                                node = node,
                                onClick = { if (node.type == FileNodeType.FOLDER) onOpenFolder(node) else onOpenFile(node) },
                                onShare = if (node.type == FileNodeType.FOLDER) null else ({ onShareFile(node) }),
                            )
                        }
                    }
                    appendFooter(items)
                }
            }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.appendFooter(items: LazyPagingItems<FileNode>) {
    when (items.loadState.append) {
        is LoadState.Loading -> item {
            Box(
                Modifier.fillMaxWidth().padding(16.dp).testTag(FilesTestTags.APPEND_FOOTER),
                contentAlignment = Alignment.Center,
            ) { CircularProgressIndicator(modifier = Modifier.size(24.dp)) }
        }
        is LoadState.Error -> item {
            Row(
                Modifier.fillMaxWidth().padding(16.dp).testTag(FilesTestTags.APPEND_FOOTER),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.files_append_error), style = MaterialTheme.typography.bodyMedium)
                TextButton(
                    onClick = items::retry,
                    modifier = Modifier.testTag(FilesTestTags.APPEND_RETRY),
                ) { Text(stringResource(R.string.action_retry)) }
            }
        }
        else -> Unit
    }
}

@Composable
private fun SearchContent(
    state: FilesUiState,
    onOpenFolder: (FileNode) -> Unit,
    onOpenFile: (FileNode) -> Unit,
    onShareFile: (FileNode) -> Unit = {},
) {
    when {
        state.searchLoading -> LoadingState()

        state.searchError != null ->
            ErrorState(
                message = state.searchError,
                onRetry = {},
                modifier = Modifier.testTag(FilesTestTags.ERROR),
            )

        state.searchResults.isEmpty() ->
            EmptyState(
                title = stringResource(R.string.files_empty_search),
                modifier = Modifier.testTag(FilesTestTags.EMPTY),
            )

        else -> LazyColumn(modifier = Modifier.fillMaxSize().testTag(FilesTestTags.LIST)) {
            items(state.searchResults, key = { it.path.ifBlank { it.name } }) { node ->
                FileRow(
                    node = node,
                    onClick = { if (node.type == FileNodeType.FOLDER) onOpenFolder(node) else onOpenFile(node) },
                    onShare = if (node.type == FileNodeType.FOLDER) null else ({ onShareFile(node) }),
                )
            }
        }
    }
}

/** AND-332 - one browse / search row: type icon, name, file size + relative modified time. */
@Composable
private fun FileRow(
    node: FileNode,
    onClick: () -> Unit,
    onShare: (() -> Unit)? = null,
) {
    val context = LocalContext.current
    val isFolder = node.type == FileNodeType.FOLDER
    val sizeText = if (!isFolder && node.sizeBytes != null) {
        Formatter.formatShortFileSize(context, node.sizeBytes!!)
    } else {
        null
    }
    val relative = remember(node.updatedAt) { relativeTime(node.updatedAt) }
    val typeLabel = if (isFolder) {
        stringResource(R.string.files_folder_cd, node.name)
    } else {
        stringResource(R.string.files_file_cd, node.name)
    }
    val cd = buildString {
        append(typeLabel)
        sizeText?.let { append(", ").append(it) }
        if (relative.isNotEmpty()) append(", ").append(relative)
    }
    val shareCd = stringResource(R.string.share_action_share)

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(FilesTestTags.row(node)),
        verticalAlignment = Alignment.CenterVertically,
    ) {
      Row(
        modifier = Modifier
            .weight(1f)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .clearAndSetSemantics { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = iconFor(node),
            contentDescription = null,
            tint = if (isFolder) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp),
        )
        Column(
            modifier = Modifier.padding(start = 12.dp).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = node.name,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (node.isEncrypted) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        modifier = Modifier.padding(start = 6.dp).size(14.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            val meta = buildString {
                sizeText?.let { append(it) }
                if (relative.isNotEmpty()) {
                    if (isNotEmpty()) append(" · ")
                    append(relative)
                }
            }
            if (meta.isNotEmpty()) {
                Text(
                    text = meta,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
      }
        // AND-335 - per-file share affordance (files only; null for folders).
        if (onShare != null) {
            IconButton(
                onClick = onShare,
                modifier = Modifier
                    .padding(end = 8.dp)
                    .clearAndSetSemantics { contentDescription = shareCd }
                    .testTag(FilesTestTags.share(node)),
            ) {
                Icon(imageVector = Icons.Filled.Share, contentDescription = null)
            }
        }
    }
}

/** Picks a row icon from node kind, then content-type / preview-kind family for files. */
private fun iconFor(node: FileNode): ImageVector {
    if (node.type == FileNodeType.FOLDER) return Icons.Filled.Folder
    val family = (node.previewKind ?: node.contentType.orEmpty()).lowercase()
    return when {
        family.startsWith("image") || family == "image" -> Icons.Filled.Image
        family.startsWith("video") || family == "video" -> Icons.Filled.Movie
        else -> Icons.AutoMirrored.Filled.InsertDriveFile
    }
}

/** AND-332 - sort affordance: a modal sheet to pick sort-by, direction, and the folders-first toggle. */
@Composable
private fun SortSheet(
    sort: FileSort,
    onSortChanged: (FileSortBy, FileSortDir, Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(Modifier.fillMaxWidth().padding(bottom = 24.dp)) {
            Text(
                text = stringResource(R.string.files_sort_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            SortOption(stringResource(R.string.files_sort_by_name), sort.sortBy == FileSortBy.NAME) {
                onSortChanged(FileSortBy.NAME, sort.sortDir, sort.foldersFirst)
            }
            SortOption(stringResource(R.string.files_sort_by_updated), sort.sortBy == FileSortBy.UPDATED) {
                onSortChanged(FileSortBy.UPDATED, sort.sortDir, sort.foldersFirst)
            }
            SortOption(stringResource(R.string.files_sort_by_size), sort.sortBy == FileSortBy.SIZE) {
                onSortChanged(FileSortBy.SIZE, sort.sortDir, sort.foldersFirst)
            }
            HorizontalDivider()
            SortOption(stringResource(R.string.files_sort_dir_asc), sort.sortDir == FileSortDir.ASC) {
                onSortChanged(sort.sortBy, FileSortDir.ASC, sort.foldersFirst)
            }
            SortOption(stringResource(R.string.files_sort_dir_desc), sort.sortDir == FileSortDir.DESC) {
                onSortChanged(sort.sortBy, FileSortDir.DESC, sort.foldersFirst)
            }
            HorizontalDivider()
            SortOption(stringResource(R.string.files_sort_folders_first), sort.foldersFirst) {
                onSortChanged(sort.sortBy, sort.sortDir, !sort.foldersFirst)
            }
        }
    }
}

@Composable
private fun SortOption(label: String, selected: Boolean, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(label) },
        trailingContent = {
            if (selected) Icon(Icons.Filled.Check, contentDescription = null)
        },
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clickable(onClick = onClick),
    )
}

/** Relative-time copy from a nullable [Instant] (minSdk24-safe; not used in JVM unit tests). */
private fun relativeTime(instant: Instant?): String {
    val epochMs = instant?.toEpochMilli() ?: return ""
    if (epochMs <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochMs,
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
