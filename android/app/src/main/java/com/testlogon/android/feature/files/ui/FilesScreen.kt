@file:OptIn(ExperimentalMaterial3Api::class, androidx.compose.foundation.ExperimentalFoundationApi::class)

package com.testlogon.android.feature.files.ui

import android.text.format.DateUtils
import android.text.format.Formatter
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.outlined.ReceiptLong
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Sort
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.AlertDialog
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
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import coil.ImageLoader
import coil.compose.AsyncImage
import coil.compose.AsyncImagePainter
import coil.request.ImageRequest
import coil.request.videoFrameMillis
import com.testlogon.android.R
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.files.data.FileSort
import com.testlogon.android.feature.files.data.FileSortBy
import com.testlogon.android.feature.files.data.FileSortDir
import com.testlogon.android.feature.files.data.FilesImageLoaderEntryPoint
import com.testlogon.android.feature.files.data.SearchMode
import com.testlogon.android.feature.files.presentation.Breadcrumb
import com.testlogon.android.feature.files.presentation.FilePath
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

    /** FE-170 - the Trading Documents entry-point tile at the file-manager root. */
    const val TRADING_DOCS_TILE = "files_trading_docs_tile"

    /** FM1 - the floating chip shown while a row is being dragged to a folder. */
    const val DRAG_CHIP = "files_drag_chip"

    /** FM4 - the inline rename text field that replaces a row's name while editing. */
    const val RENAME_FIELD = "files_rename_field"

    /** FM6/FM3 - the move/copy destination-picker banner + its Confirm / Cancel actions. */
    const val TRANSFER_BANNER = "files_transfer_banner"
    const val TRANSFER_CONFIRM = "files_transfer_confirm"
    const val TRANSFER_CANCEL = "files_transfer_cancel"

    /** AND-336 - the import-from-Google-Drive top-bar affordance. */
    const val DRIVE_IMPORT = "files_drive_import"

    /** Per-breadcrumb tag: files_breadcrumb_<index>. */
    fun breadcrumb(index: Int): String = "files_breadcrumb_$index"

    /** Per-row tag: file_row_<path-or-name>. */
    fun row(node: FileNode): String = "file_row_${node.path.ifBlank { node.name }}"

    /** AND-335 - per-row share affordance tag: file_share_<path-or-name>. */
    fun share(node: FileNode): String = "file_share_${node.path.ifBlank { node.name }}"

    /** #6 - per-row image-thumbnail tag: file_thumb_<path-or-name>. */
    fun thumbnail(node: FileNode): String = "file_thumb_${node.path.ifBlank { node.name }}"

    /** #6 - the PDF / non-image download-preview progress sheet. */
    const val DOWNLOAD_SHEET = "files_download_sheet"
}

/**
 * AND-332 - route-level entry for the read-only file-manager browse surface. Collects the (non-paging)
 * UI state + the cached browse PagingData, wires one-shot events (NavigateUp -> [onBack];
 * OpenFile -> [onOpenFile], which carries the file path - preview is a later ticket).
 */
/**
 * FM1 - shared state for drag-and-drop MOVE. A row is "picked up" on long-press-drag; while
 * [draggedNode] is non-null the finger position is tracked in ROOT coordinates ([pointer]) and
 * hit-tested against the registered destination bounds ([dropTargets] = path -> bounds-in-root for
 * every visible FOLDER row plus the breadcrumb "up" parent). [hoverPath] is the folder under the
 * finger (highlighted). On release the screen reads [finish] = (node, destinationFolderPath).
 */
private class DragMoveState {
    var draggedNode by mutableStateOf<FileNode?>(null)
        private set
    var pointer by mutableStateOf(Offset.Zero)
        private set
    val dropTargets = mutableStateMapOf<String, Rect>()

    val hoverPath by derivedStateOf {
        val node = draggedNode ?: return@derivedStateOf null
        dropTargets.entries
            .filter { it.key != node.path && it.value.contains(pointer) }
            .minByOrNull { it.value.width * it.value.height } // smallest (topmost) target wins
            ?.key
    }

    val isDragging: Boolean get() = draggedNode != null

    fun begin(node: FileNode, anchor: Offset) { draggedNode = node; pointer = anchor }
    fun update(delta: Offset) { pointer += delta }
    fun cancel() { draggedNode = null }

    /** Returns (node, destFolderPath) to move, or null if dropped on empty space / self / origin. */
    fun finish(): Pair<FileNode, String>? {
        val node = draggedNode
        val dest = hoverPath
        draggedNode = null
        if (node == null || dest == null) return null
        return node to dest
    }

    fun registerTarget(path: String, bounds: Rect) { dropTargets[path] = bounds }
    fun unregisterTarget(path: String) { dropTargets.remove(path) }
}

/** FM6/FM3 - which kind of transfer the destination-picker banner is confirming. */
private enum class TransferOp { MOVE, COPY }

/** FM6/FM3 - an in-flight "tap a destination folder" transfer of [node] via [op]. */
private data class Transfer(val node: FileNode, val op: TransferOp)

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
    // FE-170 - open the Trading Documents area (statements/1099s/confirmations). Defaults no-op so
    // existing call sites / tests are unaffected.
    onOpenTradingDocuments: () -> Unit = {},
    viewModel: FilesViewModel = hiltViewModel(),
    uploadViewModel: com.testlogon.android.feature.files.upload.FilesUploadViewModel = hiltViewModel(),
    downloadViewModel: com.testlogon.android.feature.files.download.FileActionsViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    // #6 - the AUTHENTICATED Coil loader for file thumbnails / previews (the global loader has no session
    // cookies, so the cookie-authed /v1/fs image endpoints would 401). Fetched via a Hilt EntryPoint
    // because this @Composable already injects its VMs via hiltViewModel and the loader is a plain @Provides.
    val authedImageLoader = remember(context) {
        dagger.hilt.android.EntryPointAccessors.fromApplication(
            context.applicationContext,
            FilesImageLoaderEntryPoint::class.java,
        ).filesImageLoader()
    }
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val items = viewModel.pagedItems.collectAsLazyPagingItems()
    val uploadJobs by uploadViewModel.uploadJobs.collectAsStateWithLifecycle()
    var uploadSheetVisible by remember { mutableStateOf(false) }

    // AND-334 - download / open-with state for the tapped file row.
    val downloadState by downloadViewModel.uiState.collectAsStateWithLifecycle()
    var downloadSheetVisible by remember { mutableStateOf(false) }
    var pendingDownloadNode by remember { mutableStateOf<FileNode?>(null) }
    val openLauncher = remember { com.testlogon.android.data.files.download.OpenWithLauncher() }

    // F14 - when an image row is tapped we show the full-screen viewer in-place instead of the
    // no-op file handoff. Holds the derived (server-relative) image url; null = viewer closed.
    var previewImageUrl by remember { mutableStateOf<String?>(null) }

    androidx.compose.runtime.LaunchedEffect(Unit) {
        downloadViewModel.events.collect { event ->
            // #6 - download finished: fire the external viewer and dismiss the progress sheet.
            openLauncher.open(context, event.cached)
            downloadSheetVisible = false
            pendingDownloadNode = null
        }
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
                // B13 - surface CRUD outcomes (incl. same-dir copy) so file ops are never silent.
                is com.testlogon.android.feature.files.presentation.FilesEvent.CrudMessage ->
                    android.widget.Toast.makeText(
                        context,
                        context.getString(crudMessageRes(event.kind, event.success)),
                        android.widget.Toast.LENGTH_SHORT,
                    ).show()
            }
        }
    }

    FilesScreen(
        state = state,
        items = items,
        onUp = viewModel::onUp,
        onBreadcrumb = viewModel::onBreadcrumb,
        onOpenFolder = viewModel::onOpenFolder,
        onOpenFile = { node ->
            // #6 - image files open the in-place full-screen preview (authed Coil loader). Every other
            // file (PDF, docs, ...) downloads via the authenticated pipeline then opens with an external
            // viewer (ACTION_VIEW via FileProvider) - this is the working PDF-preview path.
            if (isImageNode(node)) {
                previewImageUrl = imageViewUrl(node)
            } else {
                downloadSheetVisible = true
                pendingDownloadNode = node
                downloadViewModel.onDownload(node)
            }
        },
        imageLoader = authedImageLoader,
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
        // FE-170 - the Trading Documents entry point (a tile at the files root).
        onOpenTradingDocuments = onOpenTradingDocuments,
        // F13 - long-press CRUD context-menu actions wired to the existing FilesViewModel ops.
        onRename = { node, newName -> viewModel.rename(node.path, newName, node.type == FileNodeType.FOLDER) },
        onDelete = { node -> viewModel.delete(node.path, node.type == FileNodeType.FOLDER) },
        onMove = { node, dst -> viewModel.move(node.path, dst) },
        // FM3 - copy wires the BK1 copy endpoint (file-only; dst is the full destination path).
        onCopy = { node, dst -> viewModel.copy(node.path, dst) },
        onCreateFolder = { name -> viewModel.createFolder(name) },
    )

    // #6 - the in-place full-screen image viewer, fed the AUTHENTICATED Coil loader so the cookie-authed
    // /v1/fs/preview endpoint resolves (the global loader would 401).
    previewImageUrl?.let { url ->
        com.testlogon.android.feature.messaging.media.FullScreenImageViewer(
            url = url,
            onClose = { previewImageUrl = null },
            imageLoader = authedImageLoader,
        )
    }

    // #6 - PDF / non-image preview: a small progress sheet while the file downloads; on success the
    // FileActionsViewModel emits OpenFile -> openLauncher fires the external viewer (handled above).
    if (downloadSheetVisible) {
        FileDownloadSheet(
            node = pendingDownloadNode,
            state = downloadState,
            onCancel = {
                downloadViewModel.onCancel()
                downloadSheetVisible = false
                pendingDownloadNode = null
            },
            onDismiss = {
                downloadViewModel.onDismiss()
                downloadSheetVisible = false
                pendingDownloadNode = null
            },
            onRetry = { pendingDownloadNode?.let { downloadViewModel.onDownload(it) } },
        )
    }

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
    // #6 - authenticated Coil loader used for image-row thumbnails (null = icons only, e.g. tests/previews).
    imageLoader: ImageLoader? = null,
    // AND-335 - per-file share action (defaults to no-op so existing call sites/tests are unaffected).
    onShareFile: (FileNode) -> Unit = {},
    // AND-336 - "Import from Google Drive" action (null -> the affordance is hidden, so existing AND-332
    // FilesScreen callers / tests are unaffected).
    onImportFromDrive: (() -> Unit)? = null,
    // FE-170 - Trading Documents entry point (null -> the tile is hidden, so existing FilesScreen
    // callers / tests are unaffected).
    onOpenTradingDocuments: (() -> Unit)? = null,
    // F13 - long-press context-menu CRUD actions (defaulted no-op so existing callers / tests are
    // unaffected). Rename/Delete/New-folder are fully wired; Move targets a destination folder path.
    onRename: (FileNode, String) -> Unit = { _, _ -> },
    onDelete: (FileNode) -> Unit = {},
    onMove: (FileNode, String) -> Unit = { _, _ -> },
    // FM3 - copy a file to a destination folder (dst = full destination path). Defaulted no-op so existing
    // callers / tests are unaffected.
    onCopy: (FileNode, String) -> Unit = { _, _ -> },
    onCreateFolder: (String) -> Unit = {},
) {
    var sortSheetVisible by remember { mutableStateOf(false) }
    // F13 - which row's context menu / dialog is active (null = none). Shared across browse + search.
    var contextNode by remember { mutableStateOf<FileNode?>(null) }
    // FM4 - inline rename: the path of the row currently being renamed in-place (null = none). Editing
    // the name on the row replaces the old rename dialog.
    var renamingPath by remember { mutableStateOf<String?>(null) }
    var deleteNode by remember { mutableStateOf<FileNode?>(null) }
    // FM6/FM3 - transfer mode: the node being moved/copied to a folder the user taps into, plus which op.
    // While non-null a banner ("Moving/Copying <name> - tap a folder") is shown with Confirm / Cancel.
    var transfer by remember { mutableStateOf<Transfer?>(null) }
    var newFolderVisible by remember { mutableStateOf(false) }
    // FM1 - drag-and-drop MOVE state, shared by the browse list, breadcrumb + the drag chip.
    val dragState = remember { DragMoveState() }

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
            BreadcrumbRow(
                breadcrumbs = state.breadcrumbs,
                onBreadcrumb = onBreadcrumb,
                dragState = dragState,
            )
            SearchField(
                query = state.searchQuery,
                mode = state.searchMode,
                onSearchChanged = onSearchChanged,
                onClear = { onSearchChanged("") },
                onToggleMode = onToggleSearchMode,
            )
            HorizontalDivider()
            // FE-170 - Trading Documents entry point: a tile at the file-manager root that navigates to
            // the statements / 1099s / trade-confirmations area. Shown only at the root and only when the
            // host wired the callback (defaulted-off so existing FilesScreen callers / tests are unaffected).
            if (onOpenTradingDocuments != null && !state.isSearching && state.currentPath == FilePath.ROOT) {
                TradingDocsTile(onClick = onOpenTradingDocuments)
                HorizontalDivider()
            }
            // FM6/FM3 - destination-picker banner: while a transfer is active the user navigates into the
            // target folder (folder taps drill in, breadcrumbs jump) then taps Move/Copy here. Cancel exits.
            transfer?.let { t ->
                TransferBanner(
                    transfer = t,
                    destinationPath = state.currentPath,
                    onConfirm = {
                        val dst = FilePath.child(state.currentPath, t.node.name)
                        when (t.op) {
                            TransferOp.MOVE -> onMove(t.node, dst)
                            TransferOp.COPY -> onCopy(t.node, dst)
                        }
                        transfer = null
                    },
                    onCancel = { transfer = null },
                )
            }
            Box(Modifier.fillMaxSize()) {
                if (state.isSearching) {
                    SearchContent(
                        state = state,
                        onOpenFolder = onOpenFolder,
                        onOpenFile = onOpenFile,
                        onShareFile = onShareFile,
                        onLongPress = { contextNode = it },
                        renamingPath = renamingPath,
                        onRenameCommit = { node, newName -> onRename(node, newName); renamingPath = null },
                        onRenameCancel = { renamingPath = null },
                        imageLoader = imageLoader,
                    )
                } else {
                    BrowseContent(
                        items = items,
                        onRefresh = onRefresh,
                        onOpenFolder = onOpenFolder,
                        onOpenFile = onOpenFile,
                        onShareFile = onShareFile,
                        onLongPress = { contextNode = it },
                        renamingPath = renamingPath,
                        onRenameCommit = { node, newName -> onRename(node, newName); renamingPath = null },
                        onRenameCancel = { renamingPath = null },
                        dragState = dragState,
                        onDrop = { node, destFolder ->
                            // dst is the FULL new path of the moved node (the backend splits its
                            // parent), so place the node INSIDE the destination folder under its name.
                            onMove(node, FilePath.child(destFolder, node.name))
                        },
                        imageLoader = imageLoader,
                    )
                }
            }
        }
    }

    // FM1 - the floating "lifted" chip that follows the finger while dragging a row.
    dragState.draggedNode?.let { node ->
        val density = LocalDensity.current
        Popup(properties = PopupProperties(focusable = false)) {
            val p = dragState.pointer
            Row(
                modifier = Modifier
                    .zIndex(1f)
                    .offset {
                        IntOffset(
                            x = (p.x - with(density) { 24.dp.toPx() }).toInt(),
                            y = (p.y - with(density) { 24.dp.toPx() }).toInt(),
                        )
                    }
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.secondaryContainer)
                    .padding(horizontal = 12.dp, vertical = 8.dp)
                    .testTag(FilesTestTags.DRAG_CHIP),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = iconFor(node),
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                )
                Text(
                    text = node.name,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(start = 8.dp),
                )
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

    // F13 - the long-press context menu for the active row.
    contextNode?.let { node ->
        FileContextSheet(
            node = node,
            // FM4 - rename now edits the row name in-place instead of opening a dialog.
            onRename = { contextNode = null; renamingPath = node.path },
            onDelete = { contextNode = null; deleteNode = node },
            // FM6 - move enters a "tap a destination folder" mode (was a type-a-path dialog).
            onMove = { contextNode = null; transfer = Transfer(node, TransferOp.MOVE) },
            // FM3 - copy enters the same destination-picker mode (files only; folder copy unsupported).
            onCopy = { contextNode = null; transfer = Transfer(node, TransferOp.COPY) },
            onNewFolder = { contextNode = null; newFolderVisible = true },
            onDismiss = { contextNode = null },
        )
    }

    deleteNode?.let { node ->
        AlertDialog(
            onDismissRequest = { deleteNode = null },
            title = { Text(stringResource(R.string.files_delete_title)) },
            text = { Text(stringResource(R.string.files_delete_message, node.name)) },
            confirmButton = {
                TextButton(onClick = { onDelete(node); deleteNode = null }) {
                    Text(stringResource(R.string.files_delete_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteNode = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    if (newFolderVisible) {
        TextEntryDialog(
            title = stringResource(R.string.files_new_folder_title),
            label = stringResource(R.string.files_new_folder_label),
            confirmLabel = stringResource(R.string.files_new_folder_confirm),
            initial = "",
            onConfirm = { name -> onCreateFolder(name); newFolderVisible = false },
            onDismiss = { newFolderVisible = false },
        )
    }
}

@Composable
private fun BreadcrumbRow(
    breadcrumbs: List<Breadcrumb>,
    onBreadcrumb: (Int) -> Unit,
    dragState: DragMoveState? = null,
) {
    val goToFmt = stringResource(R.string.files_breadcrumb_cd)
    // FM1 - the PARENT crumb (second-to-last) doubles as a "move up one level" drop target while
    // dragging. Registered under its folder path so a row dropped on it moves into the parent folder.
    val parentIndex = breadcrumbs.size - 2
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
            val isDropTarget = dragState != null && dragState.isDragging && index == parentIndex
            val isHovered = isDropTarget && dragState?.hoverPath == crumb.path
            var crumbMod = Modifier
                .heightIn(min = 48.dp)
                .testTag(FilesTestTags.breadcrumb(index))
            if (dragState != null && index == parentIndex) {
                crumbMod = crumbMod.onGloballyPositioned {
                    dragState.registerTarget(crumb.path, it.boundsInRoot())
                }
            }
            if (isHovered) {
                crumbMod = crumbMod
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.primaryContainer)
            }
            TextButton(
                onClick = { onBreadcrumb(index) },
                modifier = crumbMod.clearAndSetSemantics { contentDescription = cd },
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
    onLongPress: (FileNode) -> Unit = {},
    // FM4 - inline rename plumbing.
    renamingPath: String? = null,
    onRenameCommit: (FileNode, String) -> Unit = { _, _ -> },
    onRenameCancel: () -> Unit = {},
    dragState: DragMoveState? = null,
    onDrop: (FileNode, String) -> Unit = { _, _ -> },
    imageLoader: ImageLoader? = null,
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
                        // Unique key: path can legitimately collide (dup nodes) and a duplicate
                        // LazyColumn key crashes the whole list, so include the index.
                        key = { index -> "${items.peek(index)?.path.orEmpty()}#$index" },
                    ) { index ->
                        val node = items[index]
                        if (node != null) {
                            FileRow(
                                node = node,
                                onClick = { if (node.type == FileNodeType.FOLDER) onOpenFolder(node) else onOpenFile(node) },
                                onLongClick = { onLongPress(node) },
                                onShare = if (node.type == FileNodeType.FOLDER) null else ({ onShareFile(node) }),
                                isRenaming = renamingPath == node.path,
                                onRenameCommit = { newName -> onRenameCommit(node, newName) },
                                onRenameCancel = onRenameCancel,
                                dragState = dragState,
                                onDrop = onDrop,
                                imageLoader = imageLoader,
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
    onLongPress: (FileNode) -> Unit = {},
    // FM4 - inline rename plumbing.
    renamingPath: String? = null,
    onRenameCommit: (FileNode, String) -> Unit = { _, _ -> },
    onRenameCancel: () -> Unit = {},
    imageLoader: ImageLoader? = null,
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
                    onLongClick = { onLongPress(node) },
                    onShare = if (node.type == FileNodeType.FOLDER) null else ({ onShareFile(node) }),
                    isRenaming = renamingPath == node.path,
                    onRenameCommit = { newName -> onRenameCommit(node, newName) },
                    onRenameCancel = onRenameCancel,
                    imageLoader = imageLoader,
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
    onLongClick: (() -> Unit)? = null,
    onShare: (() -> Unit)? = null,
    // FM4 - when [isRenaming] the name area becomes an inline editable field; commit calls
    // [onRenameCommit](newName), cancel (Esc / focus loss / blank) calls [onRenameCancel].
    isRenaming: Boolean = false,
    onRenameCommit: (String) -> Unit = {},
    onRenameCancel: () -> Unit = {},
    // FM1 - when provided, the row is draggable (long-press to pick up) and FOLDER rows register as
    // drop targets. A drop on a folder calls [onDrop](draggedNode, destFolderPath).
    dragState: DragMoveState? = null,
    onDrop: (FileNode, String) -> Unit = { _, _ -> },
    // #6 - authenticated Coil loader for the leading image thumbnail (null = generic icon only).
    imageLoader: ImageLoader? = null,
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

    // FM1 - drop-target highlight + dragged-row dim.
    val isDragged = dragState?.draggedNode?.path == node.path
    val isDropHovered = dragState != null && isFolder &&
        dragState.isDragging && dragState.hoverPath == node.path && !isDragged

    var rowMod = Modifier
        .fillMaxWidth()
        .heightIn(min = 48.dp)
        .testTag(FilesTestTags.row(node))
    if (dragState != null) {
        if (isFolder) {
            // FOLDER rows register their root bounds so a dropped node can be hit-tested onto them.
            rowMod = rowMod.onGloballyPositioned {
                dragState.registerTarget(node.path, it.boundsInRoot())
            }
        }
        if (isDropHovered) {
            rowMod = rowMod
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.primaryContainer)
        }
        if (isDragged) rowMod = rowMod.alpha(0.4f)
    }

    Row(
        modifier = rowMod,
        verticalAlignment = Alignment.CenterVertically,
    ) {
      // FM1 - drag pickup lives on a dedicated handle modifier so combinedClickable still owns the
      // tap + the quick long-press (context menu fallback). The drag gesture only fires once the
      // finger MOVES after the long-press threshold, so a stationary long-press opens the menu.
      val dragMod = if (dragState != null) {
          Modifier.pointerInput(node.path) {
              detectDragGesturesAfterLongPress(
                  onDragStart = { offset -> dragState.begin(node, offset) },
                  onDrag = { change, delta ->
                      change.consume()
                      dragState.update(delta)
                  },
                  onDragEnd = {
                      dragState.finish()?.let { (n, dst) -> onDrop(n, dst) }
                  },
                  onDragCancel = { dragState.cancel() },
              )
          }
      } else {
          Modifier
      }
      // FM4 - while renaming, the row's tap/drag is suppressed so the inline field owns all interaction.
      val contentMod = if (isRenaming) {
          Modifier.weight(1f).padding(horizontal = 16.dp, vertical = 8.dp)
      } else {
          Modifier
              .weight(1f)
              .combinedClickable(onClick = onClick, onLongClick = onLongClick)
              .then(dragMod)
              .padding(horizontal = 16.dp, vertical = 12.dp)
              .clearAndSetSemantics { contentDescription = cd }
      }
      Row(
        modifier = contentMod,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // #6 - image files show a real Coil thumbnail (authed loader -> /v1/fs/thumbnail); on a missing
        // loader or a load error this falls back to the generic type icon.
        // #9 - VIDEO files show a first-frame thumbnail (Coil VideoFrameDecoder over the raw bytes of
        // /v1/fs/download) with a small play glyph overlay; same error -> generic-icon fallback.
        val isVideo = isVideoNode(node)
        if (imageLoader != null && (isImageNode(node) || isVideo)) {
            var thumbFailed by remember(node.path) { mutableStateOf(false) }
            if (thumbFailed) {
                Icon(
                    imageVector = iconFor(node),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(40.dp),
                )
            } else {
                Box(modifier = Modifier.size(40.dp)) {
                    AsyncImage(
                        model = ImageRequest.Builder(context)
                            .data(if (isVideo) videoThumbnailUrl(node) else thumbnailUrl(node))
                            .crossfade(true)
                            .apply { if (isVideo) videoFrameMillis(0L) }
                            .build(),
                        imageLoader = imageLoader,
                        contentDescription = null,
                        contentScale = androidx.compose.ui.layout.ContentScale.Crop,
                        onState = { st -> if (st is AsyncImagePainter.State.Error) thumbFailed = true },
                        modifier = Modifier
                            .matchParentSize()
                            .clip(RoundedCornerShape(6.dp))
                            .testTag(FilesTestTags.thumbnail(node)),
                    )
                    // #9 - play glyph overlay so a video thumbnail reads as a video, not a still image.
                    if (isVideo) {
                        Icon(
                            imageVector = Icons.Filled.PlayArrow,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier
                                .align(Alignment.Center)
                                .size(20.dp)
                                .clip(CircleShape)
                                .background(Color.Black.copy(alpha = 0.45f))
                                .padding(2.dp),
                        )
                    }
                }
            }
        } else {
            Icon(
                imageVector = iconFor(node),
                contentDescription = null,
                tint = if (isFolder) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp),
            )
        }
        Column(
            modifier = Modifier.padding(start = 12.dp).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            if (isRenaming) {
                InlineRenameField(
                    initial = node.name,
                    onCommit = onRenameCommit,
                    onCancel = onRenameCancel,
                )
            } else {
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
      }
        // AND-335 - per-file share affordance (files only; null for folders). Hidden while renaming.
        if (onShare != null && !isRenaming) {
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

/**
 * B13 - maps a [CrudKind] + success flag to a localized toast string so every file op (create / rename /
 * delete / move / COPY) gives the user clear feedback. Same-dir copy lands here as COPY+success once the
 * backend auto-suffix ((1)) creates the duplicate.
 */
private fun crudMessageRes(
    kind: com.testlogon.android.feature.files.presentation.CrudKind,
    success: Boolean,
): Int = when (kind) {
    com.testlogon.android.feature.files.presentation.CrudKind.COPY ->
        if (success) R.string.files_crud_copy_ok else R.string.files_crud_copy_failed
    com.testlogon.android.feature.files.presentation.CrudKind.MOVE,
    com.testlogon.android.feature.files.presentation.CrudKind.MOVE_BATCH ->
        if (success) R.string.files_crud_move_ok else R.string.files_crud_move_failed
    com.testlogon.android.feature.files.presentation.CrudKind.RENAME ->
        if (success) R.string.files_crud_rename_ok else R.string.files_crud_rename_failed
    com.testlogon.android.feature.files.presentation.CrudKind.DELETE,
    com.testlogon.android.feature.files.presentation.CrudKind.DELETE_BATCH ->
        if (success) R.string.files_crud_delete_ok else R.string.files_crud_delete_failed
    com.testlogon.android.feature.files.presentation.CrudKind.CREATE_FOLDER ->
        if (success) R.string.files_crud_create_folder_ok else R.string.files_crud_create_folder_failed
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


/**
 * F13 - the long-press context menu for a file / folder row. Rename (FM4, inline on the row), Delete,
 * New folder and Move/Copy (FM6/FM3, "tap a destination folder" mode) are all wired through the
 * FilesViewModel CRUD ops. Copy is FILE-ONLY (the backend supports file copy only; recursive folder copy
 * is rejected), so it's hidden for folders.
 */
@Composable
private fun FileContextSheet(
    node: FileNode,
    onRename: () -> Unit,
    onDelete: () -> Unit,
    onMove: () -> Unit,
    onCopy: () -> Unit,
    onNewFolder: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    val isFolder = node.type == FileNodeType.FOLDER
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState) {
        Column(Modifier.fillMaxWidth().padding(bottom = 24.dp)) {
            Text(
                text = node.name,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            HorizontalDivider()
            MenuRow(stringResource(R.string.files_menu_rename), onClick = onRename)
            MenuRow(stringResource(R.string.files_menu_delete), onClick = onDelete)
            MenuRow(stringResource(R.string.files_menu_move), onClick = onMove)
            // FM3 - copy is now a real action via the BK1 copy endpoint; file-only (folder copy unsupported).
            if (!isFolder) {
                MenuRow(stringResource(R.string.files_menu_copy), onClick = onCopy)
            }
            HorizontalDivider()
            MenuRow(stringResource(R.string.files_menu_new_folder), onClick = onNewFolder)
        }
    }
}

/**
 * FM6/FM3 - a banner shown while a move/copy transfer is choosing its destination. The user navigates
 * into the target folder using the breadcrumbs / folder rows behind it; [destinationPath] is the folder
 * currently on screen. Confirm places [transfer].node into that folder; Cancel aborts.
 */
@Composable
private fun TransferBanner(
    transfer: Transfer,
    destinationPath: String,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
    val label = when (transfer.op) {
        TransferOp.MOVE -> stringResource(R.string.files_move_banner, transfer.node.name)
        TransferOp.COPY -> stringResource(R.string.files_copy_banner, transfer.node.name)
    }
    val confirmLabel = when (transfer.op) {
        TransferOp.MOVE -> stringResource(R.string.files_move_here)
        TransferOp.COPY -> stringResource(R.string.files_copy_here)
    }
    val destLabel = FilePath.segments(destinationPath).lastOrNull()
        ?: stringResource(R.string.files_root_label)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.secondaryContainer)
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(FilesTestTags.TRANSFER_BANNER),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = stringResource(R.string.files_transfer_destination, destLabel),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            TextButton(
                onClick = onCancel,
                modifier = Modifier.testTag(FilesTestTags.TRANSFER_CANCEL),
            ) { Text(stringResource(R.string.action_cancel)) }
            TextButton(
                onClick = onConfirm,
                modifier = Modifier.testTag(FilesTestTags.TRANSFER_CONFIRM),
            ) { Text(confirmLabel) }
        }
    }
}

/**
 * #6 - a small bottom-sheet shown while a PDF / non-image file downloads for preview. On success the
 * external viewer is launched (by the route) and this sheet is dismissed; on error it offers Retry.
 */
@Composable
private fun FileDownloadSheet(
    node: FileNode?,
    state: com.testlogon.android.feature.files.download.FileDownloadUiState,
    onCancel: () -> Unit,
    onDismiss: () -> Unit,
    onRetry: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(FilesTestTags.DOWNLOAD_SHEET),
    ) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = node?.name ?: stringResource(R.string.files_title),
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            when (val s = state) {
                is com.testlogon.android.feature.files.download.FileDownloadUiState.Error -> {
                    Text(s.message, style = MaterialTheme.typography.bodyMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (s.retryable) {
                            TextButton(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
                        }
                        TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
                    }
                }
                else -> {
                    val fraction = (s as? com.testlogon.android.feature.files.download.FileDownloadUiState.InProgress)?.fraction
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                        if (fraction != null) {
                            CircularProgressIndicator(progress = { fraction }, modifier = Modifier.size(28.dp))
                        } else {
                            CircularProgressIndicator(modifier = Modifier.size(28.dp))
                        }
                        Text(stringResource(R.string.files_download_opening), style = MaterialTheme.typography.bodyMedium)
                    }
                    TextButton(onClick = onCancel) { Text(stringResource(R.string.action_cancel)) }
                }
            }
        }
    }
}

/**
 * FM4 - inline rename text field for a row. Auto-focuses on appear; commits a non-blank trimmed value on
 * IME Done / Enter, cancels on a blank value or focus loss. Kept self-contained (its own remembered text).
 */
@Composable
private fun InlineRenameField(
    initial: String,
    onCommit: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var text by remember(initial) { mutableStateOf(initial) }
    val focusRequester = remember { androidx.compose.ui.focus.FocusRequester() }
    // FM4 fix: the field finishes EXACTLY ONCE. Without this guard the IME-Done commit (which clears the
    // editing row) is immediately followed by the field's focus-loss callback firing a SECOND outcome -
    // and, worse, the FIRST onFocusChanged emission (before requestFocus runs) reported isFocused=false
    // and cancelled the edit before the user could type, so the rename "never committed".
    var hasFocused by remember(initial) { mutableStateOf(false) }
    var finished by remember(initial) { mutableStateOf(false) }
    val finish = { commitIt: Boolean ->
        if (!finished) {
            finished = true
            val trimmed = text.trim()
            if (commitIt && trimmed.isNotEmpty() && trimmed != initial) onCommit(trimmed) else onCancel()
        }
    }
    androidx.compose.runtime.LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }
    OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        singleLine = true,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        // IME Done / Enter commits the typed name (this is the primary commit path).
        keyboardActions = androidx.compose.foundation.text.KeyboardActions(onDone = { finish(true) }),
        modifier = Modifier
            .fillMaxWidth()
            .focusRequester(focusRequester)
            .onFocusChanged { focusState ->
                // FM4 - track focus so the pre-focus emission can't cancel the edit; once the field has
                // actually held focus, losing it (tap elsewhere / keyboard dismiss) COMMITS the typed
                // name (falling back to cancel for a blank/unchanged value) instead of discarding it.
                if (focusState.isFocused) {
                    hasFocused = true
                } else if (hasFocused) {
                    finish(true)
                }
            }
            .testTag(FilesTestTags.RENAME_FIELD),
    )
}

@Composable
private fun MenuRow(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    ListItem(
        headlineContent = {
            Text(
                label,
                color = if (enabled) MaterialTheme.colorScheme.onSurface
                else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clickable(enabled = true, onClick = onClick),
    )
}

/** F13 - a single-field text-entry dialog used for Rename / New-folder / Move. */
@Composable
private fun TextEntryDialog(
    title: String,
    label: String,
    confirmLabel: String,
    initial: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                singleLine = true,
                label = { Text(label) },
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(value.trim()) },
                enabled = value.isNotBlank(),
            ) { Text(confirmLabel) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}

/** F14 - true when [node] is an image file, by preview-kind / content-type / filename extension. */
private fun isImageNode(node: FileNode): Boolean {
    if (node.type == FileNodeType.FOLDER) return false
    val family = (node.previewKind ?: node.contentType.orEmpty()).lowercase()
    if (family.startsWith("image")) return true
    val name = node.name.lowercase()
    return name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".png") ||
        name.endsWith(".gif") || name.endsWith(".webp") || name.endsWith(".bmp") ||
        name.endsWith(".heic") || name.endsWith(".heif")
}

/** #9 - true when [node] is a video file, by preview-kind / content-type / filename extension. */
private fun isVideoNode(node: FileNode): Boolean {
    if (node.type == FileNodeType.FOLDER) return false
    val family = (node.previewKind ?: node.contentType.orEmpty()).lowercase()
    if (family.startsWith("video")) return true
    val name = node.name.lowercase()
    return name.endsWith(".mp4") || name.endsWith(".mov") || name.endsWith(".m4v") ||
        name.endsWith(".webm") || name.endsWith(".mkv") || name.endsWith(".3gp") ||
        name.endsWith(".avi")
}

/**
 * #9 - the list-thumbnail source for a VIDEO [node]. Prefers a server-supplied poster image (a still,
 * fast); otherwise the raw video bytes from the authed `/v1/fs/download` endpoint, which Coil's
 * VideoFrameDecoder turns into a first-frame thumbnail. The url is server-RELATIVE so the authed
 * loader's RelativeUrlMapper resolves it against API_BASE_URL. (`/v1/fs/preview` 415s for video, so we
 * use the download endpoint, which streams the bytes with the real video content-type.)
 */
private fun videoThumbnailUrl(node: FileNode): String {
    node.posterUrl?.takeIf { it.isNotBlank() }?.let { return it }
    val encoded = java.net.URLEncoder.encode(node.path, "UTF-8")
    return "/v1/fs/download?path=$encoded"
}

/**
 * #6 - the full-screen viewable url for an image [node]. Prefers a server-supplied poster/preview url
 * when present; otherwise the authenticated PREVIEW endpoint (server-RELATIVE so the authed loader's
 * RelativeUrlMapper resolves it against API_BASE_URL). `/v1/fs/preview` returns image bytes the loader
 * can decode (the download endpoint advertises a misleading application/json content-type).
 */
private fun imageViewUrl(node: FileNode): String {
    node.posterUrl?.takeIf { it.isNotBlank() }?.let { return it }
    val encoded = java.net.URLEncoder.encode(node.path, "UTF-8")
    return "/v1/fs/preview?path=$encoded"
}

/**
 * #6 - the list-thumbnail url for an image [node]. Prefers a server poster url; then the dedicated
 * thumbnail endpoint; the URL is server-RELATIVE so the authed loader resolves it against API_BASE_URL.
 * NOTE: the backend only serves `/v1/fs/thumbnail` once a thumbnail artifact has been generated (it
 * 404s otherwise), so the row falls back to `/v1/fs/preview` (the full image bytes, which Coil
 * downsamples) - this is handled by the AsyncImage error-fallback chain in [FileRow].
 */
private fun thumbnailUrl(node: FileNode): String {
    node.posterUrl?.takeIf { it.isNotBlank() }?.let { return it }
    val encoded = java.net.URLEncoder.encode(node.path, "UTF-8")
    return "/v1/fs/preview?path=$encoded"
}


/**
 * FE-170 - a tappable "Trading Documents" tile at the file-manager root that opens the statements /
 * 1099s / trade-confirmations area. Mirrors the list-row idiom used elsewhere on this screen.
 */
@Composable
private fun TradingDocsTile(onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(FilesTestTags.TRADING_DOCS_TILE),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            Icons.Outlined.ReceiptLong,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(24.dp),
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 16.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = stringResource(R.string.trading_docs_title),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = stringResource(R.string.trading_docs_tile_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Icon(
            Icons.Filled.ChevronRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
