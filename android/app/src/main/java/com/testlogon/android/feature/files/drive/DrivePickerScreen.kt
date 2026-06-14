@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.files.drive

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.files.drive.model.DriveFile

/** AND-336 - stable test tags for the backend-mediated Drive picker. */
object DriveTestTags {
    const val PICKER = "drive_picker"
    const val CONNECT = "drive_connect"
    const val REFRESH = "drive_refresh"
    const val DISCONNECT = "drive_disconnect"
    const val SEARCH = "drive_search"
    const val LIST = "drive_list"

    /** Per-entry row tag: drive_file_<id>. */
    fun file(id: String): String = "drive_file_$id"

    /** Per-entry import action tag: drive_import (one per file row; keyed by id for uniqueness). */
    fun import(id: String): String = "drive_import_$id"

    /** Per-breadcrumb tag: drive_breadcrumb_<index>. */
    fun breadcrumb(index: Int): String = "drive_breadcrumb_$index"
}

/**
 * AND-336 - opens [url] externally with a plain ACTION_VIEW (the AND-324/325 openExternalUrl idiom).
 * NO Custom Tabs / androidx.browser: the backend completes the OAuth redirect server-side and the picker
 * re-checks status on return. Best-effort - a missing browser is swallowed.
 */
internal fun openDriveExternalUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, url.toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        // No browser available; the connect CTA is best-effort.
    }
}

/**
 * AND-336 - route-level entry for the backend-mediated Drive picker. Opens the consent auth_url
 * externally on [DrivePickerEvent.OpenUrl] (plain ACTION_VIEW); on [DrivePickerEvent.Imported] shows a
 * snackbar and closes via [onDone] (the AND-332 Files list refreshes itself via FolderRefreshBus). The
 * import target folder is carried into the VM through its SavedStateHandle by the nav graph.
 */
@Composable
fun DrivePickerRoute(
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DrivePickerViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val importedCopy = stringResource(R.string.drive_imported)

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is DrivePickerEvent.OpenUrl -> openDriveExternalUrl(context, event.url)
                is DrivePickerEvent.Imported -> {
                    snackbarHostState.showSnackbar(importedCopy)
                    onDone()
                }
            }
        }
    }

    DrivePickerScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onClose = onDone,
        onConnect = viewModel::onConnect,
        onRefreshStatus = viewModel::refreshStatus,
        onOpenFolder = viewModel::onOpenFolder,
        onBreadcrumb = viewModel::onBreadcrumb,
        onSearch = viewModel::onSearch,
        onImport = { file -> viewModel.onImport(file) },
        onDisconnect = viewModel::onDisconnect,
        modifier = modifier,
    )
}

/** AND-336 - stateless Drive picker UI (hoisted state + callbacks so it is directly testable). */
@Composable
fun DrivePickerScreen(
    state: DrivePickerUiState,
    snackbarHostState: SnackbarHostState,
    onClose: () -> Unit,
    onConnect: () -> Unit,
    onRefreshStatus: () -> Unit,
    onOpenFolder: (DriveFile) -> Unit,
    onBreadcrumb: (Int) -> Unit,
    onSearch: (String) -> Unit,
    onImport: (DriveFile) -> Unit,
    onDisconnect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DriveTestTags.PICKER),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.drive_title)) },
                navigationIcon = {
                    IconButton(onClick = onClose) {
                        Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.drive_close))
                    }
                },
                actions = {
                    if (state is DrivePickerUiState.Browsing) {
                        TextButton(
                            onClick = onDisconnect,
                            modifier = Modifier.testTag(DriveTestTags.DISCONNECT),
                        ) { Text(stringResource(R.string.drive_disconnect)) }
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is DrivePickerUiState.Loading -> CenteredSpinner()
                is DrivePickerUiState.NotConnected -> NotConnectedContent(onConnect = onConnect, onRefresh = onRefreshStatus)
                is DrivePickerUiState.Browsing -> BrowsingContent(
                    state = state,
                    onOpenFolder = onOpenFolder,
                    onBreadcrumb = onBreadcrumb,
                    onSearch = onSearch,
                    onImport = onImport,
                )
                is DrivePickerUiState.Error -> ErrorContent(message = state.message, onRetry = onRefreshStatus)
            }
        }
    }
}

@Composable
private fun CenteredSpinner() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun NotConnectedContent(onConnect: () -> Unit, onRefresh: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Filled.CloudUpload,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.size(12.dp))
        Text(
            text = stringResource(R.string.drive_connect_blurb),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.size(16.dp))
        Button(
            onClick = onConnect,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DriveTestTags.CONNECT),
        ) { Text(stringResource(R.string.drive_connect)) }
        Spacer(Modifier.size(8.dp))
        OutlinedButton(
            onClick = onRefresh,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DriveTestTags.REFRESH),
        ) { Text(stringResource(R.string.drive_refresh)) }
    }
}

@Composable
private fun ErrorContent(message: String, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.size(12.dp))
        OutlinedButton(
            onClick = onRetry,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DriveTestTags.REFRESH),
        ) { Text(stringResource(R.string.drive_refresh)) }
    }
}

@Composable
private fun BrowsingContent(
    state: DrivePickerUiState.Browsing,
    onOpenFolder: (DriveFile) -> Unit,
    onBreadcrumb: (Int) -> Unit,
    onSearch: (String) -> Unit,
    onImport: (DriveFile) -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        DriveBreadcrumbRow(breadcrumbs = state.breadcrumbs, onBreadcrumb = onBreadcrumb)
        DriveSearchField(query = state.query, onSearch = onSearch)
        HorizontalDivider()
        state.error?.let { error ->
            Text(
                text = error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
        Box(Modifier.fillMaxSize()) {
            when {
                state.loading && state.files.isEmpty() -> CenteredSpinner()
                state.files.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(stringResource(R.string.drive_empty), style = MaterialTheme.typography.bodyMedium)
                }
                else -> LazyColumn(modifier = Modifier.fillMaxSize().testTag(DriveTestTags.LIST)) {
                    items(state.files, key = { it.id }) { file ->
                        DriveRow(
                            file = file,
                            importing = state.importing == file.id,
                            onOpenFolder = onOpenFolder,
                            onImport = onImport,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DriveBreadcrumbRow(breadcrumbs: List<DriveCrumb>, onBreadcrumb: (Int) -> Unit) {
    val goToFmt = stringResource(R.string.drive_breadcrumb_cd)
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
                    .testTag(DriveTestTags.breadcrumb(index))
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
private fun DriveSearchField(query: String, onSearch: (String) -> Unit) {
    OutlinedTextField(
        value = query,
        onValueChange = onSearch,
        singleLine = true,
        label = { Text(stringResource(R.string.drive_search_label)) },
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onSearch("") }) {
                    Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.drive_search_clear))
                }
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag(DriveTestTags.SEARCH),
    )
}

/** AND-336 - one Drive row: a folder navigates on tap; a file shows an Import action with a per-item spinner. */
@Composable
private fun DriveRow(
    file: DriveFile,
    importing: Boolean,
    onOpenFolder: (DriveFile) -> Unit,
    onImport: (DriveFile) -> Unit,
) {
    val typeCd = if (file.isFolder) {
        stringResource(R.string.drive_folder_cd, file.name)
    } else {
        stringResource(R.string.drive_file_cd, file.name)
    }
    val importCd = stringResource(R.string.drive_import_cd, file.name)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(DriveTestTags.file(file.id)),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(
            modifier = Modifier
                .weight(1f)
                .let { if (file.isFolder) it.clickable { onOpenFolder(file) } else it }
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .clearAndSetSemantics { contentDescription = typeCd },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = if (file.isFolder) Icons.Filled.Folder else Icons.AutoMirrored.Filled.InsertDriveFile,
                contentDescription = null,
                tint = if (file.isFolder) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp),
            )
            Text(
                text = file.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 12.dp),
            )
        }
        if (!file.isFolder) {
            if (importing) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(end = 16.dp).size(24.dp),
                    strokeWidth = 2.dp,
                )
            } else {
                TextButton(
                    onClick = { onImport(file) },
                    modifier = Modifier
                        .padding(end = 8.dp)
                        .heightIn(min = 48.dp)
                        .testTag(DriveTestTags.import(file.id))
                        .clearAndSetSemantics { contentDescription = importCd },
                ) { Text(stringResource(R.string.drive_import)) }
            }
        }
    }
}
