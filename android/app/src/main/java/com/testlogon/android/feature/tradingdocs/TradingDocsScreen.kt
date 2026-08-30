@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tradingdocs

import android.content.Context
import android.content.Intent
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.tradingdocs.TradingDocument
import com.testlogon.android.feature.invoices.CustomTabsInvoicePdfLauncher
import com.testlogon.android.feature.invoices.InvoicePdfLauncher
import kotlinx.coroutines.flow.collectLatest

/** FE-170 stable testTags for the Trading Documents screen. */
object TradingDocsTestTags {
    const val SCREEN = "trading_docs_screen"
    const val LIST = "trading_docs_list"
    const val EMPTY = "trading_docs_empty"
    const val ROW = "trading_doc_row"
    const val DOWNLOAD = "trading_doc_download"
    const val SHARE = "trading_doc_share"
    const val GROUP_HEADER = "trading_docs_group_header"
}

/**
 * FE-170 route-level Trading Documents list, reachable from the file manager. Download opens the
 * presigned URL in a Custom Tab (reusing the AND-243 [InvoicePdfLauncher]); Share fires ACTION_SEND with
 * the link (or the title when no URL is resolvable). Degrades to the honest empty state on a 404.
 */
@Composable
fun TradingDocsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TradingDocsViewModel = hiltViewModel(),
    pdfLauncher: InvoicePdfLauncher = remember { CustomTabsInvoicePdfLauncher() },
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val noViewerMessage = stringResource(R.string.trading_docs_no_viewer)
    val unavailableMessage = stringResource(R.string.trading_docs_download_unavailable)
    val shareChooserTitle = stringResource(R.string.trading_docs_share_chooser)

    LaunchedEffect(viewModel) {
        viewModel.events.collectLatest { event ->
            when (event) {
                is TradingDocsEvent.OpenDownload -> {
                    val launched = pdfLauncher.launch(context, event.url)
                    if (!launched) snackbarHostState.showSnackbar(noViewerMessage)
                }
                is TradingDocsEvent.Share ->
                    shareDocument(context, event.title, event.url, shareChooserTitle)
                TradingDocsEvent.DownloadUnavailable ->
                    snackbarHostState.showSnackbar(unavailableMessage)
            }
        }
    }

    TradingDocsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onDownloadClick = viewModel::onDownloadClicked,
        onShareClick = viewModel::onShareClicked,
        onRefresh = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun TradingDocsScreen(
    state: TradingDocsUiState,
    snackbarHostState: SnackbarHostState,
    onDownloadClick: (TradingDocument) -> Unit,
    onShareClick: (TradingDocument) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TradingDocsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.trading_docs_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.isLoading && state.isEmpty ->
                    LoadingState(message = stringResource(R.string.trading_docs_loading))

                state.isEmpty ->
                    EmptyState(
                        title = stringResource(R.string.trading_docs_empty),
                        modifier = Modifier.testTag(TradingDocsTestTags.EMPTY),
                    )

                else -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    LazyColumn(modifier = Modifier.fillMaxSize().testTag(TradingDocsTestTags.LIST)) {
                        state.groups.forEach { group ->
                            item(key = "header_${group.type}") {
                                Text(
                                    text = docTypeLabel(group.type),
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 16.dp, vertical = 8.dp)
                                        .testTag(TradingDocsTestTags.GROUP_HEADER),
                                )
                            }
                            items(items = group.documents, key = { it.docId }) { doc ->
                                TradingDocRow(
                                    doc = doc,
                                    onDownloadClick = { onDownloadClick(doc) },
                                    onShareClick = { onShareClick(doc) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun TradingDocRow(
    doc: TradingDocument,
    onDownloadClick: () -> Unit,
    onShareClick: () -> Unit,
) {
    val downloadable = isDownloadable(doc)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(TradingDocsTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(text = docTitle(doc), style = MaterialTheme.typography.bodyLarge)
            Text(
                text = formatDocMeta(doc),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(
            onClick = onShareClick,
            modifier = Modifier.testTag(TradingDocsTestTags.SHARE),
        ) {
            Icon(
                Icons.Outlined.Share,
                contentDescription = stringResource(R.string.trading_docs_share_cd, docTitle(doc)),
                modifier = Modifier.size(24.dp),
            )
        }
        IconButton(
            onClick = onDownloadClick,
            enabled = downloadable,
            modifier = Modifier.testTag(TradingDocsTestTags.DOWNLOAD),
        ) {
            Icon(
                Icons.Outlined.Download,
                contentDescription = stringResource(R.string.trading_docs_download_cd, docTitle(doc)),
                modifier = Modifier.size(24.dp),
            )
        }
    }
}

/** FE-170 — share a document as a link (ACTION_SEND text/plain); falls back to the title alone. */
private fun shareDocument(context: Context, title: String, url: String?, chooserTitle: String) {
    val text = if (url != null) "$title\n$url" else title
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, title)
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val chooser = Intent.createChooser(send, chooserTitle).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(chooser)
}
