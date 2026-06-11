@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.taxforms

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
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.taxforms.Form1099
import com.testlogon.android.feature.invoices.CustomTabsInvoicePdfLauncher
import com.testlogon.android.feature.invoices.InvoicePdfLauncher
import kotlinx.coroutines.flow.collectLatest

/** AND-247 — stable testTags for the 1099 forms screen. */
object Form1099TestTags {
    const val SCREEN = "form1099_screen"
    const val LIST = "form1099_list"
    const val EMPTY = "form1099_empty"
    const val ERROR = "form1099_error"
    const val ROW = "form1099_row"
    const val DOWNLOAD = "form1099_download"
    const val CORRECTED_CHIP = "form1099_corrected_chip"
}

/**
 * AND-247 — route-level 1099-NEC forms list, reachable from the More hub / tax area. The PDF "download"
 * resolves the JSON download_url and reuses the AND-243 [InvoicePdfLauncher] (Custom Tabs) so the
 * presigned link / session cookies carry the download. The launcher is passed in (Hilt-provided at the
 * call site) to keep it testable.
 */
@Composable
fun Form1099ListRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: Form1099ListViewModel = hiltViewModel(),
    pdfLauncher: InvoicePdfLauncher = remember { CustomTabsInvoicePdfLauncher() },
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val resources = context.resources
    val noBrowserMessage = stringResource(R.string.form1099_no_viewer)

    LaunchedEffect(viewModel) {
        viewModel.events.collectLatest { event ->
            when (event) {
                is Form1099Event.ViewPdf -> {
                    val launched = pdfLauncher.launch(context, event.url)
                    if (!launched) snackbarHostState.showSnackbar(noBrowserMessage)
                }
                // Resolve the UiText against resources here (not inside the VM / not as a @Composable).
                is Form1099Event.DownloadError ->
                    snackbarHostState.showSnackbar(event.message.resolve(resources))
            }
        }
    }

    Form1099ListScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onDownloadClick = viewModel::onDownloadClicked,
        onRefresh = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun Form1099ListScreen(
    state: Form1099UiState,
    snackbarHostState: SnackbarHostState,
    onDownloadClick: (Form1099) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(Form1099TestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.form1099_title)) },
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
                state.isLoading && state.forms.isEmpty() ->
                    LoadingState(message = stringResource(R.string.form1099_loading))

                state.error != null && state.forms.isEmpty() ->
                    ErrorState(
                        message = state.error.asString(),
                        onRetry = onRefresh,
                        modifier = Modifier.testTag(Form1099TestTags.ERROR),
                    )

                state.forms.isEmpty() ->
                    EmptyState(
                        title = stringResource(R.string.form1099_empty_title),
                        body = stringResource(R.string.form1099_empty_subtitle),
                        modifier = Modifier.testTag(Form1099TestTags.EMPTY),
                    )

                else -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    LazyColumn(modifier = Modifier.fillMaxSize().testTag(Form1099TestTags.LIST)) {
                        items(items = state.forms, key = { it.taxYear }) { form ->
                            Form1099Row(
                                form = form,
                                isDownloading = state.downloadingYear == form.taxYear,
                                onDownloadClick = { onDownloadClick(form) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Form1099Row(
    form: Form1099,
    isDownloading: Boolean,
    onDownloadClick: () -> Unit,
) {
    val yearText = form.taxYear.toString()
    val title = stringResource(R.string.form1099_row_title, yearText)
    val earningsText = formatForm1099Money(form.totalEarnings)
    val downloadCd = stringResource(R.string.form1099_download_cd, yearText)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(Form1099TestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = stringResource(R.string.form1099_row_subtitle, earningsText, form.payerName),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (form.isCorrected) {
            AssistChip(
                onClick = onDownloadClick,
                label = { Text(stringResource(R.string.form1099_status_corrected)) },
                colors = AssistChipDefaults.assistChipColors(),
                modifier = Modifier.padding(end = 8.dp).testTag(Form1099TestTags.CORRECTED_CHIP),
            )
        }
        IconButton(
            onClick = onDownloadClick,
            enabled = !isDownloading,
            modifier = Modifier.testTag(Form1099TestTags.DOWNLOAD),
        ) {
            if (isDownloading) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
            } else {
                Icon(
                    Icons.Outlined.Download,
                    contentDescription = downloadCd,
                    modifier = Modifier.size(24.dp),
                )
            }
        }
    }
}
