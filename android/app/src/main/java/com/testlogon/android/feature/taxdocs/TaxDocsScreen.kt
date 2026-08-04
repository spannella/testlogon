@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.taxdocs

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
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.taxdocs.TaxDocument
import com.testlogon.android.data.taxdocs.TaxSpendingCategory
import com.testlogon.android.data.taxdocs.TaxSpendingSummary
import com.testlogon.android.feature.invoices.CustomTabsInvoicePdfLauncher
import com.testlogon.android.feature.invoices.InvoicePdfLauncher
import kotlinx.coroutines.flow.collectLatest

/** AND-246 stable testTags for the tax-documents screen. */
object TaxDocsTestTags {
    const val SCREEN = "tax_docs_screen"
    const val LIST = "tax_docs_list"
    const val EMPTY = "tax_docs_empty"
    const val ERROR = "tax_docs_error"
    const val ROW = "tax_doc_row"
    const val DOWNLOAD = "tax_doc_download"

    // PAR-24 earnings summary card
    const val SUMMARY = "tax_docs_summary"
    const val SUMMARY_TOTAL = "tax_docs_summary_total"
    const val SUMMARY_CATEGORY = "tax_docs_summary_category"
}

/**
 * AND-246 route-level tax-documents list, reachable from billing / the More hub. The PDF view /
 * download reuses the AND-243 [InvoicePdfLauncher] (Custom Tabs) so the session cookies carry the
 * download. The launcher is passed in (Hilt-provided at the call site) to keep it testable.
 */
@Composable
fun TaxDocsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TaxDocsViewModel = hiltViewModel(),
    pdfLauncher: InvoicePdfLauncher = remember { CustomTabsInvoicePdfLauncher() },
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val noBrowserMessage = stringResource(R.string.tax_docs_no_viewer)

    LaunchedEffect(viewModel) {
        viewModel.events.collectLatest { event ->
            when (event) {
                is TaxDocsEvent.ViewPdf -> {
                    val launched = pdfLauncher.launch(context, event.url)
                    if (!launched) snackbarHostState.showSnackbar(noBrowserMessage)
                }
            }
        }
    }

    TaxDocsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onDownloadClick = viewModel::onDownloadClicked,
        onRefresh = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun TaxDocsScreen(
    state: TaxDocsUiState,
    snackbarHostState: SnackbarHostState,
    onDownloadClick: (TaxDocument) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TaxDocsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tax_docs_title)) },
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
                state.isLoading && state.documents.isEmpty() ->
                    LoadingState(message = stringResource(R.string.tax_docs_loading))

                state.error != null && state.documents.isEmpty() ->
                    ErrorState(
                        message = state.error.asString(),
                        onRetry = onRefresh,
                        modifier = Modifier.testTag(TaxDocsTestTags.ERROR),
                    )

                state.documents.isEmpty() && state.summary == null ->
                    EmptyState(
                        title = stringResource(R.string.tax_docs_empty),
                        modifier = Modifier.testTag(TaxDocsTestTags.EMPTY),
                    )

                else -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    LazyColumn(modifier = Modifier.fillMaxSize().testTag(TaxDocsTestTags.LIST)) {
                        // PAR-24 earnings summary card above the list (best-effort; null hides it).
                        state.summary?.let { summary ->
                            item(key = "tax_docs_summary") {
                                EarningsSummaryCard(summary = summary, year = state.summaryYear)
                            }
                        }
                        if (state.documents.isEmpty()) {
                            item(key = "tax_docs_empty_inline") {
                                Text(
                                    text = stringResource(R.string.tax_docs_empty),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                                )
                            }
                        }
                        items(items = state.documents, key = { it.docId }) { doc ->
                            TaxDocRow(doc = doc, onDownloadClick = { onDownloadClick(doc) })
                        }
                    }
                }
            }
        }
    }
}

/** PAR-24 earnings summary card: total + txn count + per-category rows. */
@Composable
private fun EarningsSummaryCard(summary: TaxSpendingSummary, year: Int?) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(TaxDocsTestTags.SUMMARY),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            val baseTitle = stringResource(R.string.tax_docs_summary_title)
            Text(
                text = if (year != null) baseTitle + " " + year else baseTitle,
                style = MaterialTheme.typography.titleMedium,
            )
            if (summary.isEmpty) {
                Text(
                    text = if (year != null) {
                        stringResource(R.string.tax_docs_summary_empty, year)
                    } else {
                        stringResource(R.string.tax_docs_empty)
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth().testTag(TaxDocsTestTags.SUMMARY_TOTAL),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.tax_docs_summary_total_label),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            text = stringResource(
                                R.string.tax_docs_summary_txns,
                                summary.transactionCount,
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(
                        text = formatTaxMoney(summary.grandTotal),
                        style = MaterialTheme.typography.titleLarge,
                    )
                }
                if (summary.categories.isNotEmpty()) {
                    HorizontalDivider()
                    summary.categories.forEach { CategoryRow(it) }
                }
            }
        }
    }
}

@Composable
private fun CategoryRow(category: TaxSpendingCategory) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TaxDocsTestTags.SUMMARY_CATEGORY),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = taxCategoryLabel(category.category),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = stringResource(
                R.string.tax_docs_summary_category_amount,
                formatTaxMoney(category.total),
                category.transactionCount,
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** PAR-24 human label for a backend earnings-category code; unknown codes fall back to the raw code. */
@Composable
private fun taxCategoryLabel(code: String): String = when (code) {
    "subscriptions" -> stringResource(R.string.tax_docs_category_subscriptions)
    "tips" -> stringResource(R.string.tax_docs_category_tips)
    "unlocks" -> stringResource(R.string.tax_docs_category_unlocks)
    "vod_purchases" -> stringResource(R.string.tax_docs_category_vod_purchases)
    "other" -> stringResource(R.string.tax_docs_category_other)
    else -> code
}

@Composable
private fun TaxDocRow(doc: TaxDocument, onDownloadClick: () -> Unit) {
    val yearText = doc.year?.toString() ?: stringResource(R.string.tax_docs_year_unknown)
    val title = stringResource(R.string.tax_docs_row_title, yearText)
    val totalText = formatTaxMoney(doc.grandTotal)
    val downloadCd = stringResource(R.string.tax_docs_download_cd, yearText)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(TaxDocsTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = stringResource(R.string.tax_docs_row_subtitle, totalText, doc.transactionCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(
            onClick = onDownloadClick,
            enabled = doc.isDownloadable,
            modifier = Modifier.testTag(TaxDocsTestTags.DOWNLOAD),
        ) {
            Icon(
                Icons.Outlined.Download,
                contentDescription = downloadCd,
                modifier = Modifier.size(24.dp),
            )
        }
    }
}
