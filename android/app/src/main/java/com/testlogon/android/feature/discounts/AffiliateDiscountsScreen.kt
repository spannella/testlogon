@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.discounts

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.discounts.AffiliateDiscount
import com.testlogon.android.data.discounts.DiscountKind
import com.testlogon.android.feature.affiliates.displayUrl
import com.testlogon.android.feature.affiliates.formatCount

/** AND-267 — stable testTags for the affiliate-discounts screen. */
object AffiliateDiscountsTestTags {
    const val SCREEN = "discounts_screen"
    const val CONTENT = "discounts_content"
    const val LOADING = "discounts_loading"
    const val EMPTY = "discounts_empty"
    const val ERROR = "discounts_error"
    const val OFFLINE = "discounts_offline"
    const val FILTERS = "discounts_filters"
    const val ROW_PREFIX = "discounts_row_"
}

/** AND-267 — route-level affiliate-discounts entry (reachable from the More hub). */
@Composable
fun AffiliateDiscountsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AffiliateDiscountsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val shareChooserTitle = stringResource(R.string.discounts_share_chooser_title)

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is AffiliateDiscountsEffect.CopyCode -> copyToClipboard(context, effect.code)
                is AffiliateDiscountsEffect.ShareLink -> shareText(context, effect.text, shareChooserTitle)
                is AffiliateDiscountsEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    AffiliateDiscountsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onFilterSelected = viewModel::onFilterSelected,
        onCopyCode = viewModel::onCopyCode,
        onShareLink = viewModel::onShareLink,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun AffiliateDiscountsScreen(
    state: AffiliateDiscountsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onFilterSelected: (DiscountKind?) -> Unit,
    onCopyCode: (String) -> Unit,
    onShareLink: (String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(AffiliateDiscountsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.discounts_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("discounts_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                AffiliateDiscountsUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(AffiliateDiscountsTestTags.LOADING))

                AffiliateDiscountsUiState.Phase.Empty ->
                    EmptyState(
                        title = stringResource(R.string.discounts_empty_title),
                        body = stringResource(R.string.discounts_empty_body),
                        modifier = Modifier.testTag(AffiliateDiscountsTestTags.EMPTY),
                    )

                AffiliateDiscountsUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.discounts_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AffiliateDiscountsTestTags.ERROR),
                    )

                AffiliateDiscountsUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.discounts_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AffiliateDiscountsTestTags.OFFLINE),
                    )

                AffiliateDiscountsUiState.Phase.Content ->
                    DiscountsContent(
                        state = state,
                        onRefresh = onRefresh,
                        onRetry = onRetry,
                        onFilterSelected = onFilterSelected,
                        onCopyCode = onCopyCode,
                        onShareLink = onShareLink,
                    )
            }
        }
    }
}

@Composable
private fun DiscountsContent(
    state: AffiliateDiscountsUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onFilterSelected: (DiscountKind?) -> Unit,
    onCopyCode: (String) -> Unit,
    onShareLink: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier
                .testTag(AffiliateDiscountsTestTags.CONTENT)
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (state.isStale) {
                item { OfflineBanner(onRetry = onRetry) }
            }
            item {
                DiscountFilters(selected = state.filterKind, onFilterSelected = onFilterSelected)
            }
            items(state.visibleItems, key = { it.creativeId }) { discount ->
                DiscountRow(
                    discount = discount,
                    onCopy = { onCopyCode(discount.creativeId) },
                    onShare = { onShareLink(discount.creativeId) },
                )
            }
        }
    }
}

@Composable
private fun DiscountFilters(selected: DiscountKind?, onFilterSelected: (DiscountKind?) -> Unit) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().testTag(AffiliateDiscountsTestTags.FILTERS),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = selected == null,
            onClick = { onFilterSelected(null) },
            label = { Text(stringResource(R.string.discounts_filter_all)) },
        )
        FilterChip(
            selected = selected == DiscountKind.PERCENT,
            onClick = { onFilterSelected(DiscountKind.PERCENT) },
            label = { Text(stringResource(R.string.discounts_filter_percent)) },
        )
        FilterChip(
            selected = selected == DiscountKind.FIXED,
            onClick = { onFilterSelected(DiscountKind.FIXED) },
            label = { Text(stringResource(R.string.discounts_filter_fixed)) },
        )
        FilterChip(
            selected = selected == DiscountKind.FREE_TRIAL,
            onClick = { onFilterSelected(DiscountKind.FREE_TRIAL) },
            label = { Text(stringResource(R.string.discounts_filter_free_trial)) },
        )
    }
}

@Composable
private fun DiscountRow(discount: AffiliateDiscount, onCopy: () -> Unit, onShare: () -> Unit) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AffiliateDiscountsTestTags.ROW_PREFIX + discount.creativeId),
    ) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(
                modifier = Modifier.semantics(mergeDescendants = true) {},
            ) {
                val code = discount.displayCode ?: stringResource(R.string.discounts_no_code)
                Text(code, style = MaterialTheme.typography.titleMedium)
                val badge = discount.promoValueDisplay
                if (!badge.isNullOrBlank()) {
                    AssistChip(onClick = {}, label = { Text(badge) })
                }
                discount.clickThroughUrl?.takeIf { it.isNotBlank() }?.let { url ->
                    Text(
                        displayUrl(url),
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(
                    stringResource(
                        R.string.discounts_row_metrics,
                        formatCount(discount.clickCount),
                        formatCount(discount.redemptionCount),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            val copyCd = stringResource(R.string.discounts_action_copy)
            val shareCd = stringResource(R.string.discounts_action_share)
            if (discount.displayCode != null) {
                IconButton(
                    onClick = onCopy,
                    modifier = Modifier.clearAndSetSemantics { contentDescription = copyCd },
                ) {
                    Icon(Icons.Outlined.ContentCopy, contentDescription = null)
                }
            }
            if (discount.shareText() != null) {
                IconButton(
                    onClick = onShare,
                    modifier = Modifier.clearAndSetSemantics { contentDescription = shareCd },
                ) {
                    Icon(Icons.Outlined.Share, contentDescription = null)
                }
            }
        }
    }
}

// ---- Android side-effect seams (only the code/URL string crosses; never amounts/account ids) ----

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText("affiliate_discount_code", text))
}

private fun shareText(context: Context, text: String, chooserTitle: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val chooser = Intent.createChooser(send, chooserTitle).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    try {
        context.startActivity(chooser)
    } catch (_: ActivityNotFoundException) {
        // No share target available; copy remains as a fallback.
    }
}
