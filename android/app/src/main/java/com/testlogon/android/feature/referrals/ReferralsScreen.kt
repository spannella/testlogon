@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.referrals

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.referrals.DEFAULT_CURRENCY_USD
import com.testlogon.android.data.referrals.ReferralCode
import com.testlogon.android.data.referrals.ReferralStats
import com.testlogon.android.feature.earnings.formatEarningsMoney

/** AND-264 — stable testTags for the referrals screen. */
object ReferralsTestTags {
    const val SCREEN = "referrals_screen"
    const val CONTENT = "referrals_content"
    const val LOADING = "referrals_loading"
    const val INELIGIBLE = "referrals_ineligible"
    const val ERROR = "referrals_error"
    const val OFFLINE = "referrals_offline"
    const val SESSION_EXPIRED = "referrals_session_expired"
    const val SHARE = "referrals_share"
    const val COPY = "referrals_copy"
    const val NEW_CODE = "referrals_new_code"
    const val STAT_PREFIX = "referrals_stat_"
    const val CODE_PREFIX = "referrals_code_"
}

/** AND-264 — route-level referrals entry (reachable from the More hub). */
@Composable
fun ReferralsRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ReferralsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val shareChooserTitle = stringResource(R.string.referrals_share_chooser_title)

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ReferralsEffect.CopyLink -> copyToClipboard(context, effect.link)
                is ReferralsEffect.Share -> shareLink(context, effect.link, shareChooserTitle)
                is ReferralsEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == ReferralsUiState.Phase.SessionExpired) onSessionExpired()
    }

    ReferralsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onShare = viewModel::onShareClicked,
        onCopy = viewModel::onCopyClicked,
        onCopyCode = viewModel::onCopyCode,
        onShareCode = viewModel::onShareCode,
        onCreateCode = viewModel::onCreateCode,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun ReferralsScreen(
    state: ReferralsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onShare: () -> Unit,
    onCopy: () -> Unit,
    onCopyCode: (String) -> Unit,
    onShareCode: (String) -> Unit,
    onCreateCode: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(ReferralsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.referrals_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("referrals_back")) {
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
                ReferralsUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(ReferralsTestTags.LOADING))

                ReferralsUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.referrals_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(ReferralsTestTags.ERROR),
                    )

                ReferralsUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.referrals_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(ReferralsTestTags.OFFLINE),
                    )

                ReferralsUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.referrals_session_expired_title),
                        body = stringResource(R.string.referrals_session_expired_body),
                        modifier = Modifier.testTag(ReferralsTestTags.SESSION_EXPIRED),
                    )

                ReferralsUiState.Phase.Ineligible ->
                    EmptyState(
                        title = stringResource(R.string.referrals_empty_title),
                        body = stringResource(R.string.referrals_empty_body),
                        actionLabel = stringResource(R.string.referrals_new_code),
                        onAction = onCreateCode,
                        modifier = Modifier.testTag(ReferralsTestTags.INELIGIBLE),
                    )

                ReferralsUiState.Phase.Content -> {
                    val dashboard = state.dashboard
                    if (dashboard == null) {
                        LoadingState(modifier = Modifier.testTag(ReferralsTestTags.LOADING))
                    } else {
                        PullToRefreshBox(
                            isRefreshing = state.isRefreshing,
                            onRefresh = onRefresh,
                            modifier = Modifier.fillMaxSize(),
                        ) {
                            Column(
                                modifier = Modifier
                                    .testTag(ReferralsTestTags.CONTENT)
                                    .fillMaxSize()
                                    .verticalScroll(rememberScrollState())
                                    .padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(16.dp),
                            ) {
                                if (state.isStale) {
                                    OfflineBanner(onRetry = onRetry)
                                }
                                StatsCard(stats = dashboard.stats)
                                ShareActions(onShare = onShare, onCopy = onCopy)
                                dashboard.codes.forEach { code ->
                                    CodeCard(
                                        code = code,
                                        onCopy = { onCopyCode(code.code) },
                                        onShare = { onShareCode(code.code) },
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatsCard(stats: ReferralStats) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val totalReferralsLabel = stringResource(R.string.referrals_stat_total)
            val subLabel = stringResource(
                R.string.referrals_stat_total_sub,
                stats.confirmedReferrals,
                stats.pendingReferrals,
            )
            Column(
                modifier = Modifier
                    .testTag(ReferralsTestTags.STAT_PREFIX + "total")
                    .semantics(mergeDescendants = true) {},
            ) {
                Text(totalReferralsLabel, style = MaterialTheme.typography.labelMedium)
                Text(stats.totalReferrals.toString(), style = MaterialTheme.typography.headlineSmall)
                Text(subLabel, style = MaterialTheme.typography.bodySmall)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                MoneyTile("earned", R.string.referrals_stat_earned, stats.totalEarnedCents)
                MoneyTile("pending", R.string.referrals_stat_pending, stats.pendingCommissionCents)
                MoneyTile("available", R.string.referrals_stat_available, stats.availableForWithdrawalCents)
                MoneyTile("paid", R.string.referrals_stat_paid, stats.paidCommissionCents)
            }
        }
    }
}

@Composable
private fun MoneyTile(key: String, labelRes: Int, cents: Long) {
    val label = stringResource(labelRes)
    val value = formatEarningsMoney(cents, DEFAULT_CURRENCY_USD)
    Column(
        modifier = Modifier
            .testTag(ReferralsTestTags.STAT_PREFIX + key)
            .semantics(mergeDescendants = true) {},
    ) {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Text(value, style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun ShareActions(onShare: () -> Unit, onCopy: () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Button(onClick = onShare, modifier = Modifier.testTag(ReferralsTestTags.SHARE)) {
            Icon(Icons.Outlined.Share, contentDescription = null)
            Text(
                stringResource(R.string.referrals_action_share),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        OutlinedButton(onClick = onCopy, modifier = Modifier.testTag(ReferralsTestTags.COPY)) {
            Icon(Icons.Outlined.ContentCopy, contentDescription = null)
            Text(
                stringResource(R.string.referrals_action_copy),
                modifier = Modifier.padding(start = 8.dp),
            )
        }
    }
}

@Composable
private fun CodeCard(code: ReferralCode, onCopy: () -> Unit, onShare: () -> Unit) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ReferralsTestTags.CODE_PREFIX + code.code),
    ) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(modifier = Modifier.semantics(mergeDescendants = true) {}) {
                Text(code.code, style = MaterialTheme.typography.titleMedium)
                val status = if (code.active) {
                    stringResource(R.string.referrals_code_active)
                } else {
                    stringResource(R.string.referrals_code_inactive)
                }
                AssistChip(onClick = {}, label = { Text(status) })
                Text(
                    stringResource(R.string.referrals_code_count, code.referralCount),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (code.active) {
                val copyCd = stringResource(R.string.referrals_action_copy)
                val shareCd = stringResource(R.string.referrals_action_share)
                IconButton(
                    onClick = onCopy,
                    modifier = Modifier.clearAndSetSemantics { contentDescription = copyCd },
                ) {
                    Icon(Icons.Outlined.ContentCopy, contentDescription = null)
                }
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

// ---- Android side-effect seams (only the link string crosses; never cookies/PII) ----

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText("referral_link", text))
}

private fun shareLink(context: Context, link: String, chooserTitle: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, link)
    }
    val chooser = Intent.createChooser(send, chooserTitle).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    try {
        context.startActivity(chooser)
    } catch (_: ActivityNotFoundException) {
        // No share target available; the copy action remains as a fallback.
    }
}
