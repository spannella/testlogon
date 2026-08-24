@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.rewards

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
import androidx.compose.material.icons.outlined.Leaderboard
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.rewards.ReferralStatus
import com.testlogon.android.data.rewards.ReferralSummary
import com.testlogon.android.data.rewards.ReferredUser

/** Stable testTags for the Referral hub screen. */
object ReferralHubTestTags {
    const val SCREEN = "referral_hub_screen"
    const val CONTENT = "referral_hub_content"
    const val LOADING = "referral_hub_loading"
    const val ERROR = "referral_hub_error"
    const val COMING_SOON = "referral_hub_coming_soon"
    const val SHARE = "referral_hub_share"
    const val COPY = "referral_hub_copy"
    const val LEADERBOARD = "referral_hub_leaderboard"
}

/** Route-level Referral hub entry (reached from the More -> Growth hub). */
@Composable
fun ReferralHubRoute(
    onBack: () -> Unit,
    onLeaderboard: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ReferralHubViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RewardsEffect.CopyText -> copyToClipboard(context, "referral_link", effect.text)
                is RewardsEffect.ShareText -> shareText(context, effect.text, "Share your referral link")
                is RewardsEffect.Toast -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }

    ReferralHubScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onShare = viewModel::onShare,
        onCopy = viewModel::onCopy,
        onLeaderboard = onLeaderboard,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun ReferralHubScreen(
    state: ReferralHubUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onShare: () -> Unit,
    onCopy: () -> Unit,
    onLeaderboard: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(ReferralHubTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Refer & earn") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("referral_hub_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when {
                state.loading -> LoadingState(modifier = Modifier.testTag(ReferralHubTestTags.LOADING))

                // A genuine read failure (transport, or server error) — offer retry.
                state.offline || (state.errorMessage != null && !state.available) ->
                    ErrorState(
                        message = state.errorMessage ?: "Couldn't load your referrals.",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(ReferralHubTestTags.ERROR),
                    )

                // Clean 404 degrade: read succeeded as "unavailable" with no error -> honest coming-soon.
                !state.available -> ReferralComingSoon()

                else -> ReferralContent(state = state, onShare = onShare, onCopy = onCopy, onLeaderboard = onLeaderboard)
            }
        }
    }
}

@Composable
private fun ReferralComingSoon() {
    EmptyState(
        title = "Referrals coming soon",
        body = "Your referral code, link and rewards will appear here once the program is enabled for your account.",
        modifier = Modifier.testTag(ReferralHubTestTags.COMING_SOON),
    )
}

@Composable
private fun ReferralContent(
    state: ReferralHubUiState,
    onShare: () -> Unit,
    onCopy: () -> Unit,
    onLeaderboard: () -> Unit,
) {
    Column(
        modifier = Modifier
            .testTag(ReferralHubTestTags.CONTENT)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        state.errorMessage?.let { msg ->
            if (state.offline) {
                Text(msg, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
        CodeCard(summary = state.summary, hasShareable = state.hasShareable, onShare = onShare, onCopy = onCopy)
        StatsCard(state.summary)
        OutlinedButton(onClick = onLeaderboard, modifier = Modifier.fillMaxWidth().testTag(ReferralHubTestTags.LEADERBOARD)) {
            Icon(Icons.Outlined.Leaderboard, contentDescription = null)
            Text("View leaderboard", modifier = Modifier.padding(start = 8.dp))
        }
        if (state.referrals.isNotEmpty()) {
            ReferralListCard(state.referrals)
        }
        Text(
            "You earn ${RewardsMath.formatCentsUsd(state.summary.rewardPerReferralCents)} for each friend who qualifies. Rewards are credited automatically once your referral qualifies.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CodeCard(
    summary: ReferralSummary,
    hasShareable: Boolean,
    onShare: () -> Unit,
    onCopy: () -> Unit,
) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Your referral code", style = MaterialTheme.typography.labelMedium)
            Text(
                summary.code.ifBlank { "—" },
                style = MaterialTheme.typography.headlineSmall,
            )
            if (summary.link.isNotBlank()) {
                Text(summary.link, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = onShare, enabled = hasShareable, modifier = Modifier.testTag(ReferralHubTestTags.SHARE)) {
                    Icon(Icons.Outlined.Share, contentDescription = null)
                    Text("Share", modifier = Modifier.padding(start = 8.dp))
                }
                OutlinedButton(onClick = onCopy, enabled = hasShareable, modifier = Modifier.testTag(ReferralHubTestTags.COPY)) {
                    Icon(Icons.Outlined.ContentCopy, contentDescription = null)
                    Text("Copy link", modifier = Modifier.padding(start = 8.dp))
                }
            }
        }
    }
}

@Composable
private fun StatsCard(summary: ReferralSummary) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Stat("Referred", summary.referredCount.toString())
                Stat("Qualified", summary.qualifiedCount.toString())
                Stat("Earned", RewardsMath.formatCentsUsd(summary.earnedRewardCents))
                Stat("Pending", RewardsMath.formatCentsUsd(summary.pendingRewardCents))
            }
        }
    }
}

@Composable
private fun Stat(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Text(value, style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun ReferralListCard(referrals: List<ReferredUser>) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Your referrals", style = MaterialTheme.typography.titleMedium)
            referrals.forEachIndexed { i, r ->
                if (i > 0) Divider()
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(r.maskedName, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                    AssistChip(onClick = {}, label = { Text(statusLabel(r.status)) })
                    Text(RewardsMath.formatCentsUsd(r.rewardCents), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

private fun statusLabel(status: ReferralStatus): String = when (status) {
    ReferralStatus.PENDING -> "Pending"
    ReferralStatus.QUALIFIED -> "Qualified"
    ReferralStatus.REWARDED -> "Rewarded"
}

// ---- Android side-effect seams (only the share/link string crosses; never cookies/PII) ----

private fun copyToClipboard(context: Context, label: String, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
}

private fun shareText(context: Context, text: String, chooserTitle: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val chooser = Intent.createChooser(send, chooserTitle).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
    try {
        context.startActivity(chooser)
    } catch (_: ActivityNotFoundException) {
        // No share target available; the copy action remains as a fallback.
    }
}
