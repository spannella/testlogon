@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adplatform

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adplatform.AdPlatformConsole
import com.testlogon.android.feature.adminops.CardSection
import com.testlogon.android.feature.adminops.KpiGrid
import com.testlogon.android.feature.adminops.StatRow
import com.testlogon.android.feature.adminops.adminOpsErrorMessage
import com.testlogon.android.feature.adminops.cents

object AdPlatformTestTags {
    const val SCREEN = "ad_platform_screen"
    const val FORBIDDEN = "ad_platform_forbidden"
    const val ERROR_RETRY = "ad_platform_error_retry"
    fun modAccount(id: String) = "ad_platform_mod_account_$id"
    fun modCreative(id: String) = "ad_platform_mod_creative_$id"
}

/** A moderation item pending action (account or creative), carried into the reason dialog. */
private data class ModTarget(val itemType: String, val id: String, val label: String, val action: String)

@Composable
fun AdPlatformRoute(
    onBack: () -> Unit,
    viewModel: AdPlatformViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdPlatformScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onModerateAccount = viewModel::moderateAccount,
        onModerateCreative = viewModel::moderateCreative,
        onMessageShown = viewModel::clearActionMessage,
    )
}

@Composable
fun AdPlatformScreen(
    state: AdPlatformUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onModerateAccount: (id: String, action: String, reason: String?) -> Unit,
    onModerateCreative: (id: String, action: String, reason: String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var modTarget by remember { mutableStateOf<ModTarget?>(null) }

    val message = (state as? AdPlatformUiState.Content)?.actionMessage
    val transient = (state as? AdPlatformUiState.Content)?.transientError
    LaunchedEffect(message, transient) {
        val text = message ?: transient?.let { adminOpsErrorMessage(it) }
        if (text != null) {
            snackbar.showSnackbar(text)
            onMessageShown()
        }
    }
    LaunchedEffect(message) { if (message != null) modTarget = null }

    Scaffold(
        modifier = modifier.testTag(AdPlatformTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Ad platform") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        val isRefreshing = (state as? AdPlatformUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is AdPlatformUiState.Loading -> LoadingState()
                is AdPlatformUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(AdPlatformTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need platform-admin access to view the ad platform.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is AdPlatformUiState.Error -> ErrorState(
                    modifier = Modifier.testTag(AdPlatformTestTags.ERROR_RETRY),
                    message = adminOpsErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is AdPlatformUiState.Content -> ConsoleBody(
                    data = state.data,
                    actionInFlight = state.actionInFlight,
                    onModerate = { modTarget = it },
                )
            }
        }
    }

    val target = modTarget
    if (target != null) {
        val inFlight = (state as? AdPlatformUiState.Content)?.actionInFlight == true
        ModerateDialog(
            target = target,
            actionInFlight = inFlight,
            onDismiss = { if (!inFlight) modTarget = null },
            onConfirm = { reason ->
                if (target.itemType == "account") onModerateAccount(target.id, target.action, reason)
                else onModerateCreative(target.id, target.action, reason)
            },
        )
    }
}

@Composable
private fun ConsoleBody(
    data: AdPlatformConsole,
    actionInFlight: Boolean,
    onModerate: (ModTarget) -> Unit,
) {
    val m = data.metrics
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        KpiGrid(
            tiles = listOf(
                "Total spend" to cents(m.totalSpendCents),
                "Platform rev" to cents(m.platformRevenueCents),
                "Creator share" to cents(m.creatorShareCents),
                "Impressions" to m.impressions.toString(),
                "Clicks" to m.clicks.toString(),
                "Conversions" to m.conversions.toString(),
                "eCPM" to cents(m.effectiveCpmCents),
                "Accounts" to m.accountCount.toString(),
                "Campaigns" to m.campaignCount.toString(),
                "Creatives" to m.creativeCount.toString(),
            ),
        )

        CardSection(title = "Kill switch") {
            StatRow(label = "Status", value = if (data.killSwitch.active) "ACTIVE (ad serving halted)" else "Off")
            if (data.killSwitch.active && data.killSwitch.reason.isNotBlank()) {
                StatRow(label = "Reason", value = data.killSwitch.reason)
            }
            Text(
                text = "Toggling the kill switch requires root access.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
        }

        if (data.revenue.isNotEmpty()) {
            CardSection(title = "Monthly revenue") {
                data.revenue.takeLast(6).forEach { p ->
                    StatRow(label = p.month, value = cents(p.platformRevenueCents))
                }
            }
        }

        if (data.topSpenders.isNotEmpty()) {
            CardSection(title = "Top spenders") {
                data.topSpenders.forEach { sp ->
                    StatRow(
                        label = sp.companyName.ifBlank { sp.accountId },
                        value = cents(sp.spendCents),
                    )
                }
            }
        }

        Text(
            text = "Moderation queue (${data.moderation.accountCount} accounts, ${data.moderation.creativeCount} creatives)",
            style = MaterialTheme.typography.titleMedium,
        )
        if (data.moderation.accounts.isEmpty() && data.moderation.creatives.isEmpty()) {
            Text("Nothing awaiting moderation.", style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        data.moderation.accounts.forEach { acct ->
            ModerationCard(
                testTag = AdPlatformTestTags.modAccount(acct.accountId),
                title = acct.companyName.ifBlank { acct.accountId },
                subtitle = "Account · ${acct.billingEmail}",
                status = acct.status,
                actionInFlight = actionInFlight,
                onApprove = { onModerate(ModTarget("account", acct.accountId, acct.companyName.ifBlank { acct.accountId }, "approve")) },
                onReject = { onModerate(ModTarget("account", acct.accountId, acct.companyName.ifBlank { acct.accountId }, "reject")) },
            )
        }
        data.moderation.creatives.forEach { cr ->
            ModerationCard(
                testTag = AdPlatformTestTags.modCreative(cr.creativeId),
                title = cr.title.ifBlank { cr.creativeId },
                subtitle = "Creative · ${cr.format} · ${cr.campaignId}",
                status = cr.status,
                actionInFlight = actionInFlight,
                onApprove = { onModerate(ModTarget("creative", cr.creativeId, cr.title.ifBlank { cr.creativeId }, "approve")) },
                onReject = { onModerate(ModTarget("creative", cr.creativeId, cr.title.ifBlank { cr.creativeId }, "reject")) },
            )
        }
    }
}

@Composable
private fun ModerationCard(
    testTag: String,
    title: String,
    subtitle: String,
    status: String,
    actionInFlight: Boolean,
    onApprove: () -> Unit,
    onReject: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(testTag)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(subtitle, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(status.ifBlank { "pending_review" }.replace('_', ' '),
                style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
            ) {
                OutlinedButton(onClick = onReject, enabled = !actionInFlight) { Text("Reject") }
                Button(onClick = onApprove, enabled = !actionInFlight) { Text("Approve") }
            }
        }
    }
}

@Composable
private fun ModerateDialog(
    target: ModTarget,
    actionInFlight: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (reason: String?) -> Unit,
) {
    var reason by remember { mutableStateOf("") }
    val needsReason = target.action == "reject" || target.action == "suspend"
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "${target.action.replaceFirstChar { it.uppercase() }} ${target.itemType}",
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(target.label, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (needsReason) {
                    OutlinedTextField(
                        value = reason,
                        onValueChange = { if (it.length <= 500) reason = it },
                        label = { Text("Reason (required)") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !actionInFlight,
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    TextButton(onClick = onDismiss, enabled = !actionInFlight) { Text("Cancel") }
                    Button(
                        onClick = { onConfirm(reason.ifBlank { null }) },
                        enabled = !actionInFlight && (!needsReason || reason.isNotBlank()),
                    ) { Text("Confirm") }
                }
            }
        }
    }
}
