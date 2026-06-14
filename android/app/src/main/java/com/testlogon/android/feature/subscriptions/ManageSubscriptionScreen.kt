@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.subscriptions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.subscriptions.SubscriptionState

/** AND-237 — stable test tags for the manage / cancel subscription screen. */
object ManageSubscriptionTestTags {
    const val SCREEN = "manage_sub_screen"
    const val CONTENT = "manage_sub_content"
    const val EMPTY = "manage_sub_empty"
    const val ERROR = "manage_sub_error"
    const val CANCEL = "manage_sub_cancel"
    const val KEEP = "manage_sub_keep"
    const val REACTIVATE = "manage_sub_reactivate"
    const val CONFIRM_DIALOG = "manage_sub_confirm_dialog"
    const val CONFIRM_CANCEL = "manage_sub_confirm_cancel"
    const val MUTATION_PROGRESS = "manage_sub_progress"
    const val SCHEDULED_BANNER = "manage_sub_scheduled_banner"
}

/**
 * AND-237 — manage / cancel subscription route. Loads the current subscription, renders status/renewal,
 * and exposes cancel (confirm dialog -> cancel-at-period-end), keep (clear scheduled cancel), and
 * reactivate (resume). A reactivation that needs fresh payment navigates to the AND-236 subscribe flow.
 */
@Composable
fun ManageSubscriptionRoute(
    onNavigateToSubscribe: (planId: String, creatorId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ManageSubscriptionViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    androidx.compose.runtime.LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ManageSubscriptionEvent.NavigateToSubscribe ->
                    onNavigateToSubscribe(event.planId, event.creatorId)
            }
        }
    }

    ManageSubscriptionScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onCancelClicked = viewModel::onCancelClicked,
        onCancelDismissed = viewModel::onCancelDismissed,
        onCancelConfirmed = viewModel::onCancelConfirmed,
        onRenewClicked = viewModel::onRenewClicked,
        onErrorRetry = viewModel::onErrorRetry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun ManageSubscriptionScreen(
    state: ManageSubscriptionUiState,
    snackbarHostState: SnackbarHostState,
    onCancelClicked: () -> Unit,
    onCancelDismissed: () -> Unit,
    onCancelConfirmed: () -> Unit,
    onRenewClicked: () -> Unit,
    onErrorRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ManageSubscriptionTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.manage_sub_title)) },
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
            when (state) {
                is ManageSubscriptionUiState.Loading -> LoadingState()

                is ManageSubscriptionUiState.NoSubscription ->
                    EmptyState(
                        title = stringResource(R.string.manage_sub_empty_title),
                        body = stringResource(R.string.manage_sub_empty_body),
                        modifier = Modifier.testTag(ManageSubscriptionTestTags.EMPTY),
                    )

                is ManageSubscriptionUiState.Error ->
                    ErrorState(
                        message = state.message.asString(),
                        onRetry = onErrorRetry,
                        modifier = Modifier.testTag(ManageSubscriptionTestTags.ERROR),
                    )

                is ManageSubscriptionUiState.Content ->
                    ContentBody(
                        state = state,
                        onCancelClicked = onCancelClicked,
                        onCancelDismissed = onCancelDismissed,
                        onCancelConfirmed = onCancelConfirmed,
                        onRenewClicked = onRenewClicked,
                    )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: ManageSubscriptionUiState.Content,
    onCancelClicked: () -> Unit,
    onCancelDismissed: () -> Unit,
    onCancelConfirmed: () -> Unit,
    onRenewClicked: () -> Unit,
) {
    val sub = state.subscription
    val freeLabel = stringResource(R.string.subs_tiers_free)
    val priceText = formatTierPrice(sub.priceCents ?: 0L, sub.currency ?: "USD", freeLabel)
    val intervalLabel = intervalSuffix(
        interval = sub.interval,
        monthLabel = stringResource(R.string.subs_tiers_interval_month),
        yearLabel = stringResource(R.string.subs_tiers_interval_year),
        weekLabel = stringResource(R.string.subs_tiers_interval_week),
    )
    val periodEnd = formatEpochDate(sub.currentPeriodEndEpochSeconds)
    val statusLabel = stringResource(statusStringRes(sub.status))

    Column(
        Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(
            Modifier
                .fillMaxWidth()
                .testTag(ManageSubscriptionTestTags.CONTENT),
        ) {
            Column(
                Modifier
                    .padding(16.dp)
                    .clearAndSetSemantics {
                        contentDescription = buildString {
                            append(sub.planId)
                            append(", "); append(statusLabel)
                            if (periodEnd != null) { append(", "); append(periodEnd) }
                        }
                    },
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(sub.planId, style = MaterialTheme.typography.titleLarge)
                Text("$priceText$intervalLabel", style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.manage_sub_status_label, statusLabel),
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (periodEnd != null) {
                    Text(
                        stringResource(R.string.manage_sub_renews_on, periodEnd),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (state.isScheduledToCancel) {
            val endText = periodEnd ?: stringResource(R.string.manage_sub_period_end_fallback)
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(ManageSubscriptionTestTags.SCHEDULED_BANNER),
            ) {
                Text(
                    stringResource(R.string.manage_sub_will_end_on, endText),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                )
            }
        }

        when (val mutation = state.mutation) {
            is MutationStatus.Failed ->
                Text(
                    text = mutation.message.asString(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            else -> Unit
        }

        val working = state.mutation is MutationStatus.Canceling || state.mutation is MutationStatus.Renewing
        if (working) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .semantics { liveRegion = LiveRegionMode.Polite }
                    .testTag(ManageSubscriptionTestTags.MUTATION_PROGRESS),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator(modifier = Modifier.size(28.dp))
            }
        } else {
            PrimaryAction(
                state = state,
                onCancelClicked = onCancelClicked,
                onRenewClicked = onRenewClicked,
            )
        }
    }

    if (state.confirmCancelVisible) {
        CancelConfirmDialog(onConfirm = onCancelConfirmed, onDismiss = onCancelDismissed)
    }
}

@Composable
private fun PrimaryAction(
    state: ManageSubscriptionUiState.Content,
    onCancelClicked: () -> Unit,
    onRenewClicked: () -> Unit,
) {
    when {
        state.canCancel ->
            Button(
                onClick = onCancelClicked,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(ManageSubscriptionTestTags.CANCEL),
            ) { Text(stringResource(R.string.manage_sub_cancel_action)) }

        state.isScheduledToCancel ->
            Button(
                onClick = onRenewClicked,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(ManageSubscriptionTestTags.KEEP),
            ) { Text(stringResource(R.string.manage_sub_keep_action)) }

        state.isReactivatable ->
            Button(
                onClick = onRenewClicked,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(ManageSubscriptionTestTags.REACTIVATE),
            ) { Text(stringResource(R.string.manage_sub_reactivate_action)) }

        else -> Unit
    }
}

@Composable
private fun CancelConfirmDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        modifier = Modifier.testTag(ManageSubscriptionTestTags.CONFIRM_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.manage_sub_confirm_title)) },
        text = { Text(stringResource(R.string.manage_sub_confirm_body)) },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                modifier = Modifier.testTag(ManageSubscriptionTestTags.CONFIRM_CANCEL),
            ) { Text(stringResource(R.string.manage_sub_confirm_yes)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.manage_sub_confirm_no)) }
        },
    )
}

private fun statusStringRes(status: SubscriptionState): Int = when (status) {
    SubscriptionState.ACTIVE -> R.string.manage_sub_status_active
    SubscriptionState.TRIALING -> R.string.manage_sub_status_trialing
    SubscriptionState.PAST_DUE -> R.string.manage_sub_status_past_due
    SubscriptionState.CANCELED -> R.string.manage_sub_status_canceled
    SubscriptionState.EXPIRED -> R.string.manage_sub_status_expired
    SubscriptionState.UNKNOWN -> R.string.manage_sub_status_unknown
}
