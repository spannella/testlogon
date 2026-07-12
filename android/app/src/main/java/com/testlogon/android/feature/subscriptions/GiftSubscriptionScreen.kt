@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.subscriptions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.subscriptions.SubscriptionTier

/** SUB-E2 - stable test tags for the gift-a-subscription flow. */
object GiftSubscriptionTestTags {
    const val SCREEN = "gift_sub_screen"
    const val RECIPIENT = "gift_sub_recipient"
    const val MESSAGE = "gift_sub_message"
    const val CONFIRM = "gift_sub_confirm"
    const val WORKING = "gift_sub_working"
    const val SUCCESS = "gift_sub_success"
    const val ERROR = "gift_sub_error"
    const val UNAVAILABLE = "gift_sub_unavailable"
    fun tier(id: String) = "gift_sub_tier_$id"
}

@Composable
fun GiftSubscriptionRoute(
    onGifted: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GiftSubscriptionViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    androidx.compose.runtime.LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is GiftSubscriptionEvent.Gifted -> Unit // success reflected in state; back handled by CTA
                is GiftSubscriptionEvent.ShowMessage ->
                    snackbarHostState.showSnackbar(event.message.resolve(context.resources))
            }
        }
    }

    GiftSubscriptionScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onRecipientChanged = viewModel::onRecipientChanged,
        onMessageChanged = viewModel::onMessageChanged,
        onSelectTier = viewModel::onSelectTier,
        onConfirm = viewModel::confirm,
        onRetry = viewModel::retry,
        onErrorRetry = viewModel::loadTiers,
        onDone = onGifted,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun GiftSubscriptionScreen(
    state: GiftSubscriptionUiState,
    snackbarHostState: SnackbarHostState,
    onRecipientChanged: (String) -> Unit,
    onMessageChanged: (String) -> Unit,
    onSelectTier: (String) -> Unit,
    onConfirm: () -> Unit,
    onRetry: () -> Unit,
    onErrorRetry: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GiftSubscriptionTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.gift_sub_title)) },
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
            when (state.status) {
                GiftSubscriptionUiState.Status.Loading -> LoadingState()
                GiftSubscriptionUiState.Status.Empty ->
                    EmptyState(
                        title = stringResource(R.string.gift_sub_empty_title),
                        body = stringResource(R.string.gift_sub_empty_body),
                    )
                GiftSubscriptionUiState.Status.Error ->
                    ErrorState(
                        message = state.errorMessage?.asString()
                            ?: stringResource(R.string.gift_sub_empty_body),
                        onRetry = onErrorRetry,
                        modifier = Modifier.testTag(GiftSubscriptionTestTags.ERROR),
                    )
                GiftSubscriptionUiState.Status.Success -> SuccessContent(state = state, onDone = onDone)
                GiftSubscriptionUiState.Status.PaymentsUnavailable -> UnavailableContent(onBack = onBack)
                else -> ReviewContent(
                    state = state,
                    onRecipientChanged = onRecipientChanged,
                    onMessageChanged = onMessageChanged,
                    onSelectTier = onSelectTier,
                    onConfirm = onConfirm,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun ReviewContent(
    state: GiftSubscriptionUiState,
    onRecipientChanged: (String) -> Unit,
    onMessageChanged: (String) -> Unit,
    onSelectTier: (String) -> Unit,
    onConfirm: () -> Unit,
    onRetry: () -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.gift_sub_blurb),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        OutlinedTextField(
            value = state.recipient,
            onValueChange = onRecipientChanged,
            label = { Text(stringResource(R.string.gift_sub_recipient_label)) },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GiftSubscriptionTestTags.RECIPIENT),
        )

        Text(stringResource(R.string.gift_sub_pick_tier), style = MaterialTheme.typography.titleMedium)
        state.tiers.forEach { tier ->
            GiftTierRow(
                tier = tier,
                selected = tier.planId == state.selectedPlanId,
                onSelect = { onSelectTier(tier.planId) },
            )
        }

        OutlinedTextField(
            value = state.message,
            onValueChange = onMessageChanged,
            label = { Text(stringResource(R.string.gift_sub_message_label)) },
            modifier = Modifier
                .fillMaxWidth()
                .testTag(GiftSubscriptionTestTags.MESSAGE),
        )

        state.selectedTier?.let { tier ->
            val freeLabel = stringResource(R.string.subs_tiers_free)
            val price = formatTierPrice(tier.priceCents, tier.currency, freeLabel)
            Text(
                stringResource(R.string.gift_sub_charge_notice, price),
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        if (state.status == GiftSubscriptionUiState.Status.Error && state.errorMessage != null) {
            Text(
                text = state.errorMessage.asString(),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
            OutlinedButton(
                onClick = onRetry,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) { Text(stringResource(R.string.action_retry)) }
        }

        if (state.isWorking) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .semantics { liveRegion = LiveRegionMode.Polite }
                    .testTag(GiftSubscriptionTestTags.WORKING),
                contentAlignment = Alignment.Center,
            ) { CircularProgressIndicator() }
        } else {
            Button(
                onClick = onConfirm,
                enabled = state.canConfirm,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(GiftSubscriptionTestTags.CONFIRM),
            ) { Text(stringResource(R.string.gift_sub_confirm)) }
        }
    }
}

@Composable
private fun GiftTierRow(tier: SubscriptionTier, selected: Boolean, onSelect: () -> Unit) {
    val freeLabel = stringResource(R.string.subs_tiers_free)
    val price = formatTierPrice(tier.priceCents, tier.currency, freeLabel)
    val interval = intervalSuffix(
        interval = tier.interval,
        monthLabel = stringResource(R.string.subs_tiers_interval_month),
        yearLabel = stringResource(R.string.subs_tiers_interval_year),
        weekLabel = stringResource(R.string.subs_tiers_interval_week),
    )
    Card(
        Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onSelect)
            .testTag(GiftSubscriptionTestTags.tier(tier.planId)),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            RadioButton(selected = selected, onClick = onSelect)
            Column(Modifier.fillMaxWidth()) {
                Text(tier.name, style = MaterialTheme.typography.titleSmall)
                Text("$price$interval", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun SuccessContent(state: GiftSubscriptionUiState, onDone: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .semantics { liveRegion = LiveRegionMode.Polite }
            .testTag(GiftSubscriptionTestTags.SUCCESS),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.gift_sub_success_title), style = MaterialTheme.typography.titleLarge)
        Text(
            stringResource(R.string.gift_sub_success_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            onClick = onDone,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        ) { Text(stringResource(R.string.action_done)) }
    }
}

@Composable
private fun UnavailableContent(onBack: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .semantics { liveRegion = LiveRegionMode.Polite }
            .testTag(GiftSubscriptionTestTags.UNAVAILABLE),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.subscribe_unavailable_title), style = MaterialTheme.typography.titleMedium)
        Text(
            stringResource(R.string.subs_tiers_coming_soon),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedButton(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        ) { Text(stringResource(R.string.action_back)) }
    }
}
