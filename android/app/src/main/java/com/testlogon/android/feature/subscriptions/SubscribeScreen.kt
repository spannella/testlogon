@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.subscriptions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import com.testlogon.android.data.subscriptions.TierBenefit

/** AND-236 — stable test tags for the subscribe confirmation flow. */
object SubscribeTestTags {
    const val SCREEN = "subscribe_screen"
    const val CONFIRM = "subscribe_confirm"
    const val WORKING = "subscribe_working"
    const val SUCCESS = "subscribe_success"
    const val UNAVAILABLE = "subscribe_unavailable"
    const val ERROR = "subscribe_error"
    const val RETRY = "subscribe_retry"
    const val ADD_CARD_HINT = "subscribe_add_card"
    const val BENEFITS = "subscribe_benefits"
    const val DONE = "subscribe_done"
}

/**
 * AND-236 — subscribe confirmation route. Reviews the selected tier, confirms, routes the pay step
 * through the BillingAuthorizer stub (flag-gated), and reflects the activated subscription. On
 * activation it emits a one-shot result so the originating browse screen updates entitlement.
 */
@Composable
fun SubscribeRoute(
    onSubscribed: (subscriptionId: String, planId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SubscribeViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    androidx.compose.runtime.LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is SubscribeEvent.Activated -> onSubscribed(event.subscriptionId, event.planId)
                is SubscribeEvent.ShowMessage ->
                    snackbarHostState.showSnackbar(event.message.resolve(context.resources))
            }
        }
    }

    SubscribeScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onConfirm = viewModel::confirm,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun SubscribeScreen(
    state: SubscribeUiState,
    snackbarHostState: SnackbarHostState,
    onConfirm: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SubscribeTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.subscribe_title)) },
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
        Box(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            when (state.status) {
                SubscribeUiState.Status.Success -> SuccessContent()
                SubscribeUiState.Status.PaymentsUnavailable -> UnavailableContent(onBack = onBack)
                else -> ReviewContent(state = state, onConfirm = onConfirm, onRetry = onRetry)
            }
        }
    }
}

@Composable
private fun ReviewContent(
    state: SubscribeUiState,
    onConfirm: () -> Unit,
    onRetry: () -> Unit,
) {
    val freeLabel = stringResource(R.string.subs_tiers_free)
    val price = formatTierPrice(state.tier.priceCents, state.tier.currency, freeLabel)
    val intervalLabel = if (state.tier.priceCents == 0L) {
        ""
    } else {
        intervalSuffix(
            interval = state.tier.interval,
            monthLabel = stringResource(R.string.subs_tiers_interval_month),
            yearLabel = stringResource(R.string.subs_tiers_interval_year),
            weekLabel = stringResource(R.string.subs_tiers_interval_week),
        )
    }

    Column(verticalArrangement = Arrangement.spacedBy(16.dp), modifier = Modifier.fillMaxWidth()) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(state.tier.name, style = MaterialTheme.typography.titleLarge)
                Text(
                    text = "$price$intervalLabel",
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                state.tier.description?.takeIf { it.isNotBlank() }?.let {
                    Text(it, style = MaterialTheme.typography.bodyMedium)
                }

                // SUB-E0: the structured benefits the subscriber is paying for.
                if (state.tier.benefits.isNotEmpty()) {
                    Column(
                        modifier = Modifier.fillMaxWidth().testTag(SubscribeTestTags.BENEFITS),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        state.tier.benefits.forEach { BenefitRow(it) }
                    }
                }

                // SUB-E0: state the real charge explicitly (the backend REALLY charges this now).
                if (state.tier.priceCents > 0L) {
                    Text(
                        text = stringResource(R.string.subscribe_charge_notice, "$price$intervalLabel"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
                Text(
                    stringResource(R.string.subscribe_review_blurb),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (state.status == SubscribeUiState.Status.Error && state.errorMessage != null) {
            Text(
                text = state.errorMessage.asString(),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag(SubscribeTestTags.ERROR),
            )
            if (state.requiresPaymentMethod) {
                Text(
                    text = stringResource(R.string.subscribe_add_card_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(SubscribeTestTags.ADD_CARD_HINT),
                )
            }
            OutlinedButton(
                onClick = onRetry,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(SubscribeTestTags.RETRY),
            ) {
                Text(stringResource(R.string.action_retry))
            }
        }

        if (state.isWorking) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .semantics { liveRegion = LiveRegionMode.Polite }
                    .testTag(SubscribeTestTags.WORKING),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
        } else {
            Button(
                onClick = onConfirm,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(SubscribeTestTags.CONFIRM),
            ) {
                Text(stringResource(R.string.subscribe_confirm))
            }
        }
    }
}

/** SUB-E0 - a single tier benefit (checkmark + label + optional detail) on the confirm sheet. */
@Composable
private fun BenefitRow(benefit: TierBenefit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(
            imageVector = Icons.Filled.Check,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(top = 2.dp),
        )
        Column(Modifier.fillMaxWidth()) {
            Text(benefit.label, style = MaterialTheme.typography.bodyMedium)
            benefit.detail?.takeIf { it.isNotBlank() }?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun SuccessContent() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .semantics { liveRegion = LiveRegionMode.Polite }
            .testTag(SubscribeTestTags.SUCCESS),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.subscribe_success_title), style = MaterialTheme.typography.titleLarge)
        Text(
            stringResource(R.string.subscribe_success_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun UnavailableContent(onBack: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .semantics { liveRegion = LiveRegionMode.Polite }
            .testTag(SubscribeTestTags.UNAVAILABLE),
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
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(SubscribeTestTags.DONE),
        ) {
            Text(stringResource(R.string.action_back))
        }
    }
}
