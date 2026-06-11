@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.PayoutGate

/** AND-259 — stable testTags for the payout setup screen. */
object PayoutSetupTestTags {
    const val SCREEN = "payout_setup_screen"
    const val FORM = "payout_setup_form"
    const val AMOUNT = "payout_setup_amount"
    const val SUBMIT = "payout_setup_submit"
    const val GATE_PANEL = "payout_setup_gate_panel"
    const val VERIFY = "payout_setup_verify"
    const val GATE_UNKNOWN = "payout_setup_gate_unknown"
}

/** AND-259 — route-level payout setup entry; the gate routes to the KYC verification entry route. */
@Composable
fun PayoutSetupRoute(
    onNavigateToKyc: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PayoutSetupViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val resources = LocalContext.current.resources

    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                PayoutSetupViewModel.Effect.NavigateToKyc -> onNavigateToKyc()
                // resolve the UiText with Resources (non-composable lambda) per the gotchas.
                is PayoutSetupViewModel.Effect.ShowMessage ->
                    snackbarHostState.showSnackbar(effect.text.resolve(resources))
            }
        }
    }

    // Surface the created-payout confirmation once.
    val confirmId = state.lastCreatedPayoutId
    val confirmMsg = stringResource(R.string.payout_request_submitted)
    LaunchedEffect(confirmId) {
        if (confirmId != null) {
            snackbarHostState.showSnackbar(confirmMsg)
            viewModel.consumeConfirmation()
        }
    }

    PayoutSetupScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onAmountChanged = viewModel::onAmountChanged,
        onMethodSelected = viewModel::onMethodSelected,
        onNotesChanged = viewModel::onNotesChanged,
        onSubmit = viewModel::submit,
        onVerifyIdentity = viewModel::onVerifyIdentity,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun PayoutSetupScreen(
    state: PayoutSetupViewModel.UiState,
    snackbarHostState: SnackbarHostState,
    onAmountChanged: (String) -> Unit,
    onMethodSelected: (String) -> Unit,
    onNotesChanged: (String) -> Unit,
    onSubmit: () -> Unit,
    onVerifyIdentity: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PayoutSetupTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.payout_setup_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("payout_setup_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when {
            state.isLoading -> LoadingState(
                message = stringResource(R.string.payout_setup_loading),
                modifier = Modifier.padding(padding),
            )
            state.loadFailed -> ErrorState(
                message = state.error?.asString() ?: stringResource(R.string.payout_setup_error_generic),
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            else -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                state.balance?.let { BalanceCard(it) }

                when (val gate = state.gate) {
                    PayoutGate.Allowed -> PayoutForm(
                        state = state,
                        onAmountChanged = onAmountChanged,
                        onMethodSelected = onMethodSelected,
                        onNotesChanged = onNotesChanged,
                        onSubmit = onSubmit,
                    )
                    is PayoutGate.Blocked -> KycGatePanel(
                        blocked = gate,
                        evaluating = state.evaluating,
                        onVerifyIdentity = onVerifyIdentity,
                    )
                    PayoutGate.Unknown -> GateUnknownPanel(onRetry = onRetry)
                }
            }
        }
    }
}

@Composable
private fun BalanceCard(balance: com.testlogon.android.data.payouts.PayoutBalance) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.payout_balance_available),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = formatPayoutMoney(
                    com.testlogon.android.data.payouts.PayoutMoney(balance.availableCents, balance.currency),
                ),
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                text = stringResource(
                    R.string.payout_balance_minimum,
                    formatPayoutMoney(
                        com.testlogon.android.data.payouts.PayoutMoney(balance.minimumPayoutCents, balance.currency),
                    ),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PayoutForm(
    state: PayoutSetupViewModel.UiState,
    onAmountChanged: (String) -> Unit,
    onMethodSelected: (String) -> Unit,
    onNotesChanged: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val form = state.form
    val amountErrorText = form.amountError?.asString()
    Column(
        modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.FORM),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = form.amountText,
            onValueChange = onAmountChanged,
            label = { Text(stringResource(R.string.payout_amount_label)) },
            isError = amountErrorText != null,
            supportingText = if (amountErrorText != null) {
                { Text(amountErrorText) }
            } else {
                null
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.AMOUNT),
        )

        Text(stringResource(R.string.payout_method_label), style = MaterialTheme.typography.labelLarge)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PayoutMethodOption("bank_transfer", R.string.payout_method_bank_transfer, form.method, onMethodSelected)
            PayoutMethodOption("paypal", R.string.payout_method_paypal, form.method, onMethodSelected)
        }

        OutlinedTextField(
            value = form.notes,
            onValueChange = onNotesChanged,
            label = { Text(stringResource(R.string.payout_notes_label)) },
            singleLine = false,
            modifier = Modifier.fillMaxWidth(),
        )

        Button(
            onClick = onSubmit,
            enabled = form.canSubmit && !state.isSubmitting,
            modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.SUBMIT),
        ) {
            if (state.isSubmitting) {
                CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
            }
            Text(stringResource(R.string.payout_request_action))
        }
    }
}

@Composable
private fun PayoutMethodOption(
    method: String,
    labelRes: Int,
    selected: String,
    onSelected: (String) -> Unit,
) {
    FilterChip(
        selected = selected == method,
        onClick = { onSelected(method) },
        label = { Text(stringResource(labelRes)) },
    )
}

@Composable
private fun KycGatePanel(
    blocked: PayoutGate.Blocked,
    evaluating: Boolean,
    onVerifyIdentity: () -> Unit,
) {
    val title = stringResource(R.string.payout_gate_title)
    val tierLine = stringResource(
        R.string.payout_gate_tiers,
        blocked.currentTier.rank,
        blocked.requiredTier.rank,
    )
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(PayoutSetupTestTags.GATE_PANEL)
            .semantics(mergeDescendants = true) { },
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(text = tierLine, style = MaterialTheme.typography.bodyMedium)
            if (blocked.missing.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.payout_gate_missing, blocked.missing.joinToString(", ")),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            // STOP-AND-FLAG: the KYC vendor SDK is not configured; the verify action is wired but the
            // bound StubKycVerifier never launches a real flow.
            Text(
                text = stringResource(R.string.payout_gate_unavailable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            HorizontalDivider()
            Button(
                onClick = onVerifyIdentity,
                enabled = !evaluating,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.VERIFY),
            ) {
                Text(stringResource(R.string.payout_gate_verify_action))
            }
        }
    }
}

@Composable
private fun GateUnknownPanel(onRetry: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.GATE_UNKNOWN),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.payout_gate_unknown_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(R.string.payout_gate_unknown_body),
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedButton(onClick = onRetry, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_retry))
            }
        }
    }
}
