@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
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
import androidx.compose.material3.Checkbox
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.PayoutGate
import com.testlogon.android.data.payouts.PayoutMethod
import com.testlogon.android.data.payouts.PayoutMethodStatus
import com.testlogon.android.data.payouts.RoutableMethodType

/** AND-259 / PAY-13 — stable testTags for the payout setup screen. */
object PayoutSetupTestTags {
    const val SCREEN = "payout_setup_screen"
    const val FORM = "payout_setup_form"
    const val AMOUNT = "payout_setup_amount"
    const val SUBMIT = "payout_setup_submit"
    const val GATE_PANEL = "payout_setup_gate_panel"
    const val VERIFY = "payout_setup_verify"
    const val GATE_UNKNOWN = "payout_setup_gate_unknown"

    // PAY-13 — routable payout methods.
    const val METHODS = "payout_methods_section"
    const val ADD_METHOD = "payout_add_method"
    const val ADD_FORM = "payout_add_method_form"
    const val ADD_ROUTING = "payout_add_routing"
    const val ADD_ACCOUNT = "payout_add_account"
    const val ADD_EMAIL = "payout_add_email"
    const val ADD_NICKNAME = "payout_add_nickname"
    const val ADD_SUBMIT = "payout_add_submit"
    const val CONNECT_BUTTON = "payout_connect_button"

    fun methodRow(id: String) = "payout_method_$id"
    fun methodVerify(id: String) = "payout_method_verify_$id"
    fun methodDefault(id: String) = "payout_method_default_$id"
    fun methodRemove(id: String) = "payout_method_remove_$id"
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
    val uriHandler = LocalUriHandler.current

    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                PayoutSetupViewModel.Effect.NavigateToKyc -> onNavigateToKyc()
                // resolve the UiText with Resources (non-composable lambda) per the gotchas.
                is PayoutSetupViewModel.Effect.ShowMessage ->
                    snackbarHostState.showSnackbar(effect.text.resolve(resources))
                // PAY-11 — real Connect onboarding URL (only when Stripe Connect is keyed server-side).
                is PayoutSetupViewModel.Effect.OpenUrl -> uriHandler.openUri(effect.url)
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
        onAddMethodClicked = viewModel::onAddMethodClicked,
        onCancelAddMethod = viewModel::onCancelAddMethod,
        onAddChoiceSelected = viewModel::onAddChoiceSelected,
        onAddFieldChanged = viewModel::onAddFieldChanged,
        onSubmitAddMethod = viewModel::submitAddMethod,
        onVerifyMethod = viewModel::verifyMethod,
        onSetDefaultMethod = viewModel::setDefaultMethod,
        onDeleteMethod = viewModel::deleteMethod,
        onStartConnect = viewModel::startConnectOnboarding,
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
    onAddMethodClicked: () -> Unit,
    onCancelAddMethod: () -> Unit,
    onAddChoiceSelected: (PayoutSetupViewModel.MethodChoice) -> Unit,
    onAddFieldChanged: ((PayoutSetupViewModel.AddMethodForm) -> PayoutSetupViewModel.AddMethodForm) -> Unit,
    onSubmitAddMethod: () -> Unit,
    onVerifyMethod: (String) -> Unit,
    onSetDefaultMethod: (String) -> Unit,
    onDeleteMethod: (String) -> Unit,
    onStartConnect: (Boolean) -> Unit,
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

                // PAY-13 — routable payout destinations (independent of the KYC gate).
                PayoutMethodsSection(
                    state = state,
                    onAddMethodClicked = onAddMethodClicked,
                    onCancelAddMethod = onCancelAddMethod,
                    onAddChoiceSelected = onAddChoiceSelected,
                    onAddFieldChanged = onAddFieldChanged,
                    onSubmitAddMethod = onSubmitAddMethod,
                    onVerifyMethod = onVerifyMethod,
                    onSetDefaultMethod = onSetDefaultMethod,
                    onDeleteMethod = onDeleteMethod,
                    onStartConnect = onStartConnect,
                )

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

// ---- PAY-13: routable payout methods ----

@Composable
private fun PayoutMethodsSection(
    state: PayoutSetupViewModel.UiState,
    onAddMethodClicked: () -> Unit,
    onCancelAddMethod: () -> Unit,
    onAddChoiceSelected: (PayoutSetupViewModel.MethodChoice) -> Unit,
    onAddFieldChanged: ((PayoutSetupViewModel.AddMethodForm) -> PayoutSetupViewModel.AddMethodForm) -> Unit,
    onSubmitAddMethod: () -> Unit,
    onVerifyMethod: (String) -> Unit,
    onSetDefaultMethod: (String) -> Unit,
    onDeleteMethod: (String) -> Unit,
    onStartConnect: (Boolean) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.METHODS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.payout_methods_section_title),
                style = MaterialTheme.typography.titleMedium,
            )

            if (state.methods.isEmpty() && !state.methodsLoading) {
                Text(
                    text = stringResource(R.string.payout_methods_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            state.methods.forEach { method ->
                PayoutMethodRow(
                    method = method,
                    busy = state.busyMethodId == method.methodId,
                    enabled = state.busyMethodId == null,
                    onVerify = { onVerifyMethod(method.methodId) },
                    onSetDefault = { onSetDefaultMethod(method.methodId) },
                    onRemove = { onDeleteMethod(method.methodId) },
                )
                HorizontalDivider()
            }

            Text(
                text = stringResource(R.string.payout_methods_sec_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (state.addForm == null) {
                Button(
                    onClick = onAddMethodClicked,
                    modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.ADD_METHOD),
                ) {
                    Text(stringResource(R.string.payout_method_add))
                }
            } else {
                AddMethodForm(
                    form = state.addForm,
                    submitting = state.addSubmitting,
                    connectBusy = state.connectBusy,
                    onCancel = onCancelAddMethod,
                    onChoiceSelected = onAddChoiceSelected,
                    onFieldChanged = onAddFieldChanged,
                    onSubmit = onSubmitAddMethod,
                    onStartConnect = onStartConnect,
                )
            }
        }
    }
}

@Composable
private fun PayoutMethodRow(
    method: PayoutMethod,
    busy: Boolean,
    enabled: Boolean,
    onVerify: () -> Unit,
    onSetDefault: () -> Unit,
    onRemove: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(PayoutSetupTestTags.methodRow(method.methodId))
            .semantics(mergeDescendants = true) { },
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = method.nickname.ifBlank { methodTypeLabel(method.type) },
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.weight(1f),
            )
            if (method.isDefault) {
                StatusPill(
                    text = stringResource(R.string.payout_method_default_badge),
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            MethodStatusPill(method.status)
        }
        Text(
            text = methodDestinationLine(method),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            if (busy) {
                CircularProgressIndicator(modifier = Modifier.padding(8.dp))
            }
            if (method.status != PayoutMethodStatus.VERIFIED) {
                TextButton(
                    onClick = onVerify,
                    enabled = enabled,
                    modifier = Modifier.testTag(PayoutSetupTestTags.methodVerify(method.methodId)),
                ) {
                    Text(stringResource(R.string.payout_method_verify_action))
                }
            }
            if (!method.isDefault) {
                TextButton(
                    onClick = onSetDefault,
                    enabled = enabled,
                    modifier = Modifier.testTag(PayoutSetupTestTags.methodDefault(method.methodId)),
                ) {
                    Text(stringResource(R.string.payout_method_default_action))
                }
            }
            TextButton(
                onClick = onRemove,
                enabled = enabled,
                modifier = Modifier.testTag(PayoutSetupTestTags.methodRemove(method.methodId)),
            ) {
                Text(stringResource(R.string.payout_method_remove_action))
            }
        }
    }
}

@Composable
private fun AddMethodForm(
    form: PayoutSetupViewModel.AddMethodForm,
    submitting: Boolean,
    connectBusy: Boolean,
    onCancel: () -> Unit,
    onChoiceSelected: (PayoutSetupViewModel.MethodChoice) -> Unit,
    onFieldChanged: ((PayoutSetupViewModel.AddMethodForm) -> PayoutSetupViewModel.AddMethodForm) -> Unit,
    onSubmit: () -> Unit,
    onStartConnect: (Boolean) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.ADD_FORM),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.payout_method_type_label), style = MaterialTheme.typography.labelLarge)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AddTypeChip(PayoutSetupViewModel.MethodChoice.BANK, R.string.payout_method_type_bank, form.choice, onChoiceSelected)
            AddTypeChip(PayoutSetupViewModel.MethodChoice.PAYPAL, R.string.payout_method_type_paypal, form.choice, onChoiceSelected)
            AddTypeChip(PayoutSetupViewModel.MethodChoice.CONNECT, R.string.payout_method_type_connect, form.choice, onChoiceSelected)
        }

        when (form.choice) {
            PayoutSetupViewModel.MethodChoice.BANK -> {
                OutlinedTextField(
                    value = form.routingNumber,
                    onValueChange = { v -> onFieldChanged { it.copy(routingNumber = v.filter(Char::isDigit).take(9)) } },
                    label = { Text(stringResource(R.string.payout_method_routing_label)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.ADD_ROUTING),
                )
                OutlinedTextField(
                    value = form.accountNumber,
                    onValueChange = { v -> onFieldChanged { it.copy(accountNumber = v.filter(Char::isDigit).take(17)) } },
                    label = { Text(stringResource(R.string.payout_method_account_label)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.ADD_ACCOUNT),
                )
                CheckboxRow(
                    checked = form.wire,
                    label = stringResource(R.string.payout_method_wire_label),
                    onToggle = { c -> onFieldChanged { it.copy(wire = c) } },
                )
            }
            PayoutSetupViewModel.MethodChoice.PAYPAL -> {
                OutlinedTextField(
                    value = form.paypalEmail,
                    onValueChange = { v -> onFieldChanged { it.copy(paypalEmail = v.trim()) } },
                    label = { Text(stringResource(R.string.payout_method_paypal_email_label)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.ADD_EMAIL),
                )
            }
            PayoutSetupViewModel.MethodChoice.CONNECT -> {
                Text(
                    text = stringResource(R.string.payout_method_connect_blurb),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (form.choice != PayoutSetupViewModel.MethodChoice.CONNECT) {
            OutlinedTextField(
                value = form.nickname,
                onValueChange = { v -> onFieldChanged { it.copy(nickname = v.take(100)) } },
                label = { Text(stringResource(R.string.payout_method_nickname_label)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.ADD_NICKNAME),
            )
        }

        CheckboxRow(
            checked = form.setAsDefault,
            label = stringResource(R.string.payout_method_set_default),
            onToggle = { c -> onFieldChanged { it.copy(setAsDefault = c) } },
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.payout_method_add_cancel))
            }
            if (form.choice == PayoutSetupViewModel.MethodChoice.CONNECT) {
                Button(
                    onClick = { onStartConnect(form.setAsDefault) },
                    enabled = !connectBusy,
                    modifier = Modifier.weight(1f).testTag(PayoutSetupTestTags.CONNECT_BUTTON),
                ) {
                    if (connectBusy) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                    Text(stringResource(R.string.payout_method_connect_action))
                }
            } else {
                Button(
                    onClick = onSubmit,
                    enabled = form.canSubmit && !submitting,
                    modifier = Modifier.weight(1f).testTag(PayoutSetupTestTags.ADD_SUBMIT),
                ) {
                    if (submitting) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                    Text(stringResource(R.string.payout_method_add_submit))
                }
            }
        }
    }
}

@Composable
private fun AddTypeChip(
    choice: PayoutSetupViewModel.MethodChoice,
    labelRes: Int,
    selected: PayoutSetupViewModel.MethodChoice,
    onSelected: (PayoutSetupViewModel.MethodChoice) -> Unit,
) {
    FilterChip(
        selected = selected == choice,
        onClick = { onSelected(choice) },
        label = { Text(stringResource(labelRes)) },
    )
}

@Composable
private fun CheckboxRow(checked: Boolean, label: String, onToggle: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onToggle)
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun MethodStatusPill(status: PayoutMethodStatus) {
    val (labelRes, color) = when (status) {
        PayoutMethodStatus.VERIFIED -> R.string.payout_method_status_verified to MaterialTheme.colorScheme.primary
        PayoutMethodStatus.VERIFYING -> R.string.payout_method_status_verifying to MaterialTheme.colorScheme.tertiary
        PayoutMethodStatus.FAILED -> R.string.payout_method_status_failed to MaterialTheme.colorScheme.error
        PayoutMethodStatus.UNVERIFIED -> R.string.payout_method_status_unverified to MaterialTheme.colorScheme.onSurfaceVariant
        PayoutMethodStatus.UNKNOWN -> R.string.payout_method_status_unknown to MaterialTheme.colorScheme.onSurfaceVariant
    }
    StatusPill(text = stringResource(labelRes), color = color)
}

@Composable
private fun StatusPill(text: String, color: androidx.compose.ui.graphics.Color) {
    Surface(color = color.copy(alpha = 0.12f), shape = MaterialTheme.shapes.small) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

@Composable
private fun methodTypeLabel(type: RoutableMethodType): String = stringResource(
    when (type) {
        RoutableMethodType.PAYPAL -> R.string.payout_method_type_paypal
        RoutableMethodType.STRIPE_CONNECT -> R.string.payout_method_type_connect
        else -> R.string.payout_method_type_bank
    },
)

@Composable
private fun methodDestinationLine(method: PayoutMethod): String = when (method.type) {
    RoutableMethodType.PAYPAL -> stringResource(R.string.payout_method_paypal_display, method.paypalEmail)
    RoutableMethodType.STRIPE_CONNECT ->
        stringResource(R.string.payout_method_connect_display, method.connectAccountId)
    else -> {
        val bank = stringResource(R.string.payout_method_bank_display, method.accountLast4)
        if (method.routingLast4.isNotBlank()) {
            bank + "  " + stringResource(R.string.payout_method_routing_display, method.routingLast4)
        } else {
            bank
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
