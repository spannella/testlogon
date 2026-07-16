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
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.PayoutMethod
import com.testlogon.android.data.payouts.PayoutMethodStatus
import com.testlogon.android.data.payouts.RoutableMethodType
import com.testlogon.android.data.payouts.TinType
import com.testlogon.android.data.payouts.WithdrawGate

/** AND-259 / PAY-13 / PAY-22 - stable testTags for the payout setup screen. */
object PayoutSetupTestTags {
    const val SCREEN = "payout_setup_screen"
    const val FORM = "payout_setup_form"
    const val AMOUNT = "payout_setup_amount"
    const val SUBMIT = "payout_setup_submit"

    // PAY-52 - withdraw destination picker (verified PAY-B methods).
    const val NO_VERIFIED_METHOD = "payout_withdraw_no_verified_method"
    fun withdrawMethod(id: String) = "payout_withdraw_method_$id"
    const val GATE_PANEL = "payout_setup_gate_panel"
    const val VERIFY = "payout_setup_verify"
    const val GATE_UNKNOWN = "payout_setup_gate_unknown"

    // PAY-22 - pre-withdrawal gate (KYC + W-9).
    const val WITHDRAW_GATE = "payout_withdraw_gate"
    const val KYC_PANEL = "payout_kyc_panel"
    const val W9_FORM = "payout_w9_form"
    const val W9_LEGAL_NAME = "payout_w9_legal_name"
    const val W9_TIN = "payout_w9_tin"
    const val W9_ADDRESS = "payout_w9_address"
    const val W9_CITY = "payout_w9_city"
    const val W9_STATE = "payout_w9_state"
    const val W9_ZIP = "payout_w9_zip"
    const val W9_CERTIFY = "payout_w9_certify"
    const val W9_SUBMIT = "payout_w9_submit"

    // PAY-13 - routable payout methods.
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

/** AND-259 / PAY-22 - route-level payout setup entry; the gate routes to the existing KYC flow. */
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
                // PAY-11 - real Connect onboarding URL (only when Stripe Connect is keyed server-side).
                is PayoutSetupViewModel.Effect.OpenUrl -> uriHandler.openUri(effect.url)
            }
        }
    }

    // PAY-22 - re-resolve the gate whenever we return to this screen (e.g. after completing KYC).
    LifecycleResumeEffect(Unit) {
        viewModel.onReturnedFromKyc()
        onPauseOrDispose { }
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
        onRefreshGate = viewModel::refreshGate,
        onW9FieldChanged = viewModel::onW9FieldChanged,
        onSubmitW9 = viewModel::submitW9,
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
    onRefreshGate: () -> Unit,
    onW9FieldChanged: ((PayoutSetupViewModel.W9FormState) -> PayoutSetupViewModel.W9FormState) -> Unit,
    onSubmitW9: () -> Unit,
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

                // PAY-13 - routable payout destinations (independent of the KYC/tax gate).
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

                // PAY-22 - the pre-withdrawal gate status header (identity + tax info).
                WithdrawGateHeader(state.withdrawGate)

                when (val gate = state.withdrawGate) {
                    is WithdrawGate.Allowed -> PayoutForm(
                        state = state,
                        onAmountChanged = onAmountChanged,
                        onMethodSelected = onMethodSelected,
                        onNotesChanged = onNotesChanged,
                        onSubmit = onSubmit,
                    )
                    is WithdrawGate.NeedsKyc -> KycVerifyPanel(
                        status = gate.kycStatus,
                        evaluating = state.evaluating,
                        onVerifyIdentity = onVerifyIdentity,
                        onRefresh = onRefreshGate,
                    )
                    is WithdrawGate.NeedsTaxInfo -> W9FormPanel(
                        form = state.w9Form,
                        submitting = state.w9Submitting,
                        onFieldChanged = onW9FieldChanged,
                        onSubmit = onSubmitW9,
                    )
                    WithdrawGate.Loading -> GateLoadingPanel()
                    WithdrawGate.Unresolved -> GateUnknownPanel(onRetry = onRetry)
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

// ---- PAY-22: pre-withdrawal gate (KYC + W-9) ----

/** The always-visible gate status header: shows both requirements and whether each is satisfied. */
@Composable
private fun WithdrawGateHeader(gate: WithdrawGate) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(PayoutSetupTestTags.WITHDRAW_GATE)
            .semantics(mergeDescendants = true) { },
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.payout_withdraw_gate_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(R.string.payout_withdraw_gate_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            GateStepRow(
                label = stringResource(R.string.payout_gate_step_kyc),
                done = gate.kycSatisfied,
            )
            GateStepRow(
                label = stringResource(R.string.payout_gate_step_tax),
                done = gate.taxSatisfied,
            )
        }
    }
}

@Composable
private fun GateStepRow(label: String, done: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        StatusPill(
            text = stringResource(
                if (done) R.string.payout_gate_step_done else R.string.payout_gate_step_pending,
            ),
            color = if (done) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
        )
    }
}

/** WithdrawGate.NeedsKyc -> route the user to the existing KYC verification flow. */
@Composable
private fun KycVerifyPanel(
    status: KycCaseStatus,
    evaluating: Boolean,
    onVerifyIdentity: () -> Unit,
    onRefresh: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(PayoutSetupTestTags.KYC_PANEL)
            .semantics(mergeDescendants = true) { },
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.payout_kyc_panel_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(R.string.payout_kyc_panel_body),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = stringResource(R.string.payout_kyc_status_line, kycStatusLabel(status)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            HorizontalDivider()
            Button(
                onClick = onVerifyIdentity,
                enabled = !evaluating,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.VERIFY),
            ) {
                Text(stringResource(R.string.payout_kyc_verify_action))
            }
            OutlinedButton(
                onClick = onRefresh,
                enabled = !evaluating,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (evaluating) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.payout_gate_refresh))
            }
        }
    }
}

@Composable
private fun kycStatusLabel(status: KycCaseStatus): String = stringResource(
    when (status) {
        KycCaseStatus.APPROVED -> R.string.payout_kyc_status_approved
        KycCaseStatus.SUBMITTED -> R.string.payout_kyc_status_submitted
        KycCaseStatus.UNDER_REVIEW -> R.string.payout_kyc_status_under_review
        KycCaseStatus.NEEDS_MORE_INFO -> R.string.payout_kyc_status_needs_more_info
        KycCaseStatus.REJECTED -> R.string.payout_kyc_status_rejected
        KycCaseStatus.EXPIRED -> R.string.payout_kyc_status_expired
        KycCaseStatus.DRAFT -> R.string.payout_kyc_status_draft
        KycCaseStatus.UNKNOWN -> R.string.payout_kyc_status_none
    },
)

/** WithdrawGate.NeedsTaxInfo -> the W-9 collection form. The raw TIN is masked after submit (SEC). */
@Composable
private fun W9FormPanel(
    form: PayoutSetupViewModel.W9FormState,
    submitting: Boolean,
    onFieldChanged: ((PayoutSetupViewModel.W9FormState) -> PayoutSetupViewModel.W9FormState) -> Unit,
    onSubmit: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.W9_FORM),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.payout_tax_panel_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = stringResource(R.string.payout_tax_panel_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = form.legalName,
                onValueChange = { v -> onFieldChanged { it.copy(legalName = v.take(200)) } },
                label = { Text(stringResource(R.string.payout_tax_legal_name)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.W9_LEGAL_NAME),
            )

            // Tax classification (maps to the W-9 TIN type: individual/SSN vs business/EIN).
            Text(stringResource(R.string.payout_tax_classification), style = MaterialTheme.typography.labelLarge)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = form.tinType == TinType.SSN,
                    onClick = { onFieldChanged { it.copy(tinType = TinType.SSN) } },
                    label = { Text(stringResource(R.string.payout_tax_class_individual)) },
                )
                FilterChip(
                    selected = form.tinType == TinType.EIN,
                    onClick = { onFieldChanged { it.copy(tinType = TinType.EIN) } },
                    label = { Text(stringResource(R.string.payout_tax_class_business)) },
                )
            }

            OutlinedTextField(
                value = form.tin,
                onValueChange = { v -> onFieldChanged { it.copy(tin = v.filter(Char::isDigit).take(9)) } },
                label = {
                    Text(
                        stringResource(
                            if (form.tinType == TinType.SSN) {
                                R.string.payout_tax_tin_ssn
                            } else {
                                R.string.payout_tax_tin_ein
                            },
                        ),
                    )
                },
                supportingText = { Text(stringResource(R.string.payout_tax_tin_sec_note)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.W9_TIN),
            )

            OutlinedTextField(
                value = form.addressLine1,
                onValueChange = { v -> onFieldChanged { it.copy(addressLine1 = v.take(200)) } },
                label = { Text(stringResource(R.string.payout_tax_address)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.W9_ADDRESS),
            )
            OutlinedTextField(
                value = form.city,
                onValueChange = { v -> onFieldChanged { it.copy(city = v.take(100)) } },
                label = { Text(stringResource(R.string.payout_tax_city)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.W9_CITY),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = form.state,
                    onValueChange = { v -> onFieldChanged { it.copy(state = v.filter(Char::isLetter).take(2).uppercase()) } },
                    label = { Text(stringResource(R.string.payout_tax_state)) },
                    singleLine = true,
                    modifier = Modifier.weight(1f).testTag(PayoutSetupTestTags.W9_STATE),
                )
                OutlinedTextField(
                    value = form.zipCode,
                    onValueChange = { v -> onFieldChanged { it.copy(zipCode = v.filter { c -> c.isDigit() || c == '-' }.take(10)) } },
                    label = { Text(stringResource(R.string.payout_tax_zip)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f).testTag(PayoutSetupTestTags.W9_ZIP),
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = form.certified,
                    onCheckedChange = { c -> onFieldChanged { it.copy(certified = c) } },
                    modifier = Modifier.testTag(PayoutSetupTestTags.W9_CERTIFY),
                )
                Text(stringResource(R.string.payout_tax_certify), style = MaterialTheme.typography.bodySmall)
            }

            form.error?.let {
                Text(
                    text = it.asString(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = form.canSubmit && !submitting,
                modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.W9_SUBMIT),
            ) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.payout_tax_submit))
            }
        }
    }
}

@Composable
private fun GateLoadingPanel() {
    Card(modifier = Modifier.fillMaxWidth().testTag(PayoutSetupTestTags.GATE_PANEL)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CircularProgressIndicator()
            Text(
                text = stringResource(R.string.payout_gate_loading),
                style = MaterialTheme.typography.bodyMedium,
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

        // PAY-52: the withdraw targets a VERIFIED PAY-B destination (not a free-string type). If none is
        // verified yet, block the form and point the user at the destinations section above.
        Text(stringResource(R.string.payout_method_label), style = MaterialTheme.typography.labelLarge)
        val verifiedMethods = state.methods.filter { it.status == PayoutMethodStatus.VERIFIED }
        if (verifiedMethods.isEmpty()) {
            Text(
                text = stringResource(R.string.payout_withdraw_no_verified_method),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag(PayoutSetupTestTags.NO_VERIFIED_METHOD),
            )
        } else {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                verifiedMethods.forEach { method ->
                    PayoutMethodOption(
                        method = method,
                        selectedMethodId = form.selectedMethodId,
                        onSelected = onMethodSelected,
                    )
                }
            }
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

/** PAY-52: a selectable VERIFIED destination chip for the withdraw form (labelled by nickname/type + last-4). */
@Composable
private fun PayoutMethodOption(
    method: PayoutMethod,
    selectedMethodId: String?,
    onSelected: (String) -> Unit,
) {
    val label = method.nickname.ifBlank { methodTypeLabel(method.type) } +
        (if (method.accountLast4.isNotBlank()) " ••${method.accountLast4}" else "")
    FilterChip(
        selected = selectedMethodId == method.methodId,
        onClick = { onSelected(method.methodId) },
        label = { Text(label) },
        modifier = Modifier.testTag(PayoutSetupTestTags.withdrawMethod(method.methodId)),
    )
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
