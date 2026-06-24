package com.testlogon.android.feature.billing

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
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlTextField

/** Stable testTags for the Add Payment Method screen. */
object AddCardTestTags {
    const val SCREEN = "add_card_screen"
    const val TAB_CARD = "add_card_tab_card"
    const val TAB_BANK = "add_card_tab_bank"
    const val CARD_NUMBER = "add_card_number"
    const val EXP_MONTH = "add_card_exp_month"
    const val EXP_YEAR = "add_card_exp_year"
    const val CVC = "add_card_cvc"
    const val ROUTING = "add_card_routing"
    const val ACCOUNT = "add_card_account"
    const val ACCOUNT_TYPE_CHECKING = "add_card_account_type_checking"
    const val ACCOUNT_TYPE_SAVINGS = "add_card_account_type_savings"
    const val SUBMIT = "add_card_submit"
    const val FORM_ERROR = "add_card_form_error"
}

/**
 * Route-level add-payment-method entry, reached from the Payment Methods "Add" CTA. Mirrors the web
 * client: a manual-entry form with Card / Bank tabs that lets the user TYPE a fake test card or a fake
 * US bank checking/savings account, submitting directly to the BK-C dev/test backend endpoints. On a
 * successful add it asks the caller to refresh + close via [onCardSaved] (pops back -> list re-fetches).
 */
@Composable
fun AddCardRoute(
    onBack: () -> Unit,
    onCardSaved: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AddCardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val resources = LocalContext.current.resources

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is AddCardEvent.Saved -> onCardSaved()
                is AddCardEvent.Failure -> snackbarHostState.showSnackbar(event.message.resolve(resources))
            }
        }
    }

    AddCardScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onSelectTab = viewModel::selectTab,
        onCardNumberChange = viewModel::onCardNumberChange,
        onExpMonthChange = viewModel::onExpMonthChange,
        onExpYearChange = viewModel::onExpYearChange,
        onCvcChange = viewModel::onCvcChange,
        onCardholderNameChange = viewModel::onCardholderNameChange,
        onRoutingNumberChange = viewModel::onRoutingNumberChange,
        onAccountNumberChange = viewModel::onAccountNumberChange,
        onAccountTypeChange = viewModel::onAccountTypeChange,
        onAccountHolderNameChange = viewModel::onAccountHolderNameChange,
        onSubmit = viewModel::submit,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddCardScreen(
    state: AddCardUiState,
    snackbarHostState: SnackbarHostState,
    onSelectTab: (AddMethodTab) -> Unit,
    onCardNumberChange: (String) -> Unit,
    onExpMonthChange: (String) -> Unit,
    onExpYearChange: (String) -> Unit,
    onCvcChange: (String) -> Unit,
    onCardholderNameChange: (String) -> Unit,
    onRoutingNumberChange: (String) -> Unit,
    onAccountNumberChange: (String) -> Unit,
    onAccountTypeChange: (String) -> Unit,
    onAccountHolderNameChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AddCardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.add_card_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("add_card_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        val resources = LocalContext.current.resources
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            TabRow(selectedTabIndex = if (state.tab == AddMethodTab.CARD) 0 else 1) {
                Tab(
                    selected = state.tab == AddMethodTab.CARD,
                    onClick = { onSelectTab(AddMethodTab.CARD) },
                    text = { Text(stringResource(R.string.add_card_tab_card)) },
                    modifier = Modifier.testTag(AddCardTestTags.TAB_CARD),
                )
                Tab(
                    selected = state.tab == AddMethodTab.BANK,
                    onClick = { onSelectTab(AddMethodTab.BANK) },
                    text = { Text(stringResource(R.string.add_card_tab_bank)) },
                    modifier = Modifier.testTag(AddCardTestTags.TAB_BANK),
                )
            }

            Text(
                stringResource(R.string.add_card_test_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when (state.tab) {
                AddMethodTab.CARD -> CardForm(
                    state = state,
                    cardNumberError = state.cardNumberError?.resolve(resources),
                    expMonthError = state.expMonthError?.resolve(resources),
                    expYearError = state.expYearError?.resolve(resources),
                    cvcError = state.cvcError?.resolve(resources),
                    onCardNumberChange = onCardNumberChange,
                    onExpMonthChange = onExpMonthChange,
                    onExpYearChange = onExpYearChange,
                    onCvcChange = onCvcChange,
                    onCardholderNameChange = onCardholderNameChange,
                )

                AddMethodTab.BANK -> BankForm(
                    state = state,
                    routingNumberError = state.routingNumberError?.resolve(resources),
                    accountNumberError = state.accountNumberError?.resolve(resources),
                    onRoutingNumberChange = onRoutingNumberChange,
                    onAccountNumberChange = onAccountNumberChange,
                    onAccountTypeChange = onAccountTypeChange,
                    onAccountHolderNameChange = onAccountHolderNameChange,
                )
            }

            state.formError?.let { err ->
                Text(
                    err.resolve(resources),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag(AddCardTestTags.FORM_ERROR),
                )
            }

            TlButton(
                text = stringResource(R.string.add_card_save),
                onClick = onSubmit,
                loading = state.isSubmitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(AddCardTestTags.SUBMIT),
            )
        }
    }
}

@Composable
private fun CardForm(
    state: AddCardUiState,
    cardNumberError: String?,
    expMonthError: String?,
    expYearError: String?,
    cvcError: String?,
    onCardNumberChange: (String) -> Unit,
    onExpMonthChange: (String) -> Unit,
    onExpYearChange: (String) -> Unit,
    onCvcChange: (String) -> Unit,
    onCardholderNameChange: (String) -> Unit,
) {
    TlTextField(
        value = state.cardNumber,
        onValueChange = onCardNumberChange,
        label = stringResource(R.string.add_card_field_number),
        enabled = !state.isSubmitting,
        errorText = cardNumberError,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.testTag(AddCardTestTags.CARD_NUMBER),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        TlTextField(
            value = state.expMonth,
            onValueChange = onExpMonthChange,
            label = stringResource(R.string.add_card_field_exp_month),
            enabled = !state.isSubmitting,
            errorText = expMonthError,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier
                .weight(1f)
                .testTag(AddCardTestTags.EXP_MONTH),
        )
        TlTextField(
            value = state.expYear,
            onValueChange = onExpYearChange,
            label = stringResource(R.string.add_card_field_exp_year),
            enabled = !state.isSubmitting,
            errorText = expYearError,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier
                .weight(1f)
                .testTag(AddCardTestTags.EXP_YEAR),
        )
        TlTextField(
            value = state.cvc,
            onValueChange = onCvcChange,
            label = stringResource(R.string.add_card_field_cvc),
            enabled = !state.isSubmitting,
            errorText = cvcError,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier
                .weight(1f)
                .testTag(AddCardTestTags.CVC),
        )
    }
    TlTextField(
        value = state.cardholderName,
        onValueChange = onCardholderNameChange,
        label = stringResource(R.string.add_card_field_cardholder),
        enabled = !state.isSubmitting,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BankForm(
    state: AddCardUiState,
    routingNumberError: String?,
    accountNumberError: String?,
    onRoutingNumberChange: (String) -> Unit,
    onAccountNumberChange: (String) -> Unit,
    onAccountTypeChange: (String) -> Unit,
    onAccountHolderNameChange: (String) -> Unit,
) {
    TlTextField(
        value = state.routingNumber,
        onValueChange = onRoutingNumberChange,
        label = stringResource(R.string.add_card_field_routing),
        enabled = !state.isSubmitting,
        errorText = routingNumberError,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.testTag(AddCardTestTags.ROUTING),
    )
    TlTextField(
        value = state.accountNumber,
        onValueChange = onAccountNumberChange,
        label = stringResource(R.string.add_card_field_account),
        enabled = !state.isSubmitting,
        errorText = accountNumberError,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.testTag(AddCardTestTags.ACCOUNT),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(
            selected = state.accountType == "checking",
            onClick = { onAccountTypeChange("checking") },
            label = { Text(stringResource(R.string.add_card_account_type_checking)) },
            enabled = !state.isSubmitting,
            modifier = Modifier.testTag(AddCardTestTags.ACCOUNT_TYPE_CHECKING),
        )
        FilterChip(
            selected = state.accountType == "savings",
            onClick = { onAccountTypeChange("savings") },
            label = { Text(stringResource(R.string.add_card_account_type_savings)) },
            enabled = !state.isSubmitting,
            modifier = Modifier.testTag(AddCardTestTags.ACCOUNT_TYPE_SAVINGS),
        )
    }
    TlTextField(
        value = state.accountHolderName,
        onValueChange = onAccountHolderNameChange,
        label = stringResource(R.string.add_card_field_account_holder),
        enabled = !state.isSubmitting,
    )
}
