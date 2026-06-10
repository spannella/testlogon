package com.testlogon.android.feature.payments

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CreditCardOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import com.testlogon.android.core.ui.state.EmptyState
import dagger.hilt.android.EntryPointAccessors
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/** Stable testTags for the redirect checkout screen (AND-227/228/229). */
object RedirectCheckoutTestTags {
    const val SCREEN = "redirect_checkout_screen"
    const val PAY_CHECKOUT = "pay_hosted_checkout"
    const val PAY_PAYPAL = "pay_paypal"
    const val PAY_CCBILL = "pay_ccbill"
    const val PROGRESS = "redirect_checkout_progress"
    const val UNAVAILABLE = "redirect_checkout_unavailable"
    const val SUCCEEDED = "redirect_checkout_succeeded"
    const val FAILED = "redirect_checkout_failed"
    const val RETRY = "redirect_checkout_retry"
}

/** Hilt entry point so the route can resolve the singleton Custom Tab launcher in a composable. */
@dagger.hilt.EntryPoint
@dagger.hilt.InstallIn(dagger.hilt.components.SingletonComponent::class)
interface PaymentTabLauncherEntryPoint {
    fun paymentTabLauncher(): PaymentTabLauncher
}

/**
 * AND-227/228/229 — provider-selection + redirect checkout route.
 *
 * The ViewModel collects the AND-231 dispatcher internally (filtered to the redirect providers) and
 * drives [RedirectCheckoutViewModel.onReturn]; this route opens the Custom Tab on the one-shot effect
 * and renders the state machine. Under the FLAGGED stub authorizer the flow lands on
 * PaymentsUnavailable and no tab is ever opened.
 */
@Composable
fun RedirectCheckoutRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RedirectCheckoutViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val launcher = remember(context) {
        EntryPointAccessors.fromApplication(
            context.applicationContext,
            PaymentTabLauncherEntryPoint::class.java,
        ).paymentTabLauncher()
    }

    // One-shot: open the Custom Tab when a session was created (inert under the stub).
    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RedirectCheckoutEffect.OpenCustomTab -> launcher.launch(context, effect.hostedUrl)
            }
        }
    }

    RedirectCheckoutScreen(
        state = state,
        onPay = viewModel::pay,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RedirectCheckoutScreen(
    state: RedirectCheckoutUiState,
    onPay: (PaymentMethodOption) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(RedirectCheckoutTestTags.SCREEN),
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text(stringResource(R.string.redirect_checkout_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is RedirectCheckoutUiState.SelectingMethod ->
                    MethodSelection(state.amountCents, state.currency, onPay)
                is RedirectCheckoutUiState.Cancelled ->
                    MethodSelection(state.amountCents, state.currency, onPay)
                is RedirectCheckoutUiState.CreatingSession,
                is RedirectCheckoutUiState.AwaitingReturn,
                is RedirectCheckoutUiState.Confirming,
                -> Progress()
                is RedirectCheckoutUiState.Succeeded ->
                    EmptyState(
                        title = stringResource(R.string.redirect_checkout_success_title),
                        body = stringResource(R.string.redirect_checkout_success_body),
                        modifier = Modifier.testTag(RedirectCheckoutTestTags.SUCCEEDED),
                    )
                is RedirectCheckoutUiState.Pending ->
                    EmptyState(
                        title = stringResource(R.string.redirect_checkout_pending_title),
                        body = stringResource(R.string.redirect_checkout_pending_body),
                    )
                is RedirectCheckoutUiState.Failed ->
                    EmptyState(
                        title = stringResource(R.string.redirect_checkout_failed_title),
                        body = state.message,
                        actionLabel = if (state.retryable) stringResource(R.string.action_retry) else null,
                        onAction = if (state.retryable) onRetry else null,
                        modifier = Modifier.testTag(RedirectCheckoutTestTags.FAILED),
                    )
                is RedirectCheckoutUiState.PaymentsUnavailable ->
                    EmptyState(
                        title = stringResource(R.string.payments_unavailable_title),
                        body = stringResource(R.string.payments_unavailable_body),
                        imageVector = Icons.Outlined.CreditCardOff,
                        modifier = Modifier.testTag(RedirectCheckoutTestTags.UNAVAILABLE),
                    )
            }
        }
    }
}

@Composable
private fun MethodSelection(
    amountCents: Long,
    currency: String,
    onPay: (PaymentMethodOption) -> Unit,
) {
    val amountLabel = formatAmount(amountCents, currency)
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.redirect_checkout_choose_method, amountLabel))
        Button(
            onClick = { onPay(PaymentMethodOption.HOSTED_CHECKOUT) },
            modifier = Modifier.fillMaxWidth().testTag(RedirectCheckoutTestTags.PAY_CHECKOUT),
        ) { Text(stringResource(R.string.redirect_checkout_pay_card, amountLabel)) }
        OutlinedButton(
            onClick = { onPay(PaymentMethodOption.PAYPAL) },
            modifier = Modifier.fillMaxWidth().testTag(RedirectCheckoutTestTags.PAY_PAYPAL),
        ) { Text(stringResource(R.string.redirect_checkout_pay_paypal)) }
        OutlinedButton(
            onClick = { onPay(PaymentMethodOption.CCBILL) },
            modifier = Modifier.fillMaxWidth().testTag(RedirectCheckoutTestTags.PAY_CCBILL),
        ) { Text(stringResource(R.string.redirect_checkout_pay_ccbill)) }
    }
}

@Composable
private fun Progress() {
    Box(
        modifier = Modifier.fillMaxSize().semantics { liveRegion = LiveRegionMode.Polite },
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator(modifier = Modifier.testTag(RedirectCheckoutTestTags.PROGRESS))
    }
}

/** Locale-aware currency formatting from integer cents (never string-concatenated). */
private fun formatAmount(amountCents: Long, currency: String): String = try {
    NumberFormat.getCurrencyInstance(Locale.getDefault()).apply {
        this.currency = Currency.getInstance(currency.uppercase(Locale.US))
    }.format(amountCents / 100.0)
} catch (_: Exception) {
    "${amountCents / 100.0} $currency"
}
