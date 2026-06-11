@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.refunds

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.input.TlButton
import kotlinx.coroutines.flow.collectLatest

/** AND-244 — stable testTags for the refund submit screen. */
object RefundSubmitTestTags {
    const val SCREEN = "refund_submit_screen"
    const val REASON = "refund_submit_reason"
    const val AMOUNT = "refund_submit_amount"
    const val SUBMIT = "refund_submit_button"
}

/** AND-244 — route-level refund submit form (reached from an order/transaction detail). */
@Composable
fun RefundSubmitRoute(
    onSubmitted: (refundId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: RefundSubmitViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val resources = LocalContext.current.resources

    LaunchedEffect(viewModel) {
        viewModel.events.collectLatest { event ->
            when (event) {
                is RefundSubmitEvent.Success -> onSubmitted(event.refundId)
                // Resolve the UiText against Resources here (NOT a @Composable) before showing the snackbar.
                is RefundSubmitEvent.Failure -> snackbarHostState.showSnackbar(event.message.resolve(resources))
            }
        }
    }

    RefundSubmitScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onReasonChange = viewModel::onReasonChange,
        onAmountChange = viewModel::onAmountChange,
        onSubmit = viewModel::submit,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun RefundSubmitScreen(
    state: RefundSubmitUiState,
    snackbarHostState: SnackbarHostState,
    onReasonChange: (String) -> Unit,
    onAmountChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(RefundSubmitTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.refunds_submit_title)) },
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
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(R.string.refunds_submit_intro),
                style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
            )

            OutlinedTextField(
                value = state.reasonText,
                onValueChange = onReasonChange,
                label = { Text(stringResource(R.string.refunds_field_reason)) },
                isError = state.reasonError != null,
                supportingText = {
                    val err = state.reasonError
                    Text(err?.asString() ?: stringResource(R.string.refunds_field_reason_hint))
                },
                minLines = 3,
                modifier = Modifier.fillMaxWidth().testTag(RefundSubmitTestTags.REASON),
            )

            OutlinedTextField(
                value = state.amountText,
                onValueChange = onAmountChange,
                label = { Text(stringResource(R.string.refunds_field_amount)) },
                isError = state.amountError != null,
                supportingText = {
                    val err = state.amountError
                    Text(err?.asString() ?: stringResource(R.string.refunds_field_amount_hint))
                },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth().testTag(RefundSubmitTestTags.AMOUNT),
            )

            TlButton(
                text = stringResource(
                    if (state.isSubmitting) R.string.refunds_submit_sending else R.string.refunds_submit_action,
                ),
                onClick = onSubmit,
                enabled = state.submitEnabled,
                modifier = Modifier.fillMaxWidth().testTag(RefundSubmitTestTags.SUBMIT),
            )
        }
    }
}
