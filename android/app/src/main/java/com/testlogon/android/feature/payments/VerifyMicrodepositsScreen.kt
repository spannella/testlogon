package com.testlogon.android.feature.payments

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState

/** Stable testTags for the verify-microdeposits screen (AND-230). */
object VerifyMicrodepositsTestTags {
    const val SCREEN = "verify_microdeposits_screen"
    const val FIRST = "verify_first_amount"
    const val SECOND = "verify_second_amount"
    const val SUBMIT = "verify_submit"
    const val ERROR = "verify_error"
    const val SUCCESS = "verify_success"
}

/**
 * AND-230 — US bank micro-deposit verification route. Two cent amounts ($0.01–$0.99). On success it
 * emits a one-shot Verified event so the caller refreshes the payment-methods list. The verify call is
 * the VERIFIED backend contract and is NOT gated by the payments stub (it confirms an already-initiated
 * setup, not a charge).
 */
@Composable
fun VerifyMicrodepositsRoute(
    onBack: () -> Unit,
    onVerified: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: VerifyMicrodepositsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is VerifyMicrodepositsEvent.Verified -> onVerified()
            }
        }
    }

    VerifyMicrodepositsScreen(
        state = state,
        onFirstChange = viewModel::onFirstChange,
        onSecondChange = viewModel::onSecondChange,
        onSubmit = viewModel::submit,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifyMicrodepositsScreen(
    state: VerifyMicrodepositsUiState,
    onFirstChange: (String) -> Unit,
    onSecondChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val firstCd = stringResource(R.string.verify_microdeposits_first_cd)
    val secondCd = stringResource(R.string.verify_microdeposits_second_cd)
    Scaffold(
        modifier = modifier.testTag(VerifyMicrodepositsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.verify_microdeposits_title)) },
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
    ) { padding ->
        if (state.verified) {
            EmptyState(
                title = stringResource(R.string.verify_microdeposits_success_title),
                body = stringResource(R.string.verify_microdeposits_success_body),
                imageVector = Icons.Outlined.CheckCircle,
                modifier = Modifier.fillMaxSize().padding(padding).testTag(VerifyMicrodepositsTestTags.SUCCESS),
            )
            return@Scaffold
        }
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(R.string.verify_microdeposits_instructions))
            Text(stringResource(R.string.verify_microdeposits_eta_hint))
            OutlinedTextField(
                value = state.firstCents,
                onValueChange = onFirstChange,
                label = { Text(stringResource(R.string.verify_microdeposits_first_label)) },
                prefix = { Text("$0.") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                modifier = Modifier.fillMaxWidth().testTag(VerifyMicrodepositsTestTags.FIRST)
                    .semantics { contentDescription = firstCd },
            )
            OutlinedTextField(
                value = state.secondCents,
                onValueChange = onSecondChange,
                label = { Text(stringResource(R.string.verify_microdeposits_second_label)) },
                prefix = { Text("$0.") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done,
                ),
                modifier = Modifier.fillMaxWidth().testTag(VerifyMicrodepositsTestTags.SECOND)
                    .semantics { contentDescription = secondCd },
            )
            state.error?.let { message ->
                Text(
                    text = message,
                    modifier = Modifier.testTag(VerifyMicrodepositsTestTags.ERROR)
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            Button(
                onClick = onSubmit,
                enabled = state.canSubmit,
                modifier = Modifier.fillMaxWidth().testTag(VerifyMicrodepositsTestTags.SUBMIT),
            ) { Text(stringResource(R.string.verify_microdeposits_submit)) }
        }
    }
}
