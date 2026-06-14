@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.privacy.deletion

import android.text.format.DateFormat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.CloudOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.privacy.DeletionStatus
import java.util.Date

/** AND-386 - test tags for the account-deletion screen (Compose UI tests, spec §11). */
object AccountDeletionTestTags {
    const val SCREEN = "account_deletion_screen"
    const val LOADING = "account_deletion_loading"
    const val STALE_BANNER = "account_deletion_stale"
    const val START = "account_deletion_start"
    const val WARNING_CONTINUE = "account_deletion_warning_continue"
    const val CONFIRM_FIELD = "account_deletion_confirm_field"
    const val PASSWORD_FIELD = "account_deletion_password_field"
    const val REASON_FIELD = "account_deletion_reason_field"
    const val SHOW_FINAL = "account_deletion_show_final"
    const val FINAL_DIALOG = "account_deletion_final_dialog"
    const val FINAL_CONFIRM = "account_deletion_final_confirm"
    const val PENDING = "account_deletion_pending"
    const val CANCEL_CTA = "account_deletion_cancel_cta"
    const val CANCEL_DIALOG = "account_deletion_cancel_dialog"
    const val CANCEL_CONFIRM = "account_deletion_cancel_confirm"
}

/**
 * AND-386 - navigation entry. Drives the initial load, surfaces transient snackbars, and renders the
 * stateless [AccountDeletionScreen].
 */
@Composable
fun AccountDeletionRoute(
    onBack: () -> Unit,
    viewModel: AccountDeletionViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) { viewModel.load() }

    val transient = (state as? AccountDeletionUiState.Ready)?.transient
    LaunchedEffect(transient) {
        if (transient != null) {
            snackbarHostState.showSnackbar(transient.text)
            viewModel.onEvent(AccountDeletionEvent.ConsumeTransient)
        }
    }

    AccountDeletionScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onEvent = viewModel::onEvent,
    )
}

/** AND-386 - the stateless screen (FR-1..FR-7). */
@Composable
fun AccountDeletionScreen(
    state: AccountDeletionUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onEvent: (AccountDeletionEvent) -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(AccountDeletionTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.privacy_deletion_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.privacy_deletion_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                AccountDeletionUiState.Loading ->
                    Box(
                        Modifier
                            .fillMaxSize()
                            .testTag(AccountDeletionTestTags.LOADING),
                        contentAlignment = Alignment.Center,
                    ) { CircularProgressIndicator() }

                is AccountDeletionUiState.Error ->
                    ErrorState(message = state.message, retryable = state.retryable, onEvent = onEvent)

                is AccountDeletionUiState.Ready ->
                    ReadyContent(state = state, onEvent = onEvent)
            }
        }

        if (state is AccountDeletionUiState.Ready) {
            when (state.confirmStep) {
                ConfirmStep.FinalDialog -> FinalDeleteDialog(state = state, onEvent = onEvent)
                ConfirmStep.CancelDialog -> CancelDeletionDialog(state = state, onEvent = onEvent)
                else -> Unit
            }
        }
    }
}

@Composable
private fun ErrorState(message: String, retryable: Boolean, onEvent: (AccountDeletionEvent) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(message)
        if (retryable) {
            Spacer(Modifier.size(16.dp))
            OutlinedButton(onClick = { onEvent(AccountDeletionEvent.Refresh) }) {
                Text(stringResource(R.string.privacy_deletion_retry))
            }
        }
    }
}

@Composable
private fun ReadyContent(state: AccountDeletionUiState.Ready, onEvent: (AccountDeletionEvent) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (state.isStale) StaleBanner()

        when (state.status) {
            DeletionStatus.Active -> ActiveSurface(state = state, onEvent = onEvent)
            is DeletionStatus.Pending -> PendingSurface(state = state, onEvent = onEvent)
        }
    }
}

@Composable
private fun StaleBanner() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AccountDeletionTestTags.STALE_BANNER),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(Icons.Outlined.CloudOff, contentDescription = null)
        Text(stringResource(R.string.privacy_deletion_stale))
    }
}

@Composable
private fun ActiveSurface(state: AccountDeletionUiState.Ready, onEvent: (AccountDeletionEvent) -> Unit) {
    val disabled = state.isStale || state.mutationInFlight
    when (state.confirmStep) {
        ConfirmStep.Warning, ConfirmStep.TypeToConfirm, ConfirmStep.FinalDialog ->
            RequestFlow(state = state, onEvent = onEvent)
        else -> {
            Text(
                stringResource(R.string.privacy_deletion_active_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(stringResource(R.string.privacy_deletion_active_body))
            Button(
                onClick = { onEvent(AccountDeletionEvent.StartRequest) },
                enabled = !disabled,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(AccountDeletionTestTags.START),
            ) {
                Text(stringResource(R.string.privacy_deletion_start))
            }
        }
    }
}

@Composable
private fun RequestFlow(state: AccountDeletionUiState.Ready, onEvent: (AccountDeletionEvent) -> Unit) {
    // Warning gate (gate 1).
    Text(
        stringResource(R.string.privacy_deletion_warning_title),
        style = MaterialTheme.typography.titleMedium,
    )
    Text(stringResource(R.string.privacy_deletion_warning_body))

    if (state.confirmStep == ConfirmStep.Warning) {
        Button(
            onClick = { onEvent(AccountDeletionEvent.AdvanceFromWarning) },
            enabled = !state.mutationInFlight,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(AccountDeletionTestTags.WARNING_CONTINUE),
        ) {
            Text(stringResource(R.string.privacy_deletion_continue))
        }
        TextButton(onClick = { onEvent(AccountDeletionEvent.Dismiss) }) {
            Text(stringResource(R.string.privacy_deletion_cancel))
        }
        return
    }

    // Typed-confirm gate (gate 2): phrase + password.
    Spacer(Modifier.size(4.dp))
    Text(stringResource(R.string.privacy_deletion_type_instruction, DELETE_SENTINEL))
    OutlinedTextField(
        value = state.typedConfirmation,
        onValueChange = { onEvent(AccountDeletionEvent.TypedConfirmationChanged(it)) },
        singleLine = true,
        label = { Text(stringResource(R.string.privacy_deletion_type_label)) },
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AccountDeletionTestTags.CONFIRM_FIELD),
    )
    OutlinedTextField(
        value = state.password,
        onValueChange = { onEvent(AccountDeletionEvent.PasswordChanged(it)) },
        singleLine = true,
        label = { Text(stringResource(R.string.privacy_deletion_password_label)) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AccountDeletionTestTags.PASSWORD_FIELD),
    )
    OutlinedTextField(
        value = state.reason,
        onValueChange = { onEvent(AccountDeletionEvent.ReasonChanged(it)) },
        label = { Text(stringResource(R.string.privacy_deletion_reason_label)) },
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AccountDeletionTestTags.REASON_FIELD),
    )

    val enabledState = stringResource(
        if (state.confirmUnlocked) R.string.privacy_deletion_enabled else R.string.privacy_deletion_disabled,
    )
    Button(
        onClick = { onEvent(AccountDeletionEvent.ShowFinalDialog) },
        enabled = state.confirmUnlocked && !state.mutationInFlight,
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.error,
            contentColor = MaterialTheme.colorScheme.onError,
        ),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(AccountDeletionTestTags.SHOW_FINAL)
            .semantics { stateDescription = enabledState },
    ) {
        Text(stringResource(R.string.privacy_deletion_delete_button))
    }
    TextButton(onClick = { onEvent(AccountDeletionEvent.Dismiss) }) {
        Text(stringResource(R.string.privacy_deletion_cancel))
    }
}

@Composable
private fun PendingSurface(state: AccountDeletionUiState.Ready, onEvent: (AccountDeletionEvent) -> Unit) {
    val pending = state.status as DeletionStatus.Pending
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AccountDeletionTestTags.PENDING),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            stringResource(R.string.privacy_deletion_scheduled_title),
            style = MaterialTheme.typography.titleMedium,
        )
        val scheduled = pending.scheduledForEpochMs
        val scheduledText = remember(scheduled) {
            if (scheduled == null) {
                null
            } else {
                DateFormat.getMediumDateFormat(context).format(Date(scheduled))
            }
        }
        if (scheduledText != null) {
            Text(stringResource(R.string.privacy_deletion_scheduled_for, scheduledText))
        } else {
            Text(stringResource(R.string.privacy_deletion_scheduled_soon))
        }
        pending.graceDaysRemaining?.let { days ->
            Text(stringResource(R.string.privacy_deletion_grace_days, days))
        }

        if (pending.canCancel) {
            Spacer(Modifier.size(8.dp))
            Button(
                onClick = { onEvent(AccountDeletionEvent.StartCancel) },
                enabled = !state.isStale && !state.mutationInFlight,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(AccountDeletionTestTags.CANCEL_CTA),
            ) {
                Text(stringResource(R.string.privacy_deletion_cancel_cta))
            }
        }
    }
}

@Composable
private fun FinalDeleteDialog(state: AccountDeletionUiState.Ready, onEvent: (AccountDeletionEvent) -> Unit) {
    AlertDialog(
        modifier = Modifier.testTag(AccountDeletionTestTags.FINAL_DIALOG),
        onDismissRequest = { onEvent(AccountDeletionEvent.Dismiss) },
        title = { Text(stringResource(R.string.privacy_deletion_final_title)) },
        text = { Text(stringResource(R.string.privacy_deletion_final_body)) },
        confirmButton = {
            TextButton(
                onClick = { onEvent(AccountDeletionEvent.ConfirmDelete) },
                enabled = !state.mutationInFlight,
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.testTag(AccountDeletionTestTags.FINAL_CONFIRM),
            ) {
                Text(stringResource(R.string.privacy_deletion_final_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = { onEvent(AccountDeletionEvent.Dismiss) }) {
                Text(stringResource(R.string.privacy_deletion_cancel))
            }
        },
    )
}

@Composable
private fun CancelDeletionDialog(
    state: AccountDeletionUiState.Ready,
    onEvent: (AccountDeletionEvent) -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(AccountDeletionTestTags.CANCEL_DIALOG),
        onDismissRequest = { onEvent(AccountDeletionEvent.Dismiss) },
        title = { Text(stringResource(R.string.privacy_deletion_cancel_dialog_title)) },
        text = { Text(stringResource(R.string.privacy_deletion_cancel_dialog_body)) },
        confirmButton = {
            TextButton(
                onClick = { onEvent(AccountDeletionEvent.ConfirmCancel) },
                enabled = !state.mutationInFlight,
                modifier = Modifier.testTag(AccountDeletionTestTags.CANCEL_CONFIRM),
            ) {
                Text(stringResource(R.string.privacy_deletion_cancel_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = { onEvent(AccountDeletionEvent.Dismiss) }) {
                Text(stringResource(R.string.privacy_deletion_keep))
            }
        },
    )
}
