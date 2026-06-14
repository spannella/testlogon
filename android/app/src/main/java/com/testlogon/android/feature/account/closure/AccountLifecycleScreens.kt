@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.account.closure

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
import androidx.compose.material.icons.outlined.Warning
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus

/** AND-387 - test tags for the lifecycle screens (Compose UI tests, spec §11 / TC-12, TC-15). */
object AccountLifecycleTestTags {
    const val SCREEN = "account_lifecycle_screen"
    const val LOADING = "account_lifecycle_loading"
    const val OFFLINE = "account_lifecycle_offline"
    const val RETRY = "account_lifecycle_retry"
    const val PRIMARY = "account_lifecycle_primary"
    const val REASON_FIELD = "account_lifecycle_reason"
    const val TOKEN_FIELD = "account_lifecycle_token"
    const val REAUTH_PASSWORD = "account_lifecycle_reauth_password"
    const val REAUTH_CONTINUE = "account_lifecycle_reauth_continue"
    const val CONFIRM_DIALOG = "account_lifecycle_confirm_dialog"
    const val CONFIRM_BUTTON = "account_lifecycle_confirm_button"
    const val FINALIZE_CONFIRM = "account_lifecycle_finalize_confirm"
    const val FAILED_BANNER = "account_lifecycle_failed"
    const val CLOSED_TERMINAL = "account_lifecycle_closed_terminal"
}

// ===================================================================================================
// Shared scaffolding
// ===================================================================================================

@Composable
private fun LifecycleScaffold(
    titleRes: Int,
    onBack: () -> Unit,
    content: @Composable (Modifier) -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(AccountLifecycleTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(titleRes)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.account_lifecycle_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        content(Modifier.padding(padding))
    }
}

@Composable
private fun Loading(modifier: Modifier) {
    Box(
        modifier.fillMaxSize().testTag(AccountLifecycleTestTags.LOADING),
        contentAlignment = Alignment.Center,
    ) { CircularProgressIndicator() }
}

@Composable
private fun OfflineOrError(modifier: Modifier, message: String, tag: String, onRetry: () -> Unit) {
    Column(
        modifier = modifier.fillMaxSize().padding(24.dp).testTag(tag),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.CloudOff, contentDescription = null)
        Spacer(Modifier.size(12.dp))
        Text(message)
        Spacer(Modifier.size(16.dp))
        OutlinedButton(
            onClick = onRetry,
            modifier = Modifier.heightIn(min = 48.dp).testTag(AccountLifecycleTestTags.RETRY),
        ) {
            Text(stringResource(R.string.account_lifecycle_retry))
        }
    }
}

@Composable
private fun FailedBanner(message: String) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag(AccountLifecycleTestTags.FAILED_BANNER),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(
            Icons.Outlined.Warning,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.error,
        )
        Text(message, color = MaterialTheme.colorScheme.error)
    }
}

/** A single strong confirm dialog (suspend / reactivate / closure-finalize). */
@Composable
private fun ConfirmDialog(
    titleRes: Int,
    bodyRes: Int,
    confirmRes: Int,
    destructive: Boolean,
    confirmEnabled: Boolean,
    confirmTag: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(AccountLifecycleTestTags.CONFIRM_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(titleRes)) },
        text = { Text(stringResource(bodyRes)) },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                enabled = confirmEnabled,
                colors = if (destructive) {
                    ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                } else {
                    ButtonDefaults.textButtonColors()
                },
                modifier = Modifier.testTag(confirmTag),
            ) {
                Text(stringResource(confirmRes))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.account_lifecycle_cancel)) }
        },
    )
}

// ===================================================================================================
// Closure screen
// ===================================================================================================

/** AND-387 - closure route. Drives load, observes [Outcome.CLOSED_SIGNED_OUT] -> [onClosed]. */
@Composable
fun AccountClosureRoute(
    onClosed: () -> Unit,
    onBack: () -> Unit,
    viewModel: AccountLifecycleViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { viewModel.load() }
    LaunchedEffect(state) {
        val action = (state as? AccountLifecycleUiState.Ready)?.action
        if (action is ActionState.Done && action.outcome == Outcome.CLOSED_SIGNED_OUT) onClosed()
    }
    AccountClosureScreen(state = state, onBack = onBack, viewModel = viewModel)
}

@Composable
fun AccountClosureScreen(
    state: AccountLifecycleUiState,
    onBack: () -> Unit,
    viewModel: AccountLifecycleViewModel,
) {
    LifecycleScaffold(R.string.account_closure_title, onBack) { modifier ->
        when (state) {
            AccountLifecycleUiState.Loading -> Loading(modifier)
            AccountLifecycleUiState.Offline ->
                OfflineOrError(
                    modifier,
                    stringResource(R.string.account_lifecycle_offline),
                    AccountLifecycleTestTags.OFFLINE,
                    viewModel::reload,
                )
            is AccountLifecycleUiState.Error ->
                OfflineOrError(
                    modifier,
                    state.message,
                    AccountLifecycleTestTags.OFFLINE,
                    viewModel::reload,
                )
            is AccountLifecycleUiState.Ready -> ClosureReady(modifier, state, viewModel)
        }
    }
}

@Composable
private fun ClosureReady(
    modifier: Modifier,
    state: AccountLifecycleUiState.Ready,
    viewModel: AccountLifecycleViewModel,
) {
    if (state.status.state == AccountState.CLOSED) {
        ClosedTerminal(modifier, state.status)
        return
    }
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        (state.action as? ActionState.Failed)?.let { FailedBanner(it.message) }

        Text(
            stringResource(R.string.account_closure_summary_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(stringResource(R.string.account_closure_summary_body))

        val submitting = state.action.isSubmitting
        Button(
            onClick = { viewModel.requestClosure() },
            enabled = !submitting,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error,
                contentColor = MaterialTheme.colorScheme.onError,
            ),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(AccountLifecycleTestTags.PRIMARY),
        ) {
            Icon(Icons.Outlined.Warning, contentDescription = null)
            Spacer(Modifier.size(8.dp))
            Text(stringResource(R.string.account_closure_start))
        }
    }

    when (val action = state.action) {
        is ActionState.ReAuthRequired -> ReAuthDialog(viewModel)
        is ActionState.ConfirmClosureFinalize -> FinalizeDialog(action, state, viewModel)
        else -> Unit
    }
}

@Composable
private fun ReAuthDialog(viewModel: AccountLifecycleViewModel) {
    // The password is held in transient UI state and NEVER written to SavedStateHandle (spec §8).
    var password by remember { mutableStateOf("") }
    AlertDialog(
        modifier = Modifier.testTag(AccountLifecycleTestTags.CONFIRM_DIALOG),
        onDismissRequest = { viewModel.dismissDialog() },
        title = { Text(stringResource(R.string.account_closure_reauth_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.account_closure_reauth_body))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    singleLine = true,
                    label = { Text(stringResource(R.string.account_closure_reauth_password)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(AccountLifecycleTestTags.REAUTH_PASSWORD),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { viewModel.submitReAuth() },
                enabled = password.isNotEmpty(),
                modifier = Modifier.testTag(AccountLifecycleTestTags.REAUTH_CONTINUE),
            ) {
                Text(stringResource(R.string.account_closure_reauth_continue))
            }
        },
        dismissButton = {
            TextButton(onClick = { viewModel.dismissDialog() }) {
                Text(stringResource(R.string.account_lifecycle_cancel))
            }
        },
    )
}

@Composable
private fun FinalizeDialog(
    action: ActionState.ConfirmClosureFinalize,
    state: AccountLifecycleUiState.Ready,
    viewModel: AccountLifecycleViewModel,
) {
    val submitting = state.action.isSubmitting
    val enabledState = stringResource(
        if (action.tokenValid) R.string.account_lifecycle_enabled else R.string.account_lifecycle_disabled,
    )
    val tokenInstruction = stringResource(R.string.account_closure_type_instruction, CLOSE_TOKEN)
    AlertDialog(
        modifier = Modifier.testTag(AccountLifecycleTestTags.CONFIRM_DIALOG),
        onDismissRequest = { viewModel.dismissDialog() },
        title = { Text(stringResource(R.string.account_closure_final_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.account_closure_final_body))
                Text(tokenInstruction)
                OutlinedTextField(
                    value = action.typed,
                    onValueChange = { viewModel.onTypedTokenChange(it) },
                    singleLine = true,
                    label = { Text(stringResource(R.string.account_closure_type_label)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(AccountLifecycleTestTags.TOKEN_FIELD)
                        .semantics { contentDescription = tokenInstruction },
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { viewModel.confirmClosureFinalize() },
                enabled = action.tokenValid && !submitting,
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(AccountLifecycleTestTags.FINALIZE_CONFIRM)
                    .semantics { stateDescription = enabledState },
            ) {
                Text(stringResource(R.string.account_closure_final_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = { viewModel.dismissDialog() }) {
                Text(stringResource(R.string.account_lifecycle_cancel))
            }
        },
    )
}

// ===================================================================================================
// Suspend screen
// ===================================================================================================

@Composable
fun AccountSuspendRoute(
    onSuspended: () -> Unit,
    onBack: () -> Unit,
    viewModel: AccountLifecycleViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { viewModel.load() }
    LaunchedEffect(state) {
        val action = (state as? AccountLifecycleUiState.Ready)?.action
        if (action is ActionState.Done && action.outcome == Outcome.SUSPENDED_SIGNED_OUT) onSuspended()
    }
    AccountSuspendScreen(state = state, onBack = onBack, viewModel = viewModel)
}

@Composable
fun AccountSuspendScreen(
    state: AccountLifecycleUiState,
    onBack: () -> Unit,
    viewModel: AccountLifecycleViewModel,
) {
    LifecycleScaffold(R.string.account_suspend_title, onBack) { modifier ->
        when (state) {
            AccountLifecycleUiState.Loading -> Loading(modifier)
            AccountLifecycleUiState.Offline ->
                OfflineOrError(
                    modifier,
                    stringResource(R.string.account_lifecycle_offline),
                    AccountLifecycleTestTags.OFFLINE,
                    viewModel::reload,
                )
            is AccountLifecycleUiState.Error ->
                OfflineOrError(modifier, state.message, AccountLifecycleTestTags.OFFLINE, viewModel::reload)
            is AccountLifecycleUiState.Ready -> SuspendReady(modifier, state, viewModel)
        }
    }
}

@Composable
private fun SuspendReady(
    modifier: Modifier,
    state: AccountLifecycleUiState.Ready,
    viewModel: AccountLifecycleViewModel,
) {
    var reason by rememberSaveable { mutableStateOf("") }
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        (state.action as? ActionState.Failed)?.let { FailedBanner(it.message) }

        Text(stringResource(R.string.account_suspend_summary_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.account_suspend_summary_body))
        OutlinedTextField(
            value = reason,
            onValueChange = { reason = it },
            label = { Text(stringResource(R.string.account_suspend_reason_label)) },
            modifier = Modifier.fillMaxWidth().testTag(AccountLifecycleTestTags.REASON_FIELD),
        )

        val submitting = state.action.isSubmitting
        Button(
            onClick = { viewModel.requestSuspend() },
            enabled = !submitting,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(AccountLifecycleTestTags.PRIMARY),
        ) {
            Text(stringResource(R.string.account_suspend_action))
        }
    }

    if (state.action is ActionState.ConfirmSuspend) {
        ConfirmDialog(
            titleRes = R.string.account_suspend_confirm_title,
            bodyRes = R.string.account_suspend_confirm_body,
            confirmRes = R.string.account_suspend_confirm_button,
            destructive = false,
            confirmEnabled = !state.action.isSubmitting,
            confirmTag = AccountLifecycleTestTags.CONFIRM_BUTTON,
            onConfirm = { viewModel.confirmSuspend(reason) },
            onDismiss = { viewModel.dismissDialog() },
        )
    }
}

// ===================================================================================================
// Reactivate screen
// ===================================================================================================

@Composable
fun AccountReactivateRoute(
    onReactivated: () -> Unit,
    onBack: () -> Unit,
    viewModel: AccountLifecycleViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { viewModel.load() }
    LaunchedEffect(state) {
        val action = (state as? AccountLifecycleUiState.Ready)?.action
        if (action is ActionState.Done && action.outcome == Outcome.REACTIVATED) onReactivated()
    }
    AccountReactivateScreen(state = state, onBack = onBack, viewModel = viewModel)
}

@Composable
fun AccountReactivateScreen(
    state: AccountLifecycleUiState,
    onBack: () -> Unit,
    viewModel: AccountLifecycleViewModel,
) {
    LifecycleScaffold(R.string.account_reactivate_title, onBack) { modifier ->
        when (state) {
            AccountLifecycleUiState.Loading -> Loading(modifier)
            AccountLifecycleUiState.Offline ->
                OfflineOrError(
                    modifier,
                    stringResource(R.string.account_lifecycle_offline),
                    AccountLifecycleTestTags.OFFLINE,
                    viewModel::reload,
                )
            is AccountLifecycleUiState.Error ->
                OfflineOrError(modifier, state.message, AccountLifecycleTestTags.OFFLINE, viewModel::reload)
            is AccountLifecycleUiState.Ready -> ReactivateReady(modifier, state, viewModel)
        }
    }
}

@Composable
private fun ReactivateReady(
    modifier: Modifier,
    state: AccountLifecycleUiState.Ready,
    viewModel: AccountLifecycleViewModel,
) {
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        (state.action as? ActionState.Failed)?.let { FailedBanner(it.message) }

        val bodyRes = if (state.status.state == AccountState.CLOSURE_PENDING) {
            R.string.account_reactivate_body_closure
        } else {
            R.string.account_reactivate_body_suspended
        }
        Text(stringResource(R.string.account_reactivate_summary_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(bodyRes))

        val submitting = state.action.isSubmitting
        Button(
            onClick = { viewModel.requestReactivate() },
            enabled = !submitting,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(AccountLifecycleTestTags.PRIMARY),
        ) {
            Text(stringResource(R.string.account_reactivate_action))
        }
    }

    if (state.action is ActionState.ConfirmReactivate) {
        ConfirmDialog(
            titleRes = R.string.account_reactivate_confirm_title,
            bodyRes = R.string.account_reactivate_confirm_body,
            confirmRes = R.string.account_reactivate_confirm_button,
            destructive = false,
            confirmEnabled = !state.action.isSubmitting,
            confirmTag = AccountLifecycleTestTags.CONFIRM_BUTTON,
            onConfirm = { viewModel.confirmReactivate() },
            onDismiss = { viewModel.dismissDialog() },
        )
    }
}

// ===================================================================================================
// Closed terminal screen
// ===================================================================================================

/** AND-387 - terminal informational screen for a CLOSED account; no destructive actions (spec §3 FR-1). */
@Composable
fun AccountClosedScreen(
    status: AccountStatus,
    onBack: () -> Unit,
) {
    LifecycleScaffold(R.string.account_closed_title, onBack) { modifier ->
        ClosedTerminal(modifier, status)
    }
}

@Composable
private fun ClosedTerminal(modifier: Modifier, status: AccountStatus) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag(AccountLifecycleTestTags.CLOSED_TERMINAL),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error)
        Spacer(Modifier.size(12.dp))
        Text(
            stringResource(R.string.account_closed_heading),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.size(8.dp))
        Text(stringResource(R.string.account_closed_body))
    }
}
