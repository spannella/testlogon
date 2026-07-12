@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.wizard

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.MailOutline
import androidx.compose.material.icons.outlined.Phone
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material.icons.outlined.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/** Batch-9 (#18) - stable testTags for the KYC verification wizard. */
object KycWizardTestTags {
    const val SCREEN = "kyc_wizard_screen"
    const val PROGRESS = "kyc_wizard_progress"
    const val EMAIL_TARGET = "kyc_wizard_email_target"
    const val EMAIL_SEND = "kyc_wizard_email_send"
    const val EMAIL_CODE = "kyc_wizard_email_code"
    const val EMAIL_CONFIRM = "kyc_wizard_email_confirm"
    const val PHONE_TARGET = "kyc_wizard_phone_target"
    const val PHONE_SEND = "kyc_wizard_phone_send"
    const val PHONE_CODE = "kyc_wizard_phone_code"
    const val PHONE_CONFIRM = "kyc_wizard_phone_confirm"
    const val ID_START = "kyc_wizard_id_start"
    const val DONE = "kyc_wizard_done"
}

/**
 * Batch-9 (#18) - the guided KYC verification route. It walks the user through email -> phone -> ID -> done
 * with an always-visible progress header so the next action is obvious at every point. The ID step asks the
 * VM to mint a draft case then calls [onLaunchIdScanner] (the nav layer opens the proven ID-scanner screen
 * which reports completion back via the VM's [KycWizardViewModel.onIdSubmitted]).
 */
@Composable
fun KycWizardRoute(
    onBack: () -> Unit,
    onLaunchIdScanner: (caseId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: KycWizardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    KycWizardScreen(
        state = state,
        onBack = onBack,
        onEmailTargetChange = viewModel::onEmailTargetChange,
        onSendEmailCode = viewModel::sendEmailCode,
        onEmailCodeChange = viewModel::onEmailCodeChange,
        onConfirmEmail = viewModel::confirmEmail,
        onPhoneTargetChange = viewModel::onPhoneTargetChange,
        onSendPhoneCode = viewModel::sendPhoneCode,
        onPhoneCodeChange = viewModel::onPhoneCodeChange,
        onConfirmPhone = viewModel::confirmPhone,
        onStartId = { viewModel.startIdCapture(onLaunchIdScanner) },
        onSkipStep = viewModel::next,
        onGoStep = viewModel::goToStep,
        onDone = onBack,
        modifier = modifier,
    )
}

@Composable
fun KycWizardScreen(
    state: KycWizardUiState,
    onBack: () -> Unit,
    onEmailTargetChange: (String) -> Unit,
    onSendEmailCode: () -> Unit,
    onEmailCodeChange: (String) -> Unit,
    onConfirmEmail: () -> Unit,
    onPhoneTargetChange: (String) -> Unit,
    onSendPhoneCode: () -> Unit,
    onPhoneCodeChange: (String) -> Unit,
    onConfirmPhone: () -> Unit,
    onStartId: () -> Unit,
    onSkipStep: () -> Unit,
    onGoStep: (KycStep) -> Unit,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(KycWizardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kyc_wizard_title)) },
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.loading -> CenteredProgress()
                state.fatalError != null -> CenteredMessage(state.fatalError)
                else -> Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    ProgressHeader(state = state, onGoStep = onGoStep)
                    when (state.step) {
                        KycStep.EMAIL -> EmailStep(
                            state = state,
                            onTargetChange = onEmailTargetChange,
                            onSendCode = onSendEmailCode,
                            onCodeChange = onEmailCodeChange,
                            onConfirm = onConfirmEmail,
                            onSkip = onSkipStep,
                        )
                        KycStep.PHONE -> PhoneStep(
                            state = state,
                            onTargetChange = onPhoneTargetChange,
                            onSendCode = onSendPhoneCode,
                            onCodeChange = onPhoneCodeChange,
                            onConfirm = onConfirmPhone,
                            onSkip = onSkipStep,
                        )
                        KycStep.ID -> IdStep(state = state, onStartId = onStartId, onSkip = onSkipStep)
                        KycStep.DONE -> DoneStep(state = state, onDone = onDone)
                    }
                }
            }
        }
    }
}

// ---- progress header ----

@Composable
private fun ProgressHeader(state: KycWizardUiState, onGoStep: (KycStep) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.testTag(KycWizardTestTags.PROGRESS)) {
        Text(
            text = stringResource(R.string.kyc_wizard_step_of, state.step.position, KycStep.TOTAL),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        LinearProgressIndicator(
            progress = { state.completedCount.toFloat() / 3f },
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            StepChip(R.string.kyc_wizard_step_email, state.emailDone, state.step == KycStep.EMAIL) { onGoStep(KycStep.EMAIL) }
            StepChip(R.string.kyc_wizard_step_phone, state.phoneDone, state.step == KycStep.PHONE) { onGoStep(KycStep.PHONE) }
            StepChip(R.string.kyc_wizard_step_id, state.idDone, state.step == KycStep.ID) { onGoStep(KycStep.ID) }
        }
    }
}

@Composable
private fun StepChip(labelRes: Int, done: Boolean, current: Boolean, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        modifier = Modifier.heightIn(min = 32.dp),
    ) {
        Icon(
            imageVector = if (done) Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (done) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
        Text(
            text = stringResource(labelRes),
            style = if (current) MaterialTheme.typography.labelLarge else MaterialTheme.typography.labelMedium,
            color = if (current) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
        )
    }
}

// ---- email step ----

@Composable
private fun EmailStep(
    state: KycWizardUiState,
    onTargetChange: (String) -> Unit,
    onSendCode: () -> Unit,
    onCodeChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onSkip: () -> Unit,
) {
    val ch = state.email
    StepScaffold(
        icon = Icons.Outlined.MailOutline,
        titleRes = R.string.kyc_wizard_email_title,
        bodyRes = R.string.kyc_wizard_email_body,
    ) {
        if (state.emailDone) {
            VerifiedNotice(R.string.kyc_wizard_email_verified)
            Button(
                onClick = onSkip,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) { Text(stringResource(R.string.kyc_wizard_continue)) }
            return@StepScaffold
        }
        VerifyChannelFields(
            channel = ch,
            targetLabelRes = R.string.kyc_wizard_email_label,
            targetKeyboard = KeyboardType.Email,
            targetTag = KycWizardTestTags.EMAIL_TARGET,
            sendTag = KycWizardTestTags.EMAIL_SEND,
            codeTag = KycWizardTestTags.EMAIL_CODE,
            confirmTag = KycWizardTestTags.EMAIL_CONFIRM,
            targetOptional = true,
            onTargetChange = onTargetChange,
            onSendCode = onSendCode,
            onCodeChange = onCodeChange,
            onConfirm = onConfirm,
        )
    }
}

// ---- phone step ----

@Composable
private fun PhoneStep(
    state: KycWizardUiState,
    onTargetChange: (String) -> Unit,
    onSendCode: () -> Unit,
    onCodeChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onSkip: () -> Unit,
) {
    val ch = state.phone
    StepScaffold(
        icon = Icons.Outlined.Phone,
        titleRes = R.string.kyc_wizard_phone_title,
        bodyRes = R.string.kyc_wizard_phone_body,
    ) {
        if (state.phoneDone) {
            VerifiedNotice(R.string.kyc_wizard_phone_verified)
            Button(
                onClick = onSkip,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) { Text(stringResource(R.string.kyc_wizard_continue)) }
            return@StepScaffold
        }
        VerifyChannelFields(
            channel = ch,
            targetLabelRes = R.string.kyc_wizard_phone_label,
            targetKeyboard = KeyboardType.Phone,
            targetTag = KycWizardTestTags.PHONE_TARGET,
            sendTag = KycWizardTestTags.PHONE_SEND,
            codeTag = KycWizardTestTags.PHONE_CODE,
            confirmTag = KycWizardTestTags.PHONE_CONFIRM,
            targetOptional = false,
            onTargetChange = onTargetChange,
            onSendCode = onSendCode,
            onCodeChange = onCodeChange,
            onConfirm = onConfirm,
        )
    }
}

/** Shared start (target + send) -> confirm (code) fields for the email & phone steps. */
@Composable
private fun VerifyChannelFields(
    channel: ChannelState,
    targetLabelRes: Int,
    targetKeyboard: KeyboardType,
    targetTag: String,
    sendTag: String,
    codeTag: String,
    confirmTag: String,
    targetOptional: Boolean,
    onTargetChange: (String) -> Unit,
    onSendCode: () -> Unit,
    onCodeChange: (String) -> Unit,
    onConfirm: () -> Unit,
) {
    val codeSent = channel.phase == VerifyPhase.CODE_SENT || channel.phase == VerifyPhase.CONFIRMING

    OutlinedTextField(
        value = channel.target,
        onValueChange = onTargetChange,
        label = { Text(stringResource(targetLabelRes)) },
        singleLine = true,
        enabled = !channel.busy && channel.phase != VerifyPhase.CODE_SENT,
        keyboardOptions = KeyboardOptions(keyboardType = targetKeyboard),
        modifier = Modifier.fillMaxWidth().testTag(targetTag),
    )

    if (!codeSent) {
        Button(
            onClick = onSendCode,
            enabled = !channel.busy && (targetOptional || channel.target.isNotBlank()),
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(sendTag),
        ) {
            if (channel.phase == VerifyPhase.SENDING) InlineSpinner()
            else Text(stringResource(R.string.kyc_wizard_send_code))
        }
    } else {
        channel.sentTo?.let {
            Text(
                text = stringResource(R.string.kyc_wizard_code_sent_to, it),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        OutlinedTextField(
            value = channel.code,
            onValueChange = onCodeChange,
            label = { Text(stringResource(R.string.kyc_wizard_code_label)) },
            singleLine = true,
            enabled = !channel.busy,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth().testTag(codeTag),
        )
        Button(
            onClick = onConfirm,
            enabled = !channel.busy && channel.code.isNotBlank(),
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(confirmTag),
        ) {
            if (channel.phase == VerifyPhase.CONFIRMING) InlineSpinner()
            else Text(stringResource(R.string.kyc_wizard_confirm_code))
        }
        TextButton(onClick = onSendCode, enabled = !channel.busy) {
            Text(stringResource(R.string.kyc_wizard_resend_code))
        }
    }

    channel.error?.let { ErrorLine(it) }
}

// ---- ID step ----

@Composable
private fun IdStep(state: KycWizardUiState, onStartId: () -> Unit, onSkip: () -> Unit) {
    StepScaffold(
        icon = Icons.Outlined.Badge,
        titleRes = R.string.kyc_wizard_id_title,
        bodyRes = R.string.kyc_wizard_id_body,
    ) {
        if (state.idDone) {
            VerifiedNotice(R.string.kyc_wizard_id_done)
            Button(
                onClick = onSkip,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) { Text(stringResource(R.string.kyc_wizard_continue)) }
            return@StepScaffold
        }
        Button(
            onClick = onStartId,
            enabled = !state.id.creatingCase,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(KycWizardTestTags.ID_START),
        ) {
            if (state.id.creatingCase) InlineSpinner()
            else Text(stringResource(R.string.kyc_wizard_id_start))
        }
        state.id.error?.let { ErrorLine(it) }
    }
}

// ---- done step ----

@Composable
private fun DoneStep(state: KycWizardUiState, onDone: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(
                Icons.Outlined.CheckCircle,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(40.dp),
            )
            Text(
                text = stringResource(R.string.kyc_wizard_done_title),
                style = MaterialTheme.typography.titleLarge,
            )
            SummaryRow(R.string.kyc_wizard_step_email, state.emailDone)
            SummaryRow(R.string.kyc_wizard_step_phone, state.phoneDone)
            SummaryRow(R.string.kyc_wizard_step_id, state.idDone)
            Text(
                text = stringResource(R.string.kyc_wizard_done_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = onDone,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(KycWizardTestTags.DONE),
            ) { Text(stringResource(R.string.kyc_wizard_finish)) }
        }
    }
}

@Composable
private fun SummaryRow(labelRes: Int, done: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Icon(
            imageVector = if (done) Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
            contentDescription = null,
            tint = if (done) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        Text(text = stringResource(labelRes), style = MaterialTheme.typography.bodyLarge)
    }
}

// ---- shared building blocks ----

@Composable
private fun StepScaffold(
    icon: ImageVector,
    titleRes: Int,
    bodyRes: Int,
    content: @Composable () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
            Text(text = stringResource(titleRes), style = MaterialTheme.typography.titleMedium)
        }
        Text(
            text = stringResource(bodyRes),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        content()
    }
}

@Composable
private fun VerifiedNotice(messageRes: Int) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Icon(Icons.Outlined.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        Text(text = stringResource(messageRes), style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun ErrorLine(message: String) {
    Text(text = message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
}

@Composable
private fun InlineSpinner() {
    CircularProgressIndicator(
        modifier = Modifier.size(20.dp),
        strokeWidth = 2.dp,
        color = MaterialTheme.colorScheme.onPrimary,
    )
}

@Composable
private fun CenteredProgress() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
}

@Composable
private fun CenteredMessage(message: String) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
    }
}
