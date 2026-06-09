package com.testlogon.android.feature.account

import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.LaunchedEffect
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlOtpField
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.data.auth.MfaDevice
import com.testlogon.android.data.auth.MfaFactorType

/** Route-level MFA device management entry (AND-064), reached from Profile/Settings → Security. */
@Composable
fun MfaDevicesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MfaDevicesViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { viewModel.load() }

    MfaDevicesScreen(
        state = state,
        onStartTotp = viewModel::startTotpEnroll,
        onStartCode = viewModel::startCodeEnroll,
        onDestinationChange = viewModel::onDestinationChange,
        onSubmitBegin = viewModel::submitBegin,
        onCodeChange = viewModel::onCodeChange,
        onSubmitCodeConfirm = viewModel::submitCodeConfirm,
        onTotpCodeChange = viewModel::onTotpCodeChange,
        onTotpCode2Change = viewModel::onTotpCode2Change,
        onSubmitTotpConfirm = viewModel::submitTotpConfirm,
        onResend = viewModel::resend,
        onCancelEnroll = viewModel::cancelEnroll,
        onRequestRemove = viewModel::requestRemove,
        onRemoveCodeChange = viewModel::onRemoveCodeChange,
        onConfirmRemove = viewModel::confirmRemove,
        onDismissRemove = viewModel::dismissRemove,
        onDismissError = viewModel::dismissError,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
@Suppress("LongParameterList")
fun MfaDevicesScreen(
    state: MfaDevicesViewModel.UiState,
    onStartTotp: () -> Unit,
    onStartCode: (MfaFactorType) -> Unit,
    onDestinationChange: (String) -> Unit,
    onSubmitBegin: () -> Unit,
    onCodeChange: (String) -> Unit,
    onSubmitCodeConfirm: () -> Unit,
    onTotpCodeChange: (String) -> Unit,
    onTotpCode2Change: (String) -> Unit,
    onSubmitTotpConfirm: () -> Unit,
    onResend: () -> Unit,
    onCancelEnroll: () -> Unit,
    onRequestRemove: (MfaDevice) -> Unit,
    onRemoveCodeChange: (String) -> Unit,
    onConfirmRemove: () -> Unit,
    onDismissRemove: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag("mfa_devices_screen")) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Two-factor authentication", style = MaterialTheme.typography.headlineSmall)

            if (state.error != null) {
                Text(
                    text = state.error,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier
                        .testTag("mfa_devices_error")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
                TlButton("Dismiss", onClick = onDismissError, variant = TlButtonVariant.Text)
            }

            when (val enroll = state.enroll) {
                is MfaDevicesViewModel.EnrollState.Totp ->
                    TotpEnrollContent(enroll, onTotpCodeChange, onTotpCode2Change, onSubmitTotpConfirm, onCancelEnroll)
                is MfaDevicesViewModel.EnrollState.Code ->
                    CodeEnrollContent(enroll, onDestinationChange, onSubmitBegin, onCodeChange, onSubmitCodeConfirm, onResend, onCancelEnroll)
                MfaDevicesViewModel.EnrollState.None ->
                    DeviceListContent(state, onStartTotp, onStartCode, onRequestRemove)
            }
        }
    }

    val remove = state.remove
    if (remove !is MfaDevicesViewModel.RemoveState.None) {
        RemoveDialog(remove, onRemoveCodeChange, onConfirmRemove, onDismissRemove)
    }
}

@Composable
private fun DeviceListContent(
    state: MfaDevicesViewModel.UiState,
    onStartTotp: () -> Unit,
    onStartCode: (MfaFactorType) -> Unit,
    onRequestRemove: (MfaDevice) -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TlButton("Add authenticator app", onClick = onStartTotp, variant = TlButtonVariant.Secondary, modifier = Modifier.testTag("mfa_add_totp"))
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TlButton("Add phone", onClick = { onStartCode(MfaFactorType.SMS) }, variant = TlButtonVariant.Secondary, modifier = Modifier.testTag("mfa_add_sms"))
        TlButton("Add email", onClick = { onStartCode(MfaFactorType.EMAIL) }, variant = TlButtonVariant.Secondary, modifier = Modifier.testTag("mfa_add_email"))
    }

    HorizontalDivider()

    if (state.isLoading) {
        CircularProgressIndicator(modifier = Modifier.testTag("mfa_devices_loading"))
    } else if (state.devices.isEmpty()) {
        Text("No two-factor methods yet.", modifier = Modifier.testTag("mfa_devices_empty"))
    } else {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.testTag("mfa_devices_list")) {
            items(state.devices, key = { it.deviceId }) { device ->
                DeviceRow(device, onRequestRemove)
            }
        }
    }
}

@Composable
private fun DeviceRow(device: MfaDevice, onRequestRemove: (MfaDevice) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag("mfa_device_${device.deviceId}"),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.semantics(mergeDescendants = true) {}) {
            Text(device.label ?: device.type.name, style = MaterialTheme.typography.bodyLarge)
            val sub = device.destination?.let(::maskDestination) ?: device.type.name.lowercase()
            Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        TlButton("Remove", onClick = { onRequestRemove(device) }, variant = TlButtonVariant.Text, modifier = Modifier.testTag("mfa_remove_${device.deviceId}"))
    }
}

@Composable
private fun TotpEnrollContent(
    state: MfaDevicesViewModel.EnrollState.Totp,
    onCodeChange: (String) -> Unit,
    onCode2Change: (String) -> Unit,
    onSubmit: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.verticalScroll(rememberScrollState()).imePadding().testTag("mfa_totp_enroll"),
    ) {
        Text("Add an authenticator app", style = MaterialTheme.typography.titleMedium)
        val enrollment = state.enrollment
        if (enrollment != null) {
            QrImage(enrollment.qrCodeUri)
            Text("Or enter this code in your authenticator app:", style = MaterialTheme.typography.bodyMedium)
            Text(enrollment.secret, style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("mfa_totp_secret"))
        }

        if (state.recoveryCodes.isNotEmpty()) {
            Text("Save your recovery codes:", style = MaterialTheme.typography.titleSmall)
            Text(state.recoveryCodes.joinToString("\n"), modifier = Modifier.testTag("mfa_recovery_codes"))
            TlButton("Done", onClick = onCancel, modifier = Modifier.fillMaxWidth().testTag("mfa_totp_done"))
            return@Column
        }

        Text("Enter two consecutive codes:", style = MaterialTheme.typography.bodyMedium)
        TlOtpField(value = state.code, onValueChange = onCodeChange, modifier = Modifier.testTag("mfa_totp_code"))
        TlOtpField(value = state.code2, onValueChange = onCode2Change, modifier = Modifier.testTag("mfa_totp_code2"))
        if (state.error != null) {
            Text(state.error, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("mfa_totp_error"))
        }
        TlButton(
            "Confirm",
            onClick = onSubmit,
            loading = state.step == MfaDevicesViewModel.Step.ConfirmInFlight,
            enabled = state.enrollment != null,
            modifier = Modifier.fillMaxWidth().testTag("mfa_totp_confirm"),
        )
        TlButton("Cancel", onClick = onCancel, variant = TlButtonVariant.Text, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun CodeEnrollContent(
    state: MfaDevicesViewModel.EnrollState.Code,
    onDestinationChange: (String) -> Unit,
    onSubmitBegin: () -> Unit,
    onCodeChange: (String) -> Unit,
    onSubmitConfirm: () -> Unit,
    onResend: () -> Unit,
    onCancel: () -> Unit,
) {
    val isSms = state.type == MfaFactorType.SMS
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.verticalScroll(rememberScrollState()).imePadding().testTag("mfa_code_enroll"),
    ) {
        Text(if (isSms) "Add a phone" else "Add an email", style = MaterialTheme.typography.titleMedium)

        if (state.recoveryCodes.isNotEmpty()) {
            Text("Save your recovery codes:", style = MaterialTheme.typography.titleSmall)
            Text(state.recoveryCodes.joinToString("\n"), modifier = Modifier.testTag("mfa_recovery_codes"))
            TlButton("Done", onClick = onCancel, modifier = Modifier.fillMaxWidth().testTag("mfa_code_done"))
            return@Column
        }

        if (state.challenge == null) {
            TlTextField(
                value = state.destination,
                onValueChange = onDestinationChange,
                label = if (isSms) "Phone number" else "Email",
                keyboardOptions = KeyboardOptions(keyboardType = if (isSms) KeyboardType.Phone else KeyboardType.Email),
                modifier = Modifier.testTag("mfa_code_destination"),
            )
            if (state.error != null) {
                Text(state.error, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("mfa_code_error"))
            }
            TlButton(
                "Send code",
                onClick = onSubmitBegin,
                loading = state.step == MfaDevicesViewModel.Step.BeginInFlight,
                modifier = Modifier.fillMaxWidth().testTag("mfa_code_send"),
            )
        } else {
            Text("Enter the code we sent.", style = MaterialTheme.typography.bodyMedium)
            TlOtpField(value = state.code, onValueChange = onCodeChange, modifier = Modifier.testTag("mfa_code_code"))
            if (state.error != null) {
                Text(state.error, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("mfa_code_error"))
            }
            TlButton(
                "Confirm",
                onClick = onSubmitConfirm,
                loading = state.step == MfaDevicesViewModel.Step.ConfirmInFlight,
                modifier = Modifier.fillMaxWidth().testTag("mfa_code_confirm"),
            )
            val resendLabel = if (state.resendInSeconds > 0) "Resend in ${state.resendInSeconds}s" else "Resend code"
            TlButton(resendLabel, onClick = onResend, enabled = state.resendInSeconds == 0, variant = TlButtonVariant.Text, modifier = Modifier.fillMaxWidth().testTag("mfa_code_resend"))
        }
        TlButton("Cancel", onClick = onCancel, variant = TlButtonVariant.Text, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun RemoveDialog(
    state: MfaDevicesViewModel.RemoveState,
    onCodeChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag("mfa_remove_dialog"),
        title = { Text("Remove this method?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                when (state) {
                    is MfaDevicesViewModel.RemoveState.Totp -> {
                        Text("Enter a current code to confirm.")
                        TlOtpField(value = state.code, onValueChange = onCodeChange, modifier = Modifier.testTag("mfa_remove_code"))
                        if (state.error != null) Text(state.error, color = MaterialTheme.colorScheme.error)
                    }
                    is MfaDevicesViewModel.RemoveState.Code -> {
                        if (state.challenge == null) {
                            Text("We'll send a code to confirm removal.")
                        } else {
                            Text("Enter the code we sent.")
                            TlOtpField(value = state.code, onValueChange = onCodeChange, modifier = Modifier.testTag("mfa_remove_code"))
                        }
                        if (state.error != null) Text(state.error, color = MaterialTheme.colorScheme.error)
                    }
                    MfaDevicesViewModel.RemoveState.None -> Unit
                }
            }
        },
        confirmButton = {
            val label = when (state) {
                is MfaDevicesViewModel.RemoveState.Code -> if (state.challenge == null) "Send code" else "Remove"
                else -> "Remove"
            }
            TlButton(label, onClick = onConfirm, variant = TlButtonVariant.Text, modifier = Modifier.testTag("mfa_remove_confirm"))
        },
        dismissButton = {
            TlButton("Cancel", onClick = onDismiss, variant = TlButtonVariant.Text, modifier = Modifier.testTag("mfa_remove_cancel"))
        },
    )
}

@Composable
private fun QrImage(qrCodeUri: String) {
    val bitmap = remember(qrCodeUri) { decodeDataUriBitmap(qrCodeUri) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "QR code to scan in your authenticator app",
            modifier = Modifier.size(180.dp).testTag("mfa_totp_qr"),
        )
    } else {
        // Fallback: cannot render the URI as an image (e.g. an otpauth:// value); rely on the secret.
        Text(
            "Scan the QR in your authenticator, or use the code below.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.testTag("mfa_totp_qr_fallback"),
        )
    }
}

/** Decodes a `data:image/...;base64,<payload>` URI to a Bitmap; null for non-data/unsupported URIs. */
private fun decodeDataUriBitmap(uri: String): android.graphics.Bitmap? {
    val marker = "base64,"
    if (!uri.startsWith("data:") || !uri.contains(marker)) return null
    return runCatching {
        val payload = uri.substringAfter(marker)
        val bytes = Base64.decode(payload, Base64.DEFAULT)
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }.getOrNull()
}

/** Client-side masking of a phone/email for display (the list wire is not pre-masked). */
private fun maskDestination(raw: String): String {
    val at = raw.indexOf('@')
    return if (at > 0) {
        val name = raw.take(at)
        val masked = if (name.length <= 1) name else name.first() + "•••"
        masked + raw.substring(at)
    } else if (raw.length > 4) {
        "•••" + raw.takeLast(4)
    } else {
        raw
    }
}
