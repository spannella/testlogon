package com.testlogon.android.feature.auth.biometric

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag

/** Shared "enable biometric sign-in?" prompt shown after a fresh login or registration. */
@Composable
fun BiometricEnrollDialog(
    busy: Boolean,
    onEnable: () -> Unit,
    onSkip: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onSkip,
        modifier = Modifier.testTag("biometric_enroll_dialog"),
        title = { Text("Enable biometric sign-in?") },
        text = { Text("Use your fingerprint or face to sign in next time — no password needed.") },
        confirmButton = {
            TextButton(
                onClick = onEnable,
                enabled = !busy,
                modifier = Modifier.testTag("biometric_enroll_enable"),
            ) { Text("Enable") }
        },
        dismissButton = {
            TextButton(
                onClick = onSkip,
                enabled = !busy,
                modifier = Modifier.testTag("biometric_enroll_skip"),
            ) { Text("Not now") }
        },
    )
}
