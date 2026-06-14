package com.testlogon.android.notifications

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.testlogon.android.R

/**
 * AND-107 (FR-5/FR-6) — requests POST_NOTIFICATIONS once on the first authenticated session.
 *
 * Mounted high in the authenticated graph (the shell), so it fires once the user is logged in. On
 * Android < 33 the permission does not exist and this is a no-op. The first time only, a Material 3
 * rationale dialog precedes the system prompt; "Allow" launches the system request, "Not now"
 * dismisses. Denial is handled gracefully downstream (NotificationPresenter drops silently). State is
 * remembered across config changes within the session via rememberSaveable; re-prompting across
 * sessions is intentionally avoided (the user can re-enable from system settings).
 */
@Composable
fun NotificationPermissionGate() {
    val context = LocalContext.current
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

    val permissionState = remember { NotificationPermissionState(context.applicationContext) }
    var handled by rememberSaveable { mutableStateOf(false) }
    var showRationale by rememberSaveable { mutableStateOf(false) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* granted-or-not handled gracefully by the presenter; nothing to do here */ }

    LaunchedEffect(Unit) {
        if (!handled && !permissionState.isGranted()) {
            showRationale = true
        }
        handled = true
    }

    if (showRationale) {
        AlertDialog(
            onDismissRequest = { showRationale = false },
            title = { Text(stringResource(R.string.notif_perm_rationale_title)) },
            text = { Text(stringResource(R.string.notif_perm_rationale_body)) },
            confirmButton = {
                TextButton(onClick = {
                    showRationale = false
                    launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }) {
                    Text(stringResource(R.string.notif_perm_rationale_allow))
                }
            },
            dismissButton = {
                TextButton(onClick = { showRationale = false }) {
                    Text(stringResource(R.string.notif_perm_rationale_not_now))
                }
            },
        )
    }
}
