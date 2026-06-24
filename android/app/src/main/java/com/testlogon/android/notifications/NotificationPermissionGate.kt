package com.testlogon.android.notifications

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext

/**
 * AND-107 (FR-5/FR-6) — requests POST_NOTIFICATIONS on the first authenticated session.
 *
 * Reliability fix (2026-06): the previous implementation gated the system prompt behind a dismissible
 * Material rationale dialog AND remembered "handled" across the session, so a user who swiped the
 * rationale away during the busy first-login moment never reached the OS dialog and was never
 * re-asked — notifications were silently un-grantable except via system Settings. We now launch the
 * system permission request DIRECTLY on the first authenticated composition of each cold start while
 * the permission is still ungranted. The OS itself rate-limits this (after two dismissals it returns
 * immediately with no UI), so it cannot spam; and because the flag is only remembered for the current
 * Activity instance, a fresh app launch re-asks until the user grants or the OS locks it out (after
 * which they self-serve from Settings). On Android < 33 the permission does not exist and this is a
 * no-op. Denial is handled gracefully downstream (NotificationPresenter drops silently).
 */
@Composable
fun NotificationPermissionGate() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

    val context = LocalContext.current
    val permissionState = remember { NotificationPermissionState(context.applicationContext) }
    var requested by rememberSaveable { mutableStateOf(false) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* granted-or-not handled gracefully by the presenter; nothing to do here */ }

    LaunchedEffect(Unit) {
        if (!requested && !permissionState.isGranted()) {
            launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        requested = true
    }
}
