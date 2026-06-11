package com.testlogon.android.feature.golive

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/**
 * AND-288 — host "Go Live" entry. Owns the CAMERA + RECORD_AUDIO runtime permission flow via the AndroidX
 * activity-result API (RequestMultiplePermissions — NO Accompanist) and exposes the go-live action, which
 * is gated behind the FLAGGED [com.testlogon.android.data.webrtc.BroadcastPublisher] seam. Because the
 * engine is not configured (no native WebRTC SDK), tapping "Go Live" after granting permissions resolves
 * to a "broadcasting unavailable" state — nothing opens the camera/mic or starts a peer/capture.
 */
@Composable
fun GoLiveScreen(
    viewModel: GoLiveViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    // Strings resolved at composable scope (never inside the non-composable effect lambda).
    val unavailableText = stringResource(R.string.golive_broadcasting_unavailable)
    val failedText = stringResource(R.string.golive_failed)

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { grants ->
        val cameraGranted = grants[Manifest.permission.CAMERA] ?: false
        val micGranted = grants[Manifest.permission.RECORD_AUDIO] ?: false
        val showRationale = shouldShowRationale(context)
        viewModel.onPermissionResult(cameraGranted, micGranted, showRationale)
    }

    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                GoLiveEffect.RequestPermissions ->
                    permissionLauncher.launch(
                        arrayOf(Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO),
                    )
                GoLiveEffect.OpenAppSettings -> context.openAppSettings()
                is GoLiveEffect.Notice -> {
                    val msg = when (effect.kind) {
                        GoLiveNotice.BROADCASTING_UNAVAILABLE -> unavailableText
                        GoLiveNotice.GO_LIVE_FAILED -> failedText
                    }
                    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.golive_title),
            style = MaterialTheme.typography.headlineSmall,
        )

        if (state.broadcastingUnavailable) {
            Text(
                modifier = Modifier.testTag(TAG_UNAVAILABLE),
                text = stringResource(R.string.golive_broadcasting_unavailable),
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        if (state.permission == AvPermissionStatus.PERMANENTLY_DENIED) {
            Text(
                text = stringResource(R.string.golive_perm_rationale),
                style = MaterialTheme.typography.bodySmall,
            )
            Button(onClick = { context.openAppSettings() }) {
                Text(stringResource(R.string.golive_perm_settings))
            }
        }

        Button(
            modifier = Modifier.testTag(TAG_GO_LIVE),
            enabled = state.publish != GoLivePublishState.STARTING,
            onClick = { viewModel.onGoLiveClicked() },
        ) {
            Text(stringResource(R.string.golive_action))
        }
    }
}

/** True if either CAMERA or RECORD_AUDIO should still show a rationale (i.e. denied but not permanently). */
private fun shouldShowRationale(context: Context): Boolean {
    val activity = context.findActivity() ?: return false
    return activity.shouldShowRequestPermissionRationale(Manifest.permission.CAMERA) ||
        activity.shouldShowRequestPermissionRationale(Manifest.permission.RECORD_AUDIO)
}

private fun Context.openAppSettings() {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.fromParts("package", packageName, null)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    startActivity(intent)
}

private fun Context.findActivity(): android.app.Activity? {
    var ctx: Context? = this
    while (ctx is android.content.ContextWrapper) {
        if (ctx is android.app.Activity) return ctx
        ctx = ctx.baseContext
    }
    return null
}

/** True when both CAMERA and RECORD_AUDIO are currently granted (for resume-time re-check). */
internal fun Context.avPermissionsGranted(): Boolean {
    val camera = ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
        PackageManager.PERMISSION_GRANTED
    val mic = ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) ==
        PackageManager.PERMISSION_GRANTED
    return camera && mic
}

private const val TAG_GO_LIVE = "golive_action_button"
private const val TAG_UNAVAILABLE = "golive_unavailable_text"
