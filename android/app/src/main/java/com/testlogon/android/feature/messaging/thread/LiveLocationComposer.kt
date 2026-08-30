@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import android.Manifest
import android.content.pm.PackageManager
import android.location.LocationManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.testlogon.android.feature.messaging.LiveLocationModel

object LiveLocationComposerTestTags {
    const val ATTACH = "thread_attach_live_location"
    const val SHEET = "thread_live_location_composer"
    const val DURATION_PREFIX = "thread_live_location_duration_"
    const val START = "thread_live_location_start"
}

/**
 * FE-131 (EPIC D, BE-131) - "Share live location" composer. The user picks a duration (15m/1h/8h),
 * then Start captures a current location fix (COARSE-permission gated; deny/unsupported surfaces a
 * clear error and blocks start - a moving pin needs a real fix). On start it hands the first fix +
 * chosen duration to [onStart]; the ViewModel starts the (optionally BE-131-backed) session, emits
 * the optimistic TLLIVE1 card, and drives periodic updates while foregrounded.
 *
 * @param onStart (lat, lng, durationSec) for the initial fix + chosen window.
 */
@Composable
fun LiveLocationComposerSheet(
    onStart: (lat: Double, lng: Double, durationSec: Long) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current

    var durationSec by remember { mutableStateOf(LiveLocationModel.LIVE_DURATION_OPTIONS.first().seconds) }
    var note by remember { mutableStateOf<String?>(null) }
    var starting by remember { mutableStateOf(false) }

    fun currentFix(): android.location.Location? {
        val lm = context.getSystemService(android.content.Context.LOCATION_SERVICE) as? LocationManager
            ?: return null
        return runCatching {
            lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
                ?: lm.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                ?: lm.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER)
        }.getOrNull()
    }

    fun startWithFix() {
        val loc = currentFix()
        if (loc == null) {
            note = "No recent location fix available. Try again once your location is known."
            return
        }
        starting = true
        onStart(loc.latitude, loc.longitude, durationSec)
    }

    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) startWithFix() else note = "Location permission is required to share your live location."
    }

    fun onStartClicked() {
        note = null
        val coarse = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION)
        if (coarse == PackageManager.PERMISSION_GRANTED) startWithFix()
        else permLauncher.launch(Manifest.permission.ACCESS_COARSE_LOCATION)
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(LiveLocationComposerTestTags.SHEET).semantics { testTagsAsResourceId = true },
    ) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp)) {
            Text("Share live location", style = MaterialTheme.typography.titleMedium)
            Text(
                "Recipients see your position update until it expires.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )

            Text(
                "Duration",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 14.dp),
            )
            LiveLocationModel.LIVE_DURATION_OPTIONS.forEach { opt ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = durationSec == opt.seconds,
                            onClick = { durationSec = opt.seconds; note = null },
                        )
                        .padding(vertical = 6.dp)
                        .testTag(LiveLocationComposerTestTags.DURATION_PREFIX + opt.seconds),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = durationSec == opt.seconds, onClick = null)
                    Text(opt.label, modifier = Modifier.padding(start = 8.dp))
                }
            }

            note?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            Button(
                onClick = { onStartClicked() },
                enabled = !starting,
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(LiveLocationComposerTestTags.START),
            ) {
                if (starting) {
                    CircularProgressIndicator(Modifier.size(18.dp))
                } else {
                    Icon(Icons.Filled.MyLocation, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("  Share live location")
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}
