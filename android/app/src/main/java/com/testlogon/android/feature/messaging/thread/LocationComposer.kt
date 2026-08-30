@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import android.Manifest
import android.content.pm.PackageManager
import android.location.LocationManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.testlogon.android.feature.messaging.LocationCardModel
import kotlinx.coroutines.launch

object LocationComposerTestTags {
    const val ATTACH = "thread_attach_location"
    const val SHEET = "thread_location_composer"
    const val USE_CURRENT = "thread_location_use_current"
    const val LAT = "thread_location_lat"
    const val LNG = "thread_location_lng"
    const val LABEL = "thread_location_label"
    const val SEND = "thread_location_send"
}

/**
 * FE-130 (EPIC D) - Share location composer. Use-current-location is permission-gated (COARSE):
 * deny / unsupported degrades to manual lat/lng entry (always present as the no-permission fallback).
 * An optional label rides along. On send it best-effort reverse-geocodes via onReverseGeocode
 * (degrade -> skip place name) and emits the encoded TLLOC1 body through onSend. Coord validation +
 * encoding are the pure LocationCardModel; a geocode/location failure NEVER blocks the send.
 */
@Composable
fun LocationComposerSheet(
    onSend: (body: String) -> Unit,
    onReverseGeocode: suspend (lat: Double, lng: Double) -> String?,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var latText by remember { mutableStateOf("") }
    var lngText by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var sending by remember { mutableStateOf(false) }

    fun fillCurrentLocation() {
        val lm = context.getSystemService(android.content.Context.LOCATION_SERVICE) as? LocationManager
        if (lm == null) { note = "Location is unavailable. Enter coordinates manually."; return }
        val loc = runCatching {
            lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
                ?: lm.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                ?: lm.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER)
        }.getOrNull()
        if (loc == null) {
            note = "No recent location fix. Enter coordinates manually."
        } else {
            latText = loc.latitude.toString()
            lngText = loc.longitude.toString()
            note = null
        }
    }

    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) fillCurrentLocation() else note = "Location permission denied. Enter coordinates manually."
    }

    fun onUseCurrent() {
        val coarse = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION)
        if (coarse == PackageManager.PERMISSION_GRANTED) fillCurrentLocation()
        else permLauncher.launch(Manifest.permission.ACCESS_COARSE_LOCATION)
    }

    val lat = latText.trim().toDoubleOrNull()
    val lng = lngText.trim().toDoubleOrNull()
    val valid = lat != null && lng != null && LocationCardModel.isValidLatLng(lat, lng)

    fun onSendClicked() {
        val la = lat; val ln = lng
        if (la == null || ln == null || !LocationCardModel.isValidLatLng(la, ln)) {
            note = "Enter a valid latitude (-90..90) and longitude (-180..180)."
            return
        }
        sending = true
        scope.launch {
            val place = runCatching { onReverseGeocode(la, ln) }.getOrNull()
            val card = LocationCardModel.build(la, ln, label, place)
            onSend(LocationCardModel.encode(card))
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(LocationComposerTestTags.SHEET).semantics { testTagsAsResourceId = true },
    ) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState())) {
            Text("Share location", style = MaterialTheme.typography.titleMedium)

            OutlinedButton(
                onClick = { onUseCurrent() },
                enabled = !sending,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp).testTag(LocationComposerTestTags.USE_CURRENT),
            ) {
                Icon(Icons.Filled.MyLocation, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("  Use current location")
            }

            Text(
                "Or enter coordinates",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 14.dp),
            )
            Row(Modifier.fillMaxWidth().padding(top = 6.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = latText,
                    onValueChange = { latText = it; note = null },
                    modifier = Modifier.weight(1f).testTag(LocationComposerTestTags.LAT),
                    label = { Text("Latitude") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                )
                OutlinedTextField(
                    value = lngText,
                    onValueChange = { lngText = it; note = null },
                    modifier = Modifier.weight(1f).testTag(LocationComposerTestTags.LNG),
                    label = { Text("Longitude") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                )
            }
            OutlinedTextField(
                value = label,
                onValueChange = { label = it },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag(LocationComposerTestTags.LABEL),
                label = { Text("Label (optional)") },
                placeholder = { Text("Home, The cafe") },
                singleLine = true,
            )
            note?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            Button(
                onClick = { onSendClicked() },
                enabled = valid && !sending,
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(LocationComposerTestTags.SEND),
            ) {
                if (sending) CircularProgressIndicator(Modifier.size(18.dp)) else Text("Send location")
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}
