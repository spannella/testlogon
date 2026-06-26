package com.testlogon.android.feature.common

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TimePicker
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.material3.rememberTimePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * A short, curated list of common IANA time zones offered in the timezone picker. The device's own
 * zone is always added (and selected by default) by [TimeZonePicker] even if it's not in this list.
 */
internal val COMMON_TIME_ZONE_IDS: List<String> = listOf(
    "America/Los_Angeles",
    "America/Denver",
    "America/Chicago",
    "America/New_York",
    "America/Sao_Paulo",
    "UTC",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Europe/Moscow",
    "Asia/Dubai",
    "Asia/Kolkata",
    "Asia/Singapore",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "Australia/Sydney",
    "Pacific/Auckland",
)

/** A friendly label for a time zone id, e.g. "America/New_York (GMT-04:00)". */
internal fun timeZoneLabel(zoneId: String): String {
    val tz = TimeZone.getTimeZone(zoneId)
    val offsetMin = tz.getOffset(System.currentTimeMillis()) / 60000
    val sign = if (offsetMin < 0) "-" else "+"
    val abs = kotlin.math.abs(offsetMin)
    val short = zoneId.substringAfterLast('/').replace('_', ' ')
    return String.format(Locale.ROOT, "%s (GMT%s%02d:%02d)", short, sign, abs / 60, abs % 60)
}

/**
 * Combine a chosen calendar day (from a [DatePicker], which returns UTC-midnight of that day) with a
 * chosen wall-clock [hour]/[minute], INTERPRETED IN [zoneId], into an absolute epoch-SECONDS instant.
 * Pure (no Compose) so it is JVM-testable; min-SDK-24 safe (uses [Calendar], not java.time).
 */
internal fun combineToEpochSeconds(dateUtcMidnightMillis: Long, hour: Int, minute: Int, zoneId: String): Long {
    val utc = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply { timeInMillis = dateUtcMidnightMillis }
    val zoned = Calendar.getInstance(TimeZone.getTimeZone(zoneId)).apply {
        clear()
        set(
            utc.get(Calendar.YEAR), utc.get(Calendar.MONTH), utc.get(Calendar.DAY_OF_MONTH),
            hour, minute, 0,
        )
    }
    return zoned.timeInMillis / 1000L
}

/**
 * Pick an arbitrary future date + time. Works entirely in epoch millis/seconds (no java.time, so it is
 * minSdk-24 safe). [selectedEpochSeconds] drives the button label; [onPicked] fires with epoch SECONDS.
 *
 * When [zoneId] is non-null the chosen wall-clock is interpreted in THAT zone (so the absolute instant
 * is unambiguous even if the device is elsewhere); otherwise the device's default zone is used. The
 * timezone control itself is rendered by the caller via [TimeZonePicker] so the same field can be
 * reused with or without a zone selector.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DateTimePickerField(
    selectedEpochSeconds: Long?,
    onPicked: (Long) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "Pick a date & time",
    testTag: String = "datetime_pick",
    zoneId: String? = null,
) {
    var showDate by remember { mutableStateOf(false) }
    var showTime by remember { mutableStateOf(false) }
    var pendingDateMillis by remember { mutableStateOf<Long?>(null) }

    val effectiveZone = zoneId ?: TimeZone.getDefault().id
    // Label shows the instant rendered IN the chosen zone (so the time matches what was picked).
    val label = selectedEpochSeconds?.let {
        SimpleDateFormat("MMM d, yyyy 'at' h:mm a z", Locale.getDefault()).apply {
            timeZone = TimeZone.getTimeZone(effectiveZone)
        }.format(Date(it * 1000L))
    } ?: placeholder

    OutlinedButton(onClick = { showDate = true }, modifier = modifier.fillMaxWidth().testTag(testTag)) {
        Text(label)
    }

    if (showDate) {
        val dateState = rememberDatePickerState(
            // Default to today so there is always a selection (the user can change it).
            initialSelectedDateMillis = selectedEpochSeconds?.let { it * 1000L } ?: System.currentTimeMillis(),
        )
        DatePickerDialog(
            onDismissRequest = { showDate = false },
            confirmButton = {
                TextButton(onClick = {
                    pendingDateMillis = dateState.selectedDateMillis
                    showDate = false
                    if (pendingDateMillis != null) showTime = true
                }) { Text("Next") }
            },
            dismissButton = { TextButton(onClick = { showDate = false }) { Text("Cancel") } },
        ) {
            DatePicker(state = dateState)
        }
    }

    if (showTime) {
        val timeState = rememberTimePickerState()
        DatePickerDialog(
            onDismissRequest = { showTime = false },
            confirmButton = {
                TextButton(onClick = {
                    pendingDateMillis?.let { dateMillis ->
                        // DatePicker returns UTC-midnight of the chosen calendar day; combine its y/m/d
                        // with the chosen wall-clock time IN the selected zone for the correct instant.
                        onPicked(combineToEpochSeconds(dateMillis, timeState.hour, timeState.minute, effectiveZone))
                    }
                    showTime = false
                }) { Text("Done") }
            },
            dismissButton = { TextButton(onClick = { showTime = false }) { Text("Cancel") } },
        ) {
            Column(Modifier.padding(16.dp)) { TimePicker(state = timeState) }
        }
    }
}

/**
 * #21/#32 — a compact dropdown to choose the time zone the scheduled/countdown instant is expressed
 * in. Defaults to the device zone (which is added to the list if absent). [selectedZoneId] should be
 * pre-seeded by the caller with `TimeZone.getDefault().id`.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimeZonePicker(
    selectedZoneId: String,
    onZoneChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    testTag: String = "datetime_tz",
) {
    var expanded by remember { mutableStateOf(false) }
    val zones = remember(selectedZoneId) {
        val deviceId = TimeZone.getDefault().id
        (listOf(deviceId) + COMMON_TIME_ZONE_IDS + selectedZoneId).distinct()
    }
    Column(modifier) {
        OutlinedButton(
            onClick = { expanded = true },
            modifier = Modifier.fillMaxWidth().testTag(testTag),
        ) {
            Text("Time zone: " + timeZoneLabel(selectedZoneId))
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            zones.forEach { z ->
                DropdownMenuItem(
                    text = { Text(timeZoneLabel(z), style = MaterialTheme.typography.bodyMedium) },
                    onClick = { onZoneChange(z); expanded = false },
                    modifier = Modifier.testTag(testTag + "_" + z),
                )
            }
        }
    }
}
