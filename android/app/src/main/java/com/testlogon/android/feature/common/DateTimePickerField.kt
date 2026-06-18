package com.testlogon.android.feature.common

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
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
 * Pick an arbitrary future date + time. Works entirely in epoch millis/seconds (no java.time, so it is
 * minSdk-24 safe). [selectedEpochSeconds] drives the button label; [onPicked] fires with epoch SECONDS.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DateTimePickerField(
    selectedEpochSeconds: Long?,
    onPicked: (Long) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "Pick a date & time",
    testTag: String = "datetime_pick",
) {
    var showDate by remember { mutableStateOf(false) }
    var showTime by remember { mutableStateOf(false) }
    var pendingDateMillis by remember { mutableStateOf<Long?>(null) }

    // Label includes the timezone (e.g. "Jun 20, 2026 at 3:00 PM PDT") so the scheduled instant is unambiguous.
    val label = selectedEpochSeconds?.let {
        SimpleDateFormat("MMM d, yyyy 'at' h:mm a z", Locale.getDefault()).format(Date(it * 1000L))
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
                        // with the chosen wall-clock time in the DEVICE timezone for the correct absolute
                        // instant (otherwise it would be off by the local UTC offset).
                        val utc = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply { timeInMillis = dateMillis }
                        val local = Calendar.getInstance().apply {
                            clear()
                            set(
                                utc.get(Calendar.YEAR), utc.get(Calendar.MONTH), utc.get(Calendar.DAY_OF_MONTH),
                                timeState.hour, timeState.minute, 0,
                            )
                        }
                        onPicked(local.timeInMillis / 1000L)
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
