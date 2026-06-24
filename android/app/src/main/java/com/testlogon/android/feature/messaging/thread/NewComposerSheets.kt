@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.semantics.testTagsAsResourceId
import coil.compose.AsyncImage
import androidx.compose.ui.semantics.semantics
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.messaging.CalendarAccessUi
import com.testlogon.android.data.messaging.CalendarEventUi
import com.testlogon.android.data.messaging.FindDateTimeDraft
import com.testlogon.android.data.messaging.LotteryOutcomeDraft
import com.testlogon.android.data.messaging.MessageMedia

/**
 * MSG - five new in-app composer sheets (lottery / find-a-datetime / calendar-event share /
 * calendar share / file-manager share). All driven entirely from in-app UI (no Android system
 * picker). Each mirrors the existing ModalBottomSheet composer pattern (e.g. MeetingPollComposerSheet).
 */

/** Lottery composer: 2-4 outcomes (label + revealed text); weights split evenly server-side. */
@Composable
fun LotteryComposerSheet(
    onSend: (List<LotteryOutcomeDraft>, String?) -> Unit,
    onDismiss: () -> Unit,
) {
    class OutcomeDraft(var label: String, var text: String, var weight: String = "1")
    val outcomes = remember {
        mutableStateListOf(OutcomeDraft("", ""), OutcomeDraft("", ""))
    }
    // C10 — optional cover image picked from the system photo picker (no storage permission).
    var imageUri by remember { mutableStateOf<String?>(null) }
    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) imageUri = uri.toString()
    }
    var version by remember { mutableStateOf(0) }
    val valid = version >= 0 && outcomes.count { it.text.trim().isNotEmpty() } >= 2
    // Live probability = this outcome's weight / sum of all positive weights.
    val totalWeight = outcomes.fold(0f) { acc, o -> acc + (o.weight.toFloatOrNull()?.coerceAtLeast(0f) ?: 0f) }.coerceAtLeast(0.0001f)

    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(RichMessageTestTags.LOTTERY_COMPOSER).semantics { testTagsAsResourceId = true }) {
        Column(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState()),
        ) {
            Text("Create a lottery", style = MaterialTheme.typography.titleMedium)
            Text(
                "The recipient draws one random outcome to reveal.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            // C10 — optional cover image.
            val curImage = imageUri
            if (curImage == null) {
                OutlinedButton(
                    onClick = { pickImage.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                    modifier = Modifier.padding(top = 8.dp).testTag(RichMessageTestTags.LOTTERY_ADD_IMAGE),
                ) { Text("Add cover image") }
            } else {
                Row(Modifier.padding(top = 8.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    AsyncImage(
                        model = curImage,
                        contentDescription = "Lottery cover image",
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.size(64.dp).clip(RoundedCornerShape(12.dp)).testTag(RichMessageTestTags.LOTTERY_IMAGE_PREVIEW),
                    )
                    OutlinedButton(
                        onClick = { imageUri = null },
                        modifier = Modifier.padding(start = 12.dp).testTag(RichMessageTestTags.LOTTERY_REMOVE_IMAGE),
                    ) { Text("Remove") }
                }
            }
            outcomes.forEachIndexed { i, o ->
                Text("Outcome ${i + 1}", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 12.dp))
                OutlinedTextField(
                    value = o.label,
                    onValueChange = { o.label = it; version++ },
                    modifier = Modifier.fillMaxWidth().testTag(RichMessageTestTags.LOTTERY_OUTCOME_LABEL + i),
                    placeholder = { Text("Label (optional)") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = o.text,
                    onValueChange = { o.text = it; version++ },
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag(RichMessageTestTags.LOTTERY_OUTCOME_TEXT + i),
                    placeholder = { Text("Revealed text") },
                )
                Row(Modifier.fillMaxWidth().padding(top = 4.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = o.weight,
                        onValueChange = { o.weight = it.filter { c -> c.isDigit() || c == '.' }; version++ },
                        modifier = Modifier.weight(1f).testTag(RichMessageTestTags.LOTTERY_OUTCOME_WEIGHT + i),
                        label = { Text("Weight") },
                        singleLine = true,
                    )
                    val w = o.weight.toFloatOrNull()?.coerceAtLeast(0f) ?: 0f
                    val pct = (w / totalWeight * 100f)
                    Text(
                        text = String.format(java.util.Locale.getDefault(), "%.0f%%", pct),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(start = 12.dp).testTag(RichMessageTestTags.LOTTERY_OUTCOME_PCT + i),
                    )
                }
            }
            if (outcomes.size < 4) {
                OutlinedButton(
                    onClick = { outcomes.add(OutcomeDraft("", "")); version++ },
                    modifier = Modifier.padding(top = 8.dp).testTag(RichMessageTestTags.LOTTERY_ADD_OUTCOME),
                ) { Text("Add outcome") }
            }
            Button(
                onClick = {
                    onSend(
                        outcomes.filter { it.text.trim().isNotEmpty() }
                            .map {
                                val w = it.weight.toFloatOrNull()?.coerceAtLeast(0f) ?: 0f
                                // Convert the relative weight to basis points of the total.
                                val bps = (w / totalWeight * 10_000f).toInt().coerceAtLeast(1)
                                LotteryOutcomeDraft(it.label.trim().ifEmpty { null }, it.text.trim(), weightBps = bps)
                            },
                        imageUri,
                    )
                },
                enabled = valid,
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(RichMessageTestTags.LOTTERY_SEND),
            ) { Text("Send lottery") }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

/** Find-a-DateTime ("custom poll") composer: title, date range, hour range, slot-duration chip. */
@Composable
fun FindDateTimeComposerSheet(
    onSend: (FindDateTimeDraft) -> Unit,
    onDismiss: () -> Unit,
) {
    var title by rememberSaveable { mutableStateOf("") }
    var fromDate by rememberSaveable { mutableStateOf("") }
    var toDate by rememberSaveable { mutableStateOf("") }
    var startHour by rememberSaveable { mutableStateOf("9") }
    var endHour by rememberSaveable { mutableStateOf("17") }
    var slotDuration by rememberSaveable { mutableStateOf(30) }

    val dateRe = Regex("^\\d{4}-\\d{2}-\\d{2}$")
    val sh = startHour.toIntOrNull()
    val eh = endHour.toIntOrNull()
    val valid = title.trim().length in 1..200 &&
        dateRe.matches(fromDate) && dateRe.matches(toDate) &&
        sh != null && sh in 0..23 && eh != null && eh in 1..24 && eh > sh

    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(RichMessageTestTags.FADT_COMPOSER).semantics { testTagsAsResourceId = true }) {
        Column(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState()),
        ) {
            Text("Find a time", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag(RichMessageTestTags.FADT_TITLE),
                placeholder = { Text("Title (e.g. Team sync)") },
                singleLine = true,
            )
            Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = fromDate,
                    onValueChange = { fromDate = it },
                    modifier = Modifier.weight(1f).testTag(RichMessageTestTags.FADT_FROM_DATE),
                    label = { Text("From") },
                    placeholder = { Text("YYYY-MM-DD") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = toDate,
                    onValueChange = { toDate = it },
                    modifier = Modifier.weight(1f).testTag(RichMessageTestTags.FADT_TO_DATE),
                    label = { Text("To") },
                    placeholder = { Text("YYYY-MM-DD") },
                    singleLine = true,
                )
            }
            Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = startHour,
                    onValueChange = { startHour = it },
                    modifier = Modifier.weight(1f).testTag(RichMessageTestTags.FADT_START_HOUR),
                    label = { Text("Start hour (0-23)") },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = endHour,
                    onValueChange = { endHour = it },
                    modifier = Modifier.weight(1f).testTag(RichMessageTestTags.FADT_END_HOUR),
                    label = { Text("End hour (1-24)") },
                    singleLine = true,
                )
            }
            Text("Slot length", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(15, 30, 60).forEach { d ->
                    FilterChip(
                        selected = slotDuration == d,
                        onClick = { slotDuration = d },
                        label = { Text("$d min") },
                    )
                }
            }
            Button(
                onClick = {
                    onSend(
                        FindDateTimeDraft(
                            title = title.trim(),
                            fromDate = fromDate.trim(),
                            toDate = toDate.trim(),
                            startHour = sh ?: 9,
                            endHour = eh ?: 17,
                            slotDurationMinutes = slotDuration,
                        ),
                    )
                },
                enabled = valid,
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(RichMessageTestTags.FADT_SEND),
            ) { Text("Send poll") }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

/** Calendar-event share composer: pick a calendar, then an event to share. */
@Composable
fun CalendarEventComposerSheet(
    state: CalendarPickerState,
    onSelectCalendar: (String) -> Unit,
    onSendEvent: (calendarId: String, eventId: String) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(RichMessageTestTags.CAL_EVENT_COMPOSER).semantics { testTagsAsResourceId = true }) {
        Column(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState()),
        ) {
            Text("Share an event", style = MaterialTheme.typography.titleMedium)
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.calendars.isEmpty() -> Text(
                    state.error ?: "No calendars found.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                else -> {
                    Text("Calendar", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 8.dp))
                    state.calendars.forEach { cal ->
                        CalendarRow(cal, selected = cal.calendarId == state.selectedCalendarId, onClick = { onSelectCalendar(cal.calendarId) },
                            testTag = RichMessageTestTags.CAL_EVENT_CALENDAR_ROW + cal.calendarId)
                    }
                    if (state.selectedCalendarId != null) {
                        Text("Event", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 12.dp))
                        if (state.eventsLoading) {
                            CircularProgressIndicator(Modifier.padding(16.dp))
                        } else if (state.events.isEmpty()) {
                            Text("No events in this calendar.", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
                        } else {
                            state.events.forEach { ev ->
                                EventRow(ev, onClick = { onSendEvent(ev.calendarId, ev.eventId) },
                                    testTag = RichMessageTestTags.CAL_EVENT_EVENT_ROW + ev.eventId)
                            }
                        }
                    }
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

/** Calendar share composer: pick a calendar + permission + booking-link toggle, then share. */
@Composable
fun CalendarShareComposerSheet(
    state: CalendarPickerState,
    onSelectCalendar: (String) -> Unit,
    onSend: (calendarId: String, permission: String, includeBookingLink: Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    var permission by rememberSaveable { mutableStateOf("read") }
    var includeBooking by rememberSaveable { mutableStateOf(false) }
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(RichMessageTestTags.CAL_SHARE_COMPOSER).semantics { testTagsAsResourceId = true }) {
        Column(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState()),
        ) {
            Text("Share a calendar", style = MaterialTheme.typography.titleMedium)
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.calendars.isEmpty() -> Text(
                    state.error ?: "No calendars found.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                else -> {
                    state.calendars.forEach { cal ->
                        CalendarRow(cal, selected = cal.calendarId == state.selectedCalendarId, onClick = { onSelectCalendar(cal.calendarId) },
                            testTag = RichMessageTestTags.CAL_SHARE_CALENDAR_ROW + cal.calendarId)
                    }
                    Text("Permission", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("read", "write").forEach { p ->
                            FilterChip(selected = permission == p, onClick = { permission = p }, label = { Text(p) })
                        }
                    }
                    Row(Modifier.padding(top = 8.dp)) {
                        FilterChip(
                            selected = includeBooking,
                            onClick = { includeBooking = !includeBooking },
                            label = { Text("Include booking link") },
                        )
                    }
                    Button(
                        onClick = { state.selectedCalendarId?.let { onSend(it, permission, includeBooking) } },
                        enabled = state.selectedCalendarId != null,
                        modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(RichMessageTestTags.CAL_SHARE_SEND),
                    ) { Text("Share calendar") }
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

/** File-manager share composer: list the files; tap one to share its path. */
@Composable
fun FileShareComposerSheet(
    state: FilePickerState,
    onSendFile: (filePath: String) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(RichMessageTestTags.FILE_SHARE_COMPOSER).semantics { testTagsAsResourceId = true }) {
        Column(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState()),
        ) {
            Text("Share a file", style = MaterialTheme.typography.titleMedium)
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.files.none { !it.isFolder } -> Text(
                    state.error ?: "No files found.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                else -> state.files.filter { !it.isFolder }.forEach { f ->
                    OutlinedButton(
                        onClick = { onSendFile(f.path) },
                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp).testTag(RichMessageTestTags.FILE_SHARE_FILE_ROW + f.name),
                    ) {
                        Column(Modifier.fillMaxWidth()) {
                            Text(f.name, style = MaterialTheme.typography.bodyMedium)
                            Text(f.path, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

@Composable
private fun CalendarRow(cal: CalendarAccessUi, selected: Boolean, onClick: () -> Unit, testTag: String) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(cal.name.ifBlank { cal.calendarId }) },
        modifier = Modifier.padding(top = 4.dp).testTag(testTag),
    )
}

@Composable
private fun EventRow(ev: CalendarEventUi, onClick: () -> Unit, testTag: String) {
    OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag(testTag)) {
        Column(Modifier.fillMaxWidth()) {
            Text(ev.name.ifBlank { ev.eventId }, style = MaterialTheme.typography.bodyMedium)
            ev.startUtc?.let { Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
}

/** MSG-009 - simple read-only render card for a Find-a-DateTime poll message. */
@Composable
fun FindDateTimeCard(media: MessageMedia.FindDateTime, modifier: Modifier = Modifier) {
    androidx.compose.material3.Surface(
        tonalElevation = 1.dp,
        shape = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
        modifier = modifier.testTag(RichMessageTestTags.FADT_CARD),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("Find a time", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Text(media.title, style = MaterialTheme.typography.titleSmall)
            val range = listOfNotNull(media.fromDate, media.toDate).joinToString(" - ")
            if (range.isNotBlank()) {
                Text(range, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (media.startHour != null && media.endHour != null) {
                Text("${media.startHour}:00 - ${media.endHour}:00", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
