@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.thread

import android.content.Context
import android.content.Intent
import android.provider.CalendarContract
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.messaging.CountdownLogic
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.MessageMonetization
import com.testlogon.android.data.messaging.SharePermission
import com.testlogon.android.data.messaging.UnlockType
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.flow
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/** AND-137/138/139 — test tags for the paid/countdown/calendar bubbles + sheets. */
object PaidMessageTestTags {
    const val COUNTDOWN_BUBBLE = "thread_countdown_bubble"
    const val COUNTDOWN_PICKER = "thread_countdown_picker"
    const val CALENDAR_EVENT_BUBBLE = "thread_calendar_event_bubble"
    const val CALENDAR_SHARE_BUBBLE = "thread_calendar_share_bubble"
    const val LOCKED_BUBBLE = "thread_locked_bubble"
    const val UNLOCK_BUTTON = "thread_unlock_button"
    const val TIP_SHEET = "thread_tip_sheet"
    const val ADD_TO_CALENDAR = "thread_add_to_calendar"
}

// ─── AND-137: countdown ───

/**
 * AND-137 — countdown bubble with a lifecycle-aware live ticker. Remaining time is DERIVED from the
 * device clock once per second (never stored), so it self-corrects after backgrounding/rotation and
 * flips to a completed state at/after the target without a reload. The 1s ticker only runs while the
 * screen is >= STARTED (collectAsStateWithLifecycle) — no leaked coroutines, no battery drain.
 */
@Composable
fun CountdownBubble(
    media: MessageMedia.Countdown,
    isOwn: Boolean,
    modifier: Modifier = Modifier,
    nowProvider: () -> Long = { System.currentTimeMillis() / 1000L },
) {
    // One conflated 1s ticker; lifecycle-scoped collection stops it below STARTED.
    val now by remember(media.targetEpochSeconds) {
        flow {
            while (true) {
                emit(nowProvider())
                delay(1_000L)
            }
        }
    }.collectAsStateWithLifecycle(initialValue = nowProvider())

    val remaining = CountdownLogic.remainingSeconds(media.targetEpochSeconds, now)
    val done = CountdownLogic.isDone(media.targetEpochSeconds, now)
    val remainingText = CountdownLogic.format(remaining)
    val targetLabel = formatEventInstant(media.targetEpochSeconds)

    val cd = if (done) {
        stringResource(R.string.countdown_cd_done, media.title)
    } else {
        stringResource(R.string.countdown_cd_remaining, media.title, CountdownLogic.accessibilityRemaining(remaining))
    }

    Surface(
        color = if (isOwn) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .widthIn(max = 280.dp)
            .testTag(PaidMessageTestTags.COUNTDOWN_BUBBLE)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 9.dp)) {
            Text(media.title, style = MaterialTheme.typography.bodyLarge)
            // Compact, timestamp-style remaining-time line (small + muted) rather than a large timer.
            Text(
                text = if (done) {
                    stringResource(R.string.countdown_done)
                } else {
                    stringResource(R.string.countdown_remaining_inline, remainingText)
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * AND-137 — minimal countdown picker. Title field + a future-target chooser. To keep this minimal
 * (and avoid a full M3 date/time picker dependency dance), the target is offered as a few quick
 * presets (relative to now); the exact instant is computed as nowSeconds + offset. A full
 * DatePicker/TimePicker is a follow-up; the validation + send path is identical.
 */
@Composable
fun CountdownPickerSheet(
    state: CountdownPickerState,
    nowSeconds: Long,
    onTitleChange: (String) -> Unit,
    onTargetChange: (Long?) -> Unit,
    onSend: () -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(PaidMessageTestTags.COUNTDOWN_PICKER)) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp)) {
            Text(stringResource(R.string.countdown_picker_title), style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = state.title,
                onValueChange = onTitleChange,
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                placeholder = { Text(stringResource(R.string.countdown_title_hint)) },
                singleLine = true,
                isError = state.title.length > 200,
            )
            Text(stringResource(R.string.countdown_pick_when), style = MaterialTheme.typography.labelMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                CountdownPreset(state, nowSeconds, hours = 1, label = stringResource(R.string.countdown_preset_1h), onTargetChange)
                CountdownPreset(state, nowSeconds, hours = 24, label = stringResource(R.string.countdown_preset_1d), onTargetChange)
                CountdownPreset(state, nowSeconds, hours = 24 * 7, label = stringResource(R.string.countdown_preset_1w), onTargetChange)
            }
            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
            Button(
                onClick = onSend,
                enabled = state.isSendEnabled,
                modifier = Modifier.padding(top = 12.dp),
            ) {
                Text(stringResource(R.string.countdown_send))
            }
        }
    }
}

@Composable
private fun CountdownPreset(
    state: CountdownPickerState,
    nowSeconds: Long,
    hours: Int,
    label: String,
    onTargetChange: (Long?) -> Unit,
) {
    val target = nowSeconds + hours * 3600L
    FilterChip(
        selected = state.targetEpochSeconds == target,
        onClick = { onTargetChange(target) },
        label = { Text(label) },
    )
}

// ─── AND-138: calendar event / share ───

/** AND-138 — calendar-event bubble: name + formatted time + description, tappable to detail. */
@Composable
fun CalendarEventBubble(
    media: MessageMedia.CalendarEvent,
    isOwn: Boolean,
    onAddToCalendar: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val timeLabel = formatCalendarEventTime(media)
    val cd = stringResource(R.string.calendar_event_cd, media.name, timeLabel)
    Surface(
        color = if (isOwn) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .widthIn(max = 300.dp)
            .testTag(PaidMessageTestTags.CALENDAR_EVENT_BUBBLE)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(stringResource(R.string.calendar_event_label), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(media.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(timeLabel, style = MaterialTheme.typography.bodyMedium)
            media.description?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            OutlinedButton(
                onClick = onAddToCalendar,
                modifier = Modifier.padding(top = 8.dp).testTag(PaidMessageTestTags.ADD_TO_CALENDAR),
            ) {
                Text(stringResource(R.string.calendar_add_to_calendar))
            }
        }
    }
}

/** AND-138 — calendar-share bubble: name + permission badge + disabled "accept (coming soon)". */
@Composable
fun CalendarShareBubble(
    media: MessageMedia.CalendarShare,
    isOwn: Boolean,
    modifier: Modifier = Modifier,
) {
    val permissionLabel = when (media.permission) {
        SharePermission.WRITE -> stringResource(R.string.calendar_share_permission_write)
        SharePermission.READ -> stringResource(R.string.calendar_share_permission_read)
        SharePermission.UNKNOWN -> stringResource(R.string.calendar_share_permission_unknown)
    }
    val cd = stringResource(R.string.calendar_share_cd, media.name, permissionLabel)
    Surface(
        color = if (isOwn) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .widthIn(max = 300.dp)
            .testTag(PaidMessageTestTags.CALENDAR_SHARE_BUBBLE)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(stringResource(R.string.calendar_share_label), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(media.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(permissionLabel, style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = {}, enabled = false, modifier = Modifier.padding(top = 8.dp)) {
                Text(stringResource(R.string.calendar_share_accept_soon))
            }
        }
    }
}

// ─── AND-139: paid / locked / tip ───

/**
 * AND-139 — paid message bubble. While locked it renders ONLY the price + teaser caption + an Unlock
 * affordance; the gated body/media is never present in the tree or semantics. When unlocked it shows
 * the revealed text.
 */
@Composable
fun PaidMessageBubble(
    monetization: MessageMonetization,
    isOwn: Boolean,
    unlock: UnlockUiState,
    onUnlock: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (monetization.unlocked) {
        Surface(
            color = if (isOwn) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.medium,
            modifier = modifier.widthIn(max = 280.dp),
        ) {
            Text(
                text = monetization.revealedText?.takeIf { it.isNotBlank() }
                    ?: stringResource(R.string.paid_unlocked),
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )
        }
        return
    }

    val priceLabel = monetization.priceMinorUnits
        ?.let { formatMoney(it, monetization.currency) }
        ?: stringResource(R.string.paid_lottery_price)
    val phaseLabel = when (unlock.phase) {
        UnlockPhase.AUTHORIZING -> stringResource(R.string.paid_authorizing)
        UnlockPhase.UNLOCKING -> stringResource(R.string.paid_unlocking)
        else -> null
    }
    val busy = unlock.phase == UnlockPhase.AUTHORIZING || unlock.phase == UnlockPhase.UNLOCKING
    val unlockCd = if (monetization.type == UnlockType.LOTTERY) {
        stringResource(R.string.paid_unlock_lottery_cd)
    } else {
        stringResource(R.string.paid_unlock_cd, priceLabel)
    }

    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .widthIn(max = 280.dp)
            .testTag(PaidMessageTestTags.LOCKED_BUBBLE),
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(
                    text = if (monetization.type == UnlockType.LOTTERY) {
                        stringResource(R.string.paid_lottery_label)
                    } else {
                        priceLabel
                    },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(start = 6.dp),
                )
            }
            // Teaser caption ONLY — never the gated body/media.
            monetization.teaser?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp))
            }
            unlock.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp))
            }
            Button(
                onClick = onUnlock,
                enabled = !busy && !isOwn,
                modifier = Modifier
                    .padding(top = 8.dp)
                    .testTag(PaidMessageTestTags.UNLOCK_BUTTON)
                    .semantics {
                        contentDescription = unlockCd
                        phaseLabel?.let { stateDescription = it }
                    },
            ) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp))
                } else {
                    Text(stringResource(R.string.paid_unlock))
                }
            }
        }
    }
}

/** AND-139 — tip sheet: preset chips + custom amount + optional note. Amounts are integer cents. */
@Composable
fun TipSheet(
    state: TipSheetState,
    onPreset: (Long) -> Unit,
    onCustomChange: (String) -> Unit,
    onNoteChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(PaidMessageTestTags.TIP_SHEET)) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp)) {
            Text(stringResource(R.string.tip_title), style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                state.presetsCents.forEach { cents ->
                    FilterChip(
                        selected = state.selectedCents == cents,
                        onClick = { onPreset(cents) },
                        label = { Text(formatMoney(cents, "USD")) },
                    )
                }
            }
            OutlinedTextField(
                value = state.customInput,
                onValueChange = onCustomChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.tip_custom_amount)) },
                singleLine = true,
                isError = state.amountError != null,
            )
            OutlinedTextField(
                value = state.note,
                onValueChange = onNoteChange,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                label = { Text(stringResource(R.string.tip_note)) },
                supportingText = { Text("${state.note.length} / ${TipSheetState.MAX_NOTE_LENGTH}") },
                isError = state.note.length > TipSheetState.MAX_NOTE_LENGTH,
            )
            state.amountError?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
            Button(
                onClick = onConfirm,
                enabled = state.isConfirmEnabled,
                modifier = Modifier.padding(top = 12.dp),
            ) {
                if (state.submitting) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp))
                } else {
                    Text(stringResource(R.string.tip_send))
                }
            }
        }
    }
}

// ─── pure helpers (display + intent) ───

/** AND-139 — locale-aware money from integer minor units + ISO-4217 code (no hardcoded "$"). */
internal fun formatMoney(minorUnits: Long, currencyCode: String): String {
    return try {
        val currency = Currency.getInstance(currencyCode)
        val fmt = NumberFormat.getCurrencyInstance(Locale.getDefault())
        fmt.currency = currency
        val fraction = currency.defaultFractionDigits.coerceAtLeast(0)
        val divisor = Math.pow(10.0, fraction.toDouble())
        fmt.format(minorUnits / divisor)
    } catch (_: IllegalArgumentException) {
        "$currencyCode ${minorUnits}"
    }
}

/**
 * AND-137 — compact locale-safe label for an epoch-seconds instant in the DEVICE zone, WITHOUT
 * java.time (minSdk24-safe; java.text.DateFormat). Display-only.
 */
internal fun formatEventInstant(epochSeconds: Long): String {
    val df = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT, Locale.getDefault())
    return df.format(java.util.Date(epochSeconds * 1000L))
}

/**
 * AND-138 — calendar-event time label. All-day events render without a clock; timed events render
 * a localized date+time range from the RFC-3339 start/end (parsed minSdk24-safe). Falls back to raw.
 */
internal fun formatCalendarEventTime(media: MessageMedia.CalendarEvent): String {
    if (media.allDay) {
        return media.allDayDate ?: media.startUtc?.substringBefore('T') ?: ""
    }
    val start = parseRfc3339Millis(media.startUtc)
    val end = parseRfc3339Millis(media.endUtc)
    val df = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT, Locale.getDefault())
    return when {
        start != null && end != null -> "${df.format(java.util.Date(start))} – ${formatTimeOnly(end)}"
        start != null -> df.format(java.util.Date(start))
        else -> media.startUtc ?: ""
    }
}

private fun formatTimeOnly(millis: Long): String =
    java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT, Locale.getDefault()).format(java.util.Date(millis))

/** Parses an RFC-3339 UTC string to epoch millis without java.time. Returns null on any failure. */
internal fun parseRfc3339Millis(iso: String?): Long? {
    if (iso.isNullOrBlank()) return null
    val patterns = listOf("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ssXXX", "yyyy-MM-dd'T'HH:mm:ss")
    for (p in patterns) {
        try {
            val fmt = java.text.SimpleDateFormat(p, Locale.ROOT).apply {
                timeZone = java.util.TimeZone.getTimeZone("UTC")
            }
            return fmt.parse(iso)?.time
        } catch (_: java.text.ParseException) {
            // try next pattern
        }
    }
    return null
}

/**
 * AND-138 — build the system "add to calendar" intent (ACTION_INSERT). Needs NO calendar permission:
 * it opens the calendar app's own UI. All-day events derive the begin time from all_day_date at local
 * midnight; timed events use start/end (end falls back to start). Uses [media.name] (no location).
 */
fun buildInsertEventIntent(media: MessageMedia.CalendarEvent): Intent =
    Intent(Intent.ACTION_INSERT).apply {
        data = CalendarContract.Events.CONTENT_URI
        putExtra(CalendarContract.Events.TITLE, media.name)
        media.description?.takeIf { it.isNotBlank() }?.let {
            putExtra(CalendarContract.Events.DESCRIPTION, it)
        }
        putExtra(CalendarContract.EXTRA_EVENT_ALL_DAY, media.allDay)
        val begin: Long? = when {
            media.allDay && media.allDayDate != null -> localMidnightMillis(media.allDayDate)
            else -> parseRfc3339Millis(media.startUtc)
        }
        begin?.let { putExtra(CalendarContract.EXTRA_EVENT_BEGIN_TIME, it) }
        val end: Long? = parseRfc3339Millis(media.endUtc) ?: parseRfc3339Millis(media.startUtc)
        end?.let { putExtra(CalendarContract.EXTRA_EVENT_END_TIME, it) }
    }

/** Local-midnight epoch millis for an all-day "yyyy-MM-dd" date. Null on parse failure. */
internal fun localMidnightMillis(date: String): Long? = try {
    val fmt = java.text.SimpleDateFormat("yyyy-MM-dd", Locale.ROOT)
    fmt.timeZone = java.util.TimeZone.getDefault()
    fmt.parse(date)?.time
} catch (_: java.text.ParseException) {
    null
}

/** AND-138 — launch the add-to-calendar intent, guarding the no-resolver case (returns false). */
fun launchAddToCalendar(context: Context, media: MessageMedia.CalendarEvent): Boolean {
    val intent = buildInsertEventIntent(media)
    return if (intent.resolveActivity(context.packageManager) != null) {
        context.startActivity(intent)
        true
    } else {
        false
    }
}
