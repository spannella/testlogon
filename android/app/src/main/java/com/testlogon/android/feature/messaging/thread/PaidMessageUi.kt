@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import android.content.Context
import android.content.Intent
import android.provider.CalendarContract
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import coil.compose.AsyncImage
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Timer
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
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
import com.testlogon.android.data.messaging.MessageCountdown
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.MessageMonetization
import com.testlogon.android.data.messaging.RevealedMediaItem
import com.testlogon.android.feature.messaging.media.VideoClipBubble
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
    const val COUNTDOWN_TITLE = "thread_countdown_title"
    const val COUNTDOWN_SEND = "thread_countdown_send"
    const val COUNTDOWN_REVEAL_TEXT = "thread_countdown_reveal_text"
    const val COUNTDOWN_REVEAL_ADD_IMAGE = "thread_countdown_reveal_add_image"
    const val COUNTDOWN_REVEAL_IMAGE_PREVIEW = "thread_countdown_reveal_image_preview"
    const val COUNTDOWN_REVEAL_REMOVE_IMAGE = "thread_countdown_reveal_remove_image"
    const val COUNTDOWN_REVEAL_BLOCK = "thread_countdown_reveal_block"
    // #6 (B-COUNTDOWN3) — countdown surfaced as an overlay strip on ANY message.
    const val COUNTDOWN_OVERLAY = "thread_countdown_overlay"
    const val COMPOSER_COUNTDOWN_OPTION = "thread_composer_countdown_option"
    const val CALENDAR_EVENT_BUBBLE = "thread_calendar_event_bubble"
    const val CALENDAR_SHARE_BUBBLE = "thread_calendar_share_bubble"
    const val LOCKED_BUBBLE = "thread_locked_bubble"
    const val UNLOCK_BUTTON = "thread_unlock_button"
    const val TIP_SHEET = "thread_tip_sheet"
    const val ADD_TO_CALENDAR = "thread_add_to_calendar"
    // #15 — sender-facing lottery detail (the sender sees what they sent + who won what).
    const val LOTTERY_SENDER_DETAIL_TOGGLE = "thread_lottery_sender_detail_toggle"
    const val LOTTERY_SENDER_DETAIL = "thread_lottery_sender_detail"
    const val LOTTERY_SENDER_OUTCOME = "thread_lottery_sender_outcome_"
    const val LOTTERY_SENDER_UNLOCK = "thread_lottery_sender_unlock_"
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
            // #31 — once the countdown completes the server surfaces the reveal payload; show it.
            val reveal = media.reveal
            if (done && reveal != null && !reveal.isEmpty) {
                val ctx = androidx.compose.ui.platform.LocalContext.current
                Column(
                    Modifier
                        .padding(top = 8.dp)
                        .testTag(PaidMessageTestTags.COUNTDOWN_REVEAL_BLOCK),
                ) {
                    Text(
                        stringResource(R.string.countdown_reveal_revealed),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    reveal.text?.takeIf { it.isNotBlank() }?.let {
                        Text(it, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 2.dp))
                    }
                    reveal.media.forEach { m ->
                        if (m.isVideo) {
                            OutlinedButton(
                                onClick = {
                                    runCatching {
                                        ctx.startActivity(
                                            Intent(Intent.ACTION_VIEW, android.net.Uri.parse(m.url))
                                                .setDataAndType(android.net.Uri.parse(m.url), "video/*")
                                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                        )
                                    }
                                },
                                modifier = Modifier.padding(top = 6.dp),
                            ) { Text(stringResource(R.string.countdown_reveal_play_video)) }
                        } else {
                            coil.compose.AsyncImage(
                                model = m.url,
                                contentDescription = stringResource(R.string.countdown_reveal_revealed),
                                contentScale = androidx.compose.ui.layout.ContentScale.Crop,
                                modifier = Modifier
                                    .padding(top = 6.dp)
                                    .size(160.dp)
                                    .clip(RoundedCornerShape(12.dp)),
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * #6 (B-COUNTDOWN3) — countdown OVERLAY strip rendered on ANY message that carries a countdown
 * attribute (text/image/video/file), in addition to the message's own bubble. A lifecycle-scoped 1s
 * ticker derives the remaining time from the device clock (never stored), so it self-corrects after
 * backgrounding and FLIPS to the reveal at/after the target WITHOUT a manual refresh. Once done, the
 * server-surfaced [MessageCountdown.reveal] (text and/or image/video) is shown inline.
 */
@Composable
fun CountdownOverlay(
    countdown: MessageCountdown,
    isOwn: Boolean,
    modifier: Modifier = Modifier,
    nowProvider: () -> Long = { System.currentTimeMillis() / 1000L },
) {
    // One conflated 1s ticker; lifecycle-scoped collection pauses it below STARTED (no battery drain).
    val now by remember(countdown.targetEpochSeconds) {
        flow {
            while (true) {
                emit(nowProvider())
                delay(1_000L)
            }
        }
    }.collectAsStateWithLifecycle(initialValue = nowProvider())

    val remaining = CountdownLogic.remainingSeconds(countdown.targetEpochSeconds, now)
    val done = CountdownLogic.isDone(countdown.targetEpochSeconds, now)
    val remainingText = CountdownLogic.format(remaining)
    val title = countdown.title?.takeIf { it.isNotBlank() }

    val cd = if (done) {
        stringResource(R.string.countdown_cd_done, title ?: "")
    } else {
        stringResource(R.string.countdown_cd_remaining, title ?: "", CountdownLogic.accessibilityRemaining(remaining))
    }

    Surface(
        color = if (isOwn) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
        modifier = modifier
            .widthIn(max = 280.dp)
            .padding(top = 2.dp)
            .testTag(PaidMessageTestTags.COUNTDOWN_OVERLAY)
            .semantics { contentDescription = cd },
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 9.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Timer,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.primary,
                )
                Text(
                    text = title ?: stringResource(R.string.composer_add_countdown),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(start = 6.dp),
                )
            }
            // Compact, timestamp-style remaining-time line (small + muted) rather than a large timer.
            Text(
                text = if (done) {
                    stringResource(R.string.countdown_done)
                } else {
                    stringResource(R.string.countdown_remaining_inline, remainingText)
                },
                style = if (done) MaterialTheme.typography.bodyMedium else MaterialTheme.typography.labelSmall,
                color = if (done) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 2.dp),
            )
            // Once the countdown completes the server surfaces the reveal payload; show it inline.
            val reveal = countdown.reveal
            if (done && reveal != null && !reveal.isEmpty) {
                val ctx = androidx.compose.ui.platform.LocalContext.current
                Column(
                    Modifier
                        .padding(top = 8.dp)
                        .testTag(PaidMessageTestTags.COUNTDOWN_REVEAL_BLOCK),
                ) {
                    Text(
                        stringResource(R.string.countdown_reveal_revealed),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    reveal.text?.takeIf { it.isNotBlank() }?.let {
                        Text(it, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 2.dp))
                    }
                    reveal.media.forEach { m ->
                        if (m.isVideo) {
                            OutlinedButton(
                                onClick = {
                                    runCatching {
                                        ctx.startActivity(
                                            Intent(Intent.ACTION_VIEW, android.net.Uri.parse(m.url))
                                                .setDataAndType(android.net.Uri.parse(m.url), "video/*")
                                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                        )
                                    }
                                },
                                modifier = Modifier.padding(top = 6.dp),
                            ) { Text(stringResource(R.string.countdown_reveal_play_video)) }
                        } else {
                            coil.compose.AsyncImage(
                                model = m.url,
                                contentDescription = stringResource(R.string.countdown_reveal_revealed),
                                contentScale = androidx.compose.ui.layout.ContentScale.Crop,
                                modifier = Modifier
                                    .padding(top = 6.dp)
                                    .size(160.dp)
                                    .clip(RoundedCornerShape(12.dp)),
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * AND-137 / #31 / #32 — countdown composer. Title + an EXACT date/time/timezone target (#32) + an
 * OPTIONAL reveal payload (text and/or image, #31) that the recipient sees once the countdown hits
 * zero. The reveal image is picked from the system photo picker (no storage permission) and uploaded
 * on send by the ViewModel.
 */
@Composable
fun CountdownPickerSheet(
    state: CountdownPickerState,
    nowSeconds: Long,
    onTitleChange: (String) -> Unit,
    onTargetChange: (Long?) -> Unit,
    onTimeZoneChange: (String) -> Unit,
    onRevealTextChange: (String) -> Unit,
    onPickRevealImage: (String) -> Unit,
    onRemoveRevealImage: () -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
    onDismiss: () -> Unit,
) {
    val pickImage = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia(),
    ) { uri -> if (uri != null) onPickRevealImage(uri.toString()) }

    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(PaidMessageTestTags.COUNTDOWN_PICKER).semantics { testTagsAsResourceId = true }) {
        Column(
            Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(16.dp)
                .verticalScroll(androidx.compose.foundation.rememberScrollState()),
        ) {
            Text(stringResource(R.string.countdown_picker_title), style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = state.title,
                onValueChange = onTitleChange,
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag(PaidMessageTestTags.COUNTDOWN_TITLE),
                placeholder = { Text(stringResource(R.string.countdown_title_hint)) },
                singleLine = true,
                isError = state.title.length > 200,
            )
            // #32 — exact date/time + timezone (replaces the old 1h/1d/1w presets).
            Text(stringResource(R.string.countdown_pick_when), style = MaterialTheme.typography.labelMedium)
            com.testlogon.android.feature.common.TimeZonePicker(
                selectedZoneId = state.timeZoneId,
                onZoneChange = onTimeZoneChange,
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                testTag = "countdown_tz",
            )
            com.testlogon.android.feature.common.DateTimePickerField(
                selectedEpochSeconds = state.targetEpochSeconds,
                onPicked = { onTargetChange(it) },
                modifier = Modifier.padding(top = 8.dp),
                placeholder = stringResource(R.string.countdown_pick_datetime),
                testTag = "countdown_datetime",
                zoneId = state.timeZoneId,
            )
            // #31 — optional reveal text.
            Text(
                stringResource(R.string.countdown_reveal_label),
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.padding(top = 16.dp),
            )
            OutlinedTextField(
                value = state.revealText,
                onValueChange = onRevealTextChange,
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag(PaidMessageTestTags.COUNTDOWN_REVEAL_TEXT),
                placeholder = { Text(stringResource(R.string.countdown_reveal_hint)) },
            )
            // #31 — optional reveal image.
            val img = state.revealImageUri
            if (img == null) {
                OutlinedButton(
                    onClick = {
                        pickImage.launch(
                            androidx.activity.result.PickVisualMediaRequest(
                                androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia.ImageOnly,
                            ),
                        )
                    },
                    modifier = Modifier.padding(top = 8.dp).testTag(PaidMessageTestTags.COUNTDOWN_REVEAL_ADD_IMAGE),
                ) { Text(stringResource(R.string.countdown_reveal_add_image)) }
            } else {
                Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    coil.compose.AsyncImage(
                        model = img,
                        contentDescription = stringResource(R.string.countdown_reveal_add_image),
                        contentScale = androidx.compose.ui.layout.ContentScale.Crop,
                        modifier = Modifier
                            .size(64.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .testTag(PaidMessageTestTags.COUNTDOWN_REVEAL_IMAGE_PREVIEW),
                    )
                    OutlinedButton(
                        onClick = onRemoveRevealImage,
                        modifier = Modifier.padding(start = 12.dp).testTag(PaidMessageTestTags.COUNTDOWN_REVEAL_REMOVE_IMAGE),
                    ) { Text(stringResource(R.string.countdown_reveal_remove_image)) }
                }
            }
            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 8.dp))
            }
            Button(
                onClick = onSend,
                enabled = state.isSendEnabled,
                modifier = Modifier.padding(top = 12.dp).testTag(PaidMessageTestTags.COUNTDOWN_SEND),
            ) {
                Text(stringResource(R.string.countdown_send))
            }
            // #6 (B-COUNTDOWN3) — attach this countdown to the NEXT message (text / photo / video /
            // file) instead of sending a standalone countdown. Title optional; needs a future time.
            OutlinedButton(
                onClick = onAttach,
                enabled = !state.sending && state.targetEpochSeconds != null,
                modifier = Modifier.padding(top = 8.dp).testTag(PaidMessageTestTags.COMPOSER_COUNTDOWN_OPTION),
            ) {
                Text(stringResource(R.string.countdown_attach_to_message))
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
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
    /** G1 — true when the locked message is ALSO encrypted; renders an extra "Encrypted" indicator. */
    isEncrypted: Boolean = false,
) {
    if (monetization.unlocked) {
        // #24 — a lottery outcome can reveal a LIST of images/videos (not just one), plus optional
        // revealed text. Render each media item (image inline, video as a tap-to-play poster); fall
        // back to the single revealedMediaUrl, then to the revealed text.
        val revealedMediaList = monetization.revealedMedia.takeIf { it.isNotEmpty() }
            ?: monetization.revealedMediaUrl?.takeIf { it.isNotBlank() }
                ?.let { listOf(RevealedMediaItem(url = it, isVideo = monetization.revealedMediaIsVideo)) }
                .orEmpty()
        if (revealedMediaList.isNotEmpty()) {
            Column(
                modifier = modifier.widthIn(max = 280.dp).testTag(RichMessageTestTags.LOTTERY_REVEAL_MEDIA),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                val revealedCaption = monetization.revealedText?.takeIf { it.isNotBlank() }
                if (revealedCaption != null) {
                    Text(revealedCaption, style = MaterialTheme.typography.bodyMedium)
                }
                revealedMediaList.forEachIndexed { idx, item ->
                    if (item.isVideo) {
                        VideoClipBubble(
                            media = MessageMedia.VideoClip(playbackUrl = item.url),
                            modifier = Modifier.fillMaxWidth()
                                .testTag(RichMessageTestTags.LOTTERY_REVEAL_MEDIA + "_" + idx),
                        )
                    } else {
                        AsyncImage(
                            model = item.url,
                            contentDescription = stringResource(R.string.paid_unlocked),
                            contentScale = ContentScale.Fit,
                            modifier = Modifier.fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .testTag(RichMessageTestTags.LOTTERY_REVEAL_MEDIA + "_" + idx),
                        )
                    }
                }
            }
        } else {
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
            // G1 — when the locked message is ALSO encrypted, show a second "Encrypted" indicator so
            // the receiver knows BOTH gates apply (unlock to pay, then a passphrase to decrypt).
            if (isEncrypted) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .padding(top = 4.dp)
                        .testTag(RichMessageTestTags.ENCRYPTED_INDICATOR),
                ) {
                    Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(14.dp))
                    Text(
                        stringResource(R.string.paid_encrypted_indicator),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 4.dp),
                    )
                }
            }
            // Teaser caption ONLY — never the gated body/media.
            monetization.teaser?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp))
            }
            unlock.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp))
            }
            if (isOwn) {
                // M8 — the SENDER can't unlock their own gated message; show a clear "$X.XX to unlock"
                // status badge (parity with the view-once / "Disappears" sender badges) instead of a
                // dead disabled Unlock button.
                val senderBadge = if (monetization.type == UnlockType.LOTTERY) {
                    stringResource(R.string.paid_sender_locked_lottery)
                } else {
                    stringResource(R.string.paid_sender_locked_badge, priceLabel)
                }
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.padding(top = 8.dp).testTag("thread_locked_sender_badge"),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    ) {
                        Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(14.dp))
                        Text(
                            senderBadge,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.padding(start = 4.dp),
                        )
                    }
                }
                // #15 (B-LOTSENDER) — the sender is no longer blind to their own lottery: show the
                // full config (every outcome + its win-chance) and, once recipients unlock, what each
                // of them drew. Collapsed by default behind a toggle to keep the bubble compact.
                monetization.lotterySenderView?.let { sv ->
                    LotterySenderDetail(view = sv, modifier = Modifier.padding(top = 8.dp))
                }
            } else {
                Button(
                    onClick = onUnlock,
                    enabled = !busy,
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
}

/**
 * #15 (B-LOTSENDER) — sender-facing lottery detail. The sender sees the FULL config (each outcome's
 * win-chance + content/media) plus, once recipients unlock, what RESULT each of them drew. Collapsed
 * behind a toggle so the bubble stays compact until tapped. Pure render of [LotterySenderView].
 */
@Composable
fun LotterySenderDetail(
    view: com.testlogon.android.data.messaging.LotterySenderView,
    modifier: Modifier = Modifier,
) {
    var expanded by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    val total = view.totalWeightBps.takeIf { it > 0 } ?: 10_000
    val toggleLabel = if (expanded) {
        stringResource(R.string.lottery_sender_hide_details)
    } else {
        stringResource(R.string.lottery_sender_show_details, view.outcomes.size, view.unlockCount)
    }
    Column(modifier = modifier.testTag(PaidMessageTestTags.LOTTERY_SENDER_DETAIL)) {
        OutlinedButton(
            onClick = { expanded = !expanded },
            modifier = Modifier.testTag(PaidMessageTestTags.LOTTERY_SENDER_DETAIL_TOGGLE),
        ) { Text(toggleLabel) }
        if (!expanded) return@Column
        Surface(
            color = MaterialTheme.colorScheme.surface,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.padding(top = 6.dp).widthIn(max = 280.dp),
        ) {
            Column(Modifier.padding(10.dp)) {
                Text(
                    stringResource(R.string.lottery_sender_options_header),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
                view.outcomes.forEachIndexed { idx, o ->
                    val pct = (o.weightBps.toDouble() / total.toDouble()) * 100.0
                    val pctText = String.format(Locale.ROOT, "%.1f%%", pct)
                    val label = o.displayLabel?.takeIf { it.isNotBlank() }
                        ?: stringResource(R.string.lottery_sender_option_n, idx + 1)
                    Column(Modifier.padding(top = 6.dp).testTag(PaidMessageTestTags.LOTTERY_SENDER_OUTCOME + idx)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(label, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                            Text(pctText, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        o.textContent?.takeIf { it.isNotBlank() }?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (o.media.isNotEmpty()) {
                            Text(
                                stringResource(R.string.lottery_sender_option_media, o.media.size),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Row(
                                modifier = Modifier.padding(top = 2.dp),
                                horizontalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                o.media.take(4).forEach { m ->
                                    if (!m.isVideo) {
                                        AsyncImage(
                                            model = m.url,
                                            contentDescription = null,
                                            contentScale = ContentScale.Crop,
                                            modifier = Modifier.size(40.dp).clip(RoundedCornerShape(8.dp)),
                                        )
                                    } else {
                                        // FAIL-2: a video option asset shows a play-badged tile (was a
                                        // blank box) so the sender can see the option carries a video.
                                        Surface(
                                            color = MaterialTheme.colorScheme.surfaceVariant,
                                            shape = RoundedCornerShape(8.dp),
                                            modifier = Modifier.size(40.dp),
                                        ) {
                                            Box(
                                                Modifier.fillMaxWidth(),
                                                contentAlignment = Alignment.Center,
                                            ) {
                                                Icon(
                                                    Icons.Filled.PlayArrow,
                                                    contentDescription = null,
                                                    modifier = Modifier.size(22.dp),
                                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Results: who unlocked + what they drew (only present once recipients unlock).
                Text(
                    stringResource(R.string.lottery_sender_results_header, view.unlockCount),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 10.dp),
                )
                if (view.unlocks.isEmpty()) {
                    Text(
                        stringResource(R.string.lottery_sender_results_empty),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                } else {
                    view.unlocks.forEachIndexed { idx, u ->
                        val drew = u.selectedOutcome?.displayLabel?.takeIf { it.isNotBlank() }
                            ?: u.selectedOutcome?.textContent?.takeIf { it.isNotBlank() }
                            ?: stringResource(R.string.lottery_sender_result_unknown)
                        Text(
                            stringResource(R.string.lottery_sender_result_line, u.recipientId, drew),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(top = 4.dp).testTag(PaidMessageTestTags.LOTTERY_SENDER_UNLOCK + idx),
                        )
                    }
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
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(PaidMessageTestTags.TIP_SHEET).semantics { testTagsAsResourceId = true }) {
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
