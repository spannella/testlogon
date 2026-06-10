@file:OptIn(
    androidx.compose.material3.ExperimentalMaterial3Api::class,
    androidx.compose.foundation.layout.ExperimentalLayoutApi::class,
)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.data.messaging.MeetingPollDraft
import com.testlogon.android.data.messaging.MeetingPollSlot
import com.testlogon.android.data.messaging.MeetingPollSlotDraft
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.SlotVote
import com.testlogon.android.data.messaging.cycle

/**
 * AND-136 — compact, locale-safe slot-range label from ISO-8601 UTC strings WITHOUT java.time
 * (minSdk24-safe). Shows "YYYY-MM-DD HH:MM - HH:MM" by slicing the ISO strings; falls back to the
 * raw values if the format is unexpected. Display-only; the wire value stays UTC ISO-8601.
 */
internal fun formatSlotRange(startUtc: String, endUtc: String): String {
    fun datePart(iso: String) = iso.substringBefore('T').takeIf { it.length == 10 } ?: iso
    fun timePart(iso: String) = iso.substringAfter('T', "").take(5).takeIf { it.length == 5 } ?: ""
    val d = datePart(startUtc)
    val st = timePart(startUtc)
    val et = timePart(endUtc)
    return when {
        st.isNotEmpty() && et.isNotEmpty() -> "$d $st - $et"
        st.isNotEmpty() -> "$d $st"
        else -> "$d"
    }
}

object RichMessageTestTags {
    const val GIF_BUBBLE = "thread_gif_bubble"
    const val STICKER_BUBBLE = "thread_sticker_bubble"
    const val VOICEMAIL_BUBBLE = "thread_voicemail_bubble"
    const val MEDIA_PICKER = "thread_media_picker"
    const val POLL_CARD = "thread_poll_card"
    const val POLL_COMPOSER = "thread_poll_composer"
    const val ATTACH_MEDIA = "thread_attach_media"
    const val ATTACH_POLL = "thread_attach_poll"
}

/** AND-135 — animated GIF bubble (Coil GIF decoder is registered on the app ImageLoader). */
@Composable
fun GifBubble(media: MessageMedia.Gif, modifier: Modifier = Modifier) {
    val cd = media.altText?.takeIf { it.isNotBlank() }
        ?.let { stringResource(R.string.thread_gif_cd, it) }
        ?: stringResource(R.string.thread_gif_cd_generic)
    val ratio = if ((media.width ?: 0) > 0 && (media.height ?: 0) > 0) {
        media.width!!.toFloat() / media.height!!.toFloat()
    } else {
        1f
    }
    AsyncImage(
        model = media.url,
        contentDescription = cd,
        contentScale = ContentScale.Fit,
        modifier = modifier
            .width(220.dp)
            .aspectRatio(ratio)
            .clip(RoundedCornerShape(12.dp))
            .testTag(RichMessageTestTags.GIF_BUBBLE),
    )
}

/** AND-135 — sticker bubble fixed at <=128dp (mirrors the web 128x128 treatment). */
@Composable
fun StickerBubble(media: MessageMedia.Sticker, modifier: Modifier = Modifier) {
    val cd = media.altText?.takeIf { it.isNotBlank() }
        ?.let { stringResource(R.string.thread_sticker_cd, it) }
        ?: stringResource(R.string.thread_sticker_cd_generic)
    AsyncImage(
        model = media.url,
        contentDescription = cd,
        contentScale = ContentScale.Fit,
        modifier = modifier
            .size(128.dp)
            .testTag(RichMessageTestTags.STICKER_BUBBLE),
    )
}

/**
 * AND-134 — voicemail bubble: a call-state label + a play affordance. Audio plays via the shared
 * voice player (reused from AND-133); video is launched by the caller's [onPlay].
 */
@Composable
fun VoicemailBubble(
    media: MessageMedia.Voicemail,
    isOwn: Boolean,
    onPlay: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val callLabel = when (media.callState) {
        "missed" -> stringResource(R.string.voicemail_state_missed)
        "declined" -> stringResource(R.string.voicemail_state_declined)
        "busy" -> stringResource(R.string.voicemail_state_busy)
        else -> stringResource(R.string.voicemail_label)
    }
    val seconds = media.durationSeconds.toInt()
    val cd = stringResource(R.string.voicemail_bubble_cd, callLabel, seconds)
    Surface(
        color = if (isOwn) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .widthIn(max = 280.dp)
            .testTag(RichMessageTestTags.VOICEMAIL_BUBBLE)
            .semantics { contentDescription = cd },
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onPlay, enabled = media.mediaUrl != null, modifier = Modifier.size(40.dp)) {
                Icon(Icons.Filled.PlayCircle, contentDescription = stringResource(R.string.voicemail_play))
            }
            Column(modifier = Modifier.padding(start = 4.dp)) {
                Text(callLabel, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Text(
                    stringResource(R.string.voicemail_duration, seconds),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** AND-135 — the unified GIF / sticker / emoji picker sheet. */
@Composable
fun MediaPickerSheet(
    state: MediaPickerState,
    onTab: (MediaTab) -> Unit,
    onGifQuery: (String) -> Unit,
    onGifSelect: (com.testlogon.android.data.messaging.GifResult) -> Unit,
    onSelectCollection: (String) -> Unit,
    onStickerSelect: (collectionId: String, stickerId: String, url: String, altText: String?) -> Unit,
    onEmojiSelect: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(RichMessageTestTags.MEDIA_PICKER)) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 12.dp).height(420.dp)) {
            TabRow(selectedTabIndex = state.tab.ordinal) {
                MediaTab.entries.forEach { tab ->
                    Tab(
                        selected = state.tab == tab,
                        onClick = { onTab(tab) },
                        text = {
                            Text(
                                when (tab) {
                                    MediaTab.GIF -> stringResource(R.string.media_tab_gif)
                                    MediaTab.STICKERS -> stringResource(R.string.media_tab_stickers)
                                    MediaTab.EMOJI -> stringResource(R.string.media_tab_emoji)
                                },
                            )
                        },
                    )
                }
            }
            when (state.tab) {
                MediaTab.GIF -> GifTab(state, onGifQuery, onGifSelect)
                MediaTab.STICKERS -> StickerTab(state, onSelectCollection, onStickerSelect)
                MediaTab.EMOJI -> EmojiTab(state, onEmojiSelect)
            }
        }
    }
}

@Composable
private fun GifTab(
    state: MediaPickerState,
    onGifQuery: (String) -> Unit,
    onGifSelect: (com.testlogon.android.data.messaging.GifResult) -> Unit,
) {
    OutlinedTextField(
        value = state.gifQuery,
        onValueChange = onGifQuery,
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        placeholder = { Text(stringResource(R.string.gif_search_hint)) },
        singleLine = true,
    )
    when {
        state.gifLoading -> CenterProgress()
        state.gifError != null -> Text(state.gifError, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(8.dp))
        state.gifResults.isEmpty() -> EmptyHint(stringResource(R.string.gif_empty))
        else -> LazyVerticalGrid(columns = GridCells.Fixed(2), modifier = Modifier.fillMaxWidth()) {
            items(state.gifResults, key = { it.id }) { gif ->
                AsyncImage(
                    model = gif.url,
                    contentDescription = gif.altText?.let { stringResource(R.string.thread_gif_cd, it) }
                        ?: stringResource(R.string.thread_gif_cd_generic),
                    contentScale = ContentScale.Crop,
                    modifier = Modifier
                        .padding(4.dp)
                        .aspectRatio(1f)
                        .clip(RoundedCornerShape(8.dp))
                        .clickable { onGifSelect(gif) },
                )
            }
        }
    }
}

@Composable
private fun StickerTab(
    state: MediaPickerState,
    onSelectCollection: (String) -> Unit,
    onStickerSelect: (String, String, String, String?) -> Unit,
) {
    when {
        state.collectionsLoading -> CenterProgress()
        state.collectionsError != null -> Text(state.collectionsError, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(8.dp))
        state.collections.isEmpty() -> EmptyHint(stringResource(R.string.stickers_empty))
        else -> {
            FlowRow(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                state.collections.forEach { c ->
                    FilterChip(
                        selected = state.selectedCollectionId == c.collectionId,
                        onClick = { onSelectCollection(c.collectionId) },
                        label = { Text(c.name, maxLines = 1) },
                    )
                }
            }
            val selected = state.collections.firstOrNull { it.collectionId == state.selectedCollectionId }
                ?: state.collections.first()
            LazyVerticalGrid(columns = GridCells.Adaptive(72.dp), modifier = Modifier.fillMaxWidth()) {
                items(selected.stickers, key = { it.stickerId }) { s ->
                    AsyncImage(
                        model = s.url,
                        contentDescription = s.altText?.let { stringResource(R.string.thread_sticker_cd, it) }
                            ?: stringResource(R.string.thread_sticker_cd_generic),
                        contentScale = ContentScale.Fit,
                        modifier = Modifier
                            .padding(6.dp)
                            .size(64.dp)
                            .clickable { onStickerSelect(selected.collectionId, s.stickerId, s.url, s.altText) },
                    )
                }
            }
        }
    }
}

@Composable
private fun EmojiTab(state: MediaPickerState, onEmojiSelect: (String) -> Unit) {
    if (state.emoji.isEmpty()) {
        EmptyHint(stringResource(R.string.emoji_empty))
        return
    }
    LazyVerticalGrid(columns = GridCells.Adaptive(48.dp), modifier = Modifier.fillMaxWidth()) {
        items(state.emoji, key = { it.shortcode }) { e ->
            AsyncImage(
                model = e.imageUrl,
                contentDescription = ":${e.shortcode}:",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .padding(6.dp)
                    .size(36.dp)
                    .clickable { onEmojiSelect(e.shortcode) },
            )
        }
    }
}

@Composable
private fun CenterProgress() {
    Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun EmptyHint(text: String) {
    Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
        Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/**
 * AND-136 — meeting-poll card: title + per-slot yes/maybe/no counts + the caller's response, with a
 * tap-to-cycle vote affordance (open polls only) and a creator-only Confirm per slot.
 */
@Composable
fun MeetingPollCard(
    state: MeetingPollCardUiState,
    onVote: (slotId: String, vote: SlotVote?) -> Unit,
    onConfirm: (slotId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val poll = state.poll
    val isOpen = poll.status == com.testlogon.android.data.messaging.MeetingPollStatus.OPEN
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier
            .widthIn(max = 320.dp)
            .testTag(RichMessageTestTags.POLL_CARD),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(poll.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                when (poll.status) {
                    com.testlogon.android.data.messaging.MeetingPollStatus.CONFIRMED -> stringResource(R.string.poll_status_confirmed)
                    com.testlogon.android.data.messaging.MeetingPollStatus.CANCELLED -> stringResource(R.string.poll_status_cancelled)
                    else -> stringResource(R.string.poll_status_open)
                },
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            poll.slots.forEach { slot ->
                PollSlotRow(
                    slot = slot,
                    isConfirmed = poll.confirmedSlotId == slot.slotId,
                    votingEnabled = isOpen && !state.isMutating,
                    canManage = state.canManage,
                    onVote = { onVote(slot.slotId, slot.myVote.cycle()) },
                    onConfirm = { onConfirm(slot.slotId) },
                )
            }
            state.inlineError?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable
private fun PollSlotRow(
    slot: MeetingPollSlot,
    isConfirmed: Boolean,
    votingEnabled: Boolean,
    canManage: Boolean,
    onVote: () -> Unit,
    onConfirm: () -> Unit,
) {
    val voteLabel = when (slot.myVote) {
        SlotVote.YES -> stringResource(R.string.poll_vote_yes)
        SlotVote.MAYBE -> stringResource(R.string.poll_vote_maybe)
        SlotVote.NO -> stringResource(R.string.poll_vote_no)
        null -> stringResource(R.string.poll_vote_none)
    }
    val rangeCd = stringResource(
        R.string.poll_slot_cd,
        formatSlotRange(slot.startUtc, slot.endUtc),
        slot.yesCount,
        slot.maybeCount,
        slot.noCount,
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .semantics { contentDescription = rangeCd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(formatSlotRange(slot.startUtc, slot.endUtc), style = MaterialTheme.typography.bodyMedium)
            Text(
                stringResource(R.string.poll_counts, slot.yesCount, slot.maybeCount, slot.noCount),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (isConfirmed) {
            Icon(Icons.Filled.Check, contentDescription = stringResource(R.string.poll_confirmed_slot))
        }
        OutlinedButton(onClick = onVote, enabled = votingEnabled) { Text(voteLabel) }
        if (canManage) {
            AssistChip(onClick = onConfirm, label = { Text(stringResource(R.string.poll_confirm)) })
        }
    }
}

/**
 * AND-136 — meeting-poll composer: title, duration chips, and 2-5 candidate slots. Slot date/time
 * editing UI is intentionally minimal here (preset slots); validation gates submit to 2-5 slots and
 * a non-blank title 1-200 chars.
 */
@Composable
fun MeetingPollComposerSheet(
    initialSlots: List<MeetingPollSlotDraft>,
    onSubmit: (MeetingPollDraft) -> Unit,
    onDismiss: () -> Unit,
) {
    var title by rememberSaveable { mutableStateOf("") }
    var durationMinutes by rememberSaveable { mutableStateOf(30) }
    val slots = remember { mutableStateListOf(*initialSlots.toTypedArray()) }

    val valid = title.trim().length in 1..200 && slots.size in 2..5

    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(RichMessageTestTags.POLL_COMPOSER)) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp)) {
            Text(stringResource(R.string.poll_composer_title), style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                placeholder = { Text(stringResource(R.string.poll_title_hint)) },
                singleLine = true,
                isError = title.length > 200,
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(15, 30, 60, 120).forEach { d ->
                    FilterChip(
                        selected = durationMinutes == d,
                        onClick = { durationMinutes = d },
                        label = { Text(stringResource(R.string.poll_duration_minutes, d)) },
                    )
                }
            }
            Text(
                stringResource(R.string.poll_slots_count, slots.size),
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.padding(top = 8.dp),
            )
            slots.forEach { slot ->
                Text(
                    formatSlotRange(slot.startUtc, slot.endUtc),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(vertical = 2.dp),
                )
            }
            OutlinedButton(
                onClick = { onSubmit(MeetingPollDraft(title.trim(), durationMinutes, slots.toList())) },
                enabled = valid,
                modifier = Modifier.padding(top = 12.dp),
            ) {
                Text(stringResource(R.string.poll_create))
            }
        }
    }
}
