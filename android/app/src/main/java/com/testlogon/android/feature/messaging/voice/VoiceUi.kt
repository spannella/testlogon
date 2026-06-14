package com.testlogon.android.feature.messaging.voice

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.PauseCircle
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.feature.messaging.media.AttachmentFormat

object VoiceTestTags {
    const val BUBBLE = "thread_voice_bubble"
    const val PLAY_PAUSE = "thread_voice_play_pause"
    const val RECORD = "thread_record_voice"
    const val OVERLAY = "thread_voice_overlay"
    const val SEND = "thread_voice_send"
    const val CANCEL = "thread_voice_cancel"
    const val STOP = "thread_voice_stop"
}

/**
 * AND-133 — shared waveform renderer used by capture overlay + playback bubble. Bars are positioned
 * by bucket; the portion up to [progress] (0..1) is drawn in [activeColor], the rest in [inactiveColor].
 */
@Composable
fun WaveformView(
    peaks: List<Float>,
    progress: Float,
    activeColor: Color,
    inactiveColor: Color,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier) {
        if (peaks.isEmpty()) return@Canvas
        val barCount = peaks.size
        val gap = size.width / (barCount * 2f)
        val barWidth = gap
        val midY = size.height / 2f
        val progressX = size.width * progress.coerceIn(0f, 1f)
        peaks.forEachIndexed { i, peak ->
            val x = i * (barWidth + gap) + gap
            val barHeight = (peak.coerceIn(0f, 1f) * size.height).coerceAtLeast(2f)
            val color = if (x <= progressX) activeColor else inactiveColor
            drawLine(
                color = color,
                start = Offset(x, midY - barHeight / 2f),
                end = Offset(x, midY + barHeight / 2f),
                strokeWidth = barWidth,
            )
        }
    }
}

/**
 * AND-133 — playback bubble: play/pause + waveform (fills with progress) + tap/drag seek + duration.
 * The waveform bars are decorative; the accessible label conveys duration + state.
 */
@Composable
fun VoiceMessageBubble(
    voice: MessageMedia.Voice,
    isOwn: Boolean,
    playing: Boolean,
    positionMs: Long,
    onTogglePlay: () -> Unit,
    onSeek: (Float) -> Unit,
    modifier: Modifier = Modifier,
) {
    val bubbleColor = if (isOwn) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val durationMs = (voice.durationSeconds * 1000.0).toLong()
    val fraction = if (durationMs <= 0L) 0f else (positionMs.toFloat() / durationMs).coerceIn(0f, 1f)
    val peaks = rememberPeaks(voice.waveform)
    val shownMs = if (playing || positionMs > 0L) positionMs else durationMs
    val durationLabel = AttachmentFormat.duration(shownMs)
    val accessibleLabel = stringResource(R.string.voice_message_cd, durationLabel)
    val playLabel = if (playing) stringResource(R.string.voice_pause) else stringResource(R.string.voice_play)

    Surface(
        color = bubbleColor,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .widthIn(max = 260.dp)
            .testTag(VoiceTestTags.BUBBLE)
            .semantics { contentDescription = accessibleLabel },
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(
                onClick = onTogglePlay,
                modifier = Modifier
                    .size(48.dp)
                    .testTag(VoiceTestTags.PLAY_PAUSE)
                    .semantics { role = Role.Button; contentDescription = playLabel },
            ) {
                Icon(
                    imageVector = if (playing) Icons.Filled.PauseCircle else Icons.Filled.PlayCircle,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp),
                )
            }
            Box(
                modifier = Modifier
                    .width(140.dp)
                    .height(36.dp)
                    .pointerInput(durationMs) {
                        detectTapGestures { offset ->
                            val f = (offset.x / size.width.toFloat()).coerceIn(0f, 1f)
                            onSeek(f)
                        }
                    },
                contentAlignment = Alignment.Center,
            ) {
                WaveformView(
                    peaks = peaks,
                    progress = fraction,
                    activeColor = MaterialTheme.colorScheme.primary,
                    inactiveColor = MaterialTheme.colorScheme.outlineVariant,
                    modifier = Modifier.fillMaxWidth().height(28.dp),
                )
            }
            Spacer(Modifier.width(6.dp))
            Text(
                text = durationLabel,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** AND-133 — live recording overlay: mic + timer + live waveform + cancel/stop. */
@Composable
fun RecordingOverlay(
    elapsedMs: Long,
    peaks: List<Float>,
    countdownSeconds: Int?,
    onCancel: () -> Unit,
    onStop: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val recordingDesc = stringResource(R.string.voice_recording)
    val cancelDesc = stringResource(R.string.voice_cancel)
    val stopDesc = stringResource(R.string.voice_stop)
    Surface(tonalElevation = 3.dp, modifier = modifier.testTag(VoiceTestTags.OVERLAY)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp)
                .semantics { stateDescription = recordingDesc },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(
                onClick = onCancel,
                modifier = Modifier
                    .size(48.dp)
                    .testTag(VoiceTestTags.CANCEL)
                    .semantics { role = Role.Button; contentDescription = cancelDesc },
            ) {
                Icon(Icons.Filled.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error)
            }
            Icon(
                Icons.Filled.Mic,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(6.dp))
            Text(
                text = countdownSeconds?.let { "$it" } ?: AttachmentFormat.duration(elapsedMs),
                style = MaterialTheme.typography.labelMedium,
                color = if (countdownSeconds != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
            WaveformView(
                peaks = peaks.ifEmpty { List(1) { 0f } },
                progress = 1f,
                activeColor = MaterialTheme.colorScheme.primary,
                inactiveColor = MaterialTheme.colorScheme.outlineVariant,
                modifier = Modifier
                    .weight(1f)
                    .height(28.dp)
                    .padding(horizontal = 8.dp),
            )
            IconButton(
                onClick = onStop,
                modifier = Modifier
                    .size(48.dp)
                    .testTag(VoiceTestTags.STOP)
                    .semantics { role = Role.Button; contentDescription = stopDesc },
            ) {
                Icon(Icons.Filled.Stop, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            }
        }
    }
}

/** AND-133 — preview card: play preview / re-record / cancel / send. */
@Composable
fun VoicePreviewCard(
    durationMs: Long,
    peaks: List<Float>,
    onCancel: () -> Unit,
    onSend: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cancelDesc = stringResource(R.string.voice_cancel)
    val sendDesc = stringResource(R.string.voice_send)
    Surface(tonalElevation = 3.dp, modifier = modifier) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(
                onClick = onCancel,
                modifier = Modifier
                    .size(48.dp)
                    .testTag(VoiceTestTags.CANCEL)
                    .semantics { role = Role.Button; contentDescription = cancelDesc },
            ) {
                Icon(Icons.Filled.Close, contentDescription = null)
            }
            WaveformView(
                peaks = peaks.ifEmpty { List(1) { 0f } },
                progress = 1f,
                activeColor = MaterialTheme.colorScheme.primary,
                inactiveColor = MaterialTheme.colorScheme.outlineVariant,
                modifier = Modifier.weight(1f).height(28.dp).padding(horizontal = 8.dp),
            )
            Text(
                text = AttachmentFormat.duration(durationMs),
                style = MaterialTheme.typography.labelMedium,
            )
            IconButton(
                onClick = onSend,
                modifier = Modifier
                    .size(48.dp)
                    .testTag(VoiceTestTags.SEND)
                    .semantics { role = Role.Button; contentDescription = sendDesc },
            ) {
                Icon(Icons.Filled.Send, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            }
        }
    }
}

@Composable
private fun rememberPeaks(waveform: List<Float>): List<Float> =
    androidx.compose.runtime.remember(waveform) {
        if (waveform.isEmpty()) List(Waveform.DEFAULT_BUCKETS) { 0.15f } else Waveform.resample(waveform)
    }
