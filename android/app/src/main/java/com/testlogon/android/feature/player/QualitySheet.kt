package com.testlogon.android.feature.player

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** AND-169 — stable testTags for the quality bottom sheet UI. */
object QualitySheetTestTags {
    const val SHEET = "quality_sheet"
    const val CAP_TOGGLE = "quality_cap_toggle"
    const val CAPTION = "quality_caption"
    fun option(quality: VideoQuality) = "quality_option_${quality.name}"
}

/** AND-169 §4.6 — the immutable state driving [QualitySheet]. */
data class QualitySheetState(
    val selected: VideoQuality = VideoQuality.DEFAULT,
    val capOnMetered: Boolean = true,
    val effective: EffectiveQuality = EffectiveQuality(),
)

/** AND-169 — the ordered option list shown in the sheet (FR-1). */
private val QUALITY_OPTIONS: List<VideoQuality> = listOf(
    VideoQuality.AUTO,
    VideoQuality.P1080,
    VideoQuality.P720,
    VideoQuality.P480,
    VideoQuality.P360,
    VideoQuality.DATA_SAVER,
)

@Composable
private fun qualityLabel(quality: VideoQuality): String = when (quality) {
    VideoQuality.AUTO -> stringResource(R.string.quality_auto)
    VideoQuality.P1080 -> stringResource(R.string.quality_1080p)
    VideoQuality.P720 -> stringResource(R.string.quality_720p)
    VideoQuality.P480 -> stringResource(R.string.quality_480p)
    VideoQuality.P360 -> stringResource(R.string.quality_360p)
    VideoQuality.DATA_SAVER -> stringResource(R.string.quality_data_saver)
}

/**
 * AND-169 §4.6 — Material 3 modal bottom sheet for quality selection. A [RadioButton] row per option
 * with the active one checked, a [Switch] for "Cap quality on mobile data", and a supporting caption
 * rendering the effective resolved ceiling. The overflow affordance that opens this lives in the host
 * player screen (`Icons.Outlined.HighQuality`, contentDescription = R.string.cd_video_quality).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QualitySheet(
    state: QualitySheetState,
    onSelect: (VideoQuality) -> Unit,
    onToggleCap: (Boolean) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = modifier.testTag(QualitySheetTestTags.SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.quality_sheet_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )

            QUALITY_OPTIONS.forEach { option ->
                val label = qualityLabel(option)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .selectable(
                            selected = option == state.selected,
                            role = Role.RadioButton,
                            onClick = { onSelect(option) },
                        )
                        .testTag(QualitySheetTestTags.option(option)),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = option == state.selected, onClick = null)
                    Text(
                        text = label,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(start = 12.dp),
                    )
                }
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .toggleable(
                        value = state.capOnMetered,
                        role = Role.Switch,
                        onValueChange = onToggleCap,
                    )
                    .testTag(QualitySheetTestTags.CAP_TOGGLE),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.quality_cap_metered_title),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(1f),
                )
                Switch(checked = state.capOnMetered, onCheckedChange = null)
            }

            val caption = effectiveCaption(state.effective)
            Text(
                text = caption,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .padding(top = 8.dp, bottom = 16.dp)
                    .testTag(QualitySheetTestTags.CAPTION),
            )
        }
    }
}

/** AND-169 FR-6 — the supporting caption describing the effective ceiling/reason. */
@Composable
private fun effectiveCaption(effective: EffectiveQuality): String =
    when {
        effective.capped && effective.maxHeightPx != null ->
            stringResource(R.string.quality_capped_caption, effective.maxHeightPx)
        effective.forceLowest -> stringResource(R.string.quality_data_saver)
        effective.maxHeightPx == null -> stringResource(R.string.quality_unbounded_caption)
        else -> "${effective.maxHeightPx}p"
    }
