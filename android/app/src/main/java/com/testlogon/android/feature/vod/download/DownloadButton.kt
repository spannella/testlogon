package com.testlogon.android.feature.vod.download

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Download
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.vod.download.DownloadError
import com.testlogon.android.data.vod.download.DownloadUiState

/** AND-195 — stable test tags for the download affordance. */
object DownloadButtonTestTags {
    const val BUTTON = "vod_download_button"
}

/**
 * AND-195 — the Download affordance for the VOD detail screen. Maps [DownloadUiState] to a
 * label + affordance (Download / determinate progress ring / Downloaded ✓ Delete / Retry). Stateless;
 * only shown by the host when the title's allow_download flag is true (AC-8). Exposes a stateful
 * contentDescription + a live region so TalkBack announces completion/failure (FR-9 / §9).
 */
@Composable
fun DownloadButton(
    state: DownloadUiState,
    onDownload: () -> Unit,
    onDelete: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cd = downloadContentDescription(state)
    Row(
        modifier = modifier
            .testTag(DownloadButtonTestTags.BUTTON)
            .semantics {
                contentDescription = cd
                liveRegion = LiveRegionMode.Polite
            },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        when (state) {
            DownloadUiState.Idle, DownloadUiState.Cancelled -> TextButton(onClick = onDownload) {
                Icon(Icons.Filled.Download, contentDescription = null)
                Text(stringResource(R.string.vod_download))
            }

            DownloadUiState.Queued -> {
                CircularProgressIndicator(modifier = Modifier.size(20.dp))
                Text(stringResource(R.string.vod_download_queued))
            }

            is DownloadUiState.Downloading -> {
                CircularProgressIndicator(
                    progress = { state.percent / 100f },
                    modifier = Modifier.size(20.dp),
                )
                Text(stringResource(R.string.vod_download_downloading, state.percent))
            }

            DownloadUiState.Watermarking -> {
                CircularProgressIndicator(modifier = Modifier.size(20.dp))
                Text(stringResource(R.string.vod_download_watermarking))
            }

            is DownloadUiState.Completed -> TextButton(onClick = onDelete) {
                Icon(Icons.Filled.CheckCircle, contentDescription = null)
                Text(stringResource(R.string.vod_download_completed))
            }

            is DownloadUiState.Failed -> TextButton(onClick = onRetry) {
                Text(
                    text = when (state.reason) {
                        DownloadError.NOT_ENTITLED -> stringResource(R.string.vod_download_failed_not_entitled)
                        DownloadError.WATERMARK_FAILED -> stringResource(R.string.vod_download_failed_watermark)
                        else -> stringResource(R.string.vod_download_retry)
                    },
                )
            }
        }
    }
}

@Composable
private fun downloadContentDescription(state: DownloadUiState): String = when (state) {
    DownloadUiState.Idle, DownloadUiState.Cancelled -> stringResource(R.string.vod_download)
    DownloadUiState.Queued -> stringResource(R.string.vod_download_queued)
    is DownloadUiState.Downloading -> stringResource(R.string.vod_download_downloading, state.percent)
    DownloadUiState.Watermarking -> stringResource(R.string.vod_download_watermarking)
    is DownloadUiState.Completed -> stringResource(R.string.vod_download_completed)
    is DownloadUiState.Failed -> stringResource(R.string.vod_download_failed)
}
