package com.testlogon.android.feature.messaging.media

import android.content.ActivityNotFoundException
import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Article
import androidx.compose.material.icons.filled.Audiotrack
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.testlogon.android.R
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.feature.messaging.thread.FileDownloadUi
import java.io.File

object FileBubbleTestTags {
    const val BUBBLE = "thread_file_bubble"
    const val ACTION = "thread_file_action"
}

/**
 * AND-132 — file message bubble: MIME-derived icon, file name, human-readable size, and a
 * download/open control reflecting the four download states (not-downloaded / downloading /
 * downloaded / failed). The control invokes [onDownload]; opening a downloaded file is launched by
 * the caller (FileProvider + ACTION_VIEW) via [onDownload] when already downloaded.
 */
@Composable
fun FileMessageBubble(
    file: MessageMedia.File,
    download: FileDownloadUi,
    isOwn: Boolean,
    onDownload: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val bubbleColor = if (isOwn) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val category = AttachmentFormat.iconCategory(file.mimeType, file.fileName)
    val sizeText = AttachmentFormat.fileSize(file.sizeBytes)

    Surface(
        color = bubbleColor,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier
            .widthIn(max = 280.dp)
            .testTag(FileBubbleTestTags.BUBBLE),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = iconFor(category),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(36.dp),
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.widthIn(max = 170.dp)) {
                Text(
                    text = file.fileName,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val subtitle = when {
                    file.isShare && sizeText.isNotEmpty() ->
                        stringResource(R.string.file_share_label) + " · " + sizeText
                    file.isShare -> stringResource(R.string.file_share_label)
                    else -> sizeText
                }
                if (subtitle.isNotEmpty()) {
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Spacer(Modifier.width(8.dp))
            // Optimistic upload (sending) renders an indeterminate spinner; received files get the
            // download/open control.
            if (file.uploadProgress != null && file.localUri != null) {
                CircularProgressIndicator(
                    progress = { file.uploadProgress },
                    modifier = Modifier.size(28.dp),
                )
            } else {
                DownloadControl(file = file, download = download, onDownload = onDownload)
            }
        }
    }
}

@Composable
private fun DownloadControl(
    file: MessageMedia.File,
    download: FileDownloadUi,
    onDownload: () -> Unit,
) {
    when (download) {
        is FileDownloadUi.Downloading -> CircularProgressIndicator(
            progress = { download.fraction },
            modifier = Modifier
                .size(28.dp)
                .semantics {
                    progressBarRangeInfo = ProgressBarRangeInfo(download.fraction, 0f..1f)
                },
        )
        is FileDownloadUi.Downloaded -> {
            val cd = stringResource(R.string.file_open_cd, file.fileName)
            Icon(
                imageVector = Icons.Filled.OpenInNew,
                contentDescription = cd,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .size(40.dp)
                    .padding(6.dp)
                    .testTag(FileBubbleTestTags.ACTION)
                    .clickable(onClick = onDownload)
                    .semantics { role = Role.Button; contentDescription = cd },
            )
        }
        is FileDownloadUi.Failed -> {
            val cd = stringResource(R.string.file_download_failed)
            Icon(
                imageVector = Icons.Filled.ErrorOutline,
                contentDescription = cd,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier
                    .size(40.dp)
                    .padding(6.dp)
                    .testTag(FileBubbleTestTags.ACTION)
                    .clickable(onClick = onDownload)
                    .semantics { role = Role.Button; contentDescription = cd },
            )
        }
        FileDownloadUi.NotDownloaded -> {
            val cd = stringResource(R.string.file_download_cd, file.fileName)
            Icon(
                imageVector = Icons.Filled.Download,
                contentDescription = cd,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .size(40.dp)
                    .padding(6.dp)
                    .testTag(FileBubbleTestTags.ACTION)
                    .clickable(onClick = onDownload)
                    .semantics { role = Role.Button; contentDescription = cd },
            )
        }
    }
}

private fun iconFor(category: FileIconCategory) = when (category) {
    FileIconCategory.PDF -> Icons.Filled.PictureAsPdf
    FileIconCategory.AUDIO -> Icons.Filled.Audiotrack
    FileIconCategory.VIDEO -> Icons.Filled.Movie
    FileIconCategory.TEXT -> Icons.Filled.Article
    FileIconCategory.ARCHIVE -> Icons.Filled.Folder
    FileIconCategory.IMAGE -> Icons.Filled.InsertDriveFile
    FileIconCategory.GENERIC -> Icons.Filled.InsertDriveFile
}

/**
 * AND-132 — open a downloaded file with an external viewer via FileProvider + ACTION_VIEW (transient
 * read grant; no file:// leaves the app). Returns false (caller shows a "no viewer" message) if no
 * app can handle the type.
 */
fun openDownloadedFile(
    context: android.content.Context,
    localPath: String,
    mimeType: String?,
): Boolean {
    val file = File(localPath)
    if (!file.exists()) return false
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val intent = Intent(Intent.ACTION_VIEW)
        .setDataAndType(uri, mimeType ?: "*/*")
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    return try {
        context.startActivity(intent)
        true
    } catch (e: ActivityNotFoundException) {
        false
    }
}
