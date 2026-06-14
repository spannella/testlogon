@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.idscanner

import android.Manifest
import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.idscanner.model.IdDocumentType
import com.testlogon.android.feature.kyc.idscanner.model.IdSide
import com.testlogon.android.feature.kyc.idscanner.model.ScanResult
import com.testlogon.android.feature.kyc.idscanner.model.ScanStatus
import java.io.File

/** AND-322 - stable testTags for the ID-scanner screen. */
object IdScannerTestTags {
    const val SCREEN = "idscan_screen"
    const val TAKE_PHOTO = "idscan_take_photo"
    const val PICK = "idscan_pick"
    const val CONFIRM = "idscan_confirm"
    const val UNAVAILABLE = "idscan_unavailable"
    const val RESTART = "idscan_restart"

    fun typeTag(type: IdDocumentType): String = "idscan_type_${type.wireType}"
    fun retakeTag(side: IdSide): String = "idscan_retake_${side.fileType}"
    fun resultTag(side: IdSide): String = "idscan_result_${side.fileType}"
}

/**
 * AND-322 - the ID-scanner route. Owns the dependency-free system-intent image acquisition (REUSED from
 * AND-321): a runtime CAMERA permission request, ActivityResultContracts.TakePicture() writing to a
 * FileProvider Uri, and GetContent() for "choose from library". NO CameraX live preview — the embedded
 * auto-capture preview + MRZ OCR are DEFERRED behind the FLAGGED StubIdFrameAnalyzer (STOP-AND-FLAG).
 */
@Composable
fun IdScannerRoute(
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: IdScannerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val captureFile = remember(state.currentSide) {
        File(context.cacheDir, "kyc-capture").apply { mkdirs() }
            .let { File(it, "idscan-${state.currentSide.fileType}-${System.currentTimeMillis()}.jpg") }
    }
    val captureUri = remember(captureFile) {
        androidx.core.content.FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            captureFile,
        )
    }

    val takePicture = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { ok ->
        if (ok) viewModel.onImageAcquired(state.currentSide, captureFile)
    }
    val pickFromLibrary = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) viewModel.onImageAcquired(state.currentSide, copyUriToCache(context, uri))
    }
    val requestCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) takePicture.launch(captureUri)
    }

    IdScannerScreen(
        state = state,
        onSelectType = viewModel::selectType,
        onTakePhoto = {
            val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
            if (granted) takePicture.launch(captureUri) else requestCamera.launch(Manifest.permission.CAMERA)
        },
        onPickFromLibrary = { pickFromLibrary.launch("image/*") },
        onRetake = viewModel::retake,
        onConfirm = viewModel::confirmAndUpload,
        onRestart = viewModel::retryAfterReject,
        onDone = onDone,
        modifier = modifier,
    )
}

@Composable
fun IdScannerScreen(
    state: IdScannerUiState,
    onSelectType: (IdDocumentType) -> Unit,
    onTakePhoto: () -> Unit,
    onPickFromLibrary: () -> Unit,
    onRetake: (IdSide) -> Unit,
    onConfirm: () -> Unit,
    onRestart: () -> Unit,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag(IdScannerTestTags.SCREEN)) { padding ->
        Box(Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            // A blocking, non-retryable error (e.g. no KYC case) replaces the whole surface.
            val blockingError = state.error?.takeIf { !it.retryable }
            when {
                blockingError != null -> CenteredMessage(blockingError.message)
                else -> when (state.step) {
                    IdScannerStep.TYPE_SELECT -> TypeSelectContent(
                        error = state.error,
                        onSelectType = onSelectType,
                    )
                    IdScannerStep.CAPTURE -> CaptureContent(
                        state = state,
                        onTakePhoto = onTakePhoto,
                        onPickFromLibrary = onPickFromLibrary,
                    )
                    IdScannerStep.REVIEW -> ReviewContent(
                        state = state,
                        onRetake = onRetake,
                        onConfirm = onConfirm,
                    )
                    IdScannerStep.UPLOADING -> ProgressContent(R.string.idscan_uploading)
                    IdScannerStep.SCANNING -> ProgressContent(R.string.idscan_scanning)
                    IdScannerStep.RESULT -> ResultContent(
                        state = state,
                        onRestart = onRestart,
                        onDone = onDone,
                    )
                }
            }
        }
    }
}

@Composable
private fun TypeSelectContent(
    error: UiError?,
    onSelectType: (IdDocumentType) -> Unit,
) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Text(
                text = stringResource(R.string.idscan_type_prompt),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (error != null) {
            item {
                Text(
                    text = error.message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        items(IdDocumentType.entries) { type ->
            Button(
                onClick = { onSelectType(type) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(IdScannerTestTags.typeTag(type)),
            ) {
                Text(stringResource(type.label))
            }
        }
    }
}

@Composable
private fun CaptureContent(
    state: IdScannerUiState,
    onTakePhoto: () -> Unit,
    onPickFromLibrary: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.idscan_capture_prompt, stringResource(state.currentSide.label)),
            style = MaterialTheme.typography.titleMedium,
        )
        // The framed placeholder where a live preview would appear; NO CameraX preview is embedded.
        Box(
            modifier = Modifier.fillMaxWidth().aspectRatio(1.6f),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.idscan_overlay_hint),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
        }
        if (state.mediaUnavailable) {
            Text(
                text = stringResource(R.string.idscan_auto_capture_unavailable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(IdScannerTestTags.UNAVAILABLE),
            )
        }
        if (state.error?.retryable == true) {
            Text(
                text = state.error.message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onTakePhoto,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(IdScannerTestTags.TAKE_PHOTO),
            ) {
                Text(stringResource(R.string.idscan_take_photo))
            }
            OutlinedButton(
                onClick = onPickFromLibrary,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(IdScannerTestTags.PICK),
            ) {
                Text(stringResource(R.string.idscan_pick))
            }
        }
    }
}

@Composable
private fun ReviewContent(
    state: IdScannerUiState,
    onRetake: (IdSide) -> Unit,
    onConfirm: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.idscan_review_prompt),
            style = MaterialTheme.typography.titleMedium,
        )
        state.requiredSides.forEach { side ->
            val captured = state.captured[side]
            if (captured != null) {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = stringResource(side.label),
                            style = MaterialTheme.typography.bodyLarge,
                        )
                        AsyncImage(
                            model = captured.file,
                            contentDescription = stringResource(R.string.idscan_review_image_cd, stringResource(side.label)),
                            contentScale = ContentScale.Fit,
                            modifier = Modifier.fillMaxWidth().aspectRatio(1.6f),
                        )
                        OutlinedButton(
                            onClick = { onRetake(side) },
                            modifier = Modifier.heightIn(min = 48.dp).testTag(IdScannerTestTags.retakeTag(side)),
                        ) {
                            Text(stringResource(R.string.idscan_retake))
                        }
                    }
                }
            }
        }
        if (state.error?.retryable == true) {
            Text(
                text = state.error.message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Button(
            onClick = onConfirm,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(IdScannerTestTags.CONFIRM),
        ) {
            Text(stringResource(R.string.idscan_confirm))
        }
    }
}

@Composable
private fun ProgressContent(messageRes: Int) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Text(text = stringResource(messageRes), style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun ResultContent(
    state: IdScannerUiState,
    onRestart: () -> Unit,
    onDone: () -> Unit,
) {
    val anyFailure = state.results.any {
        it.status == ScanStatus.REJECTED || it.status == ScanStatus.DECLINED
    }
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.idscan_result_prompt),
            style = MaterialTheme.typography.titleMedium,
        )
        state.results.forEach { result -> ResultRow(result) }
        if (anyFailure) {
            Button(
                onClick = onRestart,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(IdScannerTestTags.RESTART),
            ) {
                Text(stringResource(R.string.idscan_restart))
            }
        } else {
            Button(
                onClick = onDone,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) {
                Text(stringResource(R.string.idscan_done))
            }
        }
    }
}

@Composable
private fun ResultRow(result: ScanResult) {
    Card(Modifier.fillMaxWidth().testTag(IdScannerTestTags.resultTag(result.side))) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(result.side.label),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = stringResource(statusLabel(result.status)),
                style = MaterialTheme.typography.bodyMedium,
                color = statusColor(result.status),
            )
            result.reason?.takeIf { it.isNotBlank() }?.let { reason ->
                Text(text = reason, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun CenteredMessage(message: String) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
    }
}

@Composable
private fun statusColor(status: ScanStatus) = when (status) {
    ScanStatus.MATCHED, ScanStatus.APPROVED -> MaterialTheme.colorScheme.primary
    ScanStatus.REJECTED, ScanStatus.DECLINED -> MaterialTheme.colorScheme.error
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}

private fun statusLabel(status: ScanStatus): Int = when (status) {
    ScanStatus.MATCHED -> R.string.idscan_status_matched
    ScanStatus.APPROVED -> R.string.idscan_status_approved
    ScanStatus.FLAGGED -> R.string.idscan_status_flagged
    ScanStatus.REJECTED -> R.string.idscan_status_rejected
    ScanStatus.DECLINED -> R.string.idscan_status_declined
    ScanStatus.UNKNOWN -> R.string.idscan_status_unknown
}

/** Copies a picked content:// [uri] into the app cache so the VM/processor get a stable [File] (AND-321). */
private fun copyUriToCache(context: Context, uri: Uri): File {
    val dir = File(context.cacheDir, "kyc-capture").apply { mkdirs() }
    val out = File(dir, "idscan-pick-${System.currentTimeMillis()}.jpg")
    context.contentResolver.openInputStream(uri)?.use { input ->
        out.outputStream().use { input.copyTo(it) }
    }
    return out
}
