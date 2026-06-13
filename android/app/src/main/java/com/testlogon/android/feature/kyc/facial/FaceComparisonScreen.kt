@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.facial

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
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
import androidx.compose.runtime.LaunchedEffect
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
import androidx.core.content.FileProvider
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.facial.model.FaceComparison
import com.testlogon.android.feature.kyc.facial.model.FaceResult
import java.io.File

/** AND-323 - stable testTags for the facial-comparison screen. */
object FaceComparisonTestTags {
    const val SCREEN = "face_screen"
    const val TAKE = "face_take"
    const val PICK = "face_pick"
    const val RETAKE = "face_retake"
    const val SUBMIT = "face_submit"
    const val RESULT = "face_result"
    const val RETRY = "face_retry"
    const val DONE = "face_done"
    const val UNAVAILABLE = "face_unavailable"
    const val HISTORY = "face_history"
}

/**
 * AND-323 - the facial-comparison route. Owns the dependency-free system-intent selfie acquisition
 * (REUSED from AND-321): a runtime CAMERA permission request, ActivityResultContracts.TakePicture()
 * writing to a FileProvider Uri, and GetContent() for "choose photo". NO CameraX live preview — the
 * embedded front-camera oval-guide preview + on-device liveness auto-capture are DEFERRED (STOP-AND-FLAG).
 * The selfie taken via the system intent is NOT guaranteed front-facing; that is acceptable this wave.
 */
@Composable
fun FaceComparisonRoute(
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: FaceComparisonViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LaunchedEffect(Unit) { viewModel.loadHistory() }

    val captureFile = remember(state.phase, state.capturedFile) {
        File(context.cacheDir, "kyc-capture").apply { mkdirs() }
            .let { File(it, "face-selfie-${System.currentTimeMillis()}.jpg") }
    }
    val captureUri = remember(captureFile) {
        FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", captureFile)
    }

    val takePicture = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { ok ->
        if (ok) viewModel.onSelfieAcquired(captureFile)
    }
    val pickPhoto = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) viewModel.onSelfieAcquired(copyUriToCache(context, uri))
    }
    val requestCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) takePicture.launch(captureUri)
    }

    FaceComparisonScreen(
        state = state,
        onTakeSelfie = {
            val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
            if (granted) takePicture.launch(captureUri) else requestCamera.launch(Manifest.permission.CAMERA)
        },
        onPickPhoto = { pickPhoto.launch("image/*") },
        onRetake = viewModel::onRetake,
        onSubmit = viewModel::submit,
        onRetryAfterFail = viewModel::retryAfterFail,
        onDone = onDone,
        modifier = modifier,
    )
}

@Composable
fun FaceComparisonScreen(
    state: FaceComparisonUiState,
    onTakeSelfie: () -> Unit,
    onPickPhoto: () -> Unit,
    onRetake: () -> Unit,
    onSubmit: () -> Unit,
    onRetryAfterFail: () -> Unit,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag(FaceComparisonTestTags.SCREEN)) { padding ->
        Box(Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            val blockingError = state.error?.takeIf { !it.retryable }
            when {
                blockingError != null -> CenteredMessage(blockingError.message)
                else -> when (state.phase) {
                    FacePhase.CAPTURE -> CaptureContent(
                        state = state,
                        onTakeSelfie = onTakeSelfie,
                        onPickPhoto = onPickPhoto,
                    )
                    FacePhase.REVIEW -> ReviewContent(
                        state = state,
                        onRetake = onRetake,
                        onSubmit = onSubmit,
                    )
                    FacePhase.SUBMITTING -> ProgressContent(R.string.face_submitting)
                    FacePhase.RESULT -> ResultContent(
                        state = state,
                        onRetryAfterFail = onRetryAfterFail,
                        onDone = onDone,
                    )
                }
            }
        }
    }
}

@Composable
private fun CaptureContent(
    state: FaceComparisonUiState,
    onTakeSelfie: () -> Unit,
    onPickPhoto: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            text = stringResource(R.string.face_capture_prompt),
            style = MaterialTheme.typography.titleMedium,
        )
        // The oval guide placeholder where a live front-camera preview would appear; NO CameraX preview.
        Box(
            modifier = Modifier.fillMaxWidth().aspectRatio(1f),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.face_oval_hint),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
        }
        if (state.autoCaptureUnavailable) {
            Text(
                text = stringResource(R.string.face_auto_capture_unavailable),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(FaceComparisonTestTags.UNAVAILABLE),
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
                onClick = onTakeSelfie,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(FaceComparisonTestTags.TAKE),
            ) {
                Text(stringResource(R.string.face_take))
            }
            OutlinedButton(
                onClick = onPickPhoto,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(FaceComparisonTestTags.PICK),
            ) {
                Text(stringResource(R.string.face_pick))
            }
        }
        HistorySection(state.history)
    }
}

@Composable
private fun ReviewContent(
    state: FaceComparisonUiState,
    onRetake: () -> Unit,
    onSubmit: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(
            text = stringResource(R.string.face_review_prompt),
            style = MaterialTheme.typography.titleMedium,
        )
        state.capturedFile?.let { file ->
            AsyncImage(
                model = file,
                contentDescription = stringResource(R.string.face_review_image_cd),
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxWidth().aspectRatio(1f),
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
            OutlinedButton(
                onClick = onRetake,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(FaceComparisonTestTags.RETAKE),
            ) {
                Text(stringResource(R.string.face_retake))
            }
            Button(
                onClick = onSubmit,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(FaceComparisonTestTags.SUBMIT),
            ) {
                Text(stringResource(R.string.face_submit))
            }
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
    state: FaceComparisonUiState,
    onRetryAfterFail: () -> Unit,
    onDone: () -> Unit,
) {
    val result = state.result
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        if (result == null) {
            CenteredMessage(stringResource(R.string.face_result_prompt))
            return@Column
        }
        Card(Modifier.fillMaxWidth().testTag(FaceComparisonTestTags.RESULT)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(resultLabel(result.result)),
                    style = MaterialTheme.typography.titleLarge,
                    color = resultColor(result.result),
                )
                Text(
                    text = stringResource(R.string.face_confidence, result.confidenceScore),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = stringResource(
                        R.string.face_anti_spoof,
                        result.antiSpoofPassedChecks,
                        result.antiSpoofTotalChecks,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = stringResource(
                        R.string.face_attempts,
                        result.attemptNumber,
                        result.maxAttempts,
                        result.remainingAttempts,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        when {
            result.result == FaceResult.PASS -> Button(
                onClick = onDone,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(FaceComparisonTestTags.DONE),
            ) {
                Text(stringResource(R.string.face_done))
            }
            state.canRetry -> Button(
                onClick = onRetryAfterFail,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(FaceComparisonTestTags.RETRY),
            ) {
                Text(stringResource(R.string.face_retry))
            }
            result.result == FaceResult.FAIL -> Text(
                // FAIL with no attempts left: route to support (no retry affordance).
                text = stringResource(R.string.face_contact_support),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
            else -> Button(
                // REVIEW / UNKNOWN: neutral — the case continues out-of-band, so allow Done.
                onClick = onDone,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(FaceComparisonTestTags.DONE),
            ) {
                Text(stringResource(R.string.face_done))
            }
        }
        HistorySection(state.history)
    }
}

@Composable
private fun HistorySection(history: List<FaceComparison>) {
    if (history.isEmpty()) return
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.face_history_title),
            style = MaterialTheme.typography.titleSmall,
        )
        LazyColumn(
            modifier = Modifier.fillMaxWidth().heightIn(max = 200.dp).testTag(FaceComparisonTestTags.HISTORY),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items(history) { item ->
                Text(
                    text = stringResource(
                        R.string.face_history_row,
                        item.attemptNumber,
                        stringResource(resultLabel(item.result)),
                        item.confidenceScore,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
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
private fun resultColor(result: FaceResult) = when (result) {
    FaceResult.PASS -> MaterialTheme.colorScheme.primary
    FaceResult.FAIL -> MaterialTheme.colorScheme.error
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}

private fun resultLabel(result: FaceResult): Int = when (result) {
    FaceResult.PASS -> R.string.face_result_pass
    FaceResult.REVIEW -> R.string.face_result_review
    FaceResult.FAIL -> R.string.face_result_fail
    FaceResult.UNKNOWN -> R.string.face_result_unknown
}

/** Copies a picked content:// [uri] into the app cache so the VM/processor get a stable [File] (AND-321). */
private fun copyUriToCache(context: Context, uri: Uri): File {
    val dir = File(context.cacheDir, "kyc-capture").apply { mkdirs() }
    val out = File(dir, "face-pick-${System.currentTimeMillis()}.jpg")
    context.contentResolver.openInputStream(uri)?.use { input ->
        out.outputStream().use { input.copyTo(it) }
    }
    return out
}
