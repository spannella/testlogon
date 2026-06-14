@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.capture

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import java.io.File

/** AND-321 - stable testTags for the document capture+upload screen. */
object DocumentCaptureTestTags {
    const val SCREEN = "kyc_doc_screen"
    const val TYPE_ID_FRONT = "kyc_doc_type_id_front"
    const val TYPE_ID_BACK = "kyc_doc_type_id_back"
    const val TAKE_PHOTO = "kyc_doc_take_photo"
    const val PICK = "kyc_doc_pick"
    const val RETAKE = "kyc_doc_retake"
    const val CONFIRM = "kyc_doc_confirm"
    const val UPLOAD = "kyc_doc_upload"
    const val CANCEL = "kyc_doc_cancel"
    const val SUCCESS = "kyc_doc_success"
    const val PERMISSION = "kyc_doc_permission"

    fun typeTag(docType: DocType): String = when (docType) {
        DocType.ID_FRONT -> TYPE_ID_FRONT
        DocType.ID_BACK -> TYPE_ID_BACK
    }
}

/**
 * AND-321 - document capture route. Owns the dependency-free image-acquisition machinery:
 *  - a runtime CAMERA permission request (RequestPermission),
 *  - the live system camera via ActivityResultContracts.TakePicture() writing to a FileProvider Uri
 *    (reusing the existing `${applicationId}.fileprovider` + the kyc-capture cache-path), and
 *  - "choose from library" via ActivityResultContracts.GetContent() with an image mime filter.
 *
 * It hands the acquired File to the VM ([DocumentCaptureViewModel.onImageAcquired]); all processing and
 * the sequential upload live in the VM/processor/repo. The embedded CameraX live-preview (FR-3) is
 * DEFERRED -- see the class KDoc on [DocumentCaptureViewModel] and the AND-321 report.
 */
@Composable
fun DocumentCaptureRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DocumentCaptureViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // A stable capture target File + its FileProvider content Uri for the live-camera TakePicture intent.
    val captureFile = remember {
        File(context.cacheDir, "kyc-capture").apply { mkdirs() }
            .let { File(it, "kyc-camera-${System.currentTimeMillis()}.jpg") }
    }
    val captureUri = remember {
        androidx.core.content.FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            captureFile,
        )
    }

    val takePicture = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { ok ->
        if (ok) viewModel.onImageAcquired(captureFile)
    }
    val pickFromLibrary = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) viewModel.onImageAcquired(copyUriToCache(context, uri))
    }
    val requestCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            viewModel.onPermissionGranted()
            takePicture.launch(captureUri)
        } else {
            val activity = context as? Activity
            val permanently = activity != null &&
                !activity.shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)
            viewModel.onPermissionDenied(permanentlyDenied = permanently)
        }
    }

    DocumentCaptureScreen(
        state = state,
        allConfirmed = viewModel.allConfirmed,
        onBack = onBack,
        onSelectType = viewModel::onSelectType,
        onTakePhoto = {
            val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
            if (granted) takePicture.launch(captureUri) else requestCamera.launch(Manifest.permission.CAMERA)
        },
        onPickFromLibrary = { pickFromLibrary.launch("image/*") },
        onRetake = viewModel::onRetake,
        onConfirm = viewModel::onConfirm,
        onStartUpload = viewModel::onStartUpload,
        onCancel = viewModel::onCancel,
        onRetry = viewModel::onRetry,
        onOpenSettings = { openAppSettings(context) },
        modifier = modifier,
    )
}

@Composable
fun DocumentCaptureScreen(
    state: DocumentCaptureUiState,
    allConfirmed: Boolean,
    onBack: () -> Unit,
    onSelectType: (DocType) -> Unit,
    onTakePhoto: () -> Unit,
    onPickFromLibrary: () -> Unit,
    onRetake: () -> Unit,
    onConfirm: () -> Unit,
    onStartUpload: () -> Unit,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DocumentCaptureTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kyc_doc_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            when (state) {
                is DocumentCaptureUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is DocumentCaptureUiState.SelectingType -> SelectingTypeContent(
                    available = state.available,
                    allConfirmed = allConfirmed,
                    onSelectType = onSelectType,
                    onTakePhoto = onTakePhoto,
                    onPickFromLibrary = onPickFromLibrary,
                    onStartUpload = onStartUpload,
                )

                is DocumentCaptureUiState.Reviewing -> ReviewingContent(
                    state = state,
                    onRetake = onRetake,
                    onConfirm = onConfirm,
                )

                is DocumentCaptureUiState.Uploading -> UploadingContent(
                    state = state,
                    onCancel = onCancel,
                )

                is DocumentCaptureUiState.Success -> SuccessContent()

                is DocumentCaptureUiState.Error -> ErrorContent(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )

                is DocumentCaptureUiState.PermissionRequired -> PermissionContent(
                    permanentlyDenied = state.permanentlyDenied,
                    onRetry = onTakePhoto,
                    onOpenSettings = onOpenSettings,
                )
            }
        }
    }
}

@Composable
private fun SelectingTypeContent(
    available: List<DocType>,
    allConfirmed: Boolean,
    onSelectType: (DocType) -> Unit,
    onTakePhoto: () -> Unit,
    onPickFromLibrary: () -> Unit,
    onStartUpload: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.kyc_doc_select_prompt),
            style = MaterialTheme.typography.titleMedium,
        )
        available.forEach { docType ->
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(DocumentCaptureTestTags.typeTag(docType)),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = stringResource(docType.label),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    CaptureActionButtons(
                        onTakePhoto = { onSelectType(docType); onTakePhoto() },
                        onPickFromLibrary = { onSelectType(docType); onPickFromLibrary() },
                    )
                }
            }
        }
        if (allConfirmed) {
            Button(
                onClick = onStartUpload,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(DocumentCaptureTestTags.UPLOAD),
            ) {
                Text(stringResource(R.string.kyc_doc_upload))
            }
        }
    }
}

@Composable
private fun CaptureActionButtons(onTakePhoto: () -> Unit, onPickFromLibrary: () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            onClick = onTakePhoto,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DocumentCaptureTestTags.TAKE_PHOTO),
        ) {
            Text(stringResource(R.string.kyc_doc_take_photo))
        }
        OutlinedButton(
            onClick = onPickFromLibrary,
            modifier = Modifier.heightIn(min = 48.dp).testTag(DocumentCaptureTestTags.PICK),
        ) {
            Text(stringResource(R.string.kyc_doc_pick))
        }
    }
}

@Composable
private fun ReviewingContent(
    state: DocumentCaptureUiState.Reviewing,
    onRetake: () -> Unit,
    onConfirm: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.kyc_doc_review_prompt, stringResource(state.docType.label)),
            style = MaterialTheme.typography.titleMedium,
        )
        AsyncImage(
            model = state.file,
            contentDescription = stringResource(R.string.kyc_doc_review_image_cd),
            contentScale = ContentScale.Fit,
            modifier = Modifier.fillMaxWidth().aspectRatio(1.6f),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = onRetake,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(DocumentCaptureTestTags.RETAKE),
            ) {
                Text(stringResource(R.string.kyc_doc_retake))
            }
            Button(
                onClick = onConfirm,
                modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag(DocumentCaptureTestTags.CONFIRM),
            ) {
                Text(stringResource(R.string.kyc_doc_confirm))
            }
        }
    }
}

@Composable
private fun UploadingContent(
    state: DocumentCaptureUiState.Uploading,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.kyc_doc_uploading),
            style = MaterialTheme.typography.titleMedium,
        )
        LinearProgressIndicator(
            progress = { state.progress },
            modifier = Modifier.fillMaxWidth(),
        )
        state.perItem.forEach { item ->
            Text(
                text = "${stringResource(item.docType.label)}: ${stringResource(itemStatusLabel(item.state))}",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        OutlinedButton(
            onClick = onCancel,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(DocumentCaptureTestTags.CANCEL),
        ) {
            Text(stringResource(R.string.kyc_doc_cancel))
        }
    }
}

@Composable
private fun SuccessContent() {
    Column(
        modifier = Modifier.fillMaxSize().testTag(DocumentCaptureTestTags.SUCCESS),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            Icons.Outlined.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = stringResource(R.string.kyc_doc_success_message),
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
private fun ErrorContent(message: String, retryable: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
        if (retryable) {
            Button(
                onClick = onRetry,
                modifier = Modifier.heightIn(min = 48.dp),
            ) {
                Text(stringResource(R.string.kyc_doc_retry))
            }
        }
    }
}

@Composable
private fun PermissionContent(
    permanentlyDenied: Boolean,
    onRetry: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().testTag(DocumentCaptureTestTags.PERMISSION),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.kyc_doc_permission_message),
            style = MaterialTheme.typography.bodyLarge,
        )
        if (permanentlyDenied) {
            Button(onClick = onOpenSettings, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(R.string.kyc_doc_open_settings))
            }
        } else {
            Button(onClick = onRetry, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(R.string.kyc_doc_grant_permission))
            }
        }
        TextButton(onClick = onOpenSettings) {
            Text(stringResource(R.string.kyc_doc_open_settings))
        }
    }
}

private fun itemStatusLabel(state: ItemUploadState): Int = when (state) {
    ItemUploadState.PENDING -> R.string.kyc_doc_item_pending
    ItemUploadState.UPLOADING -> R.string.kyc_doc_item_uploading
    ItemUploadState.SUCCEEDED -> R.string.kyc_doc_item_succeeded
    ItemUploadState.FAILED -> R.string.kyc_doc_item_failed
}

/**
 * Copies a picked content:// [uri] into the app cache so the VM/processor get a stable [File] (mirrors the
 * processor's own temp-copy, but the screen owns the picker result). Best-effort; throws nothing the caller
 * can't surface as a processing error downstream.
 */
private fun copyUriToCache(context: android.content.Context, uri: Uri): File {
    val dir = File(context.cacheDir, "kyc-capture").apply { mkdirs() }
    val out = File(dir, "kyc-pick-${System.currentTimeMillis()}.jpg")
    context.contentResolver.openInputStream(uri)?.use { input ->
        out.outputStream().use { input.copyTo(it) }
    }
    return out
}

private fun openAppSettings(context: android.content.Context) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.fromParts("package", context.packageName, null)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    runCatching { context.startActivity(intent) }
}
