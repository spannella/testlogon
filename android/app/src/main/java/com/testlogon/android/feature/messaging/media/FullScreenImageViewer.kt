package com.testlogon.android.feature.messaging.media

import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.widget.Toast
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.core.graphics.drawable.toBitmap
import coil.compose.AsyncImage
import coil.imageLoader
import coil.request.ImageRequest
import coil.request.SuccessResult
import com.testlogon.android.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Stable testTags for the image viewer (AND-130). */
object ImageViewerTestTags {
    const val SCREEN = "image_viewer"
    const val IMAGE = "image_viewer_image"
    const val CLOSE = "image_viewer_close"
    const val SAVE = "image_viewer_save"
}

/**
 * AND-130 — full-screen, zoomable image viewer. Pinch (detectTransformGestures) and double-tap
 * (1x..3x) drive a graphicsLayer scale/translation, clamped to [1x, 4x]. Dark scrim + labelled
 * Close affordance (back gesture handled by the caller's nav). A Download action saves the image to
 * the device gallery (MediaStore Pictures/TestLogon) via the shared Coil loader (resolves the same
 * relative /mock URLs the on-screen image uses).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FullScreenImageViewer(
    url: String,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    contentDescription: String? = null,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var saving by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(ImageViewerTestTags.SCREEN),
        containerColor = Color.Black,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.image_viewer_title)) },
                navigationIcon = {
                    IconButton(
                        onClick = onClose,
                        modifier = Modifier.testTag(ImageViewerTestTags.CLOSE),
                    ) {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = stringResource(R.string.image_viewer_close),
                        )
                    }
                },
                actions = {
                    IconButton(
                        enabled = !saving,
                        onClick = {
                            saving = true
                            scope.launch {
                                val ok = saveImageToGallery(context, url)
                                Toast.makeText(
                                    context,
                                    if (ok) "Saved to Photos" else "Couldn't save image",
                                    Toast.LENGTH_SHORT,
                                ).show()
                                saving = false
                            }
                        },
                        modifier = Modifier.testTag(ImageViewerTestTags.SAVE),
                    ) {
                        Icon(Icons.Filled.Download, contentDescription = "Save to phone")
                    }
                },
            )
        },
    ) { padding ->
        var scale by remember { mutableFloatStateOf(1f) }
        var offsetX by remember { mutableFloatStateOf(0f) }
        var offsetY by remember { mutableFloatStateOf(0f) }
        val cd = contentDescription ?: stringResource(R.string.image_viewer_cd)

        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentAlignment = Alignment.Center,
        ) {
            AsyncImage(
                model = url,
                contentDescription = cd,
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .testTag(ImageViewerTestTags.IMAGE)
                    .semantics { this.contentDescription = cd }
                    .graphicsLayer(
                        scaleX = scale,
                        scaleY = scale,
                        translationX = offsetX,
                        translationY = offsetY,
                    )
                    .pointerInput(Unit) {
                        detectTransformGestures { _, pan, zoom, _ ->
                            scale = (scale * zoom).coerceIn(1f, 4f)
                            if (scale > 1f) {
                                offsetX += pan.x
                                offsetY += pan.y
                            } else {
                                offsetX = 0f
                                offsetY = 0f
                            }
                        }
                    }
                    .pointerInput(Unit) {
                        detectTapGestures(
                            onDoubleTap = {
                                if (scale > 1f) {
                                    scale = 1f
                                    offsetX = 0f
                                    offsetY = 0f
                                } else {
                                    scale = 3f
                                }
                            },
                        )
                    },
            )
        }
    }
}

/**
 * Loads [url] through the app's shared Coil loader (so relative /mock URLs + auth resolve exactly as
 * the on-screen image) and writes the bitmap to the device gallery. MediaStore on API 29+ needs no
 * runtime permission; pre-29 falls back to the same insert (best-effort).
 */
private suspend fun saveImageToGallery(context: Context, url: String): Boolean = withContext(Dispatchers.IO) {
    runCatching {
        val request = ImageRequest.Builder(context).data(url).allowHardware(false).build()
        val result = context.imageLoader.execute(request)
        val bitmap = (result as? SuccessResult)?.drawable?.toBitmap() ?: return@runCatching false

        val name = "TestLogon_" + url.substringAfterLast('/').substringBefore('?').ifBlank { "image" }
            .let { if (it.endsWith(".jpg", true) || it.endsWith(".png", true) || it.endsWith(".jpeg", true)) it else "$it.jpg" }
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, name)
            put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/TestLogon")
                put(MediaStore.Images.Media.IS_PENDING, 1)
            }
        }
        val resolver = context.contentResolver
        val itemUri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
            ?: return@runCatching false
        resolver.openOutputStream(itemUri)?.use { out ->
            bitmap.compress(Bitmap.CompressFormat.JPEG, 95, out)
        } ?: return@runCatching false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            values.clear()
            values.put(MediaStore.Images.Media.IS_PENDING, 0)
            resolver.update(itemUri, values, null, null)
        }
        true
    }.getOrDefault(false)
}

/** AND-130 — convenience holder so the viewer route can be driven from a single nullable url state. */
@Composable
fun rememberImageViewerState(): MutableImageViewerState = remember { MutableImageViewerState() }

class MutableImageViewerState {
    var url by mutableStateOf<String?>(null)
        private set

    fun open(url: String) { this.url = url }
    fun close() { url = null }
}
