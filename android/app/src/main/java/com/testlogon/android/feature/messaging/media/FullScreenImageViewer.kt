package com.testlogon.android.feature.messaging.media

import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import coil.compose.AsyncImage
import com.testlogon.android.R

/** Stable testTags for the image viewer (AND-130). */
object ImageViewerTestTags {
    const val SCREEN = "image_viewer"
    const val IMAGE = "image_viewer_image"
    const val CLOSE = "image_viewer_close"
}

/**
 * AND-130 — full-screen, zoomable image viewer. Pinch (detectTransformGestures) and double-tap
 * (1x..3x) drive a graphicsLayer scale/translation, clamped to [1x, 4x]. Dark scrim + labelled
 * Close affordance (back gesture handled by the caller's nav).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FullScreenImageViewer(
    url: String,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    contentDescription: String? = null,
) {
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

/** AND-130 — convenience holder so the viewer route can be driven from a single nullable url state. */
@Composable
fun rememberImageViewerState(): MutableImageViewerState = remember { MutableImageViewerState() }

class MutableImageViewerState {
    var url by mutableStateOf<String?>(null)
        private set

    fun open(url: String) { this.url = url }
    fun close() { url = null }
}
