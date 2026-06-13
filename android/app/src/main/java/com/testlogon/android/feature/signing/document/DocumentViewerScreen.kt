@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.signing.document

import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.signing.document.model.DocumentUiState
import com.testlogon.android.feature.signing.document.model.PageLayout
import com.testlogon.android.feature.signing.document.model.PageOnScreen

/** AND-341 - stable testTags for the PDF document viewer. */
object DocumentViewerTestTags {
    const val SCREEN = "document_viewer"
    const val LOADING = "document_loading"
    const val ERROR = "document_error"
    const val RETRY = "document_retry"

    /** Per-page item tag, suffixed by the 0-based page index. */
    fun page(index: Int): String = "document_page_$index"
}

/**
 * AND-341 - route-level document viewer. Sources the VM (packetId from the nav arg), forwards [onBack],
 * and bridges per-page geometry to [onPageLayout] (the AND-342 overlay seam). Per-page bitmaps are
 * requested from the VM as pages scroll into view; zoom drives a re-render at the zoomed width.
 */
@Composable
fun DocumentViewerRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onPageLayout: (List<PageOnScreen>) -> Unit = {},
    viewModel: DocumentViewerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DocumentViewerScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onPageLayout = onPageLayout,
        requestPage = viewModel::requestPage,
        onPageComposed = viewModel::onPageComposed,
        onPageDisposed = viewModel::onPageDisposed,
        onRenderWidth = viewModel::setRenderWidth,
        modifier = modifier,
    )
}

/**
 * Stateless document viewer. [requestPage] renders/caches a page bitmap; [onRenderWidth] reports the base
 * column width + zoom so the VM can pick a render width. Default lambdas keep the
 * fixed-state preview/test path (an in-test reducer over [DocumentUiState]) decoupled from the renderer.
 */
@Composable
fun DocumentViewerScreen(
    state: DocumentUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    onPageLayout: (List<PageOnScreen>) -> Unit = {},
    requestPage: suspend (index: Int, targetWidthPx: Int) -> android.graphics.Bitmap? = { _, _ -> null },
    onPageComposed: (index: Int, targetWidthPx: Int) -> Unit = { _, _ -> },
    onPageDisposed: (index: Int, targetWidthPx: Int) -> Unit = { _, _ -> },
    onRenderWidth: (baseWidthPx: Int, zoom: Float) -> Unit = { _, _ -> },
) {
    Scaffold(
        modifier = modifier.testTag(DocumentViewerTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.document_title)) },
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is DocumentUiState.Loading ->
                    CircularProgressIndicator(
                        Modifier
                            .align(Alignment.Center)
                            .testTag(DocumentViewerTestTags.LOADING),
                    )

                is DocumentUiState.Ready -> ReadyBody(
                    state = state,
                    onPageLayout = onPageLayout,
                    requestPage = requestPage,
                    onPageComposed = onPageComposed,
                    onPageDisposed = onPageDisposed,
                    onRenderWidth = onRenderWidth,
                )

                is DocumentUiState.Error -> ErrorBody(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun ReadyBody(
    state: DocumentUiState.Ready,
    onPageLayout: (List<PageOnScreen>) -> Unit,
    requestPage: suspend (index: Int, targetWidthPx: Int) -> android.graphics.Bitmap?,
    onPageComposed: (index: Int, targetWidthPx: Int) -> Unit,
    onPageDisposed: (index: Int, targetWidthPx: Int) -> Unit,
    onRenderWidth: (baseWidthPx: Int, zoom: Float) -> Unit,
) {
    // Zoom 1.0x..3.0x via pinch + double-tap, applied to the scroll content as a graphicsLayer scale.
    var zoom by remember { mutableFloatStateOf(1f) }
    var baseWidthPx by remember { mutableStateOf(0) }

    // Per-page bounds in scroll-content pixel space, assembled then surfaced to AND-342.
    val pageBounds = remember { androidx.compose.runtime.mutableStateMapOf<Int, Rect>() }

    // The zoomed render width is baseWidth * zoom; the VM debounces the re-render off this single write.
    LaunchedEffect(baseWidthPx, zoom) {
        if (baseWidthPx > 0) onRenderWidth(baseWidthPx, zoom)
    }

    val targetWidthPx = if (baseWidthPx > 0) (baseWidthPx * zoom).toInt().coerceAtLeast(1) else 0

    Box(
        modifier = Modifier
            .fillMaxSize()
            .onGloballyPositioned { coords ->
                baseWidthPx = coords.size.width
            }
            .pointerInput(Unit) {
                detectTransformGestures { _, _, gestureZoom, _ ->
                    zoom = (zoom * gestureZoom).coerceIn(MIN_ZOOM, MAX_ZOOM)
                }
            }
            .pointerInput(Unit) {
                detectTapGestures(
                    onDoubleTap = { zoom = if (zoom > MIN_ZOOM) MIN_ZOOM else DOUBLE_TAP_ZOOM },
                )
            },
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .graphicsLayer { scaleX = zoom; scaleY = zoom; transformOrigin = topStartOrigin() },
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(state.pages, key = { it.index }) { layout ->
                PdfPageItem(
                    layout = layout,
                    pageCount = state.pageCount,
                    targetWidthPx = targetWidthPx,
                    requestPage = requestPage,
                    onPageComposed = onPageComposed,
                    onPageDisposed = onPageDisposed,
                    onBounds = { rect ->
                        pageBounds[layout.index] = rect
                        onPageLayout(
                            pageBounds.entries
                                .sortedBy { it.key }
                                .map { PageOnScreen(index = it.key, contentRect = it.value) },
                        )
                    },
                )
            }
        }
    }
}

/**
 * One page item. Requests its bitmap from [requestPage] (windowed -- only composed pages render); shows
 * a correct-aspect placeholder with a "Page N of M" label until ready. Reports its bounds in
 * scroll-content space via [onBounds] for the AND-342 overlay, and retains/releases its bitmap key so
 * off-screen bitmaps are recycled.
 */
@Composable
private fun PdfPageItem(
    layout: PageLayout,
    pageCount: Int,
    targetWidthPx: Int,
    requestPage: suspend (index: Int, targetWidthPx: Int) -> android.graphics.Bitmap?,
    onPageComposed: (index: Int, targetWidthPx: Int) -> Unit,
    onPageDisposed: (index: Int, targetWidthPx: Int) -> Unit,
    onBounds: (Rect) -> Unit,
) {
    val density = LocalDensity.current
    val placeholderHeightDp = with(density) {
        if (targetWidthPx > 0) layout.heightForWidth(targetWidthPx).toDp() else 0.dp
    }

    DisposableEffect(layout.index, targetWidthPx) {
        if (targetWidthPx > 0) onPageComposed(layout.index, targetWidthPx)
        onDispose { if (targetWidthPx > 0) onPageDisposed(layout.index, targetWidthPx) }
    }

    val bitmap by produceState<android.graphics.Bitmap?>(
        initialValue = null,
        key1 = layout.index,
        key2 = targetWidthPx,
    ) {
        value = if (targetWidthPx > 0) requestPage(layout.index, targetWidthPx) else null
    }

    val pageLabel = stringResource(R.string.document_page_label, layout.index + 1, pageCount)

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DocumentViewerTestTags.page(layout.index))
            .onGloballyPositioned { coords ->
                val pos = coords.positionInRoot()
                onBounds(
                    Rect(
                        offset = Offset(pos.x, pos.y),
                        size = androidx.compose.ui.geometry.Size(
                            coords.size.width.toFloat(),
                            coords.size.height.toFloat(),
                        ),
                    ),
                )
            },
        contentAlignment = Alignment.Center,
    ) {
        val current = bitmap
        if (current != null && !current.isRecycled) {
            Image(
                bitmap = current.asImageBitmap(),
                contentDescription = pageLabel,
                modifier = Modifier.fillMaxWidth(),
            )
        } else {
            // Correct-aspect placeholder so scroll geometry is stable before the bitmap arrives.
            Spacer(
                Modifier
                    .fillMaxWidth()
                    .height(if (placeholderHeightDp > 0.dp) placeholderHeightDp else 200.dp),
            )
            Text(
                text = pageLabel,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ErrorBody(message: String, retryable: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag(DocumentViewerTestTags.ERROR),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
        if (retryable) {
            Button(
                onClick = onRetry,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(DocumentViewerTestTags.RETRY),
            ) {
                Text(stringResource(R.string.document_retry))
            }
        }
    }
}

private const val MIN_ZOOM = 1f
private const val MAX_ZOOM = 3f
private const val DOUBLE_TAP_ZOOM = 2f

/** Top-start transform origin so zoom scales from the top-left of the content (not the centre). */
private fun topStartOrigin() = androidx.compose.ui.graphics.TransformOrigin(0f, 0f)
