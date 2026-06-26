package com.testlogon.android.feature.messaging.media

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color as AndroidColor
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * #26 — self-contained PDF preview/viewer built on the BUILT-IN [android.graphics.pdf.PdfRenderer]
 * (no third-party PDF library; mirrors the signing-flow renderer). All rendering is off the main
 * thread; bitmaps are pre-filled white (PDFs assume an opaque page) and the longest edge is capped to
 * bound memory.
 */
object PdfPreviewTestTags {
    const val THUMBNAIL = "thread_pdf_thumbnail"
    const val VIEWER = "thread_pdf_viewer"
    const val VIEWER_CLOSE = "thread_pdf_viewer_close"
    const val VIEWER_PAGE = "thread_pdf_viewer_page"
}

private const val MAX_EDGE_PX = 2048

/** Renders page [index] of the PDF at [path] to a bitmap whose width is [targetWidthPx]. */
private suspend fun renderPdfPage(path: String, index: Int, targetWidthPx: Int): Bitmap? =
    withContext(Dispatchers.IO) {
        val file = File(path)
        if (!file.exists()) return@withContext null
        runCatching {
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                PdfRenderer(pfd).use { renderer ->
                    if (index !in 0 until renderer.pageCount) return@use null
                    renderer.openPage(index).use { page ->
                        val safeWidth = targetWidthPx.coerceAtLeast(1)
                        val aspect = if (page.width > 0) page.height.toFloat() / page.width else 1f
                        var width = safeWidth
                        var height = (safeWidth * aspect).toInt().coerceAtLeast(1)
                        val longest = maxOf(width, height)
                        if (longest > MAX_EDGE_PX) {
                            val scale = MAX_EDGE_PX.toFloat() / longest
                            width = (width * scale).toInt().coerceAtLeast(1)
                            height = (height * scale).toInt().coerceAtLeast(1)
                        }
                        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                        Canvas(bitmap).drawColor(AndroidColor.WHITE)
                        page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        bitmap
                    }
                }
            }
        }.getOrNull()
    }

/** The page count of the PDF at [path], or 0 if it can't be opened. */
private suspend fun pdfPageCount(path: String): Int = withContext(Dispatchers.IO) {
    val file = File(path)
    if (!file.exists()) return@withContext 0
    runCatching {
        ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
            PdfRenderer(pfd).use { it.pageCount }
        }
    }.getOrDefault(0)
}

/**
 * #26 — a tappable first-page thumbnail for a downloaded PDF in a message bubble. Renders page 1 off
 * the main thread; while it renders (or if it fails) a PDF placeholder shows. Tapping invokes [onOpen].
 */
@Composable
fun PdfThumbnail(
    localPath: String,
    onOpen: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val page by produceState<Bitmap?>(initialValue = null, localPath) {
        value = renderPdfPage(localPath, 0, 600)
    }
    Box(
        modifier = modifier
            .size(width = 200.dp, height = 260.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(Color.White)
            .clickable(onClick = onOpen)
            .testTag(PdfPreviewTestTags.THUMBNAIL),
        contentAlignment = Alignment.Center,
    ) {
        val bmp = page
        if (bmp != null) {
            Image(
                bitmap = bmp.asImageBitmap(),
                contentDescription = "PDF preview",
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Icon(
                Icons.Filled.PictureAsPdf,
                contentDescription = "PDF",
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(56.dp),
            )
        }
    }
}

/**
 * #26 — a full-screen in-app PDF viewer: a vertically-scrolling list of rendered pages. Pure built-in
 * PdfRenderer; each page renders lazily on first display.
 */
@Composable
fun PdfViewerDialog(localPath: String, onDismiss: () -> Unit) {
    val pageCount by produceState(initialValue = 0, localPath) {
        value = pdfPageCount(localPath)
    }
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFF202124))
                .testTag(PdfPreviewTestTags.VIEWER),
        ) {
            if (pageCount <= 0) {
                CircularProgressIndicator(
                    color = Color.White,
                    modifier = Modifier.align(Alignment.Center),
                )
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize().padding(top = 56.dp)) {
                    items((0 until pageCount).toList()) { index ->
                        PdfViewerPage(localPath = localPath, index = index)
                    }
                }
            }
            IconButton(
                onClick = onDismiss,
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(8.dp)
                    .testTag(PdfPreviewTestTags.VIEWER_CLOSE),
            ) {
                Icon(Icons.Filled.Close, contentDescription = "Close", tint = Color.White)
            }
        }
    }
}

@Composable
private fun PdfViewerPage(localPath: String, index: Int) {
    val page by produceState<Bitmap?>(initialValue = null, localPath, index) {
        value = renderPdfPage(localPath, index, 1080)
    }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 6.dp)
            .background(Color.White)
            .testTag(PdfPreviewTestTags.VIEWER_PAGE),
        contentAlignment = Alignment.Center,
    ) {
        val bmp = page
        if (bmp != null) {
            Image(
                bitmap = bmp.asImageBitmap(),
                contentDescription = "PDF page ${index + 1}",
                contentScale = ContentScale.FillWidth,
                modifier = Modifier.fillMaxWidth(),
            )
        } else {
            CircularProgressIndicator(modifier = Modifier.padding(40.dp))
        }
    }
}

/** Whether a message file is a PDF (by MIME or extension). */
fun isPdfFile(mime: String?, fileName: String?): Boolean =
    mime?.equals("application/pdf", ignoreCase = true) == true ||
        fileName?.endsWith(".pdf", ignoreCase = true) == true
