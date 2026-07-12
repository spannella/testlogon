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
import androidx.compose.material.icons.filled.Download
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
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
import kotlinx.coroutines.launch
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
    const val VIEWER_DOWNLOAD = "thread_pdf_viewer_download"
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
fun PdfViewerDialog(localPath: String, fileName: String? = null, onDismiss: () -> Unit) {
    val pageCount by produceState(initialValue = 0, localPath) {
        value = pdfPageCount(localPath)
    }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
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
            // #9 — a DOWNLOAD action saves the (already-downloaded) PDF to the phone's Downloads via
            // MediaStore (no runtime permission on API29+); reuses the shared save-to-phone path.
            IconButton(
                onClick = {
                    scope.launch {
                        val ok = saveFileToDownloads(context, localPath, fileName, "application/pdf")
                        android.widget.Toast.makeText(
                            context,
                            if (ok) "Saved to Downloads" else "Couldn't save",
                            android.widget.Toast.LENGTH_SHORT,
                        ).show()
                    }
                },
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(8.dp)
                    .testTag(PdfPreviewTestTags.VIEWER_DOWNLOAD),
            ) {
                Icon(Icons.Filled.Download, contentDescription = "Download", tint = Color.White)
            }
        }
    }
}

/**
 * #9 — saves an already-downloaded local file to the device's public Downloads folder via MediaStore
 * (Q+: scoped storage + IS_PENDING, no runtime permission; pre-Q: writes into the public Downloads
 * dir). Best-effort; returns false on any failure. Self-contained (no VM/repo), mirroring the image/
 * video save-to-gallery helpers.
 */
internal suspend fun saveFileToDownloads(
    context: android.content.Context,
    localPath: String,
    fileName: String?,
    mimeType: String?,
): Boolean = withContext(Dispatchers.IO) {
    runCatching {
        val src = File(localPath)
        if (!src.exists()) return@runCatching false
        val name = (fileName?.takeIf { it.isNotBlank() } ?: src.name).let {
            if (it.contains('.')) it else "$it.pdf"
        }
        val mime = mimeType ?: "application/octet-stream"
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
            val values = android.content.ContentValues().apply {
                put(android.provider.MediaStore.Downloads.DISPLAY_NAME, name)
                put(android.provider.MediaStore.Downloads.MIME_TYPE, mime)
                put(android.provider.MediaStore.Downloads.RELATIVE_PATH, android.os.Environment.DIRECTORY_DOWNLOADS + "/TestLogon")
                put(android.provider.MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = context.contentResolver
            val itemUri = resolver.insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return@runCatching false
            src.inputStream().use { input ->
                resolver.openOutputStream(itemUri)?.use { out -> input.copyTo(out) }
                    ?: return@runCatching false
            }
            values.clear()
            values.put(android.provider.MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(itemUri, values, null, null)
            true
        } else {
            @Suppress("DEPRECATION")
            val dir = File(
                android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS),
                "TestLogon",
            ).apply { mkdirs() }
            val dest = File(dir, name)
            src.inputStream().use { input -> dest.outputStream().use { out -> input.copyTo(out) } }
            true
        }
    }.getOrDefault(false)
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
