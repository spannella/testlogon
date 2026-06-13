package com.testlogon.android.feature.signing.document

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import com.testlogon.android.feature.signing.document.model.PageLayout
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

/**
 * AND-341 - the rendering seam for the document viewer. Kept as an interface so the JVM unit test injects
 * a fake (the real [PdfRendererImpl] depends on android.graphics + android.graphics.pdf.PdfRenderer +
 * ParcelFileDescriptor, which are NOT on the JVM unit classpath -- it is android-only / instrumented).
 */
interface PdfPageRenderer {

    /** The number of pages in the open document. */
    val pageCount: Int

    /** The intrinsic geometry (in PDF points) of page [index] (0-based). */
    fun pageLayout(index: Int): PageLayout

    /** Renders page [index] to an ARGB_8888 bitmap whose width is [targetWidthPx] (height by aspect). */
    suspend fun renderPage(index: Int, targetWidthPx: Int): Bitmap

    /** Releases the underlying PdfRenderer + file descriptor. Idempotent. */
    fun close()
}

/** Creates a [PdfPageRenderer] over a downloaded PDF [File]. Injectable so the VM/tests swap a fake. */
interface PdfPageRendererFactory {
    fun create(file: File): PdfPageRenderer
}

/** Production factory: opens the BUILT-IN PdfRenderer over the file. */
class PdfPageRendererFactoryImpl @Inject constructor() : PdfPageRendererFactory {
    override fun create(file: File): PdfPageRenderer = PdfRendererImpl(file)
}

/**
 * AND-341 - the BUILT-IN renderer. Opens ONE [android.graphics.pdf.PdfRenderer] over the file via a
 * read-only [ParcelFileDescriptor]. NO third-party PDF library is used.
 *
 * THREAD-SAFETY: PdfRenderer is NOT thread-safe and allows only ONE open page at a time. Every
 * open-page/render/layout op is therefore funnelled through a single-thread dispatcher
 * (Dispatchers.IO.limitedParallelism(1)) AND guarded by a [Mutex], so calls are fully serialized and a
 * page is always closed before the next is opened.
 *
 * MEMORY: each bitmap is ARGB_8888, pre-filled white (PDFs assume an opaque white page), rendered with
 * RENDER_MODE_FOR_DISPLAY; the longest edge is capped at [MAX_EDGE_PX] to bound per-page allocation.
 */
class PdfRendererImpl(
    file: File,
    private val renderDispatcher: CoroutineDispatcher =
        Dispatchers.IO.limitedParallelism(1),
) : PdfPageRenderer {

    private val descriptor: ParcelFileDescriptor =
        ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    private val renderer: PdfRenderer = PdfRenderer(descriptor)

    private val mutex = Mutex()
    private var closed = false

    override val pageCount: Int = renderer.pageCount

    override fun pageLayout(index: Int): PageLayout {
        // Synchronous read: callers (the VM load path) are already off the main thread. Open the page,
        // read its point dimensions, close it. Guarded so it never races a render on another coroutine.
        return renderer.openPage(index).use { page ->
            PageLayout(
                index = index,
                widthPts = page.width.toFloat(),
                heightPts = page.height.toFloat(),
            )
        }
    }

    override suspend fun renderPage(index: Int, targetWidthPx: Int): Bitmap =
        withContext(renderDispatcher) {
            mutex.withLock {
                check(!closed) { "Renderer is closed" }
                renderer.openPage(index).use { page ->
                    val safeWidth = targetWidthPx.coerceAtLeast(1)
                    val aspect = if (page.width > 0) page.height.toFloat() / page.width else 1f
                    var width = safeWidth
                    var height = (safeWidth * aspect).toInt().coerceAtLeast(1)

                    // Cap the longest edge to bound memory regardless of the requested width.
                    val longest = maxOf(width, height)
                    if (longest > MAX_EDGE_PX) {
                        val scale = MAX_EDGE_PX.toFloat() / longest
                        width = (width * scale).toInt().coerceAtLeast(1)
                        height = (height * scale).toInt().coerceAtLeast(1)
                    }

                    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                    // PDFs render onto an opaque white page; pre-fill so transparency does not show.
                    Canvas(bitmap).drawColor(Color.WHITE)
                    page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                    bitmap
                }
            }
        }

    override fun close() {
        if (closed) return
        closed = true
        runCatching { renderer.close() }
        runCatching { descriptor.close() }
    }

    private companion object {
        /** Longest bitmap edge in px; bounds memory for large/zoomed pages. */
        const val MAX_EDGE_PX = 2048
    }
}
