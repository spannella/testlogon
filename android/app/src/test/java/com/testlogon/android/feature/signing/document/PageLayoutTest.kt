package com.testlogon.android.feature.signing.document

import com.testlogon.android.feature.signing.document.model.PageLayout
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-341 - pure math tests for [PageLayout] (aspect ratio + target height from width). No android deps.
 */
class PageLayoutTest {

    @Test
    fun aspectRatio_isHeightOverWidth() {
        val layout = PageLayout(index = 0, widthPts = 612f, heightPts = 792f)
        assertEquals(792f / 612f, layout.aspectRatio, 0.0001f)
    }

    @Test
    fun aspectRatio_isZero_whenWidthIsZero() {
        val layout = PageLayout(index = 0, widthPts = 0f, heightPts = 792f)
        assertEquals(0f, layout.aspectRatio, 0.0001f)
    }

    @Test
    fun heightForWidth_preservesAspect() {
        // A US-Letter page (8.5x11) at a 1000px column width -> 1000 * (792/612) ~= 1294px.
        val layout = PageLayout(index = 0, widthPts = 612f, heightPts = 792f)
        assertEquals(1294, layout.heightForWidth(1000))
    }

    @Test
    fun heightForWidth_isZero_whenWidthIsZero() {
        val layout = PageLayout(index = 0, widthPts = 0f, heightPts = 792f)
        assertEquals(0, layout.heightForWidth(1000))
    }
}
