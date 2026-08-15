package com.testlogon.android.feature.custody

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Renders [content] as a scannable QR code on a Compose Canvas using the vendored [QrCode] generator
 * (no gradle dependency). Draws a white quiet-zone background + dark modules. If the content cannot be
 * encoded (should not happen for an address), shows a small fallback note instead of crashing.
 */
@Composable
fun QrCodeImage(
    content: String,
    modifier: Modifier = Modifier,
    dimension: Dp = 200.dp,
    dark: Color = Color(0xFF000000),
    light: Color = Color(0xFFFFFFFF),
) {
    val matrix = remember(content) { QrCode.encode(content) }
    Box(
        modifier = modifier.size(dimension),
        contentAlignment = Alignment.Center,
    ) {
        if (matrix == null) {
            Text("QR unavailable", style = MaterialTheme.typography.bodySmall)
        } else {
            Canvas(modifier = Modifier.size(dimension)) {
                val modules = matrix.size
                val quiet = 4 // standard 4-module quiet zone
                val total = modules + quiet * 2
                val cell = size.minDimension / total
                // background (incl. quiet zone)
                drawRect(color = light, topLeft = Offset(0f, 0f), size = Size(size.width, size.height))
                for (y in 0 until modules) {
                    for (x in 0 until modules) {
                        if (matrix[y][x]) {
                            drawRect(
                                color = dark,
                                topLeft = Offset((x + quiet) * cell, (y + quiet) * cell),
                                size = Size(cell, cell),
                            )
                        }
                    }
                }
            }
        }
    }
}
