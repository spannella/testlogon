@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.signing.capture

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlTextField

/** AND-342 - stable testTags for the full-screen signature pad. */
object SignaturePadTestTags {
    const val SCREEN = "sigpad_screen"
    const val CANVAS = "sigpad_canvas"
    const val CLEAR = "sigpad_clear"
    const val UNDO = "sigpad_undo"
    const val MODE_TOGGLE = "sigpad_mode_toggle"
    const val TYPED_TEXT = "sigpad_typed_text"
    const val CONFIRM = "sigpad_confirm"
    const val USE_SAVED = "sigpad_use_saved"

    /** Per-font-style chip tag, suffixed by the style index. */
    fun font(index: Int): String = "sigpad_font_$index"
}

/** Which capture mode the pad is in. */
enum class PadMode { DRAW, TYPE }

/**
 * AND-342 - full-screen signature pad. DRAW mode captures strokes on a Compose [Canvas] via
 * [detectDragGestures] (live polyline render) with Clear + Undo (drop last stroke). TYPE mode offers a
 * name field + >= 3 selectable BUILT-IN font styles previewing the name. Confirm returns the captured
 * input to the caller, which rasterizes it.
 *
 * STATELESS over its callbacks: [onStrokesConfirmed] / [onTypedConfirmed] hand the raw input up to the
 * ViewModel (the rasterizer is android-only and lives behind a seam). [onUseSaved] is offered only when
 * a saved-signature pointer exists.
 */
@Composable
fun SignaturePadScreen(
    hasSaved: Boolean,
    onBack: () -> Unit,
    onStrokesConfirmed: (strokes: List<List<Offset>>) -> Unit,
    onTypedConfirmed: (text: String, fontStyleIndex: Int) -> Unit,
    onUseSaved: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var mode by remember { mutableStateOf(PadMode.DRAW) }
    val strokes = remember { mutableStateListOf<SnapshotStateList<Offset>>() }
    var typedText by remember { mutableStateOf("") }
    var fontIndex by remember { mutableStateOf(0) }

    Scaffold(
        modifier = modifier.testTag(SignaturePadTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sigpad_title)) },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                FilterChip(
                    selected = mode == PadMode.DRAW,
                    onClick = { mode = PadMode.DRAW },
                    label = { Text(stringResource(R.string.sigpad_mode_draw)) },
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag(SignaturePadTestTags.MODE_TOGGLE),
                )
                FilterChip(
                    selected = mode == PadMode.TYPE,
                    onClick = { mode = PadMode.TYPE },
                    label = { Text(stringResource(R.string.sigpad_mode_type)) },
                    modifier = Modifier.heightIn(min = 48.dp),
                )
                Spacer(Modifier.weight(1f))
                if (hasSaved) {
                    OutlinedButton(
                        onClick = onUseSaved,
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(SignaturePadTestTags.USE_SAVED),
                    ) {
                        Text(stringResource(R.string.sigpad_use_saved))
                    }
                }
            }

            Box(modifier = Modifier.weight(1f)) {
                if (mode == PadMode.DRAW) {
                    DrawArea(strokes = strokes)
                } else {
                    TypeArea(
                        text = typedText,
                        onTextChange = { typedText = it },
                        fontIndex = fontIndex,
                        onFontChange = { fontIndex = it },
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (mode == PadMode.DRAW) {
                    OutlinedButton(
                        onClick = { strokes.clear() },
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(SignaturePadTestTags.CLEAR),
                    ) {
                        Text(stringResource(R.string.sigpad_clear))
                    }
                    OutlinedButton(
                        onClick = { if (strokes.isNotEmpty()) strokes.removeAt(strokes.lastIndex) },
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(SignaturePadTestTags.UNDO),
                    ) {
                        Text(stringResource(R.string.sigpad_undo))
                    }
                }
                Spacer(Modifier.weight(1f))
                Button(
                    onClick = {
                        if (mode == PadMode.DRAW) {
                            onStrokesConfirmed(strokes.map { it.toList() })
                        } else {
                            onTypedConfirmed(typedText, fontIndex)
                        }
                    },
                    enabled = if (mode == PadMode.DRAW) strokes.isNotEmpty() else typedText.isNotBlank(),
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag(SignaturePadTestTags.CONFIRM),
                ) {
                    Text(stringResource(R.string.sigpad_confirm))
                }
            }
        }
    }
}

@Composable
private fun DrawArea(strokes: SnapshotStateList<SnapshotStateList<Offset>>) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .border(1.dp, MaterialTheme.colorScheme.outline)
            .background(MaterialTheme.colorScheme.surfaceVariant),
    ) {
        val strokeColor = MaterialTheme.colorScheme.onSurface
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .testTag(SignaturePadTestTags.CANVAS)
                .pointerInput(Unit) {
                    detectDragGestures(
                        onDragStart = { offset ->
                            strokes.add(mutableStateListOf(offset))
                        },
                        onDrag = { change, _ ->
                            strokes.lastOrNull()?.add(change.position)
                        },
                    )
                },
        ) {
            for (polyline in strokes) {
                if (polyline.size < 2) continue
                val path = Path().apply {
                    moveTo(polyline.first().x, polyline.first().y)
                    for (i in 1 until polyline.size) {
                        lineTo(polyline[i].x, polyline[i].y)
                    }
                }
                drawPath(
                    path = path,
                    color = strokeColor,
                    style = Stroke(width = 6f, cap = StrokeCap.Round, join = StrokeJoin.Round),
                )
            }
        }
    }
}

@Composable
private fun TypeArea(
    text: String,
    onTextChange: (String) -> Unit,
    fontIndex: Int,
    onFontChange: (Int) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TlTextField(
            value = text,
            onValueChange = onTextChange,
            label = stringResource(R.string.sigpad_typed_label),
            modifier = Modifier.testTag(SignaturePadTestTags.TYPED_TEXT),
        )
        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items((0 until TYPED_FONT_STYLE_COUNT).toList()) { index ->
                FilterChip(
                    selected = fontIndex == index,
                    onClick = { onFontChange(index) },
                    label = {
                        Text(
                            text = text.ifBlank { stringResource(R.string.sigpad_typed_preview) },
                            fontFamily = previewFontFamily(index),
                            fontStyle = previewFontStyle(index),
                        )
                    },
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag(SignaturePadTestTags.font(index)),
                )
            }
        }
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(120.dp)
                .border(1.dp, MaterialTheme.colorScheme.outline)
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = text.ifBlank { stringResource(R.string.sigpad_typed_preview) },
                style = MaterialTheme.typography.headlineMedium,
                color = if (text.isBlank()) {
                    MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
                fontFamily = previewFontFamily(fontIndex),
                fontStyle = previewFontStyle(fontIndex),
            )
        }
    }
}

// AND-342 - the Compose preview font family/style per style index keeps parity with the rasterizer's
// built-in Typefaces so the on-screen preview matches the eventual PNG.

/** The Compose preview font family per style index (parity with the rasterizer's built-in Typefaces). */
private fun previewFontFamily(index: Int): FontFamily = when (index.mod(TYPED_FONT_STYLE_COUNT)) {
    0 -> FontFamily.Serif
    1 -> FontFamily.SansSerif
    else -> FontFamily.Monospace
}

/** The Compose preview font style per style index. */
private fun previewFontStyle(index: Int): FontStyle = when (index.mod(TYPED_FONT_STYLE_COUNT)) {
    0 -> FontStyle.Italic
    1 -> FontStyle.Normal
    else -> FontStyle.Italic
}
