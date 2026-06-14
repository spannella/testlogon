@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.signing.capture

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.SignatureField
import com.testlogon.android.feature.signing.document.model.PageOnScreen

/** AND-342 - stable testTags for the placement overlay. */
object SigningOverlayTestTags {
    const val OVERLAY = "signing_overlay"
    const val PROGRESS = "signing_progress"
    const val CONTINUE = "signing_continue"
    const val LOADING = "signing_loading"

    /** Per-field tap-target tag, suffixed by the field id. */
    fun field(id: String): String = "signing_field_$id"

    /** Per-field clear tag, suffixed by the field id. */
    fun clearField(id: String): String = "signing_clear_field_$id"
}

/**
 * AND-342 - the placement overlay drawn ON TOP of the AND-341 document viewer (the PDF is NOT
 * re-rendered here). Given the AND-341 [pages] geometry plus the projected [fields] + [placements], each
 * field box is positioned by projecting its NormalizedRect onto the owning page's on-screen contentRect
 * EVERY frame (so the overlay stays aligned across scroll / zoom / rotation). The overlay coordinates are
 * shifted by [overlayOrigin] so they are relative to the overlay's own root.
 *
 * Tapping an unsatisfied signature / initials field invokes [onFieldTap] (the host opens the pad or
 * stamps the saved asset); tapping a date field auto-fills via [onFieldTap]; tapping a satisfied field's
 * Clear invokes [onClearField]. A progress chip + a Continue button (disabled until [isComplete]) drive
 * the one-shot ContinueToSubmit.
 */
@Composable
fun SigningPlacementOverlay(
    pages: List<PageOnScreen>,
    fields: List<SignatureField>,
    placements: Map<String, FieldPlacement>,
    requiredDone: Int,
    requiredTotal: Int,
    isComplete: Boolean,
    onFieldTap: (fieldId: String) -> Unit,
    onClearField: (fieldId: String) -> Unit,
    onContinue: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val density = LocalDensity.current
    // The overlay's own root position; field rects (in scroll-content/root space) are drawn relative to it.
    var overlayOrigin by remember { mutableStateOf(Offset.Zero) }
    val pagesByIndex = remember(pages) { pages.associateBy { it.index } }

    Box(
        modifier = modifier
            .fillMaxSize()
            .testTag(SigningOverlayTestTags.OVERLAY)
            .onGloballyPositioned { overlayOrigin = it.positionInRoot() },
    ) {
        for (field in fields) {
            // AND-341 pages are 0-based; AND-340 fields are 1-based, so page-1 indexes the geometry.
            val page = pagesByIndex[field.page - 1] ?: continue
            val projected: Rect = field.rect.project(page.contentRect)
            val local = projected.translate(-overlayOrigin.x, -overlayOrigin.y)
            val placement = placements[field.id]

            with(density) {
                // Absolute offset (NOT padding) so a partially-scrolled page with a negative top does not
                // crash; the projection is recomputed every frame for scroll / zoom / rotation stability.
                val leftDp = local.left.toDp()
                val topDp = local.top.toDp()
                val widthDp = local.width.toDp().coerceAtLeast(0.dp)
                val heightDp = local.height.toDp().coerceAtLeast(0.dp)
                FieldBox(
                    field = field,
                    placement = placement,
                    modifier = Modifier
                        .offset(x = leftDp, y = topDp)
                        .size(widthDp = widthDp, heightDp = heightDp),
                    onTap = { onFieldTap(field.id) },
                    onClear = { onClearField(field.id) },
                )
            }
        }

        ProgressBar(
            requiredDone = requiredDone,
            requiredTotal = requiredTotal,
            isComplete = isComplete,
            onContinue = onContinue,
            modifier = Modifier.align(Alignment.BottomCenter),
        )
    }
}

/** Applies an explicit width/height in dp (a tiny helper so the call site reads cleanly). */
private fun Modifier.size(widthDp: Dp, heightDp: Dp) = this.width(widthDp).height(heightDp)

@Composable
private fun FieldBox(
    field: SignatureField,
    placement: FieldPlacement?,
    modifier: Modifier,
    onTap: () -> Unit,
    onClear: () -> Unit,
) {
    val satisfied = placement?.satisfied == true
    val label = fieldLabel(field.type)
    val description = if (satisfied) {
        stringResource(R.string.signing_field_satisfied_cd, label)
    } else {
        stringResource(R.string.signing_field_tap_cd, label)
    }
    val borderColor = if (satisfied) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.outline
    }
    Box(
        modifier = modifier
            .border(2.dp, borderColor)
            .background(MaterialTheme.colorScheme.primaryContainer.copy(alpha = if (satisfied) 0.25f else 0.10f))
            .testTag(SigningOverlayTestTags.field(field.id))
            .semantics { contentDescription = description }
            .pointerInput(field.id, satisfied) {
                detectTapGestures(onTap = { if (satisfied) onClear() else onTap() })
            },
        contentAlignment = Alignment.Center,
    ) {
        // A satisfied field carries a hidden clear tap-target tag for tests; the box tap also clears.
        if (satisfied) {
            Box(
                modifier = Modifier
                    .testTag(SigningOverlayTestTags.clearField(field.id))
                    .pointerInput(field.id) { detectTapGestures(onTap = { onClear() }) },
            )
            Text(
                text = placement?.textValue ?: label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        } else {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ProgressBar(
    requiredDone: Int,
    requiredTotal: Int,
    isComplete: Boolean,
    onContinue: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AssistChip(
            onClick = {},
            label = {
                Text(stringResource(R.string.signing_progress, requiredDone, requiredTotal))
            },
            modifier = Modifier.testTag(SigningOverlayTestTags.PROGRESS),
        )
        Button(
            onClick = onContinue,
            enabled = isComplete,
            modifier = Modifier
                .heightIn(min = 48.dp)
                .testTag(SigningOverlayTestTags.CONTINUE),
        ) {
            Text(stringResource(R.string.signing_continue))
        }
    }
}

/** Loading placeholder while the packet + fields project. */
@Composable
fun SigningOverlayLoading(modifier: Modifier = Modifier) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(Modifier.testTag(SigningOverlayTestTags.LOADING))
    }
}

/** A localized label for a field type (reuses the AND-340 field string keys). */
@Composable
private fun fieldLabel(type: FieldType): String = when (type) {
    FieldType.SIGNATURE -> stringResource(R.string.signing_field_signature)
    FieldType.INITIALS -> stringResource(R.string.signing_field_initials)
    FieldType.DATE -> stringResource(R.string.signing_field_date)
    FieldType.TEXT -> stringResource(R.string.signing_field_text)
    FieldType.NOTARY_STAMP -> stringResource(R.string.signing_field_notary_stamp)
}
