package com.testlogon.android.feature.player

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.testlogon.android.R
import kotlinx.coroutines.delay

/** AND-170 — stable testTags for the watermark overlay. */
object WatermarkOverlayTestTags {
    const val OVERLAY = "watermark_overlay"
    const val PLACEHOLDER = "watermark_placeholder"
}

/**
 * AND-170 §4.4 — the forensic watermark overlay hook.
 *
 * A presentation-layer DETERRENT (not DRM, §8): renders the signed-in user's identity + a coarse
 * timestamp over the video for the whole protected session. It is a reusable HOOK other video screens
 * enable by passing a [WatermarkUiState.Required]; [WatermarkUiState.NotRequired] renders NOTHING
 * (the node is absent, not transparent — FR-3 zero draw cost). The overlay sits above the video frame
 * but is touch pass-through ([pointerInput] no-op, no clickable) so the controls layer above it
 * remains fully operable (FR-6), and it is excluded from the a11y tree (`clearAndSetSemantics`, FR
 * AC-8). Motion (anti-static-crop, FR-4) cycles the anchor across the NxN grid via [WatermarkMotion].
 *
 * @param compact true in Picture-in-Picture -> reduced font size, still present (FR-5).
 * @param nowMs injectable clock for deterministic tests; defaults to wall clock.
 */
@Composable
fun WatermarkOverlay(
    state: WatermarkUiState,
    modifier: Modifier = Modifier,
    compact: Boolean = false,
    nowMs: () -> Long = { System.currentTimeMillis() },
) {
    when (state) {
        WatermarkUiState.NotRequired -> Unit // FR-3: no node at all.
        WatermarkUiState.PendingIdentity -> PlaceholderOverlay(modifier)
        is WatermarkUiState.Required -> RequiredOverlay(state.spec, modifier, compact, nowMs)
    }
}

@Composable
private fun RequiredOverlay(
    spec: WatermarkSpec,
    modifier: Modifier,
    compact: Boolean,
    nowMs: () -> Long,
) {
    // Phase derives from wall clock so motion is independent of recomposition count; we re-read it on
    // a slow tick aligned to the dwell time, never per-frame.
    var clock by remember { mutableLongStateOf(nowMs()) }
    LaunchedEffect(spec) {
        while (true) {
            clock = nowMs()
            delay(spec.cycleMillis.coerceAtLeast(250L))
        }
    }
    val index = WatermarkMotion.cellIndex(spec, clock)
    val (fx, fy) = WatermarkMotion.anchorFraction(spec, index)

    // testTag rides the outer container (kept for tests); the inner content clears its own semantics
    // so the identity text is never announced/focusable by TalkBack (FR AC-8).
    BoxWithConstraints(
        modifier = modifier
            .fillMaxSize()
            .testTag(WatermarkOverlayTestTags.OVERLAY),
    ) {
        val xDp = maxWidth * fx
        val yDp = maxHeight * fy
        Box(
            modifier = Modifier
                .wrapContentSize(align = Alignment.TopStart)
                .offset(x = xDp, y = yDp)
                // Never consume gestures (FR-6 touch pass-through); never announced (FR a11y).
                .pointerInput(Unit) { }
                .clearAndSetSemantics { },
        ) {
            Text(
                text = "${spec.primaryLine}\n${spec.secondaryLine}",
                color = Color.White,
                style = MaterialTheme.typography.labelMedium,
                fontSize = if (compact) 9.sp else 13.sp,
                modifier = Modifier.graphicsLayer {
                    rotationZ = spec.rotationDeg
                    alpha = spec.opacity
                },
            )
        }
    }
}

/** AND-170 FR-8 — non-fatal placeholder shown while a protected item awaits identity resolution. */
@Composable
private fun PlaceholderOverlay(modifier: Modifier) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .testTag(WatermarkOverlayTestTags.PLACEHOLDER),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = stringResource(R.string.watermark_protected_content),
            color = Color.White,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier
                .padding(12.dp)
                .graphicsLayer { alpha = 0.85f },
        )
    }
}
