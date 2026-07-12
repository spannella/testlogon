package com.testlogon.android.core.ui.state

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.theme.TestLogonTheme

/**
 * Reusable shimmer/skeleton placeholders for loading states.
 *
 * A single shared infinite [rememberInfiniteTransition] drives an animated alpha over
 * [MaterialTheme.colorScheme.surfaceVariant], giving each placeholder a subtle pulse. These are
 * stateless and previewable; tag them at the call site if a test needs to assert presence.
 */
private const val SKELETON_MIN_ALPHA = 0.3f
private const val SKELETON_MAX_ALPHA = 0.9f
private const val SKELETON_PERIOD_MS = 900

@Composable
private fun shimmerAlpha(): Float {
    val transition = rememberInfiniteTransition(label = "skeleton_shimmer")
    val alpha by transition.animateFloat(
        initialValue = SKELETON_MIN_ALPHA,
        targetValue = SKELETON_MAX_ALPHA,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = SKELETON_PERIOD_MS),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "skeleton_alpha",
    )
    return alpha
}

/** A single pulsing placeholder block of the given [shape]. */
@Composable
fun SkeletonBox(
    modifier: Modifier = Modifier,
    shape: Shape = RoundedCornerShape(8.dp),
) {
    val alpha = shimmerAlpha()
    Box(
        modifier = modifier
            .clip(shape)
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = alpha)),
    ) {}
}

/** A placeholder text line; [fraction] sets its width relative to the parent. */
@Composable
fun SkeletonLine(
    modifier: Modifier = Modifier,
    height: Dp = 14.dp,
    fraction: Float = 1f,
) {
    SkeletonBox(
        modifier = modifier
            .fillMaxWidth(fraction)
            .height(height),
        shape = RoundedCornerShape(6.dp),
    )
}

/** A single placeholder card: a header line plus a couple of body lines. */
@Composable
private fun SkeletonCard(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.25f))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SkeletonBox(modifier = Modifier.size(40.dp), shape = CircleShape)
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SkeletonLine(fraction = 0.5f)
                SkeletonLine(fraction = 0.3f, height = 12.dp)
            }
        }
        SkeletonLine(fraction = 0.9f)
        SkeletonLine(fraction = 0.75f)
    }
}

/**
 * Drop-in loading placeholder showing a few skeleton cards. Use in place of a bare spinner where a
 * content-shaped loading state reads better (e.g. the dashboard). [count] controls how many cards.
 */
@Composable
fun LoadingSkeleton(
    modifier: Modifier = Modifier,
    count: Int = 3,
) {
    val loadingCd = stringResource(com.testlogon.android.core.ui.R.string.state_loading)
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .semantics { contentDescription = loadingCd },
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        repeat(count) { SkeletonCard() }
    }
}

@Preview
@Composable
private fun LoadingSkeletonPreview() {
    TestLogonTheme(dynamicColor = false) {
        LoadingSkeleton(modifier = Modifier.testTag("skeleton_preview"))
    }
}
