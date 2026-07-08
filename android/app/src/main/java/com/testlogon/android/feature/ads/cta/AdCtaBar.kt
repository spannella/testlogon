package com.testlogon.android.feature.ads.cta

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.ads.CtaAction

/** ADV2-208 — stable test tags for the shared CTA bar. */
object AdCtaBarTestTags {
    const val BAR = "ad_cta_bar"
    /** Per-button tag suffix; the full tag is BUTTON_PREFIX + cta_type wire (e.g. ad_cta_btn_buy_product). */
    const val BUTTON_PREFIX = "ad_cta_btn_"
}

/**
 * ADV2-208 (F2) — the SHARED, reusable CTA overlay bar rendering the structured CTA(s) served with an
 * ad. Rendered identically over the VOD pre-roll ([com.testlogon.android.feature.videos.detail.DetailAdAwarePlayer]),
 * the broadcast pre/mid-roll ([com.testlogon.android.feature.broadcast.viewer.ViewerScreen]) and in the
 * newsfeed sponsored card. Stateless: it renders one button per [CtaAction] and emits the tapped action
 * via [onCta]; the caller pairs [onCta] with [AdCtaClicker] (the CPC + attribution money side) and
 * [AdCtaRouter] / [navigateCta] (the in-app destination). The FIRST cta is the primary (filled) button;
 * the rest are tonal. Renders nothing when [ctas] is empty (legacy single-CTA creatives are unaffected).
 */
@Composable
fun AdCtaBar(
    ctas: List<CtaAction>,
    onCta: (CtaAction) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (ctas.isEmpty()) return
    Row(
        modifier = modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .testTag(AdCtaBarTestTags.BAR),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ctas.forEachIndexed { index, action ->
            val tag = AdCtaBarTestTags.BUTTON_PREFIX + action.ctaType.wire
            if (index == 0) {
                Button(
                    onClick = { onCta(action) },
                    modifier = Modifier.testTag(tag),
                ) { Text(action.label, maxLines = 1, overflow = TextOverflow.Ellipsis) }
            } else {
                FilledTonalButton(
                    onClick = { onCta(action) },
                    modifier = Modifier.testTag(tag),
                ) { Text(action.label, maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
        }
    }
}
