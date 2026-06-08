package com.testlogon.android.feature.health

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.OfflineBanner

/**
 * AND-042 — global backend-health banner. Stateless; animates in/out and reuses the core-ui
 * [OfflineBanner] styling. Shown when the backend is unreachable, hidden on recovery.
 */
@Composable
fun GlobalHealthBanner(
    state: HealthBannerUiState,
    modifier: Modifier = Modifier,
) {
    AnimatedVisibility(
        visible = state.visible,
        enter = expandVertically() + fadeIn(),
        exit = shrinkVertically() + fadeOut(),
        modifier = modifier.testTag("health_banner_container"),
    ) {
        OfflineBanner(
            message = "Can't reach the server. Showing saved data where available.",
            modifier = Modifier.testTag("health_banner"),
        )
    }
}

/** Hilt-bound host; collects the ViewModel and renders [GlobalHealthBanner]. */
@Composable
fun HealthBannerHost(
    modifier: Modifier = Modifier,
    viewModel: HealthBannerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GlobalHealthBanner(state = state, modifier = modifier)
}
