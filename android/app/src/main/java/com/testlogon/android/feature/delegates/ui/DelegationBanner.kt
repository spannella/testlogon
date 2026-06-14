package com.testlogon.android.feature.delegates.ui

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.SupervisorAccount
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/** AND-360 - stable testTags for the manage-as-creator banner. */
object DelegationBannerTestTags {
    const val BANNER = "delegation_banner"
    const val EXIT = "delegation_exit"
}

/**
 * AND-360 - the persistent, distinct-color "Managing @{creator}" banner. STATELESS: rendered only when
 * [creatorName] is non-null OR [visible] is true (the Route variant only mounts it when a delegate context
 * exists). The Exit action calls [onExit] (the AND-359 pure-local exit). Uses the tertiaryContainer color
 * so it is visually distinct from the surrounding chrome; the role is conveyed by icon + text (not color
 * alone) and announced as a polite live region.
 */
@Composable
fun DelegationBanner(
    creatorName: String?,
    onExit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val label = creatorName?.takeIf { it.isNotBlank() }
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        modifier = modifier
            .fillMaxWidth()
            .testTag(DelegationBannerTestTags.BANNER)
            .semantics { liveRegion = LiveRegionMode.Polite },
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            Icon(
                Icons.Outlined.SupervisorAccount,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Text(
                text = if (label != null) {
                    stringResource(R.string.delegation_banner_managing, label)
                } else {
                    stringResource(R.string.delegation_banner_managing_unnamed)
                },
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier
                    .padding(start = 8.dp)
                    .weight(1f),
            )
            TextButton(
                onClick = onExit,
                modifier = Modifier.testTag(DelegationBannerTestTags.EXIT),
            ) {
                Text(stringResource(R.string.delegation_exit))
            }
        }
    }
}

/**
 * AND-360 - the connected banner: observes the typed delegation context and renders the [DelegationBanner]
 * ONLY when a delegate context is active (null context = acting as oneself = nothing rendered). Exit
 * delegates to the AND-359 pure-local exit through the ViewModel. Host screens can mount this above their
 * content to surface the persistent overlay.
 */
@Composable
fun DelegationBannerHost(
    modifier: Modifier = Modifier,
    viewModel: DelegationBannerViewModel = hiltViewModel(),
) {
    val context by viewModel.delegationContext.collectAsStateWithLifecycle()
    val active = context ?: return
    DelegationBanner(
        creatorName = active.creatorName,
        onExit = viewModel::exit,
        modifier = modifier,
    )
}
