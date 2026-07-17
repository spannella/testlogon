package com.testlogon.android.feature.profile.publicprofile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Login
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.blocking.BlockConfirmDialog
import com.testlogon.android.feature.blocking.BlockInteractionViewModel
import com.testlogon.android.core.model.profile.PublicProfile
import com.testlogon.android.core.ui.scaffold.TlScaffold
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.profile.ProfileTestTags
import com.testlogon.android.feature.profile.components.ProfileHeader
import com.testlogon.android.feature.report.ContentReportSheetHost
import kotlinx.coroutines.launch

/**
 * AND-073 / AND-390 — route-level public-profile entry for /u/{identifier}.
 *
 * AND-390 polish: wires the share-sheet / copy-link affordances (FR-5) through the injectable
 * [ProfileShareIntents] seam (resolved in composable scope so a test can fake it), gates auth-only
 * affordances and the Sign-in CTA on [PublicProfileViewModel.isAuthenticated] (FR-7/FR-8), and routes
 * the Sign-in CTA via [onSignIn] into the auth flow (FR-8). The public read itself never requires a
 * session (FR-1) — auth state only changes presentation.
 */
@Composable
fun PublicProfileRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    // SUBX-24: organic Subscribe entry -> the creator's subscription tier browse.
    onSubscribe: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    // Defaulted no-op so the authenticated graph (where the CTA is hidden) need not supply it.
    onSignIn: () -> Unit = {},
    shareIntents: ProfileShareIntents = remember { ProfileShareIntents() },
    viewModel: PublicProfileViewModel = hiltViewModel(),
    tipViewModel: ProfileTipViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val isAuthenticated by viewModel.isAuthenticated.collectAsStateWithLifecycle()
    val tipState by tipViewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    var tipTotalOverride by remember { mutableStateOf<Int?>(null) }
    val linkCopied = stringResource(R.string.link_copied)
    val copyFailed = stringResource(R.string.link_copy_failed)
    val shareFailed = stringResource(R.string.share_profile_failed)

    LaunchedEffect(tipViewModel) {
        tipViewModel.effects.collect { effect ->
            when (effect) {
                is ProfileTipEffect.ShowSnackbar -> snackbarHostState.showSnackbar(effect.message)
                is ProfileTipEffect.TotalUpdated -> tipTotalOverride = effect.tipTotalCents
            }
        }
    }

    PublicProfileScreen(
        state = state,
        identifier = viewModel.identifier,
        isAuthenticated = isAuthenticated,
        tipTotalOverride = tipTotalOverride,
        onTipCreator = { creatorId, displayName -> tipViewModel.open(creatorId, displayName) },
        shareUrl = viewModel.shareUrl,
        snackbarHostState = snackbarHostState,
        onRetry = viewModel::onRetry,
        onBack = onBack,
        onOpenFanClub = onOpenFanClub,
        onSubscribe = onSubscribe,
        onSignIn = onSignIn,
        onShare = { displayName ->
            val url = viewModel.shareUrl ?: return@PublicProfileScreen
            if (!shareIntents.share(context, url, displayName)) {
                scope.launch { snackbarHostState.showSnackbar(shareFailed) }
            }
        },
        onCopyLink = {
            val url = viewModel.shareUrl ?: return@PublicProfileScreen
            val ok = shareIntents.copyLink(context, url)
            // On API 33+ the OS shows its own clipboard toast; suppress the duplicate in-app snackbar.
            if (ok && shareIntents.shouldShowCopyConfirmation()) {
                scope.launch { snackbarHostState.showSnackbar(linkCopied) }
            } else if (!ok) {
                scope.launch { snackbarHostState.showSnackbar(copyFailed) }
            }
        },
        modifier = modifier,
    )

    ProfileTipSheet(
        state = tipState,
        onSelectPreset = tipViewModel::selectPreset,
        onCustomAmount = tipViewModel::setCustomAmount,
        onSend = tipViewModel::send,
        onDismiss = tipViewModel::dismiss,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PublicProfileScreen(
    state: PublicProfileUiState,
    identifier: String,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    isAuthenticated: Boolean = false,
    shareUrl: String? = null,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    tipTotalOverride: Int? = null,
    onTipCreator: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    onSubscribe: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    onSignIn: () -> Unit = {},
    onShare: (displayName: String) -> Unit = {},
    onCopyLink: () -> Unit = {},
) {
    val title = (state as? PublicProfileUiState.Content)?.profile?.displayName
        ?.takeIf { it.isNotBlank() } ?: identifier
    // The share URL needs only the identifier, so copy-link can be enabled before Content; the share
    // sheet (which carries a display name) is enabled once a name is available (§7).
    val canShareOrCopy = shareUrl != null
    val displayName = (state as? PublicProfileUiState.Content)?.profile
        ?.let { it.displayName.ifBlank { it.identifier } }
        ?: identifier
    TlScaffold(
        modifier = modifier.testTag(ProfileTestTags.PUBLIC_ROOT),
        snackbarHostState = snackbarHostState,
        topBar = {
            TopAppBar(
                title = { Text(title.ifBlank { stringResource(R.string.profile_public_title) }) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("public_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    // AND-390: copy-link + share affordances. The canonical https URL is always the
                    // production App Link host so a shared link round-trips back into the app (FR-5/FR-6).
                    IconButton(
                        onClick = onCopyLink,
                        enabled = canShareOrCopy,
                        modifier = Modifier.testTag(ProfileTestTags.PUBLIC_COPY_LINK),
                    ) {
                        Icon(
                            Icons.Outlined.ContentCopy,
                            contentDescription = stringResource(R.string.cd_copy_link),
                        )
                    }
                    IconButton(
                        onClick = { onShare(displayName) },
                        enabled = canShareOrCopy,
                        modifier = Modifier.testTag(ProfileTestTags.PUBLIC_SHARE),
                    ) {
                        Icon(
                            Icons.Outlined.Share,
                            contentDescription = stringResource(R.string.cd_share_profile),
                        )
                    }
                },
            )
        },
    ) {
        when (state) {
            is PublicProfileUiState.Loading ->
                LoadingState(modifier = Modifier.testTag(ProfileTestTags.PUBLIC_LOADING))

            is PublicProfileUiState.Content ->
                PublicContent(
                    profile = state.profile,
                    isStale = state.isStale,
                    isAuthenticated = isAuthenticated,
                    tipTotalOverride = tipTotalOverride,
                    onTipCreator = onTipCreator,
                    onRetry = onRetry,
                    onOpenFanClub = onOpenFanClub,
                    onSubscribe = onSubscribe,
                    onSignIn = onSignIn,
                )

            is PublicProfileUiState.NotFound ->
                // AND-390: the not-found surface folds private/suppressed (both 404). Signing in may
                // reveal a profile suppressed from anonymous viewers, so offer the Sign-in CTA here.
                EmptyState(
                    title = stringResource(R.string.profile_public_not_found_title),
                    body = stringResource(R.string.profile_public_not_found_body),
                    actionLabel = if (!isAuthenticated) stringResource(R.string.sign_in_cta) else null,
                    onAction = if (!isAuthenticated) onSignIn else null,
                    modifier = Modifier.testTag(ProfileTestTags.PUBLIC_NOT_FOUND),
                )

            is PublicProfileUiState.RateLimited ->
                EmptyState(
                    title = stringResource(R.string.profile_public_rate_limited_title),
                    body = stringResource(R.string.profile_public_rate_limited_body),
                    actionLabel = stringResource(R.string.action_retry),
                    onAction = onRetry,
                    modifier = Modifier.testTag(ProfileTestTags.PUBLIC_RATE_LIMITED),
                )

            is PublicProfileUiState.Error ->
                ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(ProfileTestTags.PUBLIC_ERROR),
                )
        }
    }
}

@Composable
private fun PublicContent(
    profile: PublicProfile,
    isStale: Boolean,
    isAuthenticated: Boolean,
    tipTotalOverride: Int? = null,
    onTipCreator: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    onRetry: () -> Unit,
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    onSubscribe: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    onSignIn: () -> Unit = {},
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .testTag(ProfileTestTags.PUBLIC_CONTENT),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (isStale) {
            StaleBanner(
                stale = true,
                refreshing = false,
                onRetry = onRetry,
                modifier = Modifier.testTag(ProfileTestTags.PUBLIC_STALE_BANNER),
            )
        }
        Box(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            contentAlignment = Alignment.Center,
        ) {
            AsyncImage(
                model = profile.profilePhotoUrl,
                contentDescription = stringResource(
                    R.string.profile_public_avatar_cd,
                    profile.displayName.ifBlank { profile.identifier },
                ),
                modifier = Modifier.size(96.dp),
            )
        }
        ProfileHeader(
            displayName = profile.displayName,
            title = profile.title,
            location = profile.location,
            description = profile.description,
            fallbackName = profile.identifier,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        StatsRow(profile = profile, modifier = Modifier.padding(horizontal = 16.dp))

        val supportCents = maxOf(profile.tipTotalCents, tipTotalOverride ?: 0)
        if (supportCents > 0) {
            Text(
                text = "Tips received · $" + String.format(java.util.Locale.US, "%.2f", supportCents / 100.0),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 16.dp).testTag("public_tip_total"),
            )
        }

        // AND-390: auth-only affordances (fan-club, report) are HIDDEN (not disabled) when signed out;
        // the unauthenticated viewer instead gets a non-blocking Sign-in CTA (FR-7/FR-8).
        if (isAuthenticated) {
            Button(
                onClick = { onTipCreator(profile.identifier, profile.displayName) },
                modifier = Modifier
                    .padding(horizontal = 16.dp)
                    .fillMaxWidth()
                    .testTag(ProfileTestTags.PUBLIC_TIP),
            ) {
                Text(stringResource(R.string.profile_public_tip_creator))
            }

            // SUBX-24: organic Subscribe entry -> the creator's subscription tiers.
            Button(
                onClick = { onSubscribe(profile.userId, profile.displayName) },
                modifier = Modifier
                    .padding(horizontal = 16.dp)
                    .fillMaxWidth()
                    .testTag(ProfileTestTags.PUBLIC_SUBSCRIBE),
            ) {
                Text(stringResource(R.string.profile_public_subscribe))
            }

            // AND-238: entry point into this creator's fan-club channels.
            OutlinedButton(
                onClick = { onOpenFanClub(profile.userId, profile.displayName) },
                modifier = Modifier
                    .padding(horizontal = 16.dp)
                    .fillMaxWidth()
                    .testTag(ProfileTestTags.PUBLIC_OPEN_FANCLUB),
            ) {
                Text(stringResource(R.string.profile_public_open_fanclub))
            }

            // AND-383: reuse the cross-cutting report flow as a real USER call site.
            var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
            OutlinedButton(
                onClick = { reportTarget = ReportTarget.User(profile.userId, profile.displayName) },
                modifier = Modifier
                    .padding(horizontal = 16.dp)
                    .fillMaxWidth()
                    .testTag(ProfileTestTags.PUBLIC_REPORT_USER),
            ) {
                Text(stringResource(R.string.msg_action_report))
            }
            // MODX-7 — route through the SAME host every other surface uses (consistent wiring +
            // report_* tags). USER targets get no licensing/DMCA entry (a profile is not a copyright
            // claim surface); the host enforces that.
            ContentReportSheetHost(
                target = reportTarget,
                onDismiss = { reportTarget = null },
            )

            // P0-BLOCK: block / unblock this user, on the same surface as report. Uses the shared
            // BlockInteractionViewModel (hydrated with the viewed user) + shared confirm dialog.
            val blockVm: BlockInteractionViewModel = hiltViewModel()
            val blockState by blockVm.uiState.collectAsStateWithLifecycle()
            LaunchedEffect(profile.userId) { blockVm.hydrate(profile.userId, profile.identifier) }
            OutlinedButton(
                onClick = {
                    if (blockState.blockedByMe) blockVm.onUnblock() else blockVm.onBlockRequested()
                },
                enabled = !blockState.inFlight,
                modifier = Modifier
                    .padding(horizontal = 16.dp)
                    .fillMaxWidth()
                    .testTag("public_block_user"),
            ) {
                Text(
                    if (blockState.blockedByMe) stringResource(R.string.unblock_action)
                    else stringResource(R.string.block_action, profile.identifier),
                )
            }
            if (blockState.confirmVisible) {
                BlockConfirmDialog(
                    title = stringResource(R.string.block_confirm_title, profile.identifier),
                    body = stringResource(R.string.block_confirm_body),
                    confirmLabel = stringResource(R.string.block_confirm_cta),
                    dismissLabel = stringResource(R.string.block_confirm_cancel),
                    onConfirm = blockVm::onBlockConfirmed,
                    onDismiss = blockVm::onBlockDismissed,
                )
            }
        } else {
            Button(
                onClick = onSignIn,
                modifier = Modifier
                    .padding(horizontal = 16.dp)
                    .fillMaxWidth()
                    .testTag(ProfileTestTags.PUBLIC_SIGN_IN_CTA),
            ) {
                Icon(Icons.Filled.Login, contentDescription = null)
                Text(
                    text = stringResource(R.string.sign_in_cta),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun StatsRow(profile: PublicProfile, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceEvenly,
    ) {
        StatItem(profile.followerCount, stringResource(R.string.profile_stat_followers))
        StatItem(profile.followingCount, stringResource(R.string.profile_stat_following))
        StatItem(profile.postCount, stringResource(R.string.profile_stat_posts))
    }
}

@Composable
private fun StatItem(count: Int, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(text = count.toString(), style = MaterialTheme.typography.titleMedium)
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}
