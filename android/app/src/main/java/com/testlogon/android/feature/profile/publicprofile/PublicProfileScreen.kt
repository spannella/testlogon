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
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.model.profile.PublicProfile
import com.testlogon.android.core.ui.scaffold.TlScaffold
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.feature.profile.ProfileTestTags
import com.testlogon.android.feature.profile.components.ProfileHeader

/** AND-073 — route-level public-profile entry for /u/{identifier}. */
@Composable
fun PublicProfileRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    viewModel: PublicProfileViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PublicProfileScreen(
        state = state,
        identifier = viewModel.identifier,
        onRetry = viewModel::onRetry,
        onBack = onBack,
        onOpenFanClub = onOpenFanClub,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PublicProfileScreen(
    state: PublicProfileUiState,
    identifier: String,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier,
) {
    val title = (state as? PublicProfileUiState.Content)?.profile?.displayName
        ?.takeIf { it.isNotBlank() } ?: identifier
    TlScaffold(
        modifier = modifier.testTag(ProfileTestTags.PUBLIC_ROOT),
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
                    onRetry = onRetry,
                    onOpenFanClub = onOpenFanClub,
                )

            is PublicProfileUiState.NotFound ->
                EmptyState(
                    title = stringResource(R.string.profile_public_not_found_title),
                    body = stringResource(R.string.profile_public_not_found_body),
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
    onRetry: () -> Unit,
    onOpenFanClub: (creatorId: String, displayName: String?) -> Unit = { _, _ -> },
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
        // AND-238: entry point into this creator's fan-club channels.
        OutlinedButton(
            onClick = { onOpenFanClub(profile.userId, profile.displayName) },
            modifier = Modifier
                .padding(horizontal = 16.dp)
                .fillMaxWidth()
                .testTag("public_open_fanclub"),
        ) {
            Text(stringResource(R.string.profile_public_open_fanclub))
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
