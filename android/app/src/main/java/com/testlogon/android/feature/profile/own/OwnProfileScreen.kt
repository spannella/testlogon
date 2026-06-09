package com.testlogon.android.feature.profile.own

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.scaffold.TlScaffold
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.profile.MediaKind
import com.testlogon.android.feature.profile.AccountActionsSection
import com.testlogon.android.feature.profile.ProfileTestTags
import com.testlogon.android.feature.profile.components.ProfileDetailRows
import com.testlogon.android.feature.profile.components.ProfileHeader
import com.testlogon.android.feature.profile.media.MediaUploadEffect
import com.testlogon.android.feature.profile.media.ProfileMediaViewModel

/**
 * AND-071 — route-level own-profile entry wired into the Profile tab. Collects state lifecycle-aware,
 * routes the "Edit" effect to the edit screen, and lets the user replace their avatar via the system
 * Photo Picker (AND-074, gated gracefully when no picker handles the request).
 */
@Composable
fun OwnProfileRoute(
    onEditProfile: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenMfaDevices: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: OwnProfileViewModel = hiltViewModel(),
    mediaViewModel: ProfileMediaViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    val photoPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri -> if (uri != null) mediaViewModel.startUpload(MediaKind.AVATAR, uri) }

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is OwnProfileEffect.NavigateToEdit -> onEditProfile()
                is OwnProfileEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }
    LaunchedEffect(mediaViewModel) {
        mediaViewModel.effects.collect { effect ->
            when (effect) {
                is MediaUploadEffect.Uploaded -> viewModel.onRefresh()
                is MediaUploadEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    OwnProfileScreen(
        state = state,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onEdit = viewModel::onEditClicked,
        onChangePhoto = {
            photoPicker.launch(
                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly),
            )
        },
        onOpenSessions = onOpenSessions,
        onOpenMfaDevices = onOpenMfaDevices,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OwnProfileScreen(
    state: OwnProfileUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onEdit: () -> Unit,
    onChangePhoto: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenMfaDevices: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    accountActions: @Composable () -> Unit = {
        AccountActionsSection(onOpenSessions = onOpenSessions, onOpenMfaDevices = onOpenMfaDevices)
    },
) {
    TlScaffold(
        modifier = modifier.testTag(ProfileTestTags.OWN_SCREEN),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.profile_title)) }) },
        snackbarHostState = snackbarHostState,
    ) {
        PullToRefreshBox(
            isRefreshing = state.isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize(),
        ) {
            when (state.phase) {
                OwnProfileUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(ProfileTestTags.OWN_LOADING))

                OwnProfileUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage.orEmpty(),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(ProfileTestTags.OWN_ERROR),
                    )

                OwnProfileUiState.Phase.Content ->
                    OwnProfileContent(
                        profile = state.profile ?: Profile.EMPTY,
                        isStale = state.isStale,
                        isRefreshing = state.isRefreshing,
                        onRetry = onRetry,
                        onEdit = onEdit,
                        onChangePhoto = onChangePhoto,
                        accountActions = accountActions,
                    )
            }
        }
    }
}

@Composable
private fun OwnProfileContent(
    profile: Profile,
    isStale: Boolean,
    isRefreshing: Boolean,
    onRetry: () -> Unit,
    onEdit: () -> Unit,
    onChangePhoto: () -> Unit,
    accountActions: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .testTag(ProfileTestTags.OWN_CONTENT),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (isStale) {
            StaleBanner(
                stale = true,
                refreshing = isRefreshing,
                onRetry = onRetry,
                modifier = Modifier.testTag(ProfileTestTags.OWN_STALE_BANNER),
            )
        }
        Box(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            contentAlignment = Alignment.Center,
        ) {
            AsyncImage(
                model = profile.profilePhotoUrl,
                contentDescription = stringResource(R.string.profile_avatar_cd),
                modifier = Modifier
                    .size(96.dp)
                    .testTag(ProfileTestTags.OWN_AVATAR),
            )
        }
        ProfileHeader(
            displayName = profile.bestName,
            title = profile.title,
            location = profile.location,
            description = profile.description,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        ProfileDetailRows(
            email = profile.displayedEmail,
            phone = profile.displayedTelephoneNumber,
            languages = profile.languages,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            TlButton(
                text = stringResource(R.string.profile_edit_action),
                onClick = onEdit,
                modifier = Modifier.fillMaxWidth().testTag(ProfileTestTags.OWN_EDIT),
            )
            TlButton(
                text = stringResource(R.string.profile_change_photo),
                onClick = onChangePhoto,
                variant = TlButtonVariant.Secondary,
                modifier = Modifier.fillMaxWidth().testTag(ProfileTestTags.OWN_CHANGE_PHOTO),
            )
            accountActions()
        }
    }
}
