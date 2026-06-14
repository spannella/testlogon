package com.testlogon.android.feature.profile.edit

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.core.ui.scaffold.TlScaffold
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.profile.ProfileTestTags

/** AND-072 — route-level edit-profile entry. */
@Composable
fun EditProfileRoute(
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: EditProfileViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    var showDiscard by remember { mutableStateOf(false) }

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is EditProfileEffect.NavigateBack -> onNavigateBack()
                is EditProfileEffect.ConfirmDiscard -> showDiscard = true
                is EditProfileEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    EditProfileScreen(
        state = state,
        onDisplayNameChange = viewModel::onDisplayNameChange,
        onDescriptionChange = viewModel::onDescriptionChange,
        onTitleChange = viewModel::onTitleChange,
        onLocationChange = viewModel::onLocationChange,
        onSave = viewModel::onSave,
        onBack = viewModel::onBackPressed,
        onRetryLoad = viewModel::onRetryLoad,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )

    if (showDiscard) {
        AlertDialog(
            onDismissRequest = { showDiscard = false },
            title = { Text(stringResource(R.string.profile_edit_discard_title)) },
            text = { Text(stringResource(R.string.profile_edit_discard_body)) },
            confirmButton = {
                TextButton(onClick = { showDiscard = false; onNavigateBack() }) {
                    Text(stringResource(R.string.profile_edit_discard_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDiscard = false }) {
                    Text(stringResource(R.string.profile_edit_discard_cancel))
                }
            },
            modifier = Modifier.testTag(ProfileTestTags.EDIT_DISCARD_DIALOG),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditProfileScreen(
    state: EditProfileUiState,
    onDisplayNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onTitleChange: (String) -> Unit,
    onLocationChange: (String) -> Unit,
    onSave: () -> Unit,
    onBack: () -> Unit,
    onRetryLoad: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    // Intercept system back while there are unsaved changes so the VM can prompt to discard.
    BackHandler(enabled = state.isDirty) { onBack() }

    TlScaffold(
        modifier = modifier.testTag(ProfileTestTags.EDIT_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.profile_edit_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("edit_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        snackbarHostState = snackbarHostState,
    ) {
        when (state.phase) {
            EditProfileUiState.Phase.Loading ->
                LoadingState(modifier = Modifier.testTag(ProfileTestTags.EDIT_SCREEN + "_loading"))

            EditProfileUiState.Phase.Error ->
                ErrorState(message = state.loadError.orEmpty(), onRetry = onRetryLoad)

            EditProfileUiState.Phase.Editing ->
                EditForm(
                    state = state,
                    onDisplayNameChange = onDisplayNameChange,
                    onDescriptionChange = onDescriptionChange,
                    onTitleChange = onTitleChange,
                    onLocationChange = onLocationChange,
                    onSave = onSave,
                )
        }
    }
}

@Composable
private fun EditForm(
    state: EditProfileUiState,
    onDisplayNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onTitleChange: (String) -> Unit,
    onLocationChange: (String) -> Unit,
    onSave: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        TlTextField(
            value = state.form.displayName,
            onValueChange = onDisplayNameChange,
            label = stringResource(R.string.profile_edit_display_name),
            errorText = state.errors.displayName?.let { stringResource(it) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            modifier = Modifier.testTag(ProfileTestTags.EDIT_DISPLAY_NAME),
        )
        TlTextField(
            value = state.form.title,
            onValueChange = onTitleChange,
            label = stringResource(R.string.profile_edit_title_field),
            errorText = state.errors.title?.let { stringResource(it) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            modifier = Modifier.testTag(ProfileTestTags.EDIT_TITLE),
        )
        TlTextField(
            value = state.form.location,
            onValueChange = onLocationChange,
            label = stringResource(R.string.profile_edit_location),
            errorText = state.errors.location?.let { stringResource(it) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            modifier = Modifier.testTag(ProfileTestTags.EDIT_LOCATION),
        )
        TlTextField(
            value = state.form.description,
            onValueChange = onDescriptionChange,
            label = stringResource(R.string.profile_edit_description),
            errorText = state.errors.description?.let { stringResource(it) },
            helperText = "${state.form.description.length}/${ProfileValidator.MAX_DESCRIPTION}",
            singleLine = false,
            modifier = Modifier.testTag(ProfileTestTags.EDIT_DESCRIPTION),
        )
        if (state.saveError != null) {
            Text(
                text = state.saveError,
                color = MaterialTheme.colorScheme.error,
            )
        }
        TlButton(
            text = stringResource(R.string.profile_edit_save),
            onClick = onSave,
            enabled = state.canSave,
            loading = state.isSaving,
            modifier = Modifier.fillMaxWidth().testTag(ProfileTestTags.EDIT_SAVE),
        )
    }
}
