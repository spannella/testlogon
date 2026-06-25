@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.apikeys.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/** B-APIKEY (batch 7) - stable testTags for the create-API-key screen. */
object CreateApiKeyTestTags {
    const val SCREEN = "api_keys_create_screen"
    const val LABEL_FIELD = "api_keys_create_label"
    const val SCOPES_FIELD = "api_keys_create_scopes"
    const val EXPIRES_FIELD = "api_keys_create_expires"
    const val SUBMIT = "api_keys_create_submit"
}

/**
 * B-APIKEY (batch 7) - route-level entry for the create screen. Collects the form, wires CreateSucceeded to a
 * back-pop carrying the one-time secret (the list shows it once) and NavigateToLogin to the re-auth handoff.
 */
@Composable
fun CreateApiKeyRoute(
    onBack: () -> Unit,
    onCreated: (secret: String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: CreateApiKeyViewModel = hiltViewModel(),
) {
    val form by viewModel.form.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ApiKeysEffect.CreateSucceeded -> onCreated(effect.secret)
                is ApiKeysEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    CreateApiKeyScreen(
        form = form,
        onBack = onBack,
        onLabelChange = viewModel::onLabelChange,
        onCapabilitiesChange = viewModel::onCapabilitiesChange,
        onExpiresChange = viewModel::onExpiresChange,
        onSubmit = viewModel::submit,
    )
}

/** B-APIKEY (batch 7) - stateless create form (label + optional scopes + optional expiry-days + gated submit). */
@Composable
fun CreateApiKeyScreen(
    form: CreateApiKeyForm,
    onBack: () -> Unit,
    onLabelChange: (String) -> Unit,
    onCapabilitiesChange: (String) -> Unit,
    onExpiresChange: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CreateApiKeyTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.api_keys_create_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.api_keys_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            val labelError = form.labelError
            OutlinedTextField(
                value = form.label,
                onValueChange = onLabelChange,
                label = { Text(stringResource(R.string.api_keys_create_label_label)) },
                placeholder = { Text(stringResource(R.string.api_keys_create_label_placeholder)) },
                singleLine = true,
                isError = labelError != null,
                supportingText = {
                    if (labelError != null) Text(labelError)
                    else Text(stringResource(R.string.api_keys_create_label_hint))
                },
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.LABEL_FIELD)
                    .then(if (labelError != null) Modifier.semantics { error(labelError) } else Modifier),
            )

            OutlinedTextField(
                value = form.capabilityInput,
                onValueChange = onCapabilitiesChange,
                label = { Text(stringResource(R.string.api_keys_create_scopes_label)) },
                placeholder = { Text(stringResource(R.string.api_keys_create_scopes_placeholder)) },
                singleLine = true,
                supportingText = { Text(stringResource(R.string.api_keys_create_scopes_hint)) },
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.SCOPES_FIELD),
            )

            OutlinedTextField(
                value = form.expiresInDays,
                onValueChange = onExpiresChange,
                label = { Text(stringResource(R.string.api_keys_create_expires_label)) },
                placeholder = { Text(stringResource(R.string.api_keys_create_expires_placeholder)) },
                singleLine = true,
                supportingText = { Text(stringResource(R.string.api_keys_create_expires_hint)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.EXPIRES_FIELD),
            )

            if (form.submitError != null) {
                Text(
                    text = form.submitError,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = form.canSubmit && !form.submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateApiKeyTestTags.SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.heightIn(max = 20.dp))
                } else {
                    Text(stringResource(R.string.api_keys_create_submit))
                }
            }
        }
    }
}
