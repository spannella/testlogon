@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.create.creative

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdCampaign

/** ADV-109 - stable testTags for the create-creative screen. */
object CreateCreativeTestTags {
    const val SCREEN = "create_creative_screen"
    const val ACCOUNT = "create_creative_account"
    const val CAMPAIGN = "create_creative_campaign"
    const val FORMAT = "create_creative_format"
    const val TITLE = "create_creative_title"
    const val CTA_URL = "create_creative_cta_url"
    const val PICK_IMAGE = "create_creative_pick_image"
    const val SUBMIT = "create_creative_submit"
    const val SUCCESS = "create_creative_success"
    const val REVIEW = "create_creative_review"
}

/** ADV-109 - route-level create-creative entry. */
@Composable
fun CreateCreativeRoute(
    onBack: () -> Unit,
    onDone: () -> Unit,
    viewModel: CreateCreativeViewModel = hiltViewModel(),
) {
    val accounts by viewModel.accountsState.collectAsStateWithLifecycle()
    val campaigns by viewModel.campaignsState.collectAsStateWithLifecycle()
    val selectedAccount by viewModel.selectedAccountId.collectAsStateWithLifecycle()
    val selectedCampaign by viewModel.selectedCampaignId.collectAsStateWithLifecycle()
    val format by viewModel.format.collectAsStateWithLifecycle()
    val title by viewModel.title.collectAsStateWithLifecycle()
    val headline by viewModel.headline.collectAsStateWithLifecycle()
    val body by viewModel.body.collectAsStateWithLifecycle()
    val ctaText by viewModel.ctaText.collectAsStateWithLifecycle()
    val ctaUrl by viewModel.ctaUrl.collectAsStateWithLifecycle()
    val imageUri by viewModel.imageUri.collectAsStateWithLifecycle()
    val imageProcessing by viewModel.imageProcessing.collectAsStateWithLifecycle()
    val createState by viewModel.createState.collectAsStateWithLifecycle()
    val reviewState by viewModel.reviewState.collectAsStateWithLifecycle()

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) viewModel.onImagePicked(uri)
    }

    CreateCreativeScreen(
        accounts = accounts,
        campaigns = campaigns,
        selectedAccountId = selectedAccount,
        selectedCampaignId = selectedCampaign,
        format = format,
        title = title,
        headline = headline,
        body = body,
        ctaText = ctaText,
        ctaUrl = ctaUrl,
        imageUri = imageUri?.toString(),
        imageProcessing = imageProcessing,
        createState = createState,
        reviewState = reviewState,
        canSubmit = viewModel.canSubmit,
        onAccount = viewModel::onAccountSelected,
        onCampaign = viewModel::onCampaignSelected,
        onFormat = viewModel::onFormat,
        onTitle = viewModel::onTitle,
        onHeadline = viewModel::onHeadline,
        onBody = viewModel::onBody,
        onCtaText = viewModel::onCtaText,
        onCtaUrl = viewModel::onCtaUrl,
        onPickImage = {
            picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
        },
        onSubmit = viewModel::submit,
        onSubmitForReview = viewModel::submitForReview,
        onDone = onDone,
        onBack = onBack,
    )
}

/** ADV-109 - stateless create-creative form. */
@Composable
fun CreateCreativeScreen(
    accounts: CreateCreativeViewModel.AccountsState,
    campaigns: CreateCreativeViewModel.CampaignsState,
    selectedAccountId: String?,
    selectedCampaignId: String?,
    format: String,
    title: String,
    headline: String,
    body: String,
    ctaText: String,
    ctaUrl: String,
    imageUri: String?,
    imageProcessing: Boolean,
    createState: CreateCreativeViewModel.CreateState,
    reviewState: CreateCreativeViewModel.ReviewState,
    canSubmit: Boolean,
    onAccount: (String) -> Unit,
    onCampaign: (String) -> Unit,
    onFormat: (String) -> Unit,
    onTitle: (String) -> Unit,
    onHeadline: (String) -> Unit,
    onBody: (String) -> Unit,
    onCtaText: (String) -> Unit,
    onCtaUrl: (String) -> Unit,
    onPickImage: () -> Unit,
    onSubmit: () -> Unit,
    onSubmitForReview: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val submitting = createState is CreateCreativeViewModel.CreateState.Submitting
    Scaffold(
        modifier = modifier.testTag(CreateCreativeTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.create_creative_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ads_create_back),
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
            (createState as? CreateCreativeViewModel.CreateState.Success)?.let {
                CreativeCreatedCard(
                    reviewState = reviewState,
                    onSubmitForReview = onSubmitForReview,
                    onDone = onDone,
                )
                return@Column
            }

            LabeledDropdown(
                label = stringResource(R.string.create_creative_account_label),
                selectedLabel = (accounts as? CreateCreativeViewModel.AccountsState.Content)
                    ?.accounts?.firstOrNull { it.accountId == selectedAccountId }?.label()
                    ?: accountsPlaceholder(accounts),
                options = (accounts as? CreateCreativeViewModel.AccountsState.Content)
                    ?.accounts?.mapNotNull { acc -> acc.accountId?.let { it to acc.label() } }
                    ?: emptyList(),
                onSelect = onAccount,
                enabled = !submitting,
                testTag = CreateCreativeTestTags.ACCOUNT,
            )

            LabeledDropdown(
                label = stringResource(R.string.create_creative_campaign_label),
                selectedLabel = (campaigns as? CreateCreativeViewModel.CampaignsState.Content)
                    ?.campaigns?.firstOrNull { it.campaignId == selectedCampaignId }?.label()
                    ?: campaignsPlaceholder(campaigns),
                options = (campaigns as? CreateCreativeViewModel.CampaignsState.Content)
                    ?.campaigns?.map { it.campaignId to it.label() } ?: emptyList(),
                onSelect = onCampaign,
                enabled = !submitting,
                testTag = CreateCreativeTestTags.CAMPAIGN,
            )

            LabeledDropdown(
                label = stringResource(R.string.create_creative_format_label),
                selectedLabel = format,
                options = CreateCreativeViewModel.FORMATS.map { it to it },
                onSelect = onFormat,
                enabled = !submitting,
                testTag = CreateCreativeTestTags.FORMAT,
            )

            OutlinedTextField(
                value = title,
                onValueChange = onTitle,
                label = { Text(stringResource(R.string.create_creative_title_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(CreateCreativeTestTags.TITLE),
            )
            OutlinedTextField(
                value = headline,
                onValueChange = onHeadline,
                label = { Text(stringResource(R.string.create_creative_headline_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = body,
                onValueChange = onBody,
                label = { Text(stringResource(R.string.create_creative_body_label)) },
                enabled = !submitting,
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = ctaText,
                onValueChange = onCtaText,
                label = { Text(stringResource(R.string.create_creative_cta_text_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = ctaUrl,
                onValueChange = onCtaUrl,
                label = { Text(stringResource(R.string.create_creative_cta_url_label)) },
                singleLine = true,
                enabled = !submitting,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth().testTag(CreateCreativeTestTags.CTA_URL),
            )

            if (imageUri != null) {
                AsyncImage(
                    model = ImageRequest.Builder(LocalContext.current).data(imageUri).crossfade(true).build(),
                    contentDescription = stringResource(R.string.create_creative_image_preview),
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.fillMaxWidth().height(160.dp),
                )
            }
            OutlinedButton(
                onClick = onPickImage,
                enabled = !submitting && !imageProcessing,
                modifier = Modifier.fillMaxWidth().testTag(CreateCreativeTestTags.PICK_IMAGE),
            ) {
                if (imageProcessing) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(
                    stringResource(
                        if (imageUri != null) R.string.create_creative_change_image
                        else R.string.create_creative_pick_image,
                    ),
                )
            }

            (createState as? CreateCreativeViewModel.CreateState.Error)?.let {
                Text(it.message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }

            Button(
                onClick = onSubmit,
                enabled = canSubmit && !submitting,
                modifier = Modifier.fillMaxWidth().testTag(CreateCreativeTestTags.SUBMIT),
            ) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.create_creative_submit))
            }
        }
    }
}

@Composable
private fun CreativeCreatedCard(
    reviewState: CreateCreativeViewModel.ReviewState,
    onSubmitForReview: () -> Unit,
    onDone: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CreateCreativeTestTags.SUCCESS)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(stringResource(R.string.create_creative_success_title), style = MaterialTheme.typography.titleMedium)
            when (reviewState) {
                is CreateCreativeViewModel.ReviewState.Done -> Text(
                    stringResource(R.string.create_creative_review_done, reviewState.status),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                is CreateCreativeViewModel.ReviewState.Error -> Text(
                    reviewState.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
                else -> Text(
                    stringResource(R.string.create_creative_success_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val reviewing = reviewState is CreateCreativeViewModel.ReviewState.Submitting
            val reviewed = reviewState is CreateCreativeViewModel.ReviewState.Done
            Button(
                onClick = onSubmitForReview,
                enabled = !reviewing && !reviewed,
                modifier = Modifier.fillMaxWidth().testTag(CreateCreativeTestTags.REVIEW),
            ) {
                if (reviewing) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.create_creative_review))
            }
            OutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.create_creative_done))
            }
        }
    }
}

@Composable
private fun LabeledDropdown(
    label: String,
    selectedLabel: String,
    options: List<Pair<String, String>>,
    onSelect: (String) -> Unit,
    enabled: Boolean,
    testTag: String,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = selectedLabel,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            enabled = enabled,
            modifier = Modifier
                .menuAnchor()
                .fillMaxWidth()
                .testTag(testTag),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { (value, optLabel) ->
                DropdownMenuItem(
                    text = { Text(optLabel) },
                    onClick = {
                        onSelect(value)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun accountsPlaceholder(state: CreateCreativeViewModel.AccountsState): String = when (state) {
    is CreateCreativeViewModel.AccountsState.Loading -> stringResource(R.string.create_campaign_account_loading)
    is CreateCreativeViewModel.AccountsState.Empty -> stringResource(R.string.create_campaign_account_none)
    is CreateCreativeViewModel.AccountsState.Error -> state.message
    is CreateCreativeViewModel.AccountsState.Content -> stringResource(R.string.create_campaign_account_hint)
}

@Composable
private fun campaignsPlaceholder(state: CreateCreativeViewModel.CampaignsState): String = when (state) {
    is CreateCreativeViewModel.CampaignsState.Idle -> stringResource(R.string.create_creative_campaign_hint)
    is CreateCreativeViewModel.CampaignsState.Loading -> stringResource(R.string.create_campaign_account_loading)
    is CreateCreativeViewModel.CampaignsState.Empty -> stringResource(R.string.create_creative_campaign_none)
    is CreateCreativeViewModel.CampaignsState.Error -> state.message
    is CreateCreativeViewModel.CampaignsState.Content -> stringResource(R.string.create_creative_campaign_hint)
}

private fun AdAccountSummary.label(): String {
    val name = companyName ?: accountId ?: "account"
    val status = status?.takeIf { it.isNotBlank() }
    return if (status != null) "$name ($status)" else name
}

private fun AdCampaign.label(): String = name ?: campaignId
