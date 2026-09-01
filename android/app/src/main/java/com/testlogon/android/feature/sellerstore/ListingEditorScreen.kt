@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sellerstore

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.AddPhotoAlternate
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.LoadingState

/** ECOM (seller store) — stable test tags for the listing editor. */
object ListingEditorTestTags {
    const val SCREEN = "listing_editor_screen"
    const val NAME = "listing_name_input"
    const val DESCRIPTION = "listing_description_input"
    const val PRICE = "listing_price_input"
    const val STOCK = "listing_stock_input"
    const val PICK_IMAGE = "listing_pick_image"
    const val SAVE = "listing_save"
    const val DELETE = "listing_delete"
    const val ADVANCED_DEPTH = "listing_advanced_depth"

    /** LIVECOM L5 — the seller-set affiliate commission percent field. */
    const val AFFILIATE_COMMISSION = "listing_affiliate_commission_input"
}

@Composable
fun ListingEditorRoute(
    onDone: () -> Unit,
    onBack: () -> Unit,
    onOpenDepth: (itemId: String, itemName: String) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier,
    viewModel: ListingEditorViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) viewModel.onImagePicked(uri)
    }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ListingEditorEvent.Saved -> onDone()
                is ListingEditorEvent.Deleted -> onDone()
                is ListingEditorEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    ListingEditorScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onName = viewModel::onNameChange,
        onDescription = viewModel::onDescriptionChange,
        onPrice = viewModel::onPriceChange,
        onStock = viewModel::onStockChange,
        onCommission = viewModel::onCommissionChange,
        onPickImage = { picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
        onSave = viewModel::save,
        onDelete = viewModel::deleteListing,
        onOpenDepth = { state.savedItemId?.let { onOpenDepth(it, state.name) } },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun ListingEditorScreen(
    state: ListingEditorUiState,
    snackbarHostState: SnackbarHostState,
    onName: (String) -> Unit,
    onDescription: (String) -> Unit,
    onPrice: (String) -> Unit,
    onStock: (String) -> Unit,
    onCommission: (String) -> Unit = {},
    onPickImage: () -> Unit,
    onSave: () -> Unit,
    onDelete: () -> Unit,
    onOpenDepth: () -> Unit = {},
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ListingEditorTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    Text(stringResource(if (state.isNew) R.string.listing_editor_new_title else R.string.listing_editor_edit_title))
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
                actions = {
                    if (!state.isNew) {
                        IconButton(onClick = onDelete, modifier = Modifier.testTag(ListingEditorTestTags.DELETE)) {
                            Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.listing_delete))
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        if (state.loading) {
            Box(Modifier.fillMaxSize().padding(padding)) { LoadingState() }
            return@Scaffold
        }
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ImagePicker(
                imageUrl = state.imageUrl,
                pendingUri = state.pendingImageUri?.toString(),
                uploading = state.uploadingImage,
                onPick = onPickImage,
            )
            OutlinedTextField(
                value = state.name,
                onValueChange = onName,
                label = { Text(stringResource(R.string.listing_name)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(ListingEditorTestTags.NAME),
            )
            OutlinedTextField(
                value = state.description,
                onValueChange = onDescription,
                label = { Text(stringResource(R.string.listing_description)) },
                modifier = Modifier.fillMaxWidth().testTag(ListingEditorTestTags.DESCRIPTION),
            )
            OutlinedTextField(
                value = state.priceText,
                onValueChange = onPrice,
                label = { Text(stringResource(R.string.listing_price)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag(ListingEditorTestTags.PRICE),
            )
            OutlinedTextField(
                value = state.stockText,
                onValueChange = onStock,
                label = { Text(stringResource(R.string.listing_stock)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth().testTag(ListingEditorTestTags.STOCK),
            )
            // LIVECOM L5 — the seller-set affiliate commission a host earns for selling this listing via a
            // live stream (percent). Only meaningful for an existing/saved listing (needs an item id).
            if (!state.isNew) {
                OutlinedTextField(
                    value = state.affiliateCommissionText,
                    onValueChange = onCommission,
                    label = { Text("Affiliate commission %") },
                    supportingText = { Text("What a host earns for selling this via their live stream (e.g. 10 = 10%).") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag(ListingEditorTestTags.AFFILIATE_COMMISSION),
                )
            }
            Button(
                onClick = onSave,
                enabled = state.canSave,
                modifier = Modifier.fillMaxWidth().testTag(ListingEditorTestTags.SAVE),
            ) {
                if (state.saving) {
                    CircularProgressIndicator(Modifier.height(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.listing_save))
                }
            }
            if (state.canOpenDepth) {
                OutlinedButton(
                    onClick = onOpenDepth,
                    modifier = Modifier.fillMaxWidth().testTag(ListingEditorTestTags.ADVANCED_DEPTH),
                ) {
                    Icon(Icons.Outlined.Tune, contentDescription = null)
                    Text("  Advanced product options")
                }
            }
        }
    }
}

@Composable
private fun ImagePicker(
    imageUrl: String?,
    pendingUri: String?,
    uploading: Boolean,
    onPick: () -> Unit,
) {
    val model = pendingUri ?: imageUrl
    Box(
        Modifier
            .fillMaxWidth()
            .height(180.dp)
            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(12.dp)),
        contentAlignment = Alignment.Center,
    ) {
        if (model != null) {
            SubcomposeAsyncImage(
                model = ImageRequest.Builder(LocalContext.current).data(model).crossfade(true).build(),
                contentDescription = stringResource(R.string.listing_image),
                modifier = Modifier.fillMaxSize(),
            )
        }
        if (uploading) {
            CircularProgressIndicator()
        } else {
            OutlinedButton(onClick = onPick, modifier = Modifier.testTag(ListingEditorTestTags.PICK_IMAGE)) {
                Icon(Icons.Outlined.AddPhotoAlternate, contentDescription = null)
                Text("  " + stringResource(R.string.listing_pick_image))
            }
        }
    }
}
