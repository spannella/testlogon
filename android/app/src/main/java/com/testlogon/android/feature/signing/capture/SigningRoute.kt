package com.testlogon.android.feature.signing.capture

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.document.DocumentViewerRoute
import com.testlogon.android.feature.signing.document.model.PageOnScreen

/**
 * AND-342 - route-level capture + placement surface. Hosts the AND-341 [DocumentViewerRoute] (which
 * renders + scrolls the PDF and reports per-page geometry via onPageLayout) and overlays the AND-342
 * field boxes + progress + Continue on top. A full-screen [SignaturePadScreen] is shown when the user
 * taps an unsatisfied signature / initials field with no captured asset yet.
 *
 * The captured [SignedPacketDraft] is handed to AND-343 via [onContinueToSubmit]; there is NO network
 * submit here.
 */
@Composable
fun SigningRoute(
    onBack: () -> Unit,
    onContinueToSubmit: (SignedPacketDraft) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SigningViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var pages by remember { mutableStateOf<List<PageOnScreen>>(emptyList()) }
    var showPad by remember { mutableStateOf(false) }

    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is SigningEvent.ContinueToSubmit -> onContinueToSubmit(event.draft)
            }
        }
    }

    val editing = state as? SigningUiState.Editing

    if (showPad) {
        SignaturePadScreen(
            hasSaved = editing?.savedAsset != null,
            onBack = { showPad = false },
            onStrokesConfirmed = { strokes ->
                viewModel.onStrokesConfirmed(strokes)
                showPad = false
            },
            onTypedConfirmed = { text, fontIndex ->
                viewModel.onTypedConfirmed(text, fontIndex)
                showPad = false
            },
            onUseSaved = {
                viewModel.onUseSaved()
                showPad = false
            },
            modifier = modifier,
        )
        return
    }

    Box(modifier = modifier.fillMaxSize()) {
        // AND-341 viewer renders the PDF + reports per-page geometry; we do NOT re-render the PDF.
        DocumentViewerRoute(
            onBack = onBack,
            onPageLayout = { pages = it },
            modifier = Modifier.fillMaxSize(),
        )

        when (val s = state) {
            is SigningUiState.Loading -> SigningOverlayLoading()
            is SigningUiState.Editing -> SigningPlacementOverlay(
                pages = pages,
                fields = s.fields,
                placements = s.placements,
                requiredDone = s.requiredDone,
                requiredTotal = s.requiredTotal,
                isComplete = s.isComplete,
                onFieldTap = { fieldId ->
                    val field = s.fields.firstOrNull { it.id == fieldId }
                    val needsCapture = field != null &&
                        (field.type == FieldType.SIGNATURE || field.type == FieldType.INITIALS)
                    if (needsCapture && s.asset == null) {
                        showPad = true
                    } else {
                        viewModel.placeField(fieldId)
                    }
                },
                onClearField = viewModel::clearField,
                onContinue = viewModel::onContinue,
            )
            is SigningUiState.Error -> Unit
        }
    }
}
