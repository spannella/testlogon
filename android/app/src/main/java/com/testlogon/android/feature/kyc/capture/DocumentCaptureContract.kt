package com.testlogon.android.feature.kyc.capture

import androidx.annotation.StringRes
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.capture.model.KycDocument
import java.io.File

// AND-321 - UI state + supporting types for the KYC document capture+upload screen.

/**
 * A document slot the user captures. [wireType] is the FIXED server enum id (id_front | id_back); the
 * [label] is a static localized app string (the server has no template-page list per the contract).
 */
enum class DocType(val wireType: String, @StringRes val label: Int) {
    ID_FRONT("id_front", R.string.kyc_doc_type_id_front),
    ID_BACK("id_back", R.string.kyc_doc_type_id_back),
}

/** Per-image upload status, surfaced during the [DocumentCaptureUiState.Uploading] phase. */
data class ItemStatus(
    val docType: DocType,
    val state: ItemUploadState,
)

enum class ItemUploadState { PENDING, UPLOADING, SUCCEEDED, FAILED }

/** A confirmed, processed image ready to upload (and to show as a review thumbnail via Coil). */
data class ConfirmedImage(
    val docType: DocType,
    val file: File,
)

/** The sealed UI state for the document capture+upload flow. */
sealed interface DocumentCaptureUiState {

    /** Transient: processing a just-acquired image (decode/rotate/scale/encode off the main thread). */
    data object Loading : DocumentCaptureUiState

    /** Pick which document to capture next. [available] excludes already-confirmed slots. */
    data class SelectingType(val available: List<DocType>) : DocumentCaptureUiState

    /**
     * Review a freshly processed image for [docType] before confirming. [file] backs the Coil thumbnail.
     * [confirmedCount] / [totalCount] let the screen show progress through a multi-image flow.
     */
    data class Reviewing(
        val docType: DocType,
        val file: File,
        val confirmedCount: Int,
        val totalCount: Int,
    ) : DocumentCaptureUiState

    /** Uploading the confirmed images sequentially. [progress] is done/total in 0f..1f. */
    data class Uploading(
        val progress: Float,
        val perItem: List<ItemStatus>,
    ) : DocumentCaptureUiState

    /** All confirmed images uploaded; [document] is the LAST returned document. */
    data class Success(val document: KycDocument) : DocumentCaptureUiState

    /** A terminal-for-now error. [retryable] gates the retry affordance. */
    data class Error(val message: String, val retryable: Boolean) : DocumentCaptureUiState

    /** The CAMERA runtime permission is required. [permanentlyDenied] drives the open-settings path. */
    data class PermissionRequired(val permanentlyDenied: Boolean) : DocumentCaptureUiState
}
