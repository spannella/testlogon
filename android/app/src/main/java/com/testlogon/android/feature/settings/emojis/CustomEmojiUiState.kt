package com.testlogon.android.feature.settings.emojis

/** Stable testTags for the custom-emoji settings screen. */
object CustomEmojiTestTags {
    const val SCREEN = "custom_emojis_screen"
    const val ERROR_RETRY = "custom_emojis_error_retry"
    const val SHORTCODE_INPUT = "custom_emojis_shortcode_input"
    const val NAME_INPUT = "custom_emojis_name_input"
    const val CATEGORY_INPUT = "custom_emojis_category_input"
    const val PICK_IMAGE = "custom_emojis_pick_image"
    const val UPLOAD = "custom_emojis_upload"

    fun card(shortcode: String) = "custom_emoji_card_$shortcode"
    fun delete(shortcode: String) = "custom_emoji_delete_$shortcode"
}

/**
 * Exhaustive UI state for the custom-emoji settings screen, mirroring the web CustomEmojisPage (personal scope):
 * an upload form + a grid of the caller's personal emojis (with delete). [Loading] first-load; [Content] the
 * list + the upload-form sub-state; [Error] the retry surface.
 */
sealed interface CustomEmojiUiState {

    data object Loading : CustomEmojiUiState

    data class Content(
        val emojis: List<CustomEmoji>,
        val personalCount: Int,
        val form: UploadForm = UploadForm(),
        val deletingId: String? = null,
        val message: String? = null,
    ) : CustomEmojiUiState

    data class Error(val message: String) : CustomEmojiUiState
}

/**
 * Upload-form sub-state. [pickedFileName] non-null once an image has been chosen (the actual bytes live in the VM
 * until submit). [canSubmit] is derived (a non-blank shortcode + a picked file).
 */
data class UploadForm(
    val shortcode: String = "",
    val name: String = "",
    val category: String = "Uncategorized",
    val altText: String = "",
    val pickedFileName: String? = null,
    val uploading: Boolean = false,
    val error: String? = null,
) {
    val canSubmit: Boolean get() = shortcode.isNotBlank() && pickedFileName != null && !uploading
}
