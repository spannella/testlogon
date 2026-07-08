package com.testlogon.android.feature.ads.create.creative

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdCreative
import com.testlogon.android.feature.ads.create.data.AdsCreateRepository
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import com.testlogon.android.feature.profile.media.ProfileImageProcessor
import com.testlogon.android.data.profile.ProfileMediaUploader
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV-109 - presentation logic for the CREATE-CREATIVE screen (format, title, headline, body, cta_text,
 * cta_url) + image asset upload (via the OS picker seam) -> POST ui/ads/campaigns/{cid}/creatives, POST
 * .../{crid}/upload, then submit-for-review.
 *
 * A REAL account+campaign PICKER chooses the target campaign (preselecting the studio [AdsStudioSelection]
 * account/campaign, or an optional campaignId nav arg). The primary action creates the draft creative and,
 * when an image was picked, uploads it; a second action submits it for admin review. Create/upload/submit are
 * NON-idempotent (in-flight guard, no auto-retry). The picked image is processed to JPEG (<=5MB, matching the
 * backend image whitelist) off the main thread before upload.
 */
@HiltViewModel
class CreateCreativeViewModel @Inject constructor(
    private val repository: AdsCreateRepository,
    private val selection: AdsStudioSelection,
    private val imageProcessor: ProfileImageProcessor,
    savedState: SavedStateHandle,
) : ViewModel() {

    sealed interface AccountsState {
        data object Loading : AccountsState
        data class Content(val accounts: List<AdAccountSummary>) : AccountsState
        data object Empty : AccountsState
        data class Error(val message: String) : AccountsState
    }

    sealed interface CampaignsState {
        data object Idle : CampaignsState
        data object Loading : CampaignsState
        data class Content(val campaigns: List<AdCampaign>) : CampaignsState
        data object Empty : CampaignsState
        data class Error(val message: String) : CampaignsState
    }

    sealed interface CreateState {
        data object Idle : CreateState
        data object Submitting : CreateState
        data class Success(val creative: AdCreative) : CreateState
        data class Error(val message: String) : CreateState
    }

    sealed interface ReviewState {
        data object Idle : ReviewState
        data object Submitting : ReviewState
        data class Done(val status: String) : ReviewState
        data class Error(val message: String) : ReviewState
    }

    private val navCampaignId: String? = savedState[ARG_CAMPAIGN_ID]

    private val _accountsState = MutableStateFlow<AccountsState>(AccountsState.Loading)
    val accountsState: StateFlow<AccountsState> = _accountsState.asStateFlow()

    private val _campaignsState = MutableStateFlow<CampaignsState>(CampaignsState.Idle)
    val campaignsState: StateFlow<CampaignsState> = _campaignsState.asStateFlow()

    private val _selectedAccountId = MutableStateFlow<String?>(null)
    val selectedAccountId: StateFlow<String?> = _selectedAccountId.asStateFlow()

    private val _selectedCampaignId = MutableStateFlow<String?>(navCampaignId ?: selection.selectedCampaignId)
    val selectedCampaignId: StateFlow<String?> = _selectedCampaignId.asStateFlow()

    private val _format = MutableStateFlow(FORMATS.first())
    val format: StateFlow<String> = _format.asStateFlow()

    private val _title = MutableStateFlow("")
    val title: StateFlow<String> = _title.asStateFlow()

    private val _headline = MutableStateFlow("")
    val headline: StateFlow<String> = _headline.asStateFlow()

    private val _body = MutableStateFlow("")
    val body: StateFlow<String> = _body.asStateFlow()

    private val _ctaText = MutableStateFlow("")
    val ctaText: StateFlow<String> = _ctaText.asStateFlow()

    private val _ctaUrl = MutableStateFlow("")
    val ctaUrl: StateFlow<String> = _ctaUrl.asStateFlow()

    /** Preview uri of the picked image (null until picked). */
    private val _imageUri = MutableStateFlow<Uri?>(null)
    val imageUri: StateFlow<Uri?> = _imageUri.asStateFlow()

    /** Whether an image is currently being decoded/processed. */
    private val _imageProcessing = MutableStateFlow(false)
    val imageProcessing: StateFlow<Boolean> = _imageProcessing.asStateFlow()

    private var preparedImage: ProfileMediaUploader.PreparedUpload? = null

    private val _createState = MutableStateFlow<CreateState>(CreateState.Idle)
    val createState: StateFlow<CreateState> = _createState.asStateFlow()

    private val _reviewState = MutableStateFlow<ReviewState>(ReviewState.Idle)
    val reviewState: StateFlow<ReviewState> = _reviewState.asStateFlow()

    init {
        loadAccounts()
    }

    fun loadAccounts() {
        _accountsState.value = AccountsState.Loading
        viewModelScope.launch {
            when (val r = repository.listAccounts()) {
                is ApiResult.Success -> {
                    _accountsState.value =
                        if (r.data.isEmpty()) AccountsState.Empty else AccountsState.Content(r.data)
                    val preAccount = selection.current.accountId
                        ?.let { id -> r.data.firstOrNull { it.accountId == id } }
                        ?: r.data.firstOrNull { it.status == "active" }
                        ?: r.data.firstOrNull()
                    preAccount?.accountId?.let { onAccountSelected(it) }
                }
                is ApiResult.Failure -> _accountsState.value = AccountsState.Error(r.error.message)
                is ApiResult.NetworkError -> _accountsState.value = AccountsState.Error(OFFLINE)
            }
        }
    }

    fun onAccountSelected(accountId: String) {
        if (_selectedAccountId.value == accountId && _campaignsState.value is CampaignsState.Content) return
        _selectedAccountId.value = accountId
        selection.selectAccount(accountId)
        loadCampaigns(accountId)
    }

    private fun loadCampaigns(accountId: String) {
        _campaignsState.value = CampaignsState.Loading
        viewModelScope.launch {
            when (val r = repository.listCampaigns(accountId)) {
                is ApiResult.Success -> {
                    _campaignsState.value =
                        if (r.data.isEmpty()) CampaignsState.Empty else CampaignsState.Content(r.data)
                    // Preserve a valid prior/selected campaign, else preselect the first.
                    val valid = r.data.any { it.campaignId == _selectedCampaignId.value }
                    if (!valid) _selectedCampaignId.value = r.data.firstOrNull()?.campaignId
                }
                is ApiResult.Failure -> _campaignsState.value = CampaignsState.Error(r.error.message)
                is ApiResult.NetworkError -> _campaignsState.value = CampaignsState.Error(OFFLINE)
            }
        }
    }

    fun onCampaignSelected(campaignId: String) {
        _selectedCampaignId.value = campaignId
        selection.selectCampaign(campaignId, _selectedAccountId.value)
    }

    fun onFormat(value: String) { _format.value = value }
    fun onTitle(text: String) { _title.value = text; clearError() }
    fun onHeadline(text: String) { _headline.value = text }
    fun onBody(text: String) { _body.value = text }
    fun onCtaText(text: String) { _ctaText.value = text }
    fun onCtaUrl(text: String) { _ctaUrl.value = text; clearError() }

    /** Decodes/processes the picked image to JPEG bytes off the main thread; holds it for upload. */
    fun onImagePicked(uri: Uri) {
        _imageProcessing.value = true
        viewModelScope.launch {
            val prepared = runCatching { imageProcessor.process(uri) }.getOrNull()
            _imageProcessing.value = false
            if (prepared == null) {
                _createState.value = CreateState.Error(IMAGE_ERROR)
                return@launch
            }
            preparedImage = prepared
            _imageUri.value = uri
        }
    }

    /** True when a campaign is selected, a title is present, and any CTA URL is http(s). */
    val canSubmit: Boolean
        get() = _selectedCampaignId.value != null &&
            _title.value.isNotBlank() &&
            (_ctaUrl.value.isBlank() || isHttpUrl(_ctaUrl.value)) &&
            !_imageProcessing.value

    /**
     * Creates the draft creative and (when an image was picked) uploads it. Ignored when invalid or in
     * flight. On success -> [CreateState.Success] with the creative (imageUrl set from the upload).
     */
    fun submit() {
        if (_createState.value is CreateState.Submitting) return
        val campaignId = _selectedCampaignId.value ?: return
        if (_title.value.isBlank()) return
        if (_ctaUrl.value.isNotBlank() && !isHttpUrl(_ctaUrl.value)) return

        _createState.value = CreateState.Submitting
        viewModelScope.launch {
            val created = repository.createCreative(
                campaignId = campaignId,
                format = _format.value,
                title = _title.value.trim(),
                headline = _headline.value.trim().ifBlank { null },
                bodyText = _body.value.trim().ifBlank { null },
                ctaText = _ctaText.value.trim().ifBlank { null },
                ctaUrl = _ctaUrl.value.trim().ifBlank { null },
                rotationWeight = DEFAULT_ROTATION_WEIGHT,
            )
            when (created) {
                is ApiResult.Success -> {
                    val creative = created.data
                    val image = preparedImage
                    if (image != null) {
                        when (val up = repository.uploadCreativeAsset(
                            campaignId = campaignId,
                            creativeId = creative.creativeId,
                            bytes = image.bytes,
                            contentType = image.contentType,
                            fileName = image.fileName,
                            assetType = "image",
                        )) {
                            is ApiResult.Success ->
                                _createState.value = CreateState.Success(creative.copy(imageUrl = up.data))
                            is ApiResult.Failure ->
                                _createState.value = CreateState.Error(UPLOAD_PREFIX + up.error.message)
                            is ApiResult.NetworkError ->
                                _createState.value = CreateState.Error(OFFLINE)
                        }
                    } else {
                        _createState.value = CreateState.Success(creative)
                    }
                }
                is ApiResult.Failure -> _createState.value = CreateState.Error(created.error.message)
                is ApiResult.NetworkError -> _createState.value = CreateState.Error(OFFLINE)
            }
        }
    }

    /** ADV-109 - submit the just-created draft creative for admin review. */
    fun submitForReview() {
        val created = _createState.value as? CreateState.Success ?: return
        val campaignId = _selectedCampaignId.value ?: created.creative.campaignId ?: return
        if (_reviewState.value is ReviewState.Submitting) return

        _reviewState.value = ReviewState.Submitting
        viewModelScope.launch {
            when (val r = repository.submitCreative(campaignId, created.creative.creativeId)) {
                is ApiResult.Success -> _reviewState.value = ReviewState.Done(r.data)
                is ApiResult.Failure -> _reviewState.value = ReviewState.Error(r.error.message)
                is ApiResult.NetworkError -> _reviewState.value = ReviewState.Error(OFFLINE)
            }
        }
    }

    private fun clearError() {
        if (_createState.value is CreateState.Error) _createState.value = CreateState.Idle
    }

    companion object {
        const val ARG_CAMPAIGN_ID = "campaignId"

        val FORMATS = listOf("native_post", "image", "video", "carousel")
        const val DEFAULT_ROTATION_WEIGHT = 50

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val IMAGE_ERROR = "Couldn't read that image. Try another."
        private const val UPLOAD_PREFIX = "Creative created, but the image upload failed: "

        fun isHttpUrl(s: String): Boolean {
            val t = s.trim()
            return t.startsWith("http://") || t.startsWith("https://")
        }
    }
}
