package com.testlogon.android.feature.sellerstore

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogRepository
import com.testlogon.android.data.livecommerce.LiveCommerceRepository
import com.testlogon.android.data.profile.ProfileMediaUploader
import com.testlogon.android.data.sellerstore.SellerCatalogRepository
import com.testlogon.android.feature.profile.media.ProfileImageProcessor
import com.testlogon.android.navigation.ListingEditorDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.math.BigDecimal
import javax.inject.Inject

/**
 * ECOM (seller store) — create/edit a single catalog listing. `_new` itemId means create; any other id
 * loads the existing item (there is no single-item GET, so it is resolved from the category list) and
 * PATCHes it. An image is picked via the system photo picker, processed to JPEG bytes, and uploaded via
 * the multipart images/upload endpoint (deferred until after create for a brand-new item).
 */
data class ListingEditorUiState(
    val isNew: Boolean,
    val loading: Boolean = false,
    val name: String = "",
    val description: String = "",
    val priceText: String = "",
    val stockText: String = "",
    val imageUrl: String? = null,
    val pendingImageUri: Uri? = null,
    val uploadingImage: Boolean = false,
    val saving: Boolean = false,
    /**
     * LIVECOM L5 — the seller-set affiliate commission a host earns for selling this listing via a
     * stream, as a PERCENT string (e.g. "10" = 10%). Loaded/saved as bps against the live-commerce
     * endpoints. Only meaningful for an existing (saved) listing.
     */
    val affiliateCommissionText: String = "",
) {
    val canSave: Boolean get() = name.isNotBlank() && priceText.isNotBlank() && !saving && !uploadingImage
}

sealed interface ListingEditorEvent {
    data object Saved : ListingEditorEvent
    data object Deleted : ListingEditorEvent
    data class Message(val text: String) : ListingEditorEvent
}

@HiltViewModel
class ListingEditorViewModel @Inject constructor(
    private val catalogRepository: CatalogRepository,
    private val sellerRepository: SellerCatalogRepository,
    private val liveCommerceRepository: LiveCommerceRepository,
    private val imageProcessor: ProfileImageProcessor,
    savedState: SavedStateHandle,
) : ViewModel() {

    val categoryId: String = checkNotNull(savedState[ListingEditorDest.ARG_CATEGORY_ID])
    private val argItemId: String = checkNotNull(savedState[ListingEditorDest.ARG_ITEM_ID])
    private val isNew: Boolean = argItemId == ListingEditorDest.NEW

    /** Resolved on load for an existing item; null while creating. */
    private var itemId: String? = if (isNew) null else argItemId
    private var currency: String = "USD"
    private var pendingImage: ProfileMediaUploader.PreparedUpload? = null

    private val _uiState = MutableStateFlow(ListingEditorUiState(isNew = isNew, loading = !isNew))
    val uiState: StateFlow<ListingEditorUiState> = _uiState.asStateFlow()

    private val _events = Channel<ListingEditorEvent>(Channel.BUFFERED)
    val events: Flow<ListingEditorEvent> = _events.receiveAsFlow()

    init {
        if (!isNew) loadExisting()
    }

    private fun loadExisting() {
        viewModelScope.launch {
            when (val r = catalogRepository.getItem(categoryId, argItemId)) {
                is ApiResult.Success -> {
                    val item = r.data
                    currency = item.currency
                    itemId = item.itemId
                    _uiState.update {
                        it.copy(
                            loading = false,
                            name = item.name,
                            description = item.description.orEmpty(),
                            priceText = centsToText(item.priceCents),
                            stockText = item.stockCount?.toString().orEmpty(),
                            imageUrl = item.thumbnailUrl,
                        )
                    }
                    loadCommission(item.itemId)
                }
                is ApiResult.Failure -> { _uiState.update { it.copy(loading = false) }; _events.send(ListingEditorEvent.Message(r.error.message)) }
                is ApiResult.NetworkError -> { _uiState.update { it.copy(loading = false) }; _events.send(ListingEditorEvent.Message(OFFLINE)) }
            }
        }
    }

    /** LIVECOM L5 — reads the listing's current affiliate commission (bps) and shows it as a percent. */
    private fun loadCommission(id: String) {
        viewModelScope.launch {
            (liveCommerceRepository.affiliateCommissionBps(categoryId, id) as? ApiResult.Success)?.let { r ->
                _uiState.update { it.copy(affiliateCommissionText = bpsToPercentText(r.data)) }
            }
        }
    }

    fun onCommissionChange(v: String) =
        _uiState.update { it.copy(affiliateCommissionText = v.filter { c -> c.isDigit() || c == '.' }) }

    fun onNameChange(v: String) = _uiState.update { it.copy(name = v) }
    fun onDescriptionChange(v: String) = _uiState.update { it.copy(description = v) }
    fun onPriceChange(v: String) = _uiState.update { it.copy(priceText = v.filter { c -> c.isDigit() || c == '.' }) }
    fun onStockChange(v: String) = _uiState.update { it.copy(stockText = v.filter { c -> c.isDigit() }) }

    /** Picked image: process to bytes; for an existing item upload now, for a new item defer to save(). */
    fun onImagePicked(uri: Uri) {
        _uiState.update { it.copy(uploadingImage = true, pendingImageUri = uri) }
        viewModelScope.launch {
            val prepared = runCatching { imageProcessor.process(uri) }.getOrNull()
            if (prepared == null) {
                _uiState.update { it.copy(uploadingImage = false, pendingImageUri = null) }
                _events.send(ListingEditorEvent.Message(IMAGE_FAILED))
                return@launch
            }
            val existing = itemId
            if (isNew || existing == null) {
                pendingImage = prepared
                _uiState.update { it.copy(uploadingImage = false) }
            } else {
                when (val r = sellerRepository.uploadItemImage(categoryId, existing, prepared.bytes, prepared.contentType, prepared.fileName)) {
                    is ApiResult.Success -> _uiState.update { it.copy(uploadingImage = false, pendingImageUri = null, imageUrl = r.data.thumbnailUrl) }
                    is ApiResult.Failure -> { _uiState.update { it.copy(uploadingImage = false, pendingImageUri = null) }; _events.send(ListingEditorEvent.Message(r.error.message)) }
                    is ApiResult.NetworkError -> { _uiState.update { it.copy(uploadingImage = false, pendingImageUri = null) }; _events.send(ListingEditorEvent.Message(OFFLINE)) }
                }
            }
        }
    }

    fun save() {
        val s = _uiState.value
        if (!s.canSave) return
        val priceCents = parseCents(s.priceText)
        if (priceCents == null) { emit(ListingEditorEvent.Message(BAD_PRICE)); return }
        val stock = s.stockText.toIntOrNull()
        _uiState.update { it.copy(saving = true) }
        viewModelScope.launch {
            if (isNew) {
                when (val r = sellerRepository.createItem(categoryId, s.name.trim(), s.description, priceCents, currency, stock)) {
                    is ApiResult.Success -> {
                        val created = r.data
                        pendingImage?.let { img ->
                            sellerRepository.uploadItemImage(categoryId, created.itemId, img.bytes, img.contentType, img.fileName)
                        }
                        finishSaved()
                    }
                    is ApiResult.Failure -> failSave(r.error.message)
                    is ApiResult.NetworkError -> failSave(OFFLINE)
                }
            } else {
                val id = itemId ?: argItemId
                when (val r = sellerRepository.updateItem(categoryId, id, s.name.trim(), s.description, priceCents, stock)) {
                    is ApiResult.Success -> {
                        // LIVECOM L5 — owner-scoped: persist the affiliate commission (percent -> bps).
                        percentTextToBps(s.affiliateCommissionText)?.let { bps ->
                            liveCommerceRepository.setAffiliateCommissionBps(categoryId, id, bps)
                        }
                        finishSaved()
                    }
                    is ApiResult.Failure -> failSave(r.error.message)
                    is ApiResult.NetworkError -> failSave(OFFLINE)
                }
            }
        }
    }

    fun deleteListing() {
        val id = itemId ?: return
        if (isNew) return
        _uiState.update { it.copy(saving = true) }
        viewModelScope.launch {
            when (val r = sellerRepository.deleteItem(categoryId, id)) {
                is ApiResult.Success -> _events.send(ListingEditorEvent.Deleted)
                is ApiResult.Failure -> failSave(r.error.message)
                is ApiResult.NetworkError -> failSave(OFFLINE)
            }
        }
    }

    private suspend fun finishSaved() {
        _uiState.update { it.copy(saving = false) }
        _events.send(ListingEditorEvent.Saved)
    }

    private suspend fun failSave(message: String) {
        _uiState.update { it.copy(saving = false) }
        _events.send(ListingEditorEvent.Message(message))
    }

    private fun emit(event: ListingEditorEvent) { viewModelScope.launch { _events.send(event) } }

    private fun parseCents(text: String): Long? = try {
        BigDecimal(text.trim()).movePointRight(2).setScale(0, java.math.RoundingMode.HALF_UP).longValueExact()
            .takeIf { it >= 0 }
    } catch (_: Exception) {
        null
    }

    private fun centsToText(cents: Long): String =
        BigDecimal(cents).movePointLeft(2).stripTrailingZeros().toPlainString()

    /** LIVECOM L5 — percent string (e.g. "10", "12.5") -> bps (0..10000), or null if blank/invalid. */
    private fun percentTextToBps(text: String): Int? = try {
        text.trim().takeIf { it.isNotBlank() }?.let {
            BigDecimal(it).movePointRight(2).setScale(0, java.math.RoundingMode.HALF_UP).intValueExact()
                .coerceIn(0, 10000)
        }
    } catch (_: Exception) {
        null
    }

    /** LIVECOM L5 — bps -> percent string for display (e.g. 1000 -> "10"). */
    private fun bpsToPercentText(bps: Int): String =
        BigDecimal(bps).movePointLeft(2).stripTrailingZeros().toPlainString()

    companion object {
        private const val OFFLINE = "You're offline"
        private const val IMAGE_FAILED = "Couldn't prepare the image"
        private const val BAD_PRICE = "Enter a valid price"
    }
}
