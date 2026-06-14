package com.testlogon.android.feature.share

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.share.data.DownloadOutcome
import com.testlogon.android.feature.share.data.ShareDownloader
import com.testlogon.android.feature.share.data.ShareRepository
import com.testlogon.android.feature.share.model.PublicShare
import com.testlogon.android.feature.share.model.PublicShareState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-335 - presentation logic for the session-free PublicShareScreen.
 *
 * The link id comes from the route ([SavedStateHandle]). On init the link is resolved (no password) via
 * the COOKIELESS [ShareRepository.resolvePublic]; the result becomes [PublicShareUiState.Info] (with a
 * password gate when required) or a [PublicShareUiState.Terminal] panel for expired / revoked / exhausted
 * / unavailable. [submitPassword] re-checks the password by attempting the download (the info endpoint
 * carries no password); a valid password unlocks the download. [download] streams the bytes to MediaStore
 * via [ShareDownloader] with progress. DOUBLE-SEND GUARDED (no download while one is in flight). There is
 * NO poll loop. Plain MutableStateFlow.
 */
@HiltViewModel
class PublicShareViewModel @Inject constructor(
    private val repository: ShareRepository,
    private val downloader: ShareDownloader,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val linkId: String = savedState.get<String>(ARG_LINK_ID).orEmpty()

    private val _uiState = MutableStateFlow<PublicShareUiState>(PublicShareUiState.Loading)
    val uiState: StateFlow<PublicShareUiState> = _uiState.asStateFlow()

    init {
        if (linkId.isBlank()) {
            _uiState.value = PublicShareUiState.Terminal(PublicShareState.UNAVAILABLE)
        } else {
            resolve()
        }
    }

    /** Resolve (or re-resolve) the public link metadata. */
    fun resolve() {
        if (linkId.isBlank()) return
        _uiState.value = PublicShareUiState.Loading
        viewModelScope.launch {
            when (val result = repository.resolvePublic(linkId, password = null)) {
                is ApiResult.Success -> _uiState.value = toState(result.data)
                is ApiResult.Failure ->
                    _uiState.value = PublicShareUiState.Error(
                        message = result.error.message,
                        retryable = result.error.status >= 500 || result.error.status == 429,
                    )
                is ApiResult.NetworkError ->
                    _uiState.value = PublicShareUiState.Error(message = OFFLINE, retryable = true)
            }
        }
    }

    /** Maps a resolved [PublicShare] to the matching UI phase. */
    private fun toState(share: PublicShare): PublicShareUiState = when (share.state) {
        PublicShareState.AVAILABLE ->
            PublicShareUiState.Info(share = share, needsPassword = share.passwordRequired)
        PublicShareState.EXPIRED -> PublicShareUiState.Terminal(PublicShareState.EXPIRED)
        PublicShareState.REVOKED -> PublicShareUiState.Terminal(PublicShareState.REVOKED)
        PublicShareState.EXHAUSTED -> PublicShareUiState.Terminal(PublicShareState.EXHAUSTED)
        PublicShareState.UNAVAILABLE -> PublicShareUiState.Terminal(PublicShareState.UNAVAILABLE)
    }

    fun onPasswordChange(value: String) {
        val info = _uiState.value as? PublicShareUiState.Info ?: return
        _uiState.value = info.copy(password = value, passwordError = null)
    }

    /**
     * Submit the typed password. The public info endpoint carries no password, so this unlocks the gate
     * client-side then performs the download (the server is the real arbiter: a wrong password returns
     * 401/403 from the download, which re-raises the gate with an error).
     */
    fun submitPassword() {
        val info = _uiState.value as? PublicShareUiState.Info ?: return
        if (info.password.isBlank() || info.verifyingPassword || info.downloading) return
        _uiState.value = info.copy(needsPassword = false)
        download()
    }

    /**
     * Stream the file to MediaStore Downloads. DOUBLE-SEND GUARDED. A 401/403 (wrong password) re-raises
     * the password gate with an error; other failures surface inline on the Info panel.
     */
    fun download() {
        val info = _uiState.value as? PublicShareUiState.Info ?: return
        if (info.downloading) return
        val password = if (info.share.passwordRequired) info.password else null
        _uiState.value = info.copy(downloading = true, progress = null, passwordError = null)
        viewModelScope.launch {
            downloader.downloadPublic(
                linkId = linkId,
                password = password,
                fileName = info.share.fileName,
                contentType = info.share.contentType,
            ).collect { outcome -> applyOutcome(outcome) }
        }
    }

    private fun applyOutcome(outcome: DownloadOutcome) {
        val info = _uiState.value as? PublicShareUiState.Info ?: return
        when (outcome) {
            is DownloadOutcome.InProgress ->
                _uiState.value = info.copy(
                    downloading = true,
                    progress = outcome.totalBytes
                        ?.takeIf { it > 0L }
                        ?.let { (outcome.bytesDownloaded.toFloat() / it).coerceIn(0f, 1f) },
                )
            is DownloadOutcome.Success ->
                _uiState.value = info.copy(
                    downloading = false,
                    progress = null,
                    savedFileName = outcome.displayName,
                )
            is DownloadOutcome.Error -> {
                val isAuth = outcome.error.status == 401 || outcome.error.status == 403
                _uiState.value = if (isAuth && info.share.passwordRequired) {
                    // Wrong/missing password -> re-raise the gate with a clear, non-leaking message.
                    info.copy(
                        downloading = false,
                        progress = null,
                        needsPassword = true,
                        passwordError = WRONG_PASSWORD,
                    )
                } else {
                    info.copy(downloading = false, progress = null, passwordError = outcome.error.message)
                }
            }
        }
    }

    companion object {
        /** Nav arg carrying the public link id (from the deep link / route). */
        const val ARG_LINK_ID = "linkId"

        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val WRONG_PASSWORD = "That password is incorrect."
    }
}
