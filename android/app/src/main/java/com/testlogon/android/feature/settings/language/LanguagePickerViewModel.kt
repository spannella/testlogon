package com.testlogon.android.feature.settings.language

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.locale.LocaleSource
import com.testlogon.android.core.model.locale.LocaleTag
import com.testlogon.android.core.model.locale.SupportedLocales
import com.testlogon.android.data.locale.LocaleRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.util.Locale
import javax.inject.Inject

/**
 * A single row in the language picker. [tag] null is the "System default" sentinel; [displayName]
 * is the endonym (the language shown in its own script) so each option is self-identifiable.
 */
data class LocaleOption(
    val tag: LocaleTag?,
    val displayName: String,
)

data class LanguagePickerUiState(
    val options: List<LocaleOption> = emptyList(),
    /** The selected tag, or null when following the system default. */
    val selectedTag: LocaleTag? = null,
)

/**
 * AND-114 — drives the in-app language picker. Options are exactly the System-default sentinel plus
 * the [SupportedLocales] catalog set (kept in lockstep with locales_config.xml). Selecting an option
 * persists + best-effort PUTs it via [LocaleRepository.setUserLocale] and applies it immediately via
 * [LocaleController] so the UI re-renders without a manual restart.
 */
@HiltViewModel
class LanguagePickerViewModel @Inject constructor(
    private val repository: LocaleRepository,
    private val localeController: LocaleController,
) : ViewModel() {

    val uiState: StateFlow<LanguagePickerUiState> = repository.preference
        .map { pref ->
            val selected = if (pref.source == LocaleSource.IN_APP_OVERRIDE) pref.effective else null
            LanguagePickerUiState(options = buildOptions(), selectedTag = selected)
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = LanguagePickerUiState(
                options = buildOptions(),
                selectedTag = repository.currentPreference()
                    .takeIf { it.source == LocaleSource.IN_APP_OVERRIDE }?.effective,
            ),
        )

    /** [tag] null == "System default" (clears the override and follows the device language). */
    fun onSelect(tag: LocaleTag?) {
        // Apply immediately for an instant switch; persist + server-sync in the background.
        localeController.apply(tag)
        viewModelScope.launch { repository.setUserLocale(tag) }
    }

    private companion object {
        fun buildOptions(): List<LocaleOption> = buildList {
            add(LocaleOption(tag = null, displayName = "")) // System default; label resolved in UI.
            SupportedLocales.all.forEach { tag ->
                val locale = Locale.forLanguageTag(tag.value)
                val endonym = locale.getDisplayName(locale)
                    .replaceFirstChar { if (it.isLowerCase()) it.titlecase(locale) else it.toString() }
                add(LocaleOption(tag = tag, displayName = endonym))
            }
        }
    }
}
