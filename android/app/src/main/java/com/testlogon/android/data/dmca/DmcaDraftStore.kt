package com.testlogon.android.data.dmca

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dmcaDraftDataStore by preferencesDataStore(name = "dmca_drafts")

/**
 * AND-384 - the best-effort in-progress DMCA form, persisted so a process death / submit failure does not
 * lose typed text (FR-7).
 *
 * SECURITY (§8 / AC-6): the [signature] and the two attestation booleans are INTENTIONALLY excluded from the
 * draft - they must be re-affirmed every submission and can never be auto-restored, so a restored draft can
 * never be auto-submitted. This data class therefore carries ONLY non-attestation text fields.
 */
data class DmcaDraft(
    val originalWorkDescription: String = "",
    val contentUrl: String = "",
    val contentType: String = DmcaContentType.OTHER,
    val contentId: String? = null,
    val claimantName: String = "",
    val claimantEmail: String = "",
    val claimantAddress: String = "",
    val claimantPhone: String = "",
) {
    /** True when nothing worth persisting has been typed yet (avoids writing empty drafts). */
    val isEmpty: Boolean
        get() = originalWorkDescription.isBlank() && contentUrl.isBlank() && contentId.isNullOrBlank() &&
            claimantName.isBlank() && claimantEmail.isBlank() && claimantAddress.isBlank() &&
            claimantPhone.isBlank() && contentType == DmcaContentType.OTHER
}

/**
 * AND-384 - Preferences-DataStore-backed cache of [DmcaDraft]s keyed by `targetKey`
 * (= "contentType:contentId" for a pre-targeted form, or "standalone"). Drafts hold only non-attestation
 * text; the signature + checkboxes are never persisted. Cleared on successful submit (FR-7) and on sign-out
 * (PII hygiene, AC-6 - via [clearAll]).
 */
interface DmcaDraftStore {
    suspend fun load(targetKey: String): DmcaDraft?
    suspend fun save(targetKey: String, draft: DmcaDraft)
    suspend fun clear(targetKey: String)
    suspend fun clearAll()
}

@Singleton
class DataStoreDmcaDraftStore @Inject constructor(
    @ApplicationContext context: Context,
) : DmcaDraftStore {

    private val dataStore = context.dmcaDraftDataStore

    private fun keys(targetKey: String) = DraftKeys(targetKey)

    override suspend fun load(targetKey: String): DmcaDraft? {
        val k = keys(targetKey)
        val prefs = readPrefs()
        // Presence of the marker distinguishes "no draft" from "an all-blank draft".
        prefs[k.marker] ?: return null
        return DmcaDraft(
            originalWorkDescription = prefs[k.description].orEmpty(),
            contentUrl = prefs[k.contentUrl].orEmpty(),
            contentType = DmcaContentType.normalize(prefs[k.contentType]),
            contentId = prefs[k.contentId],
            claimantName = prefs[k.name].orEmpty(),
            claimantEmail = prefs[k.email].orEmpty(),
            claimantAddress = prefs[k.address].orEmpty(),
            claimantPhone = prefs[k.phone].orEmpty(),
        )
    }

    override suspend fun save(targetKey: String, draft: DmcaDraft) {
        val k = keys(targetKey)
        dataStore.edit { p ->
            p[k.marker] = "1"
            p[k.description] = draft.originalWorkDescription
            p[k.contentUrl] = draft.contentUrl
            p[k.contentType] = draft.contentType
            draft.contentId?.let { p[k.contentId] = it } ?: p.remove(k.contentId)
            p[k.name] = draft.claimantName
            p[k.email] = draft.claimantEmail
            p[k.address] = draft.claimantAddress
            p[k.phone] = draft.claimantPhone
            // Defensive: the signature/attestations are never written; nothing to remove here.
        }
    }

    override suspend fun clear(targetKey: String) {
        val k = keys(targetKey)
        dataStore.edit { p ->
            p.remove(k.marker)
            p.remove(k.description)
            p.remove(k.contentUrl)
            p.remove(k.contentType)
            p.remove(k.contentId)
            p.remove(k.name)
            p.remove(k.email)
            p.remove(k.address)
            p.remove(k.phone)
        }
    }

    override suspend fun clearAll() {
        dataStore.edit { it.clear() }
    }

    private suspend fun readPrefs(): Preferences = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    /** Per-target namespaced preference keys. The signature + attestation booleans have NO keys by design. */
    private class DraftKeys(targetKey: String) {
        private val p = "dmca/$targetKey/"
        val marker = stringPreferencesKey("${p}marker")
        val description = stringPreferencesKey("${p}original_work_description")
        val contentUrl = stringPreferencesKey("${p}content_url")
        val contentType = stringPreferencesKey("${p}content_type")
        val contentId = stringPreferencesKey("${p}content_id")
        val name = stringPreferencesKey("${p}claimant_name")
        val email = stringPreferencesKey("${p}claimant_email")
        val address = stringPreferencesKey("${p}claimant_address")
        val phone = stringPreferencesKey("${p}claimant_phone")
    }

    companion object {
        /** The draft key for the standalone (non-pre-targeted) form. */
        const val STANDALONE_KEY = "standalone"

        /** Builds the draft key for a pre-targeted form (mirrors the navigation target). */
        fun targetKey(contentType: String?, contentId: String?): String =
            if (contentType.isNullOrBlank() && contentId.isNullOrBlank()) {
                STANDALONE_KEY
            } else {
                "${contentType.orEmpty()}:${contentId.orEmpty()}"
            }
    }
}
