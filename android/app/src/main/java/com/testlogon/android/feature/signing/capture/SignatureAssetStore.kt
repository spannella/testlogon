package com.testlogon.android.feature.signing.capture

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.capture.model.SignatureSource
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.signatureAssetDataStore by preferencesDataStore(name = "signature_asset_prefs")

/**
 * AND-342 - persists a single SAVED-signature pointer (the signature + initials PNG paths + source) via
 * DataStore so re-entry can offer "Use saved". Mirrors the DataStore-preferences pattern of
 * [com.testlogon.android.feature.broadcast.host.DataStoreHostSessionPrefs] /
 * [com.testlogon.android.feature.files.data.SortPrefs]. NO Room, NO migration, NO new dependency. The
 * PNG bytes themselves live in cacheDir/signatures (written by the rasterizer); only the pointer is
 * persisted here.
 */
interface SignatureAssetStore {

    /** Persists the saved-signature pointer (overwrites any previous pointer). */
    suspend fun save(asset: SignatureAsset)

    /** Loads the saved-signature pointer, or null if none / the stored paths no longer exist. */
    suspend fun load(): SignatureAsset?

    /** Clears the saved-signature pointer. */
    suspend fun clear()
}

@Singleton
class DataStoreSignatureAssetStore @Inject constructor(
    @ApplicationContext context: Context,
) : SignatureAssetStore {

    private val dataStore = context.signatureAssetDataStore

    override suspend fun save(asset: SignatureAsset) {
        dataStore.edit { prefs ->
            prefs[Keys.SIGNATURE_PATH] = asset.signaturePngPath
            prefs[Keys.INITIALS_PATH] = asset.initialsPngPath
            prefs[Keys.SOURCE] = asset.source.name
            prefs[Keys.WIDTH] = asset.widthPx
            prefs[Keys.HEIGHT] = asset.heightPx
        }
    }

    override suspend fun load(): SignatureAsset? {
        val prefs = read()
        val signaturePath = prefs[Keys.SIGNATURE_PATH] ?: return null
        val initialsPath = prefs[Keys.INITIALS_PATH] ?: return null
        val source = prefs[Keys.SOURCE]
            ?.let { token -> SignatureSource.entries.firstOrNull { it.name == token } }
            ?: SignatureSource.SAVED
        return SignatureAsset(
            signaturePngPath = signaturePath,
            initialsPngPath = initialsPath,
            // A re-used asset is, by definition, the SAVED source on re-entry.
            source = if (source == SignatureSource.SAVED) source else SignatureSource.SAVED,
            widthPx = prefs[Keys.WIDTH] ?: 0,
            heightPx = prefs[Keys.HEIGHT] ?: 0,
        )
    }

    override suspend fun clear() {
        dataStore.edit { it.clear() }
    }

    private suspend fun read() = dataStore.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .first()

    private object Keys {
        val SIGNATURE_PATH = stringPreferencesKey("signature_png_path")
        val INITIALS_PATH = stringPreferencesKey("initials_png_path")
        val SOURCE = stringPreferencesKey("signature_source")
        val WIDTH = intPreferencesKey("signature_width_px")
        val HEIGHT = intPreferencesKey("signature_height_px")
    }
}
