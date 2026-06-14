package com.testlogon.android.feature.orgs.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.selectedOrgDataStore by preferencesDataStore(name = "orgs_selection")

/**
 * AND-353 - DataStore-backed persistence of the caller's currently-selected org id (NO Room migration).
 *
 * The selected org id is the org whose roster the members screen shows. When unset the ViewModel
 * defaults to the caller's primary org (the first entry from listOrgs / GET ui/orgs). Mirrors the
 * AND-029 DataStore prefs pattern (catch IOException -> emptyPreferences so a disk read never throws).
 */
interface SelectedOrgStore {
    /** Hot flow of the selected org id, or null when unset. */
    val selectedOrgId: Flow<String?>

    /** Persists the selected org id. */
    suspend fun setSelectedOrgId(orgId: String)
}

@Singleton
class DataStoreSelectedOrgStore @Inject constructor(
    @ApplicationContext context: Context,
) : SelectedOrgStore {

    private val dataStore = context.selectedOrgDataStore

    private object Keys {
        val SELECTED_ORG_ID = stringPreferencesKey("selected_org_id")
    }

    override val selectedOrgId: Flow<String?> =
        dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .map { prefs -> prefs[Keys.SELECTED_ORG_ID] }

    override suspend fun setSelectedOrgId(orgId: String) {
        dataStore.edit { it[Keys.SELECTED_ORG_ID] = orgId }
    }
}

/** AND-353 - binds the [SelectedOrgStore] seam to its DataStore-backed impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class SelectedOrgStoreModule {
    @Binds
    @Singleton
    abstract fun bindSelectedOrgStore(impl: DataStoreSelectedOrgStore): SelectedOrgStore
}
