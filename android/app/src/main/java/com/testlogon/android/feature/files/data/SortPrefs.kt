package com.testlogon.android.feature.files.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
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

private val Context.filesSortDataStore by preferencesDataStore(name = "files_sort_prefs")

/**
 * AND-332 - the server-side browse sort key. The wire token ([apiValue]) is sent verbatim as the
 * `sort_by` query param of the AND-331 list endpoint (name, updated, size).
 */
enum class FileSortBy(val apiValue: String) {
    NAME("name"),
    UPDATED("updated"),
    SIZE("size"),
    ;

    companion object {
        /** Resolves a persisted/wire token to a [FileSortBy], defaulting to [NAME]. */
        fun fromApiValue(value: String?): FileSortBy =
            entries.firstOrNull { it.apiValue == value } ?: NAME
    }
}

/**
 * AND-332 - the server-side browse sort direction. The wire token ([apiValue]) is sent verbatim as the
 * `sort_dir` query param of the AND-331 list endpoint (asc, desc).
 */
enum class FileSortDir(val apiValue: String) {
    ASC("asc"),
    DESC("desc"),
    ;

    companion object {
        /** Resolves a persisted/wire token to a [FileSortDir], defaulting to [ASC]. */
        fun fromApiValue(value: String?): FileSortDir =
            entries.firstOrNull { it.apiValue == value } ?: ASC
    }
}

/**
 * AND-332 - the user's chosen browse sort: [sortBy] + [sortDir] (both server-side) plus the client-side
 * [foldersFirst] grouping toggle (folders rendered before files, applied only for the NAME sort - see
 * FilesPagingSource). Default: name ascending, folders first.
 */
data class FileSort(
    val sortBy: FileSortBy = FileSortBy.NAME,
    val sortDir: FileSortDir = FileSortDir.ASC,
    val foldersFirst: Boolean = true,
)

/**
 * AND-332 - persists the file-manager browse sort across process death (DataStore Preferences),
 * mirroring the AND-252 EarningsPrefs / AND-320 KycTierStore pattern. NO new dependency (DataStore is
 * already used), NO Room. Only small enum tokens + a boolean are stored.
 */
interface SortPrefs {

    /** Reads the persisted sort once (defaults applied for absent / malformed values). */
    suspend fun read(): FileSort

    /** Replaces the persisted sort. */
    suspend fun write(sort: FileSort)
}

@Singleton
class DataStoreSortPrefs @Inject constructor(
    @ApplicationContext context: Context,
) : SortPrefs {

    private val dataStore = context.filesSortDataStore

    override suspend fun read(): FileSort {
        val prefs = dataStore.data
            .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
            .first()
        return FileSort(
            sortBy = FileSortBy.fromApiValue(prefs[Keys.SORT_BY]),
            sortDir = FileSortDir.fromApiValue(prefs[Keys.SORT_DIR]),
            foldersFirst = prefs[Keys.FOLDERS_FIRST] ?: true,
        )
    }

    override suspend fun write(sort: FileSort) {
        dataStore.edit {
            it[Keys.SORT_BY] = sort.sortBy.apiValue
            it[Keys.SORT_DIR] = sort.sortDir.apiValue
            it[Keys.FOLDERS_FIRST] = sort.foldersFirst
        }
    }

    private object Keys {
        val SORT_BY = stringPreferencesKey("files_sort_by")
        val SORT_DIR = stringPreferencesKey("files_sort_dir")
        val FOLDERS_FIRST = booleanPreferencesKey("files_folders_first")
    }
}
