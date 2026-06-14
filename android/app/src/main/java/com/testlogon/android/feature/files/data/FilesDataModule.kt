package com.testlogon.android.feature.files.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-332 - binds the file-manager browse repository + sort-prefs implementations.
 *
 * [com.testlogon.android.core.network.files.FilesApi] is already provided by the AND-331 core-network
 * FilesNetworkModule, so this module only binds the :app-side seams. No new dependency, no Room.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class FilesDataModule {

    @Binds
    @Singleton
    abstract fun bindFilesRepository(impl: FilesRepositoryImpl): FilesRepository

    @Binds
    @Singleton
    abstract fun bindSortPrefs(impl: DataStoreSortPrefs): SortPrefs
}
