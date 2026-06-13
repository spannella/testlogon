package com.testlogon.android.data.files.download

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-334 - binds the file-download repository.
 *
 * [com.testlogon.android.core.network.files.FilesApi] is already provided by the AND-331 core-network
 * FilesNetworkModule; [FileCacheStore] and [OpenWithLauncher] are constructor-injected singletons. No
 * new dependency, no Room.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class DownloadDataModule {

    @Binds
    @Singleton
    abstract fun bindDownloadRepository(impl: DownloadRepositoryImpl): DownloadRepository
}
