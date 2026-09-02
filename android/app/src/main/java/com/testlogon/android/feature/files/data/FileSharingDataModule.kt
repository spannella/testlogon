package com.testlogon.android.feature.files.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * FM-SHARE - binds the user-to-user sharing / archive / storage-usage repository. The
 * [com.testlogon.android.core.network.files.FileSharingApi] is provided by the core-network
 * FileSharingNetworkModule, so this module only binds the :app-side seam. No new dependency.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class FileSharingDataModule {

    @Binds
    @Singleton
    abstract fun bindFileSharingRepository(impl: FileSharingRepositoryImpl): FileSharingRepository
}
