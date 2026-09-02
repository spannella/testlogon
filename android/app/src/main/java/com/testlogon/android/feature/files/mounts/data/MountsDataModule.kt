package com.testlogon.android.feature.files.mounts.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * FM-MOUNTS - binds the file-manager mount CRUD repository.
 *
 * [com.testlogon.android.core.network.files.FileMountsApi] is provided by the core-network
 * FileMountsNetworkModule, so this module only binds the :app-side seam. No new dependency.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class MountsDataModule {

    @Binds
    @Singleton
    abstract fun bindMountsRepository(impl: MountsRepositoryImpl): MountsRepository
}
