package com.testlogon.android.feature.orgs.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-353 - Hilt wiring for the organizations feature. Binds the repository seam to its default impl.
 * The impl consumes AND-353's [com.testlogon.android.core.network.orgs.OrgsApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser] (both provided by core-network). NO new
 * endpoint module, migration, or dependency is added here. The SelectedOrgStore binding lives next to
 * the store (SelectedOrgStoreModule).
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class OrgsDataModule {

    @Binds
    @Singleton
    abstract fun bindOrgsRepository(impl: OrgsRepositoryImpl): OrgsRepository
}
