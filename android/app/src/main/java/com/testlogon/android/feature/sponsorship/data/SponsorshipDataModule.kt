package com.testlogon.android.feature.sponsorship.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-365 - Hilt wiring for the sponsorship inbox feature. Binds the repository seam to its default impl. The
 * impl consumes AND-365's [com.testlogon.android.core.network.sponsorship.SponsorshipApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency
 * is added here. Mirrors the AND-358 CollaborationsDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class SponsorshipDataModule {

    @Binds
    @Singleton
    abstract fun bindSponsorshipRepository(impl: SponsorshipRepositoryImpl): SponsorshipRepository
}
