package com.testlogon.android.feature.tickets.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-372 - Hilt wiring for the READ-ONLY ticket-spaces feature. Binds the repository seam to its default impl.
 * The impl consumes the AND-371 [com.testlogon.android.core.network.tickets.TicketsApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency is
 * added here. Mirrors the AND-358 CollaborationsDataModule / AND-365 SponsorshipDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class TicketsDataModule {

    @Binds
    @Singleton
    abstract fun bindTicketsRepository(impl: TicketsRepositoryImpl): TicketsRepository
}
