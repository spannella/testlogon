package com.testlogon.android.feature.kyc.screening.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-328 - Hilt wiring for the READ-ONLY KYC screening feature. Binds the repository seam to its default
 * impl. The impl consumes AND-328's [com.testlogon.android.core.network.kyc.KycScreeningApi] + AND-319's
 * [com.testlogon.android.core.network.kyc.KycApi] (both provided by core-network's KycNetworkModule) and the
 * shared [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or
 * dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class ScreeningModule {

    @Binds
    @Singleton
    abstract fun bindScreeningRepository(impl: ScreeningRepositoryImpl): ScreeningRepository
}
