package com.testlogon.android.feature.kyc.cases.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-329 - Hilt wiring for the READ-ONLY KYC case-status & ongoing-monitoring feature. Binds the repository
 * seam to its default impl. The impl consumes AND-319's [com.testlogon.android.core.network.kyc.KycApi]
 * (cases) + AND-329's [com.testlogon.android.core.network.kyc.KycMonitoringApi] (schedule / triggers) and the
 * shared [com.testlogon.android.core.network.error.ApiErrorParser] (all provided by core-network). NO new
 * endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class KycCaseModule {

    @Binds
    @Singleton
    abstract fun bindKycCaseRepository(impl: KycCaseRepositoryImpl): KycCaseRepository
}
