package com.testlogon.android.feature.kyc.eidv.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-325 - Hilt wiring for the KYC electronic ID verification (eIDV) feature. Binds the repository seam to
 * its impl.
 *
 * [EidvRepositoryImpl] consumes AND-325's KycEidvApi AND REUSES AND-319's KycApi (both provided by
 * core-network's KycNetworkModule) plus the shared ApiErrorParser. NO new endpoint, migration, or
 * dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class EidvModule {

    @Binds
    @Singleton
    abstract fun bindEidvRepository(impl: EidvRepositoryImpl): EidvRepository
}
