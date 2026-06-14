package com.testlogon.android.feature.kyc.liveness.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-324 - Hilt wiring for the KYC scheduled liveness-call feature. Binds the repository seam to its
 * impl.
 *
 * [LivenessCallRepositoryImpl] consumes AND-324's KycLivenessCallApi (provided by core-network's
 * KycNetworkModule) and the shared ApiErrorParser. NO new endpoint, migration, or dependency is added
 * here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class LivenessCallModule {

    @Binds
    @Singleton
    abstract fun bindLivenessCallRepository(
        impl: LivenessCallRepositoryImpl,
    ): LivenessCallRepository
}
