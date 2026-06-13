package com.testlogon.android.feature.kyc.residency.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-326 - Hilt wiring for the KYC residency / address-verification feature. Binds the repository seam to
 * its default impl. The impl consumes AND-326's [com.testlogon.android.core.network.kyc.KycResidencyApi]
 * (provided by core-network's KycNetworkModule) + the shared [ApiErrorParser]. AND-321's
 * CaptureImageProcessor is already bound by KycDocumentsModule and is reused as-is (the proof bytes ->
 * base64). NO new endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class ResidencyModule {

    @Binds
    @Singleton
    abstract fun bindResidencyRepository(impl: ResidencyRepositoryImpl): ResidencyRepository
}
