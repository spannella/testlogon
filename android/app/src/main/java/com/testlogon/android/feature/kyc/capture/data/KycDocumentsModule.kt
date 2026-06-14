package com.testlogon.android.feature.kyc.capture.data

import com.testlogon.android.feature.kyc.capture.CaptureImageProcessor
import com.testlogon.android.feature.kyc.capture.DefaultCaptureImageProcessor
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-321 - Hilt wiring for the KYC document capture+upload feature. Binds the seam interfaces to their
 * default impls. The repo impl consumes AND-321's [com.testlogon.android.core.network.kyc.KycDocumentsApi]
 * (provided by core-network's KycNetworkModule) + the shared [ApiErrorParser]; the processor uses only the
 * Android framework graphics/EXIF APIs. NO new endpoint, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class KycDocumentsModule {

    @Binds
    @Singleton
    abstract fun bindKycDocumentsRepository(impl: KycDocumentsRepositoryImpl): KycDocumentsRepository

    @Binds
    @Singleton
    abstract fun bindCaptureImageProcessor(impl: DefaultCaptureImageProcessor): CaptureImageProcessor
}
