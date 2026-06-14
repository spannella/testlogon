package com.testlogon.android.feature.kyc.facial.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-323 - Hilt wiring for the KYC facial-comparison feature. Binds the repository seam to its impl.
 *
 * [FaceComparisonRepositoryImpl] consumes AND-323's FaceComparisonApi + AND-319's KycApi (both provided
 * by core-network's KycNetworkModule), AND-129's AttachmentApi + StorageUploadClient (provided by
 * data/upload's UploadModule, REUSED for the presign + cookieless PUT), and the shared ApiErrorParser.
 * The CaptureImageProcessor (AND-321) is already bound by KycDocumentsModule. NO new endpoint,
 * migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class FaceComparisonModule {

    @Binds
    @Singleton
    abstract fun bindFaceComparisonRepository(
        impl: FaceComparisonRepositoryImpl,
    ): FaceComparisonRepository
}
