package com.testlogon.android.feature.kyc.prooffunds.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-327 - Hilt wiring for the KYC proof-of-funds feature. Binds the repository seam to its default impl.
 * The impl consumes AND-327's [com.testlogon.android.core.network.kyc.KycProofOfFundsApi] (provided by
 * core-network's KycNetworkModule) + AND-129's presign [com.testlogon.android.data.upload.AttachmentApi] /
 * [com.testlogon.android.data.upload.StorageUploadClient] + the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. AND-321's CaptureImageProcessor is already
 * bound by KycDocumentsModule and is reused as-is. NO new endpoint module, migration, or dependency.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class ProofOfFundsModule {

    @Binds
    @Singleton
    abstract fun bindProofOfFundsRepository(impl: ProofOfFundsRepositoryImpl): ProofOfFundsRepository
}
