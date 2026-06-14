package com.testlogon.android.feature.kyc.idscanner.data

import com.testlogon.android.feature.kyc.idscanner.IdFrameAnalyzer
import com.testlogon.android.feature.kyc.idscanner.StubIdFrameAnalyzer
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-322 - Hilt wiring for the KYC ID-scanner feature. Binds the seam interfaces to their impls.
 *
 * [IdScannerRepositoryImpl] consumes AND-322's KycIdScannerApi (provided by core-network's KycNetworkModule),
 * AND-321's KycDocumentsRepository (REUSED for the base64 upload), and the shared ApiErrorParser. The FLAGGED
 * [IdFrameAnalyzer] is bound to the [StubIdFrameAnalyzer] (the deferred CameraX/ML Kit auto-capture + MRZ OCR
 * — STOP-AND-FLAG). NO new endpoint, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class IdScannerModule {

    @Binds
    @Singleton
    abstract fun bindIdScannerRepository(impl: IdScannerRepositoryImpl): IdScannerRepository

    @Binds
    @Singleton
    abstract fun bindIdFrameAnalyzer(impl: StubIdFrameAnalyzer): IdFrameAnalyzer
}
