package com.testlogon.android.feature.signing.capture

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-342 - Hilt wiring for the signature CAPTURE + PLACEMENT feature. Binds the rasterizer seam (over
 * BUILT-IN android.graphics) and the saved-signature DataStore pointer to their default impls. The
 * ViewModel also consumes AND-340's [com.testlogon.android.feature.signing.data.SignatureRepository]
 * (already bound in SigningDataModule). NO new endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class SignatureCaptureModule {

    @Binds
    @Singleton
    abstract fun bindSignatureRasterizer(impl: AndroidSignatureRasterizer): SignatureRasterizer

    @Binds
    @Singleton
    abstract fun bindSignatureAssetStore(impl: DataStoreSignatureAssetStore): SignatureAssetStore
}
