package com.testlogon.android.feature.signing.data

import com.testlogon.android.feature.signing.submit.data.FileAssetBytesReader
import com.testlogon.android.feature.signing.submit.model.AssetBytesReader
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-340 - Hilt wiring for the e-signature packet DETAIL feature. Binds the repository seam to its
 * default impl. The impl consumes AND-339's [com.testlogon.android.core.network.signing.SigningApi] and
 * the shared [com.testlogon.android.core.network.error.ApiErrorParser] (both provided by core-network).
 * NO new endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class SigningDataModule {

    @Binds
    @Singleton
    abstract fun bindSignatureRepository(impl: SignatureRepositoryImpl): SignatureRepository

    /**
     * AND-343 - the per-field fill request reads captured signature/initials PNG bytes for the base64
     * render_payload via this seam; the file-backed impl uses java.io only (NO android.graphics), so the
     * request-builder stays dependency-free and JVM-testable.
     */
    @Binds
    @Singleton
    abstract fun bindAssetBytesReader(impl: FileAssetBytesReader): AssetBytesReader
}
