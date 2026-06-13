package com.testlogon.android.feature.signing.document.data

import com.testlogon.android.feature.signing.document.PdfPageRendererFactory
import com.testlogon.android.feature.signing.document.PdfPageRendererFactoryImpl
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-341 - Hilt wiring for the document viewer. Binds the [PdfSource] seam (streams AND-339's
 * SigningApi.downloadFinalPdf to a cache file) and the [PdfPageRendererFactory] (over the BUILT-IN
 * PdfRenderer) to their default impls. NO new endpoint module, migration, or dependency is added.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class DocumentDataModule {

    @Binds
    @Singleton
    abstract fun bindPdfSource(impl: PdfSourceImpl): PdfSource

    @Binds
    @Singleton
    abstract fun bindPdfPageRendererFactory(
        impl: PdfPageRendererFactoryImpl,
    ): PdfPageRendererFactory
}
