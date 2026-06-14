package com.testlogon.android.data.taxdocs

import com.testlogon.android.core.network.SettingsStore
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-246 — provides the [TaxDocsApi] on the shared (authenticated) Retrofit + the PDF base-URL seam. */
@Module
@InstallIn(SingletonComponent::class)
object TaxDocsApiModule {

    @Provides
    @Singleton
    fun provideTaxDocsApi(retrofit: Retrofit): TaxDocsApi =
        retrofit.create(TaxDocsApi::class.java)

    /** Reads the runtime base URL from [SettingsStore] for the absolute PDF link (matches AND-243). */
    @Provides
    @Singleton
    fun provideTaxDocsBaseUrlProvider(settingsStore: SettingsStore): TaxDocsBaseUrlProvider =
        TaxDocsBaseUrlProvider { settingsStore.baseUrl }
}

/** AND-246 — binds the tax-documents repository over [TaxDocsApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class TaxDocsDataModule {

    @Binds
    @Singleton
    abstract fun bindTaxDocsRepository(impl: TaxDocsRepositoryImpl): TaxDocsRepository
}
