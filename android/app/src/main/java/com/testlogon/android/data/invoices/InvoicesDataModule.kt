package com.testlogon.android.data.invoices

import com.testlogon.android.core.network.SettingsStore
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-243 — provides the [InvoicesApi] on the shared (authenticated) Retrofit + the PDF base-URL seam. */
@Module
@InstallIn(SingletonComponent::class)
object InvoicesApiModule {

    @Provides
    @Singleton
    fun provideInvoicesApi(retrofit: Retrofit): InvoicesApi =
        retrofit.create(InvoicesApi::class.java)

    /** Reads the runtime base URL from [SettingsStore] for the absolute PDF link. */
    @Provides
    @Singleton
    fun provideInvoiceBaseUrlProvider(settingsStore: SettingsStore): InvoiceBaseUrlProvider =
        InvoiceBaseUrlProvider { settingsStore.baseUrl }
}

/** AND-243 — binds the invoices repository over [InvoicesApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class InvoicesDataModule {

    @Binds
    @Singleton
    abstract fun bindInvoicesRepository(impl: InvoicesRepositoryImpl): InvoicesRepository
}
