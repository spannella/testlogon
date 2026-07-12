package com.testlogon.android.data.licenses

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides the compliance / requests-actions / revenue-extras Retrofit APIs on the shared client. */
@Module
@InstallIn(SingletonComponent::class)
object LicensesSubApiModule {

    @Provides
    @Singleton
    fun provideLicenseComplianceApi(retrofit: Retrofit): LicenseComplianceApi =
        retrofit.create(LicenseComplianceApi::class.java)

    @Provides
    @Singleton
    fun provideLicenseRequestsActionsApi(retrofit: Retrofit): LicenseRequestsActionsApi =
        retrofit.create(LicenseRequestsActionsApi::class.java)

    @Provides
    @Singleton
    fun provideLicenseRevenueExtrasApi(retrofit: Retrofit): LicenseRevenueExtrasApi =
        retrofit.create(LicenseRevenueExtrasApi::class.java)
}

/** Binds the licensing sub-screen data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class LicensesSubDataModule {

    @Binds
    @Singleton
    abstract fun bindLicensesSubRepository(impl: LicensesSubRepositoryImpl): LicensesSubRepository
}
