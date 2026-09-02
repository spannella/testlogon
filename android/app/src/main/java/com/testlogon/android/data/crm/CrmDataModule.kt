package com.testlogon.android.data.crm

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** CRM-AND-1 — provides the [LeadsApi] + [SalesApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object CrmApiModule {

    @Provides
    @Singleton
    fun provideLeadsApi(retrofit: Retrofit): LeadsApi = retrofit.create(LeadsApi::class.java)

    @Provides
    @Singleton
    fun provideSalesApi(retrofit: Retrofit): SalesApi = retrofit.create(SalesApi::class.java)

    // CRM-AND-PEC — projects / events / campaigns APIs on the same shared Retrofit.
    @Provides
    @Singleton
    fun provideCrmProjectsApi(retrofit: Retrofit): CrmProjectsApi = retrofit.create(CrmProjectsApi::class.java)

    @Provides
    @Singleton
    fun provideCrmEventsApi(retrofit: Retrofit): CrmEventsApi = retrofit.create(CrmEventsApi::class.java)

    @Provides
    @Singleton
    fun provideCrmCampaignsApi(retrofit: Retrofit): CrmCampaignsApi = retrofit.create(CrmCampaignsApi::class.java)

    // CMP - campaign write/send/preview, email templates, admin leads on the same Retrofit.
    @Provides
    @Singleton
    fun provideCrmCampaignsWriteApi(retrofit: Retrofit): CrmCampaignsWriteApi =
        retrofit.create(CrmCampaignsWriteApi::class.java)

    @Provides
    @Singleton
    fun provideCrmEmailTemplatesApi(retrofit: Retrofit): CrmEmailTemplatesApi =
        retrofit.create(CrmEmailTemplatesApi::class.java)

    @Provides
    @Singleton
    fun provideCrmMarketingAdminApi(retrofit: Retrofit): CrmMarketingAdminApi =
        retrofit.create(CrmMarketingAdminApi::class.java)
}

/** CRM-AND-1 — binds the CRM repositories to their implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class CrmDataModule {

    @Binds
    @Singleton
    abstract fun bindLeadsRepository(impl: LeadsRepositoryImpl): LeadsRepository

    @Binds
    @Singleton
    abstract fun bindSalesRepository(impl: SalesRepositoryImpl): SalesRepository

    // CRM-AND-PEC
    @Binds
    @Singleton
    abstract fun bindCrmProjectsRepository(impl: CrmProjectsRepositoryImpl): CrmProjectsRepository

    @Binds
    @Singleton
    abstract fun bindCrmEventsRepository(impl: CrmEventsRepositoryImpl): CrmEventsRepository

    @Binds
    @Singleton
    abstract fun bindCrmCampaignsRepository(impl: CrmCampaignsRepositoryImpl): CrmCampaignsRepository

    @Binds
    @Singleton
    abstract fun bindCrmEmailTemplatesRepository(impl: CrmEmailTemplatesRepositoryImpl): CrmEmailTemplatesRepository

    @Binds
    @Singleton
    abstract fun bindCrmMarketingAdminRepository(impl: CrmMarketingAdminRepositoryImpl): CrmMarketingAdminRepository
}
