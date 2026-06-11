package com.testlogon.android.data.contentcalendar

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-274 — provides [ContentCalendarApi] on the shared Retrofit (no new OkHttp/Retrofit) and binds
 * [ContentCalendarRepository].
 */
@Module
@InstallIn(SingletonComponent::class)
object ContentCalendarApiModule {

    @Provides
    @Singleton
    fun provideContentCalendarApi(retrofit: Retrofit): ContentCalendarApi =
        retrofit.create(ContentCalendarApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ContentCalendarDataModule {

    @Binds
    @Singleton
    abstract fun bindContentCalendarRepository(
        impl: ContentCalendarRepositoryImpl,
    ): ContentCalendarRepository
}
