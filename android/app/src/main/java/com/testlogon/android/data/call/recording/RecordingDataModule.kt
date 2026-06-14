package com.testlogon.android.data.call.recording

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-302 — Hilt wiring for the call-recording consent + upload control plane.
 *
 * Provides [RecordingApi] on the shared (authenticated) Retrofit, binds [RecordingRepository], and binds the
 * FLAGGED [RecordingCapturer] to [StubRecordingCapturer] (so capture stays "unavailable" until the native
 * WebRTC media engine is wired). The storage PUT is reused from AND-129
 * ([com.testlogon.android.data.upload.StorageUploadClient], already @Singleton @Inject-constructable) — no
 * new HTTP client is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
object RecordingProvidesModule {

    @Provides
    @Singleton
    fun provideRecordingApi(retrofit: Retrofit): RecordingApi = retrofit.create(RecordingApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RecordingBindsModule {

    @Binds
    @Singleton
    abstract fun bindRecordingRepository(impl: RecordingRepositoryImpl): RecordingRepository

    /** AND-302 — FLAGGED capture seam: the stub returns NotConfigured (never opens a MediaRecorder). */
    @Binds
    @Singleton
    abstract fun bindRecordingCapturer(impl: StubRecordingCapturer): RecordingCapturer
}
