package com.testlogon.android.feature.messaging.voice

import android.annotation.SuppressLint
import android.content.Context
import android.media.MediaRecorder
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File

/**
 * AND-133 — runtime [VoiceRecorder] backed by the platform `MediaRecorder` (AAC-LC / MP4-M4A, mono,
 * 44.1 kHz, 64 kbps). This is the ONLY class touching Android media APIs; all pure logic
 * (limits, waveform) lives in JVM-testable classes. NOT JVM-unit-tested.
 *
 * Lifecycle: this is created PER-SCREEN by [VoiceRecorderFactory] and released from the composer's
 * lifecycle — never an eager DI singleton. It polls getMaxAmplitude() on a coroutine ticker and
 * enforces the hard cap via [RecorderLimits].
 */
class MediaRecorderVoiceRecorder(
    private val appContext: Context,
) : VoiceRecorder {

    private val _state = MutableStateFlow<RecorderState>(RecorderState.Idle)
    override val state: StateFlow<RecorderState> = _state.asStateFlow()

    private val _amplitudes = MutableSharedFlow<Int>(extraBufferCapacity = 64)
    override val amplitudes = _amplitudes

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var tickerJob: Job? = null

    private var recorder: MediaRecorder? = null
    private var outputFile: File? = null
    private var startedAtMs: Long = 0L
    private val captured = mutableListOf<Int>()

    @SuppressLint("NewApi")
    override fun start(outputFile: File) {
        if (_state.value is RecorderState.Recording) return
        captured.clear()
        this.outputFile = outputFile
        val rec = newRecorder().apply {
            setAudioSource(MediaRecorder.AudioSource.MIC)
            setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            setAudioChannels(1)
            setAudioSamplingRate(44_100)
            setAudioEncodingBitRate(64_000)
            setOutputFile(outputFile.absolutePath)
        }
        try {
            rec.prepare()
            rec.start()
        } catch (e: Exception) {
            runCatching { rec.release() }
            recorder = null
            _state.value = RecorderState.Error(VoiceError.RecorderUnavailable)
            return
        }
        recorder = rec
        startedAtMs = System.currentTimeMillis()
        _state.value = RecorderState.Recording(0L)
        startTicker()
    }

    private fun startTicker() {
        tickerJob?.cancel()
        tickerJob = scope.launch {
            while (isActive) {
                delay(RecorderLimits.AMPLITUDE_CADENCE_MS)
                val rec = recorder ?: break
                val amp = runCatching { rec.maxAmplitude }.getOrDefault(0)
                captured += amp
                _amplitudes.tryEmit(amp)
                val elapsed = System.currentTimeMillis() - startedAtMs
                _state.value = RecorderState.Recording(elapsed)
                if (RecorderLimits.shouldAutoStop(elapsed)) {
                    stop()
                    break
                }
            }
        }
    }

    override fun stop(): RecordingResult? {
        val rec = recorder ?: return null
        tickerJob?.cancel()
        tickerJob = null
        val durationMs = RecorderLimits.clampDuration(System.currentTimeMillis() - startedAtMs)
        val finalized = runCatching {
            rec.stop()
        }
        runCatching { rec.release() }
        recorder = null
        val file = outputFile
        if (finalized.isFailure || file == null || !RecorderLimits.isKeepable(durationMs)) {
            file?.delete()
            outputFile = null
            _state.value = if (finalized.isFailure) {
                RecorderState.Error(VoiceError.RecorderUnavailable)
            } else {
                RecorderState.Error(VoiceError.TooShort)
            }
            return null
        }
        val result = RecordingResult(file = file, durationMs = durationMs, amplitudes = captured.toList())
        _state.value = RecorderState.Stopped(result)
        return result
    }

    override fun cancel() {
        tickerJob?.cancel()
        tickerJob = null
        runCatching { recorder?.stop() }
        runCatching { recorder?.release() }
        recorder = null
        outputFile?.delete()
        outputFile = null
        captured.clear()
        _state.value = RecorderState.Idle
    }

    override fun release() {
        cancel()
        scope.cancel()
    }

    @Suppress("DEPRECATION")
    private fun newRecorder(): MediaRecorder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            MediaRecorder(appContext)
        } else {
            MediaRecorder()
        }
}
