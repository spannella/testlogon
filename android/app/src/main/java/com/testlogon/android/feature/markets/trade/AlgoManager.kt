package com.testlogon.android.feature.markets.trade

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.feature.paper.PaperAccountStore
import com.testlogon.android.feature.paper.PaperEngine
import com.testlogon.android.feature.paper.PaperEngine.PaperOrder
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Client-side algo-order scheduler (TWAP + Iceberg). A process-wide [Singleton] that owns the live
 * coroutine timers, exposes the active-algos list as a [StateFlow], and persists every state change via
 * [AlgoOrderStore]. Children are placed through the SAME submit path the ticket uses — the real
 * [TradingRepository] for live orders, or the shared [PaperEngine] account in paper-mode — so an algo
 * never diverges from a hand-placed order.
 *
 * IMPORTANT — the timers live ONLY in this in-memory scope, so algos progress ONLY while the app process
 * is alive. On a cold start [restore] reloads the persisted snapshot but marks any still-RUNNING algo as
 * PAUSED (its timer is gone); the user can cancel it from the monitor. The monitor surfaces the
 * "client-side algos run only while the app is open" caveat.
 *
 * No WorkManager / no orphaned timers: cancel/pause cancel the per-algo [Job]; the scope is a
 * SupervisorJob so one failing child never tears down the others.
 */
@Singleton
class AlgoManager @Inject constructor(
    private val repository: TradingRepository,
    private val paperAccountStore: PaperAccountStore,
    private val algoOrderStore: AlgoOrderStore,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val jobs = ConcurrentHashMap<String, Job>()
    private val paperLock = Mutex()   // serialize paper-account read-modify-write across concurrent algos
    private var restored = false
    private var seq = 0

    private val _algos = MutableStateFlow<List<AlgoOrder>>(emptyList())
    val algos: StateFlow<List<AlgoOrder>> = _algos.asStateFlow()

    /** Reload persisted algos once; still-RUNNING ones become PAUSED (their timers didn't survive). */
    fun restore() {
        if (restored) return
        restored = true
        scope.launch {
            val persisted = algoOrderStore.load()
            val healed = persisted.map { if (it.status == AlgoStatus.RUNNING) it.copy(status = AlgoStatus.PAUSED, nextFireAtMs = null, message = "Paused (app restarted)") else it }
            _algos.value = healed
            persist()
        }
    }

    // ---- start ----

    /**
     * Start a TWAP algo: [totalQty] over [slices] children spaced across [durationMs]. [refPrice] is used
     * to fill paper children (captured now, since the manager has no live book). Returns the new algo id,
     * or null when the inputs are degenerate.
     */
    fun startTwap(
        symbolId: Int,
        symbolLabel: String,
        side: OrderSide,
        totalQty: Long,
        slices: Int,
        durationMs: Long,
        limitPrice: Long?,
        paperMode: Boolean,
        refPrice: Long?,
    ): String? {
        val schedule = OrderCalc.twapSchedule(totalQty, slices, durationMs)
        if (schedule.isEmpty()) return null
        val id = newId("twap")
        val interval = if (slices > 0) (durationMs.coerceAtLeast(0L) / slices) else 0L
        val algo = AlgoOrder(
            id = id, kind = AlgoKind.TWAP, symbolId = symbolId, symbolLabel = symbolLabel, side = side,
            totalQty = totalQty, limitPrice = limitPrice, paperMode = paperMode,
            slices = slices, durationMs = durationMs, sliceIntervalMs = interval,
            childrenTotal = schedule.size, createdTsMs = now(),
            nextFireAtMs = now(), status = AlgoStatus.RUNNING, message = "Started",
        )
        upsert(algo)
        launchTwap(algo, schedule, refPrice)
        return id
    }

    /**
     * Start an Iceberg algo: place one [visibleQty] clip at a time (last clip = remainder), replenishing
     * the next after [clipIntervalMs] (a client-side stand-in for "prior clip filled" — the manager has no
     * live fill feed). Returns the new algo id, or null when inputs are degenerate.
     */
    fun startIceberg(
        symbolId: Int,
        symbolLabel: String,
        side: OrderSide,
        totalQty: Long,
        visibleQty: Long,
        clipIntervalMs: Long,
        limitPrice: Long?,
        paperMode: Boolean,
        refPrice: Long?,
    ): String? {
        val clips = OrderCalc.icebergClips(totalQty, visibleQty)
        if (clips.isEmpty()) return null
        val id = newId("ice")
        val algo = AlgoOrder(
            id = id, kind = AlgoKind.ICEBERG, symbolId = symbolId, symbolLabel = symbolLabel, side = side,
            totalQty = totalQty, limitPrice = limitPrice, paperMode = paperMode,
            visibleQty = visibleQty, sliceIntervalMs = clipIntervalMs,
            childrenTotal = clips.size, createdTsMs = now(),
            nextFireAtMs = now(), status = AlgoStatus.RUNNING, message = "Started",
        )
        upsert(algo)
        launchIceberg(algo, clips, clipIntervalMs, refPrice)
        return id
    }

    // ---- controls ----

    /** Pause a RUNNING algo (cancels its timer; keeps progress). No-op if terminal. */
    fun pause(id: String) {
        val a = _algos.value.firstOrNull { it.id == id } ?: return
        if (a.isTerminal || a.status == AlgoStatus.PAUSED) return
        jobs.remove(id)?.cancel()
        upsert(a.copy(status = AlgoStatus.PAUSED, nextFireAtMs = null, message = "Paused"))
    }

    /** Resume a PAUSED algo from where it left off (fires the remaining children on the same cadence). */
    fun resume(id: String, refPrice: Long? = null) {
        val a = _algos.value.firstOrNull { it.id == id } ?: return
        if (a.status != AlgoStatus.PAUSED) return
        when (a.kind) {
            AlgoKind.TWAP -> {
                val remainingSchedule = OrderCalc.twapSchedule(a.remainingQty, (a.childrenTotal - a.childrenDone).coerceAtLeast(1), a.durationMs)
                if (remainingSchedule.isEmpty()) { complete(a); return }
                upsert(a.copy(status = AlgoStatus.RUNNING, nextFireAtMs = now(), message = "Resumed"))
                launchTwap(a.copy(status = AlgoStatus.RUNNING), remainingSchedule, refPrice, resuming = true)
            }
            AlgoKind.ICEBERG -> {
                val clips = OrderCalc.icebergClips(a.remainingQty, a.visibleQty)
                if (clips.isEmpty()) { complete(a); return }
                upsert(a.copy(status = AlgoStatus.RUNNING, nextFireAtMs = now(), message = "Resumed"))
                launchIceberg(a.copy(status = AlgoStatus.RUNNING), clips, a.sliceIntervalMs, refPrice, resuming = true)
            }
        }
    }

    /** Cancel an algo (cancels its timer; marks CANCELLED). Children already placed are NOT recalled. */
    fun cancel(id: String) {
        val a = _algos.value.firstOrNull { it.id == id } ?: return
        jobs.remove(id)?.cancel()
        if (a.isTerminal) return
        upsert(a.copy(status = AlgoStatus.CANCELLED, nextFireAtMs = null, message = "Cancelled (${a.placedQty}/${a.totalQty} placed)"))
    }

    /** Drop all terminal algos from the list + persistence (monitor "clear finished"). */
    fun clearFinished() {
        _algos.update { list -> list.filterNot { it.isTerminal } }
        persist()
    }

    // ---- timers ----

    private fun launchTwap(algo: AlgoOrder, schedule: List<OrderCalc.TwapSlice>, refPrice: Long?, resuming: Boolean = false) {
        jobs.remove(algo.id)?.cancel()
        val job = scope.launch {
            var prevOffset = 0L
            for (slice in schedule) {
                val wait = (slice.offsetMs - prevOffset).coerceAtLeast(0L)
                prevOffset = slice.offsetMs
                // publish the next-fire time for the countdown
                mutate(algo.id) { it.copy(nextFireAtMs = now() + wait) }
                if (wait > 0L) delay(wait)
                if (!isActive) return@launch
                val ok = placeChild(algo.id, slice.qty, refPrice)
                mutate(algo.id) { it.copy(childrenDone = it.childrenDone + 1, placedQty = it.placedQty + if (ok) slice.qty else 0L, message = if (ok) "Slice ${it.childrenDone + 1}/${it.childrenTotal} placed (${slice.qty})" else "Slice rejected") }
            }
            finalizeIfDone(algo.id)
        }
        jobs[algo.id] = job
    }

    private fun launchIceberg(algo: AlgoOrder, clips: List<Long>, clipIntervalMs: Long, refPrice: Long?, resuming: Boolean = false) {
        jobs.remove(algo.id)?.cancel()
        val job = scope.launch {
            for ((i, clip) in clips.withIndex()) {
                if (!isActive) return@launch
                val ok = placeChild(algo.id, clip, refPrice)
                mutate(algo.id) { it.copy(childrenDone = it.childrenDone + 1, placedQty = it.placedQty + if (ok) clip else 0L, message = if (ok) "Clip ${it.childrenDone + 1}/${it.childrenTotal} placed ($clip)" else "Clip rejected") }
                // replenish the next clip after the interval (stand-in for "prior clip filled")
                if (i < clips.lastIndex) {
                    val wait = clipIntervalMs.coerceAtLeast(0L)
                    mutate(algo.id) { it.copy(nextFireAtMs = now() + wait) }
                    if (wait > 0L) delay(wait)
                }
            }
            finalizeIfDone(algo.id)
        }
        jobs[algo.id] = job
    }

    private suspend fun finalizeIfDone(id: String) {
        val a = _algos.value.firstOrNull { it.id == id } ?: return
        if (a.status == AlgoStatus.RUNNING) complete(a)
        jobs.remove(id)
    }

    private fun complete(a: AlgoOrder) =
        upsert(a.copy(status = AlgoStatus.DONE, nextFireAtMs = null, message = "Done (${a.placedQty}/${a.totalQty} placed)"))

    // ---- child placement (shared submit path) ----

    /** Place one child of [qty] for algo [id]. Returns true when accepted. Respects paper-mode. */
    private suspend fun placeChild(id: String, qty: Long, refPrice: Long?): Boolean {
        val a = _algos.value.firstOrNull { it.id == id } ?: return false
        if (qty <= 0L) return false
        return if (a.paperMode) placePaperChild(a, qty, refPrice) else placeRealChild(a, qty)
    }

    private suspend fun placeRealChild(a: AlgoOrder, qty: Long): Boolean {
        val isMarket = a.limitPrice == null
        val price = a.limitPrice ?: 0L
        val clordid = "a${System.currentTimeMillis()}${seq++ % 100}"
        return when (val r = repository.placeOrder(a.symbolId, a.side, price, qty, clordid, market = if (isMarket) true else null)) {
            is ApiResult.Success -> r.data.accepted
            else -> false
        }
    }

    private suspend fun placePaperChild(a: AlgoOrder, qty: Long, refPrice: Long?): Boolean = paperLock.withLock {
        val fillPrice = a.limitPrice ?: refPrice ?: return false
        if (fillPrice <= 0L) return false
        val acct = paperAccountStore.load() ?: PaperEngine.newAccount(PAPER_STARTING_CASH)
        val order = PaperOrder(
            id = "algo-${a.id}-${System.currentTimeMillis()}",
            symbolId = a.symbolId,
            side = a.side,
            type = if (a.limitPrice == null) PaperOrderType.MARKET else PaperOrderType.LIMIT,
            qty = qty,
            limitPrice = a.limitPrice,
            createdTsMs = System.currentTimeMillis(),
        )
        val after = PaperEngine.placeOrder(acct, order, fillPrice)
        paperAccountStore.save(after)
        after !== acct
    }

    // ---- state plumbing ----

    private fun upsert(algo: AlgoOrder) {
        _algos.update { list ->
            val idx = list.indexOfFirst { it.id == algo.id }
            if (idx >= 0) list.toMutableList().also { it[idx] = algo } else list + algo
        }
        persist()
    }

    private fun mutate(id: String, block: (AlgoOrder) -> AlgoOrder) {
        _algos.update { list -> list.map { if (it.id == id) block(it) else it } }
        persist()
    }

    private fun persist() {
        val snapshot = _algos.value
        scope.launch { algoOrderStore.save(snapshot) }
    }

    private fun newId(prefix: String) = "$prefix-${System.currentTimeMillis()}-${seq++}"
    private fun now() = System.currentTimeMillis()

    private companion object {
        const val PAPER_STARTING_CASH = 100_000L
    }
}
