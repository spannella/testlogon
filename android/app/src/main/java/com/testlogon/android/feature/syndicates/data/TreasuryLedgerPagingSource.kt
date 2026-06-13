package com.testlogon.android.feature.syndicates.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.network.syndicates.SyndicateApi
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException

/**
 * AND-356 - cursor-keyed Paging 3 source over the [SyndicateApi] treasury endpoint's inline ledger for one
 * syndicate. Mirrors the AND-332 FilesPagingSource idiom (network-only, forward-only).
 *
 * The treasury endpoint carries both the summary and a page of the ledger; this source pages ONLY the
 * ledger (the summary is read separately for the in-memory header snapshot). Keys are the opaque
 * `next_cursor`; a null / blank cursor terminates pagination. DTO entries are mapped to the domain
 * (SyndicateTreasuryLedgerEntryOut.toDomain). HttpException / IOException become LoadResult.Error;
 * CancellationException is re-thrown. getRefreshKey returns null (re-anchors at the first page).
 *
 * ROOM CACHE DEFERRED: network-backed only - no Room cache, no migration this wave.
 */
class TreasuryLedgerPagingSource(
    private val api: SyndicateApi,
    private val syndicateId: String,
) : PagingSource<String, TreasuryEntry>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, TreasuryEntry> = try {
        val out = api.getTreasury(syndicateId = syndicateId, cursor = params.key)
        LoadResult.Page(
            data = out.ledger.map { it.toDomain() },
            prevKey = null,
            nextKey = out.nextCursor?.takeIf { it.isNotBlank() },
        )
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        LoadResult.Error(e)
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, TreasuryEntry>): String? = null
}
