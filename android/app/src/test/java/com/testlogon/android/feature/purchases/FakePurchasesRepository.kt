package com.testlogon.android.feature.purchases

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.purchases.Money
import com.testlogon.android.data.purchases.OrderStatus
import com.testlogon.android.data.purchases.PurchaseDetail
import com.testlogon.android.data.purchases.PurchaseListItem
import com.testlogon.android.data.purchases.PurchasesRepository
import java.math.BigDecimal

/**
 * AND-222 — in-memory [PurchasesRepository] fake for the purchases feature tests. Records the search
 * queries it receives and serves configurable list/search/detail results. Builder helpers are named
 * sampleItem/sampleDetail (not list/search/detail) so they never collide with the interface members.
 */
class FakePurchasesRepository(
    var listResult: ApiResult<List<PurchaseListItem>> = ApiResult.Success(emptyList()),
    var searchResult: ApiResult<List<PurchaseListItem>> = ApiResult.Success(emptyList()),
    var detailResult: ApiResult<PurchaseDetail> = ApiResult.Success(sampleDetail()),
) : PurchasesRepository {

    val searchQueries = mutableListOf<String>()
    var listCalls = 0
    var detailCalls = 0

    override suspend fun list(limit: Int, status: String?): ApiResult<List<PurchaseListItem>> {
        listCalls++
        return listResult
    }

    override suspend fun search(query: String, limit: Int): ApiResult<List<PurchaseListItem>> {
        searchQueries += query
        return searchResult
    }

    override suspend fun detail(txnId: String): ApiResult<PurchaseDetail> {
        detailCalls++
        return detailResult
    }

    // ECOMX-42 (B6): confirm-delivery; returns the configured detail result by default.
    var confirmReceivedResult: ApiResult<PurchaseDetail> = ApiResult.Success(sampleDetail())
    var confirmReceivedCalls = 0
    override suspend fun confirmReceived(txnId: String): ApiResult<PurchaseDetail> {
        confirmReceivedCalls++
        return confirmReceivedResult
    }

    companion object {
        fun sampleItem(
            id: String = "txn_1",
            status: OrderStatus = OrderStatus.Completed,
            createdAt: Long = 1748715724,
        ) = PurchaseListItem(
            id = id,
            status = status,
            money = Money(BigDecimal("42.99"), "USD"),
            createdAtEpochSec = createdAt,
            updatedAtEpochSec = createdAt,
            description = "Item $id",
        )

        fun sampleDetail(
            id: String = "txn_1",
            shipping: com.testlogon.android.data.purchases.PurchaseShipping? = null,
            cartId: String? = null,
        ) = PurchaseDetail(
            id = id,
            status = OrderStatus.Completed,
            money = Money(BigDecimal("49.57"), "USD"),
            createdAtEpochSec = 1748451851,
            updatedAtEpochSec = 1748455000,
            buyerId = "usr_1",
            version = 1,
            description = "Widget Pro",
            shipping = shipping,
            cartId = cartId,
        )
    }
}
