package com.testlogon.android.feature.messaging.mass

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.mass.CreateCampaignDraft
import com.testlogon.android.data.messaging.mass.MassCampaign
import com.testlogon.android.data.messaging.mass.MassCampaignCreateResult
import com.testlogon.android.data.messaging.mass.MassCampaignPage
import com.testlogon.android.data.messaging.mass.MassMessageConfigRepository
import com.testlogon.android.data.messaging.mass.MassMessageRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import java.io.IOException

/** AND-160 — in-memory mass-message repository for ViewModel tests. */
class FakeMassMessageRepository : MassMessageRepository {

    var createResult: ApiResult<MassCampaignCreateResult> =
        ApiResult.NetworkError(IOException("default"))
    var cancelResult: ApiResult<MassCampaign> =
        ApiResult.NetworkError(IOException("default"))

    val createDrafts = mutableListOf<CreateCampaignDraft>()
    val cancelledIds = mutableListOf<String>()

    override fun campaignsPager(status: String?, mode: String?): Flow<PagingData<MassCampaign>> =
        flowOf(PagingData.empty())

    override suspend fun listPage(
        cursor: String?,
        limit: Int,
        status: String?,
        mode: String?,
    ): ApiResult<MassCampaignPage> = ApiResult.Success(MassCampaignPage(emptyList(), null))

    override suspend fun create(request: CreateCampaignDraft): ApiResult<MassCampaignCreateResult> {
        createDrafts += request
        return createResult
    }

    override suspend fun cancel(id: String, prior: MassCampaign?): ApiResult<MassCampaign> {
        cancelledIds += id
        return cancelResult
    }
}

/** AND-160 — configurable mass-send gate for tests. */
class FakeMassMessageConfigRepository(
    var enabled: Boolean = true,
) : MassMessageConfigRepository {
    override suspend fun isMassSendEnabled(): Boolean = enabled
}
