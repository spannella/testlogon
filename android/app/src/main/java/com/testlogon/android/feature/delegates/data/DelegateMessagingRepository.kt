package com.testlogon.android.feature.delegates.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.DelegatePermission
import com.testlogon.android.core.model.delegates.canReadChat
import com.testlogon.android.core.model.delegates.canRespondMessages
import com.testlogon.android.core.network.delegates.DelegateMessagingApi
import com.testlogon.android.core.network.delegates.DelegatedConversationOut
import com.testlogon.android.core.network.delegates.DelegatedMessageOut
import com.testlogon.android.core.network.delegates.DelegatedSendMessageIn
import com.testlogon.android.core.network.error.ApiErrorParser
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-360 - the delegate-PATH MESSAGING overlay repository (manage-as-creator messaging).
 *
 * Every action: requires an active delegate context (else "not in delegate mode"); GATES on the typed
 * permission (PermissionDenied WITHOUT calling the API when absent); calls [DelegateMessagingApi] with the
 * active creatorId (attribution = @Path); and AUTO-EXITS on a 403. chat_read gates list / read;
 * chat_respond gates send. A sent message echoes the delegate attribution (sent_by_delegate /
 * delegate_display_name / delegate_tag); an encrypted thread may carry delegate_cannot_decrypt for the UI.
 */
@Singleton
class DelegateMessagingRepository @Inject constructor(
    private val api: DelegateMessagingApi,
    private val contextProvider: DelegationContextProvider,
    delegationRepository: DelegationRepository,
    errorParser: ApiErrorParser,
) {

    private val guard = DelegateGuard(
        context = contextProvider::current,
        errorParser = errorParser,
        autoExit = DelegateAutoExit(contextProvider, delegationRepository),
    )

    /** True when the current context may LIST / READ conversations + messages (chat_read). */
    fun canRead(): Boolean = contextProvider.current().canReadChat()

    /** True when the current context may SEND messages (chat_respond). */
    fun canRespond(): Boolean = contextProvider.current().canRespondMessages()

    /** GET the managed creator's conversations (BARE ARRAY). Gated by chat_read. */
    suspend fun conversations(): ApiResult<List<DelegatedConversationOut>> =
        guard.gated(DelegatePermission.CHAT_READ) { creatorId -> api.conversations(creatorId) }

    /** GET the messages in one conversation (BARE ARRAY). Gated by chat_read. */
    suspend fun messages(conversationId: String): ApiResult<List<DelegatedMessageOut>> =
        guard.gated(DelegatePermission.CHAT_READ) { creatorId -> api.messages(creatorId, conversationId) }

    /** POST a message into a conversation on the creator's behalf. Gated by chat_respond. */
    suspend fun send(
        conversationId: String,
        text: String,
        replyToMessageId: String? = null,
    ): ApiResult<DelegatedMessageOut> =
        guard.gated(DelegatePermission.CHAT_RESPOND) { creatorId ->
            api.send(
                creatorId,
                conversationId,
                DelegatedSendMessageIn(text = text, replyToMessageId = replyToMessageId),
            )
        }
}
