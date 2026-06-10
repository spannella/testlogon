package com.testlogon.android.data.messaging

import okhttp3.ResponseBody
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import retrofit2.http.Streaming

/**
 * AND-120 — Retrofit interface for the TestLogon messaging surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * cookies, Authorization and `X-CSRF-Token` are attached by the core-network interceptor chain.
 * All methods are `suspend` and return the typed DTO body; non-2xx surfaces as
 * `retrofit2.HttpException`.
 *
 * Endpoints verified against reference/src/api/endpoints/messaging.ts and OpenAPI:
 *  - config           -> GET  messaging/config                                (op messaging_config)
 *  - listConversations-> GET  messaging/conversations                        (BARE array, no params)
 *  - getConversation  -> GET  messaging/conversations/{id}
 *  - listMessages     -> GET  messaging/conversations/{id}/messages?limit=&before= (BARE array)
 *  - sendMessage      -> POST messaging/conversations/{id}/messages          (200 MessageOut)
 *  - markRead         -> POST messaging/conversations/{id}/read              (empty 200 body)
 *
 * Reverse history: pass the oldest loaded message id/timestamp as `before`; a short/empty array
 * signals end-of-history (there is no next_cursor).
 */
interface MessagingApi {

    /** Messaging feature config (boolean feature flags). Idempotent GET. */
    @GET("messaging/config")
    suspend fun config(): MessagingConfigDto

    /** Full conversation list (bare array, NOT paged). Idempotent GET. */
    @GET("messaging/conversations")
    suspend fun listConversations(): List<ConversationDto>

    /** Single conversation by id. Idempotent GET. */
    @GET("messaging/conversations/{id}")
    suspend fun getConversation(@Path("id") id: String): ConversationDto

    /** Messages in a conversation (bare array); reverse history via `before`. Idempotent GET. */
    @GET("messaging/conversations/{id}/messages")
    suspend fun listMessages(
        @Path("id") id: String,
        @Query("limit") limit: Int? = null,
        @Query("before") before: String? = null,
    ): List<MessageDto>

    /** Send a text message; returns the persisted MessageOut (HTTP 200). */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages")
    suspend fun sendMessage(
        @Path("id") id: String,
        @Body body: SendTextMessageReq,
    ): MessageDto

    /** Mark a conversation read up to a message id / timestamp. Empty 200 body. */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/read")
    suspend fun markRead(
        @Path("id") id: String,
        @Body body: MarkReadReq,
    )

    /**
     * Find-or-create a 1:1 DM with a peer user. Idempotent by participant pair server-side:
     * returns the existing conversation if one exists, else a freshly created one (HTTP 200,
     * ConversationOut). State-changing POST so it carries the CSRF header via the interceptor chain.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/dm/find-or-create")
    suspend fun findOrCreateDm(@Body body: FindOrCreateDmReq): ConversationDto

    /**
     * AND-130 — presign an image upload for a conversation. Body = SendImagePresignIn
     * {content_type, filename}; returns PresignOut {upload_url, bucket, key, content_type}.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/images/presign")
    suspend fun presignImage(
        @Path("id") id: String,
        @Body body: ImagePresignReq,
    ): ImagePresignResp

    /**
     * AND-130 — create an image message referencing the uploaded object by bucket+key. Returns the
     * persisted MessageOut (kind="image"). There is NO confirm step and NO client_msg_id.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/image")
    suspend fun createImageMessage(
        @Path("id") id: String,
        @Body body: CreateImageMessageReq,
    ): MessageDto

    /**
     * AND-131 — share an existing library video into a conversation. Body =
     * CreateVideoShareMessageIn {video_id, text?, send_at?}; returns MessageOut (kind="video_share").
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/video-share")
    suspend fun createVideoShareMessage(
        @Path("id") id: String,
        @Body body: CreateVideoShareReq,
    ): MessageDto

    /** AND-131 — list the current user's own videos for the share picker. Idempotent GET. */
    @GET("ui/videos")
    suspend fun listMyVideos(
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): VideoListRespDto

    /**
     * AND-132 — create a file message referencing an uploaded object by its VFS `path` (the storage
     * key returned by the fs complete-upload). Returns MessageOut (kind="file"). Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/file")
    suspend fun createFileMessage(
        @Path("id") id: String,
        @Body body: CreateFileMessageReq,
    ): MessageDto

    /**
     * AND-132 — share an EXISTING owned file (by `file_path`) into a conversation; no bytes upload.
     * Body = CreateFileShareMessageIn; returns MessageOut (kind="file_share").
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/file-share")
    suspend fun createFileShareMessage(
        @Path("id") id: String,
        @Body body: CreateFileShareReq,
    ): MessageDto

    /**
     * AND-132 — create a single-use download grant for a once-media attachment. Empty body;
     * keyed by message_id. Non-idempotent (NOT auto-retried). Returns AttachmentGrantOut.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/{messageId}/attachment/grant")
    suspend fun createAttachmentGrant(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): AttachmentGrantResp

    /**
     * AND-132 — record consumption for view_once/listen_once policies. `grant_token` is a QUERY
     * param; the body carries the client-generated attempt id + trigger. Returns metadata, NOT bytes.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/{messageId}/attachment/consume")
    suspend fun consumeAttachment(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Query("grant_token") grantToken: String,
        @Body body: ConsumeAttachmentReq,
    ): ConsumeAttachmentResp

    /**
     * AND-132 — stream the raw attachment bytes for a granted message. `grant_token` is a query
     * param. @Streaming so the body is not buffered into memory (chunked copy in the downloader).
     */
    @Streaming
    @GET("messaging/conversations/{id}/messages/{messageId}/attachment")
    suspend fun downloadAttachment(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Query("grant_token") grantToken: String,
    ): ResponseBody

    /**
     * AND-133 — presign a voice-message upload. Server allocates the message_id + s3_key + upload_url.
     * Body = PresignVoiceMessageRequest. Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/voice-message/presign")
    suspend fun presignVoice(
        @Path("id") id: String,
        @Body body: PresignVoiceReq,
    ): PresignVoiceResp

    /**
     * AND-133 — create the voice message record after the PUT. Body = CreateVoiceMessageRequest
     * (carries duration_seconds + waveform_data). Returns MessageOut (kind="voice_message").
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/voice-message")
    suspend fun createVoiceMessage(
        @Path("id") id: String,
        @Body body: CreateVoiceReq,
    ): MessageDto

    // ---- AND-134: voicemail ----

    /**
     * AND-134 — presign a voicemail upload. Server allocates message_id + s3_key + upload_url.
     * Body = PresignVoicemailRequest {call_id, content_type, size_bytes, mode}. Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/voicemail/presign")
    suspend fun presignVoicemail(
        @Path("id") id: String,
        @Body body: PresignVoicemailReq,
    ): PresignVoicemailResp

    /**
     * AND-134 — create the voicemail record after the PUT. Body = CreateVoicemailRequest. Returns
     * MessageOut (kind="voicemail"). A retry re-issues create with the SAME message_id/s3_key.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/voicemail")
    suspend fun createVoicemail(
        @Path("id") id: String,
        @Body body: CreateVoicemailReq,
    ): MessageDto

    // ---- AND-135: GIFs / stickers / custom emoji ----

    /** AND-135 — send a GIF message. Body = SendGifMessageIn; returns MessageOut (kind="gif", HTTP 201). */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/gif")
    suspend fun sendGifMessage(
        @Path("id") id: String,
        @Body body: SendGifMessageReq,
    ): MessageDto

    /** AND-135 — send a sticker message. Body = SendStickerMessageIn; returns MessageOut (kind="sticker"). */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/sticker")
    suspend fun sendStickerMessage(
        @Path("id") id: String,
        @Body body: SendStickerMessageReq,
    ): MessageDto

    /** AND-135 — GIF search via the configured provider. Bare array; idempotent GET. limit max 50. */
    @GET("ui/stickers/gifs/search")
    suspend fun searchGifs(
        @Query("q") q: String,
        @Query("limit") limit: Int = 20,
    ): List<GifSearchResultDto>

    /** AND-135 — trending GIFs (used when the query is empty). Bare array; idempotent GET. */
    @GET("ui/stickers/gifs/trending")
    suspend fun trendingGifs(
        @Query("limit") limit: Int = 20,
    ): List<GifSearchResultDto>

    /** AND-135 — list sticker collections (with their stickers). Idempotent GET. */
    @GET("ui/stickers/collections")
    suspend fun stickerCollections(): StickerCollectionListRespDto

    /** AND-135 — stickers for one collection (lazy fetch). Idempotent GET. */
    @GET("ui/stickers/collections/{collectionId}/stickers")
    suspend fun collectionStickers(
        @Path("collectionId") collectionId: String,
    ): StickerListRespDto

    /** AND-135 — workspace custom-emoji catalog. Idempotent GET. */
    @GET("ui/emojis/custom")
    suspend fun customEmoji(): CustomEmojiListRespDto

    /** AND-135 — resolve specific shortcodes to image urls (comma-joined). Idempotent GET. */
    @GET("ui/emojis/custom/resolve")
    suspend fun resolveShortcodes(
        @Query("codes") codes: String,
    ): ResolveShortcodesRespDto

    // ---- AND-136: meeting poll ----

    /**
     * AND-136 — create a meeting poll message. Body = CreateMeetingPollMessageIn; returns MessageOut
     * (kind="meeting_poll", HTTP 200). Slots/counts are fetched separately via [getMeetingPoll].
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/meeting-poll")
    suspend fun createMeetingPoll(
        @Path("id") id: String,
        @Body body: CreateMeetingPollReq,
    ): MessageDto

    /** AND-136 — authoritative poll state (per-slot counts + my_vote). Idempotent GET. */
    @GET("messaging/conversations/{id}/polls/{pollId}")
    suspend fun getMeetingPoll(
        @Path("id") id: String,
        @Path("pollId") pollId: String,
    ): MeetingPollStateDto

    /**
     * AND-136 — cast/change availability. Body = PollVoteIn {votes:{slot_id:state}}; response {ok}.
     * Re-fetch via [getMeetingPoll] to reconcile authoritative counts. Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/polls/{pollId}/vote")
    suspend fun voteMeetingPoll(
        @Path("id") id: String,
        @Path("pollId") pollId: String,
        @Body body: PollVoteReq,
    ): OkResp

    /**
     * AND-136 — confirm a winning slot (creator). Body = PollConfirmIn {slot_id}; response
     * {ok, event_id?}. Re-fetch to see status=confirmed. Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/polls/{pollId}/confirm")
    suspend fun confirmMeetingPoll(
        @Path("id") id: String,
        @Path("pollId") pollId: String,
        @Body body: PollConfirmReq,
    ): OkResp

    // ---- AND-137: countdown ----

    /**
     * AND-137 — send a countdown message. Body = SendCountdownMessageIn; returns MessageOut
     * (kind="countdown", HTTP 201). Non-idempotent POST (no client_id on the wire).
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/countdown")
    suspend fun sendCountdown(
        @Path("id") id: String,
        @Body body: SendCountdownMessageReq,
    ): MessageDto

    // ---- AND-139: tips / paid-unlockable / lottery ----

    /**
     * AND-139 — unlock a fixed-price paid message. Body = UnlockMessageIn {payment_method_id?};
     * returns UnlockOut (RECEIPT only — the revealed body is fetched separately). Non-idempotent.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/{messageId}/unlock")
    suspend fun unlockMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Body body: UnlockMessageReq,
    ): UnlockOutDto

    /**
     * AND-139 — tip a message. Body = SendTipIn {amount_cents, currency, note?, payment_method_id?};
     * returns TipOut. Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/{messageId}/tip")
    suspend fun tipMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Body body: SendTipReq,
    ): TipOutDto

    /**
     * AND-139 — single atomic lottery draw+reveal. EMPTY body (no schema). Conversation is NOT in
     * the path. Returns LotteryUnlockOut {selected_outcome, lock_state, unlocked_at}.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/messages/{messageId}/lottery/unlock")
    suspend fun unlockLottery(
        @Path("messageId") messageId: String,
        @Body body: Map<String, String> = emptyMap(),
    ): LotteryUnlockOutDto

    /** AND-139 — hydrate lottery state (idempotent GET). */
    @GET("messaging/messages/{messageId}/lottery")
    suspend fun getLottery(
        @Path("messageId") messageId: String,
    ): LotteryMessageOutDto

    /** AND-139 — re-fetch a single conversation's recent messages to reveal unlocked content. */
    // (re-uses listMessages; no separate per-message GET exists.)

    // ---- AND-140: reactions / pins / edits / delete / revoke / hide ----

    /**
     * AND-140 — toggle a reaction. ONE endpoint: body = ReactIn{emoji, action:"add"|"remove"}.
     * Response is an empty 200 (NOT a Message); the client reconciles by re-fetching the message.
     * Non-idempotent POST.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/{messageId}/reactions")
    suspend fun react(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Body body: ReactIn,
    )

    /** AND-140 — reactor details grouped by emoji. Idempotent GET. */
    @GET("messaging/conversations/{id}/messages/{messageId}/reactions/details")
    suspend fun reactionDetails(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
    ): ReactionDetailsOut

    /** AND-140 — pin a message. Returns MessageControlActionOut (ok/action/updated_at). Non-idempotent. */
    @POST("messaging/conversations/{id}/messages/{messageId}/pin")
    suspend fun pinMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
    ): MessageControlActionOut

    /** AND-140 — unpin a message (DELETE …/pin). Returns MessageControlActionOut. Non-idempotent. */
    @DELETE("messaging/conversations/{id}/messages/{messageId}/pin")
    suspend fun unpinMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
    ): MessageControlActionOut

    /** AND-140 — pinned-message refs for a conversation (cursor-paginated). Idempotent GET. */
    @GET("messaging/conversations/{id}/pins")
    suspend fun listPins(
        @Path("id") id: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): ConversationPinsPageOut

    /** AND-140 — edit a message body. PATCH body field is `text` (required). Returns MessageOut. */
    @Headers("Content-Type: application/json")
    @PATCH("messaging/conversations/{id}/messages/{messageId}")
    suspend fun editMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Body body: EditMessageIn,
    ): MessageDto

    /**
     * AND-140 — edit history. The OpenAPI response schema is unpinned (empty 200); we read the raw
     * body and parse tolerantly (bare array or {items:[...]}). Idempotent GET.
     */
    @GET("messaging/conversations/{id}/messages/{messageId}/edits")
    suspend fun editHistory(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Query("limit") limit: Int? = null,
    ): ResponseBody

    /** AND-140 — delete a message FOR ME. Returns an empty 200 (no tombstone payload). Non-idempotent. */
    @DELETE("messaging/conversations/{id}/messages/{messageId}")
    suspend fun deleteMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
    )

    /** AND-140 — revoke ("unsend") a message FOR ALL. DELETE …/revoke; returns MessageOut. Non-idempotent. */
    @DELETE("messaging/conversations/{id}/messages/{messageId}/revoke")
    suspend fun revokeMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
    ): MessageDto

    /** AND-140 — hide a message FOR ME (server-backed). Returns MessageControlActionOut. Non-idempotent. */
    @POST("messaging/conversations/{id}/messages/{messageId}/hide")
    suspend fun hideMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
    ): MessageControlActionOut

    /** AND-140 — unhide a message FOR ME (DELETE …/hide). Returns MessageControlActionOut. Non-idempotent. */
    @DELETE("messaging/conversations/{id}/messages/{messageId}/hide")
    suspend fun unhideMessage(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
    ): MessageControlActionOut

    /** AND-140 — the current user's hidden messages for a conversation (cursor-paginated). Idempotent GET. */
    @GET("messaging/conversations/{id}/hidden-messages")
    suspend fun listHiddenMessages(
        @Path("id") id: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): HiddenMessagesPageOut

    // ---- AND-147: read receipts / views ----

    /**
     * AND-147 — report that the local user viewed a message. Body = ViewMessageIn {viewed_at?}; returns
     * ViewAckOut. Idempotent server-side (repeat reports are coalesced). Non-blocking POST; the CSRF
     * header rides the shared interceptor chain.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages/{messageId}/view")
    suspend fun reportView(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Body body: ViewMessageIn = ViewMessageIn(),
    ): ViewAckOut

    /**
     * AND-147 — viewer roster for a message: a BARE JSON ARRAY of MessageViewOut (no envelope, no
     * cursor — only `limit`, default 200, max 500). Idempotent GET. Identity (name/avatar) is resolved
     * client-side from the participant cache.
     */
    @GET("messaging/conversations/{id}/messages/{messageId}/views")
    suspend fun getViews(
        @Path("id") id: String,
        @Path("messageId") messageId: String,
        @Query("limit") limit: Int = 200,
    ): List<MessageViewOut>
}
