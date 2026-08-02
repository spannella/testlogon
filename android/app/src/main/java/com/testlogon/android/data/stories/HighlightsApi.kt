package com.testlogon.android.data.stories

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * PAR-16 — dedicated Retrofit interface for the Story Highlights surface.
 *
 * Kept separate from [StoriesApi] so the highlights feature never touches the story tray/viewer/create
 * contracts. Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * session cookies, Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor
 * chain.
 *
 * Verified contract (app/routers/stories.py + app/services/stories.py on the backend; iOS
 * CoreNetwork/StoriesApi.swift + CoreModel/StoriesDTOs.swift reference):
 *  - GET    ui/stories/highlights/{user_id}            -> UserHighlightsResp { groups: HighlightGroup[] }
 *  - POST   ui/stories/highlights/groups               -> CreateHighlightGroupResp (HTTP 201)
 *  - DELETE ui/stories/highlights/groups/{group_id}    -> { ok }
 *  - POST   ui/stories/{story_id}/highlight            -> { ok } (body { group_id? })
 *  - DELETE ui/stories/{story_id}/highlight            -> { ok }
 *
 * Ownership for the three mutations is enforced server-side from the UI session `user_sub` (a non-owner
 * gets 403); the {user_id} path on the GET only scopes the read.
 */
interface HighlightsApi {

    @GET("ui/stories/highlights/{userId}")
    suspend fun getHighlights(@Path("userId") userId: String): UserHighlightsRespDto

    @Headers("Content-Type: application/json")
    @POST("ui/stories/highlights/groups")
    suspend fun createGroup(@Body body: CreateHighlightGroupReqDto): CreateHighlightGroupRespDto

    @DELETE("ui/stories/highlights/groups/{groupId}")
    suspend fun deleteGroup(@Path("groupId") groupId: String): HighlightActionRespDto

    /** Pin a story to a highlight group (group_id omitted = default/ungrouped). */
    @Headers("Content-Type: application/json")
    @POST("ui/stories/{storyId}/highlight")
    suspend fun pin(
        @Path("storyId") storyId: String,
        @Body body: AddStoryToHighlightReqDto,
    ): HighlightActionRespDto

    /** Unpin (remove from highlights) a story. */
    @DELETE("ui/stories/{storyId}/highlight")
    suspend fun unpin(@Path("storyId") storyId: String): HighlightActionRespDto
}
