import { api } from "../client";
import type {
  CreateStoryReq,
  CreateStoryResp,
  StoryBarResp,
  UserStoriesResp,
  Story,
  StoryViewResp,
  StoryViewersResp,
  UserHighlightsResp,
  CreateHighlightGroupReq,
  CreateHighlightGroupResp,
} from "../types";

// ── Story CRUD ──────────────────────────────────────────────────

export const createStory = (body: CreateStoryReq) =>
  api.post<CreateStoryResp>("/ui/stories", body);

export const getStoryBar = () =>
  api.get<StoryBarResp>("/ui/stories/bar");

export const getUserStories = (userId: string) =>
  api.get<UserStoriesResp>(`/ui/stories/user/${userId}`);

export const getStory = (storyId: string) =>
  api.get<Story>(`/ui/stories/${storyId}`);

export const deleteStory = (storyId: string) =>
  api.del<{ ok: boolean }>(`/ui/stories/${storyId}`);

// ── View tracking ───────────────────────────────────────────────

export const recordStoryView = (storyId: string) =>
  api.post<StoryViewResp>(`/ui/stories/${storyId}/view`);

export const getStoryViewers = (storyId: string) =>
  api.get<StoryViewersResp>(`/ui/stories/${storyId}/viewers`);

// ── Highlights ──────────────────────────────────────────────────

export const highlightStory = (storyId: string, groupId?: string) =>
  api.post<{ ok: boolean }>(`/ui/stories/${storyId}/highlight`, { group_id: groupId });

export const unhighlightStory = (storyId: string) =>
  api.del<{ ok: boolean }>(`/ui/stories/${storyId}/highlight`);

export const getUserHighlights = (userId: string) =>
  api.get<UserHighlightsResp>(`/ui/stories/highlights/${userId}`);

export const createHighlightGroup = (body: CreateHighlightGroupReq) =>
  api.post<CreateHighlightGroupResp>("/ui/stories/highlights/groups", body);

export const deleteHighlightGroup = (groupId: string) =>
  api.del<{ ok: boolean }>(`/ui/stories/highlights/groups/${groupId}`);

// ── Upload helper ───────────────────────────────────────────────

export const uploadStoryImage = (file: File) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.upload<{ url: string; s3_key: string }>(
    "/ui/newsfeed/uploads/image",
    formData,
  );
};
