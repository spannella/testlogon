import { newsfeedSchedulingUiEnabled } from "@/lib/featureFlags";
import { ScheduledPostsPanel } from "./ScheduledPostsPanel";
import { FeedTimeline } from "./FeedTimeline";

export function NewsFeed() {
  const schedulingUiEnabled = newsfeedSchedulingUiEnabled;
  return (
    <div className="space-y-4">
      <FeedTimeline showComposer />
      {schedulingUiEnabled ? <ScheduledPostsPanel /> : null}
    </div>
  );
}
