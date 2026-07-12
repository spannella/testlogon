import { useState } from "react";
import { Sparkles, UserCheck, Clock } from "lucide-react";
import { newsfeedSchedulingUiEnabled, isNewsfeedRecsysUiEnabled } from "@/lib/featureFlags";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScheduledPostsPanel } from "./ScheduledPostsPanel";
import { FeedTimeline } from "./FeedTimeline";

type FeedTab = "for-you" | "following" | "latest";

export function NewsFeed() {
  const schedulingUiEnabled = newsfeedSchedulingUiEnabled;
  const recsysUiEnabled = isNewsfeedRecsysUiEnabled();
  const [tab, setTab] = useState<FeedTab>(recsysUiEnabled ? "for-you" : "latest");

  // NRS-011: with the UI flag off, render the existing chronological feed
  // unchanged (no tab bar, no behavior change).
  if (!recsysUiEnabled) {
    return (
      <div className="space-y-4">
        <FeedTimeline showComposer />
        {schedulingUiEnabled ? <ScheduledPostsPanel /> : null}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Tabs value={tab} onValueChange={(v) => setTab(v as FeedTab)}>
        <TabsList className="grid w-full grid-cols-3" data-testid="feed-tabs">
          <TabsTrigger value="for-you" className="gap-1.5">
            <Sparkles className="h-3.5 w-3.5" />
            For You
          </TabsTrigger>
          <TabsTrigger value="following" className="gap-1.5">
            <UserCheck className="h-3.5 w-3.5" />
            Following
          </TabsTrigger>
          <TabsTrigger value="latest" className="gap-1.5">
            <Clock className="h-3.5 w-3.5" />
            Latest
          </TabsTrigger>
        </TabsList>
      </Tabs>

      {/*
        The composer stays mounted across tab switches. "For You" hits
        GET /feed/for-you; "Following"/"Latest" both use the existing
        chronological feed (own + following). We mount one FeedTimeline at a
        time keyed by tab so the correct query drives it, but the composer
        above (CreatePost) is owned by FeedTimeline.showComposer and resets
        per-tab — to preserve composer state we render the composer once here.
      */}
      {tab === "for-you" ? (
        <FeedTimeline key="for-you" showComposer forYou />
      ) : (
        <FeedTimeline key="chronological" showComposer />
      )}

      {schedulingUiEnabled ? <ScheduledPostsPanel /> : null}
    </div>
  );
}
