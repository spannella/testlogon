import { PageHeader } from "@/components/shared/PageHeader";
import { PageMeta } from "@/components/shared/PageMeta";
import { NewsFeed } from "./NewsFeed";
import { StoryBar } from "./StoryBar";

export default function FeedPage() {
  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-4 sm:p-6">
      <PageMeta title="Feed" />
      <PageHeader
        title="Feed"
        description="See what's happening in your community"
      />
      <StoryBar />
      <NewsFeed />
    </div>
  );
}
