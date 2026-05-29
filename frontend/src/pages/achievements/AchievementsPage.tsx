import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Trophy } from "lucide-react";
import { BadgeGrid } from "./BadgeGrid";
import { ProgressTracker } from "./ProgressTracker";
import { LeaderboardTable } from "./LeaderboardTable";

export default function AchievementsPage() {
  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <div className="flex items-center gap-3">
        <Trophy className="h-6 w-6" />
        <div>
          <h1 className="text-2xl font-bold">Achievements</h1>
          <p className="text-sm text-muted-foreground">
            Track your milestones and earn badges
          </p>
        </div>
      </div>

      <Tabs defaultValue="badges">
        <TabsList>
          <TabsTrigger value="badges">My Badges</TabsTrigger>
          <TabsTrigger value="progress">Progress</TabsTrigger>
          <TabsTrigger value="leaderboard">Leaderboard</TabsTrigger>
        </TabsList>
        <TabsContent value="badges">
          <BadgeGrid />
        </TabsContent>
        <TabsContent value="progress">
          <ProgressTracker />
        </TabsContent>
        <TabsContent value="leaderboard">
          <LeaderboardTable />
        </TabsContent>
      </Tabs>
    </div>
  );
}
