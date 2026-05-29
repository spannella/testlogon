import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getLeaderboard, getMyRank } from "@/api/endpoints/achievements";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function LeaderboardTable() {
  const [period, setPeriod] = useState("alltime");

  const { data: lbData, isLoading } = useQuery({
    queryKey: ["achievements", "leaderboard", period],
    queryFn: () => getLeaderboard({ period, limit: 50 }),
  });

  const { data: myRank } = useQuery({
    queryKey: ["achievements", "myrank", period],
    queryFn: () => getMyRank(period),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <Select value={period} onValueChange={setPeriod}>
          <SelectTrigger className="w-[180px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="weekly">Weekly</SelectItem>
            <SelectItem value="monthly">Monthly</SelectItem>
            <SelectItem value="alltime">All Time</SelectItem>
          </SelectContent>
        </Select>

        {myRank && myRank.rank != null && (
          <div className="text-sm text-muted-foreground">
            Your rank: #{myRank.rank} ({myRank.total_points} pts)
          </div>
        )}
      </div>

      {isLoading ? (
        <div className="text-muted-foreground">Loading leaderboard...</div>
      ) : (lbData?.entries ?? []).length === 0 ? (
        <p className="text-muted-foreground text-sm">
          No leaderboard entries yet.
        </p>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Leaderboard</CardTitle>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-muted-foreground">
                  <th className="text-left py-2 px-2">Rank</th>
                  <th className="text-left py-2 px-2">User</th>
                  <th className="text-right py-2 px-2">Points</th>
                  <th className="text-right py-2 px-2">Badges</th>
                </tr>
              </thead>
              <tbody>
                {(lbData?.entries ?? []).map((entry) => (
                  <tr
                    key={entry.user_sub}
                    className="border-b last:border-b-0"
                  >
                    <td className="py-2 px-2 font-medium">#{entry.rank}</td>
                    <td className="py-2 px-2">
                      {entry.display_name || entry.user_sub}
                    </td>
                    <td className="py-2 px-2 text-right">
                      {entry.total_points}
                    </td>
                    <td className="py-2 px-2 text-right">
                      {entry.achievement_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
