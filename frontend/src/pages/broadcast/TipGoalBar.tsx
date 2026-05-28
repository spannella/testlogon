import { Trophy } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import type { BroadcastTipGoal } from "@/api/endpoints/broadcast";

interface TipGoalBarProps {
  goals: BroadcastTipGoal[];
}

export function TipGoalBar({ goals }: TipGoalBarProps) {
  if (goals.length === 0) return null;

  return (
    <div className="space-y-2" data-testid="tip-goal-bar">
      {goals.map((goal) => {
        const pct = goal.target_cents > 0
          ? Math.min(100, Math.round((goal.current_cents / goal.target_cents) * 100))
          : 0;

        return (
          <div key={goal.goal_id} className="rounded-md border p-3 space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-1.5 font-medium">
                {goal.reached && <Trophy className="h-4 w-4 text-yellow-500" />}
                <span className="truncate max-w-[200px]">{goal.label}</span>
              </div>
              <span className="text-xs text-muted-foreground">
                ${(goal.current_cents / 100).toFixed(2)} / ${(goal.target_cents / 100).toFixed(2)}
              </span>
            </div>
            <Progress value={pct} className="h-2" />
            {goal.reached && (
              <p className="text-xs font-semibold text-yellow-600">REACHED!</p>
            )}
          </div>
        );
      })}
    </div>
  );
}
