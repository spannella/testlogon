import { useMutation, useQueryClient } from "@tanstack/react-query";
import { castVote, closePoll } from "@/api/endpoints/polls";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Clock, BarChart3, Check, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useAuthStore } from "@/stores/authStore";
import { invalidateFeedCaches } from "@/lib/feedCacheInvalidation";
import type {
  PollData,
  PollVoteCounts,
  PollMyVotes,
  PollQuestion,
} from "@/api/types";

interface PollCardProps {
  postId: string;
  pollData: PollData;
  voteCounts: PollVoteCounts;
  myVotes?: PollMyVotes | null;
  authorId: string;
}

export function PollCard({
  postId,
  pollData,
  voteCounts,
  myVotes,
  authorId,
}: PollCardProps) {
  const userId = useAuthStore((s) => s.userId);
  const isAuthor = userId === authorId;
  const queryClient = useQueryClient();

  const closeMut = useMutation({
    mutationFn: () => closePoll(postId),
    onSuccess: () => {
      toast.success("Poll closed");
      invalidateFeedCaches(queryClient);
    },
  });

  return (
    <div className="space-y-4 mt-3" data-testid="poll-card">
      {pollData.questions.map((question) => (
        <PollQuestionView
          key={question.question_id}
          postId={postId}
          question={question}
          counts={voteCounts?.[question.question_id] ?? {}}
          myVoteIds={myVotes?.[question.question_id] ?? []}
          closed={pollData.closed}
        />
      ))}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <BarChart3 className="h-3 w-3" />
        <span data-testid="poll-total-votes">
          {pollData.total_votes} total vote{pollData.total_votes !== 1 ? "s" : ""}
        </span>
        {pollData.closed && (
          <Badge variant="secondary" data-testid="poll-closed-badge">
            Closed
          </Badge>
        )}
        {pollData.closes_at && !pollData.closed && (
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            Closes {new Date(pollData.closes_at * 1000).toLocaleString()}
          </span>
        )}
        {isAuthor && !pollData.closed && (
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto text-xs h-6"
            onClick={() => closeMut.mutate()}
            disabled={closeMut.isPending}
            data-testid="close-poll-btn"
          >
            <X className="h-3 w-3 mr-1" />
            Close Poll
          </Button>
        )}
      </div>
    </div>
  );
}

function PollQuestionView({
  postId,
  question,
  counts,
  myVoteIds,
  closed,
}: {
  postId: string;
  question: PollQuestion;
  counts: Record<string, number>;
  myVoteIds: string[];
  closed: boolean;
}) {
  const queryClient = useQueryClient();
  const voteMut = useMutation({
    mutationFn: (optionId: string) =>
      castVote(postId, question.question_id, optionId),
    onSuccess: () => {
      invalidateFeedCaches(queryClient);
    },
  });

  const questionTotal = Object.values(counts).reduce(
    (sum, c) => sum + c,
    0
  );

  return (
    <div className="space-y-2">
      <p className="font-medium text-sm" data-testid="poll-question-text">
        {question.text}
      </p>
      {question.options.map((opt) => {
        const count = counts[opt.option_id] ?? 0;
        const pct =
          questionTotal > 0 ? (count / questionTotal) * 100 : 0;
        const selected = myVoteIds.includes(opt.option_id);

        return (
          <button
            key={opt.option_id}
            className={cn(
              "relative w-full h-10 rounded-md overflow-hidden text-left",
              "border transition-all",
              selected
                ? "border-primary bg-primary/5"
                : "border-border bg-muted/30",
              closed
                ? "cursor-default opacity-75"
                : "cursor-pointer hover:border-primary/50"
            )}
            onClick={() => !closed && voteMut.mutate(opt.option_id)}
            disabled={closed || voteMut.isPending}
            type="button"
            data-testid={`poll-option-${opt.option_id}`}
          >
            <div
              className={cn(
                "absolute inset-y-0 left-0 transition-[width] duration-500 ease-out",
                selected ? "bg-primary/20" : "bg-muted"
              )}
              style={{ width: `${pct}%` }}
            />
            <div className="relative flex items-center justify-between px-3 h-full">
              <span className="text-sm font-medium flex items-center gap-1.5">
                {selected && (
                  <Check className="h-3.5 w-3.5 text-primary" />
                )}
                {opt.text}
              </span>
              <span
                className="text-sm text-muted-foreground tabular-nums"
                data-testid={`poll-option-count-${opt.option_id}`}
              >
                {count} ({pct.toFixed(1)}%)
              </span>
            </div>
          </button>
        );
      })}
    </div>
  );
}
