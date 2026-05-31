import type { LiveQaQuestion } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ThumbsUp, Star, Check, X, Trash2, Pin } from "lucide-react";

interface LiveQaQuestionCardProps {
  question: LiveQaQuestion;
  isModerator?: boolean;
  hasVoted?: boolean;
  onVote?: () => void;
  onFeature?: () => void;
  onAnswer?: () => void;
  onDismiss?: () => void;
  onPin?: () => void;
  onRemove?: () => void;
}

export function LiveQaQuestionCard({
  question,
  isModerator = false,
  hasVoted = false,
  onVote,
  onFeature,
  onAnswer,
  onDismiss,
  onPin,
  onRemove,
}: LiveQaQuestionCardProps) {
  return (
    <div
      className="flex items-start gap-2 border-b p-3"
      data-testid="live-qa-question-card"
      data-question-id={question.question_id}
    >
      <div className="flex flex-col items-center">
        <Button
          variant={hasVoted ? "default" : "outline"}
          size="icon"
          className="h-8 w-8"
          onClick={onVote}
          aria-label="Upvote question"
        >
          <ThumbsUp className="h-4 w-4" />
        </Button>
        <span className="mt-1 text-xs font-medium" data-testid="live-qa-vote-count">
          {question.vote_count}
        </span>
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <p className="text-xs font-medium text-muted-foreground">
            {question.submitter_display_name}
          </p>
          {question.pinned && (
            <Badge variant="secondary" className="h-4 px-1 text-[10px]">
              Pinned
            </Badge>
          )}
          {question.status === "featured" && (
            <Badge className="h-4 px-1 text-[10px]">Featured</Badge>
          )}
        </div>
        <p className="mt-0.5 break-words text-sm">{question.text}</p>
        {isModerator && (
          <div className="mt-2 flex flex-wrap gap-1">
            {question.status === "pending" && (
              <Button size="sm" variant="outline" onClick={onFeature}>
                <Star className="mr-1 h-3 w-3" /> Feature
              </Button>
            )}
            {question.status === "featured" && (
              <Button size="sm" variant="outline" onClick={onAnswer}>
                <Check className="mr-1 h-3 w-3" /> Answered
              </Button>
            )}
            <Button size="sm" variant="ghost" onClick={onPin}>
              <Pin className="mr-1 h-3 w-3" /> {question.pinned ? "Unpin" : "Pin"}
            </Button>
            <Button size="sm" variant="ghost" onClick={onDismiss}>
              <X className="mr-1 h-3 w-3" /> Dismiss
            </Button>
            <Button size="sm" variant="ghost" onClick={onRemove}>
              <Trash2 className="mr-1 h-3 w-3" /> Remove
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
